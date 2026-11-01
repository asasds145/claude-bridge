import { createExecutionContext, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env";
import { queueStub } from "../src/env";
import worker from "../src/index";
import type { BoxmcpQueue } from "../src/queue";
import { ipRateLimitMaterial, sha256Hex } from "../src/util";
import { REGISTER_SHARD_HEX } from "../src/queue";
import { resetSharedDurableState } from "./isolate";
import { waitForFreshRateWindow } from "./window";

// Matches vitest.config.ts ratelimits.MCP_IP_LIMITER.simple.limit. Production wrangler uses 600.
const TEST_IP_LIMIT = 8;
const BASE = "https://chief-bridge.test";

beforeEach(() => resetSharedDurableState());
afterEach(() => vi.restoreAllMocks());

function mcp(ip: string | null, authorization: string | null, path = "/mcp") {
  const headers = new Headers({ "content-type": "application/json", host: "chief-bridge.test" });
  if (ip !== null) headers.set("cf-connecting-ip", ip);
  if (authorization !== null) headers.set("authorization", authorization);
  return new Request(`${BASE}${path}`, { method: "POST", headers, body: "{}" });
}

function register(ip: string) {
  return new Request(`${BASE}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json", host: "chief-bridge.test", "cf-connecting-ip": ip },
    body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "none" }),
  });
}

async function call(req: Request, custom?: Env) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, (custom ?? env) as never, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

function unauthCount() {
  return runInDurableObject(queueStub(env as never), (inst: BoxmcpQueue) => {
    return (inst as unknown as { buckets: Map<string, { count: number }> }).buckets.get("mcp:unauth")?.count ?? 0;
  });
}

describe("IP rate limit binding", () => {
  it("normalizes IPv4 whole and IPv6 at /64", () => {
    expect(ipRateLimitMaterial("203.0.113.10")).toBe("4:203.0.113.10");
    expect(ipRateLimitMaterial("203.0.113.11")).not.toBe(ipRateLimitMaterial("203.0.113.10"));
    expect(ipRateLimitMaterial("2001:db8:1:2::1")).toBe("6:2001:db8:1:2");
    expect(ipRateLimitMaterial("2001:0db8:0001:0002:0:0:0:9")).toBe("6:2001:db8:1:2");
    expect(ipRateLimitMaterial("2001:db8:1:3::1")).toBe("6:2001:db8:1:3");
    expect(ipRateLimitMaterial("::ffff:192.0.2.1")).toBe("4:192.0.2.1");
    expect(ipRateLimitMaterial("::ffff:c000:201")).toBe("4:192.0.2.1");
  });

  it("returns 429 before the Durable Object once the address is over the limit", async () => {
    await waitForFreshRateWindow();
    const ip = "192.0.2.50";
    const statuses: number[] = [];
    for (let i = 0; i < TEST_IP_LIMIT; i++) {
      statuses.push((await call(mcp(ip, "Bearer not-a-token"))).status);
    }
    expect(statuses.every((s) => s === 401)).toBe(true);
    expect(await unauthCount()).toBe(TEST_IP_LIMIT);

    const blocked = await call(mcp(ip, "Bearer not-a-token", "/mcp/extra"));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`);
    expect(blocked.headers.get("retry-after")).toBe("60");
    // The over-limit request never reached the shared unauth bucket.
    expect(await unauthCount()).toBe(TEST_IP_LIMIT);

    const other = await call(mcp("192.0.2.51", "Bearer not-a-token"));
    expect(other.status).toBe(401);
    const noHeader = await call(mcp(ip, null));
    expect(noHeader.status).toBe(401);
    expect(await unauthCount()).toBe(TEST_IP_LIMIT + 1);
  }, 15_000);

  it("shares one IPv6 /64 and keeps a different prefix on its own budget", async () => {
    await waitForFreshRateWindow();
    const statuses: number[] = [];
    for (let i = 0; i < TEST_IP_LIMIT; i++) {
      statuses.push((await call(mcp("2001:db8:1:2::10", "Bearer not-a-token"))).status);
    }
    expect(statuses.every((s) => s === 401)).toBe(true);
    const samePrefix = await call(mcp("2001:0db8:0001:0002::99", "Bearer not-a-token"));
    expect(samePrefix.status).toBe(429);
    const otherPrefix = await call(mcp("2001:db8:1:3::10", "Bearer not-a-token"));
    expect(otherPrefix.status).toBe(401);
  }, 15_000);

  it("shares one fallback key when CF-Connecting-IP is absent", async () => {
    await waitForFreshRateWindow();
    const statuses: number[] = [];
    for (let i = 0; i < TEST_IP_LIMIT; i++) statuses.push((await call(mcp(null, `Bearer not-a-token-${i}`))).status);
    expect(statuses.every((s) => s === 401)).toBe(true);
    const blocked = await call(mcp(null, "Bearer still-no-ip"));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBe("60");
  }, 15_000);

  it("429s POST /oauth/register from a limited address without touching the DO", async () => {
    await waitForFreshRateWindow();
    const ip = "192.0.2.70";
    for (let i = 0; i < TEST_IP_LIMIT; i++) {
      const res = await call(register(ip));
      if (i < TEST_IP_LIMIT - 1) expect(res.status).not.toBe(500);
    }
    const shard = (await sha256Hex(ipRateLimitMaterial(ip))).slice(0, REGISTER_SHARD_HEX);
    const key = `register:${shard}`;
    await runInDurableObject(queueStub(env as never), (inst: BoxmcpQueue) => {
      (inst as unknown as { publicBuckets: Map<string, { count: number; resetAt: number }> }).publicBuckets.set(key, {
        count: 1,
        resetAt: Date.now() + 3_600_000,
      });
    });
    const blocked = await call(register(ip));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBe("60");
    const count = await runInDurableObject(queueStub(env as never), (inst: BoxmcpQueue) => {
      return (inst as unknown as { publicBuckets: Map<string, { count: number }> }).publicBuckets.get(key)?.count ?? 0;
    });
    // A call that reached the object would increment this under-limit shard. The IP limiter returns first.
    expect(count).toBe(1);
  }, 15_000);

  it("fails open when the binding is missing or throws, and does not log the error text", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    try {
      const live = env as unknown as Env;
      const missing = { ...live, MCP_IP_LIMITER: undefined };
      const allowed = await call(mcp("192.0.2.52", "Bearer not-a-token"), missing);
      expect(allowed.status).toBe(401);
      const missingLine = logs.map((line) => JSON.parse(line) as { rate_limiter?: string }).find((line) => line.rate_limiter === "missing");
      expect(missingLine).toMatchObject({ rate_limiter: "missing", route: "/mcp" });

      logs.length = 0;
      const broken = {
        ...live,
        MCP_IP_LIMITER: {
          limit: async () => {
            throw new Error("limiter-boom");
          },
        },
      } as Env;
      const still = await call(mcp("192.0.2.53", "Bearer not-a-token"), broken);
      expect(still.status).toBe(401);
      const errorLine = logs.map((line) => JSON.parse(line) as { rate_limiter?: string; error_class?: string }).find((line) => line.rate_limiter === "error");
      expect(errorLine).toMatchObject({ rate_limiter: "error", error_class: "Error", route: "/mcp" });
      expect(JSON.stringify(errorLine)).not.toContain("limiter-boom");
    } finally {
      spy.mockRestore();
    }
  });
});
