import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { queueStub } from "../src/env";
import { MCP_FORGE_PER_MIN, MCP_PREAUTH_PER_MIN } from "../src/index";
import { MAX_PUBLIC_BUCKETS, type BoxmcpQueue } from "../src/queue";
import { resetSharedDurableState } from "./isolate";

const KEY = "test-chief-key-not-a-secret";
type Buckets = Map<string, { count: number; resetAt: number }>;
const trustedOf = (inst: BoxmcpQueue) => (inst as unknown as { buckets: Buckets }).buckets;
const publicOf = (inst: BoxmcpQueue) => (inst as unknown as { publicBuckets: Buckets }).publicBuckets;

beforeEach(() => resetSharedDurableState());

describe("rate limit", () => {
  it("/chief 60/min → 61st is 429", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 61; i++) {
      const r = await exports.default.fetch(new Request("https://chief-bridge.test/chief/health", { headers: { authorization: `Bearer ${KEY}` } }));
      statuses.push(r.status);
    }
    expect(statuses.slice(0, 60).every((s) => s === 200)).toBe(true);
    expect(statuses[60]).toBe(429);
  });
  it("/oauth/register 5/h per IP shard → 6th is 429", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const r = await exports.default.fetch(
        new Request("https://chief-bridge.test/oauth/register", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.9" },
          body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "none" }),
        }),
      );
      statuses.push(r.status);
    }
    expect(statuses[5]).toBe(429);
    expect(statuses.slice(0, 5).every((s) => s !== 429)).toBe(true);
  });

  it("distinct Authorization headers do not each create a bucket", async () => {
    const stub = queueStub(env as never);
    const keys = () => runInDurableObject(stub, (inst: BoxmcpQueue) => [...trustedOf(inst).keys()]);
    const before = new Set(await keys());
    const statuses: number[] = [];
    for (let i = 0; i < 30; i++) {
      const r = await exports.default.fetch(
        new Request("https://chief-bridge.test/mcp", {
          method: "POST",
          headers: { authorization: `Bearer not-a-token-${i}`, "content-type": "application/json" },
          body: "{}",
        }),
      );
      statuses.push(r.status);
    }
    expect(statuses.every((s) => s === 401)).toBe(true);
    const added = (await keys()).filter((k) => !before.has(k));
    expect(added.every((k) => k === "mcp:unauth")).toBe(true);
    expect(added.length).toBeLessThanOrEqual(1);
    for (const k of added) {
      expect(k).not.toContain("not-a-token");
    }
  });

  it("parallel forged owner-shaped tokens cannot exceed the forge cap", async () => {
    const stub = queueStub(env as never);
    // Hold the trickle closed for the whole burst so the cap does not depend on how long the test runs.
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      (inst as unknown as { forgeTrickleAt: number }).forgeTrickleAt = Date.now() + 3_600_000;
    });
    const extra = 25;
    const responses = await Promise.all(
      Array.from({ length: MCP_FORGE_PER_MIN + extra }, (_, i) => {
        const grant = ("f" + i.toString().padStart(15, "0")).slice(0, 16);
        return exports.default.fetch(
          new Request("https://chief-bridge.test/mcp", {
            method: "POST",
            headers: {
              authorization: `Bearer github-12345:${grant}:${"s".repeat(32)}`,
              "content-type": "application/json",
            },
            body: "{}",
          }),
        );
      }),
    );
    const statuses = await Promise.all(responses.map((r) => r.status));
    const lookups = statuses.filter((s) => s === 401).length;
    const blocked = statuses.filter((s) => s === 429).length;
    expect(lookups).toBe(MCP_FORGE_PER_MIN);
    expect(blocked).toBe(extra);
    const limited = responses.find((r) => r.status === 429);
    expect(limited?.headers.get("www-authenticate") ?? "").toContain("resource_metadata=");
    expect(Number(limited?.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("charges malformed Authorization and /mcp descendants, not a non-API path", async () => {
    const stub = queueStub(env as never);
    const bucketsOf = (inst: BoxmcpQueue) => (inst as unknown as { buckets: Map<string, { count: number; resetAt: number }>; forgeTrickleAt: number });
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      const view = bucketsOf(inst);
      view.buckets.set("mcp:unauth", { count: MCP_PREAUTH_PER_MIN, resetAt: Date.now() + 60_000 });
      view.forgeTrickleAt = Date.now() + 3_600_000;
    });
    const base = "https://chief-bridge.test";
    const post = (path: string, authorization?: string) =>
      exports.default.fetch(
        new Request(base + path, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(authorization ? { authorization } : {}),
          },
          body: "{}",
        }),
      );
    // Provider bearer parse is case-insensitive. A lowercase scheme is still owner-shaped, so a full unauth bucket must not 429 it.
    const lower = await post("/mcp", `bearer github-12345:${"c".repeat(16)}:${"d".repeat(32)}`);
    expect(lower.status).toBe(401);
    const spaced = await post("/mcp", "Bearer a:b:c d");
    expect(spaced.status).toBe(429);
    expect(spaced.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`);
    expect(Number(spaced.headers.get("retry-after"))).toBeGreaterThan(0);
    const child = await post("/mcp/extra", "Bearer not-a-token");
    expect(child.status).toBe(429);
    const bare = await post("/mcp");
    expect(bare.status).toBe(401);
    expect(bare.headers.get("www-authenticate") ?? "").toContain("resource_metadata=");
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      bucketsOf(inst).buckets.set("mcp:forge", { count: MCP_FORGE_PER_MIN, resetAt: Date.now() + 60_000 });
    });
    const notApi = await post("/mcpx", `Bearer github-12345:${"a".repeat(16)}:${"b".repeat(32)}`);
    expect(notApi.status).toBe(404);
  });

  it("a refund from an old forge window does not credit the current window", async () => {
    const stub = queueStub(env as never);
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue) => {
      const first = await inst.reserveForge("a".repeat(16), 60, 60_000);
      if (first.action !== "reserved" || !first.refundable) return { ok: false, count: -1 };
      const oldReset = first.resetAt;
      trustedOf(inst).set("mcp:forge", { count: 4, resetAt: oldReset + 60_000 });
      await inst.releaseForge(oldReset);
      return { ok: true, count: trustedOf(inst).get("mcp:forge")?.count ?? -1 };
    });
    expect(result.ok).toBe(true);
    expect(result.count).toBe(4);
  });

  it("the 33rd accepted grant evicts the oldest", async () => {
    const stub = queueStub(env as never);
    const oldest = ("o" + "1".padStart(15, "0")).slice(0, 16);
    const newest = ("n" + "0".repeat(15)).slice(0, 16);
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue, state) => {
      for (let i = 1; i <= 32; i++) {
        const id = ("o" + String(i).padStart(15, "0")).slice(0, 16);
        state.storage.sql.exec(`INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`, id, i);
      }
      await inst.rememberOwnerGrant(newest);
      const rows = state.storage.sql
        .exec<{ grant_id: string; seen_at: number }>(`SELECT grant_id, seen_at FROM accepted_grants`)
        .toArray();
      return {
        count: rows.length,
        hasOldest: rows.some((r) => r.grant_id === oldest),
        hasNewest: rows.some((r) => r.grant_id === newest),
      };
    });
    expect(result.count).toBe(32);
    expect(result.hasOldest).toBe(false);
    expect(result.hasNewest).toBe(true);
  });

  it("a full public map does not refuse trusted keys, and expired public keys are reclaimed", async () => {
    const stub = queueStub(env as never);
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue) => {
      const pub = publicOf(inst);
      const trusted = trustedOf(inst);
      const saved = [...pub.entries()];
      pub.clear();
      for (let i = 0; i < MAX_PUBLIC_BUCKETS; i++) pub.set(`p${i}`, { count: 1, resetAt: Date.now() + 3_600_000 });
      const trustedOk = (await inst.rateLimit("trusted:probe", 5, 60_000)).ok;
      const publicBlocked = !(await inst.rateLimitPublic("one-more", 5, 60_000)).ok;
      trusted.delete("trusted:probe");
      pub.clear();
      for (let i = 0; i < MAX_PUBLIC_BUCKETS; i++) pub.set(`e${i}`, { count: 1, resetAt: Date.now() - 5 });
      const reclaimed = (await inst.rateLimitPublic("fresh-after-expiry", 5, 60_000)).ok;
      pub.clear();
      for (const [k, v] of saved) pub.set(k, v);
      return { trustedOk, publicBlocked, reclaimed };
    });
    expect(result.trustedOk).toBe(true);
    expect(result.publicBlocked).toBe(true);
    expect(result.reclaimed).toBe(true);
  });
});
void env;
