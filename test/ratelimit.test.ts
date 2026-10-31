import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { queueStub } from "../src/env";
import { MAX_RATE_BUCKETS, type BoxmcpQueue } from "../src/queue";

const KEY = "test-chief-key-not-a-secret";
type Buckets = Map<string, { count: number; resetAt: number }>;
const bucketsOf = (inst: BoxmcpQueue) => (inst as unknown as { buckets: Buckets }).buckets;

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
  it("/oauth/register 5/h per IP → 6th is 429", async () => {
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
    const keys = () => runInDurableObject(stub, (inst: BoxmcpQueue) => [...bucketsOf(inst).keys()]);
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
    expect(added.every((k) => k === "mcp:preauth")).toBe(true);
    expect(added.length).toBeLessThanOrEqual(1);
    for (const k of added) {
      expect(k).not.toContain("not-a-token");
    }
  });

  it("refuses new buckets once the map is at the cap", async () => {
    const stub = queueStub(env as never);
    const prefix = `cap${crypto.randomUUID()}:`;
    try {
      // One DO turn: 1024 RPC round-trips would be slow, and the cap is in-memory on the instance.
      const result = await runInDurableObject(stub, async (inst: BoxmcpQueue) => {
        let sawReject = false;
        let retryAfter = 0;
        for (let i = 0; i < MAX_RATE_BUCKETS + 20; i++) {
          const r = await inst.rateLimit(`${prefix}${i}`, 10, 60_000);
          if (!r.ok) {
            sawReject = true;
            retryAfter = r.retryAfter;
            break;
          }
        }
        return { sawReject, retryAfter, size: bucketsOf(inst).size };
      });
      expect(result.sawReject).toBe(true);
      expect(result.retryAfter).toBeGreaterThan(0);
      expect(result.size).toBeLessThanOrEqual(MAX_RATE_BUCKETS);
    } finally {
      await runInDurableObject(stub, (inst: BoxmcpQueue) => {
        const buckets = bucketsOf(inst);
        for (const k of [...buckets.keys()]) if (k.startsWith(prefix)) buckets.delete(k);
      });
    }
  });
});
void env;
