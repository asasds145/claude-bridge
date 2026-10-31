import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { queueStub } from "../src/env";
import { MAX_PUBLIC_BUCKETS, type BoxmcpQueue } from "../src/queue";

const KEY = "test-chief-key-not-a-secret";
type Buckets = Map<string, { count: number; resetAt: number }>;
const trustedOf = (inst: BoxmcpQueue) => (inst as unknown as { buckets: Buckets }).buckets;
const publicOf = (inst: BoxmcpQueue) => (inst as unknown as { publicBuckets: Buckets }).publicBuckets;

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
