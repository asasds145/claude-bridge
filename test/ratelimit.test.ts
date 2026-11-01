import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { queueStub } from "../src/env";
import { MCP_FORGE_PER_MIN, MCP_PREAUTH_PER_MIN, REFRESH_TOKEN_TTL } from "../src/index";
import { GRANT_TTL_MS, GRANT_TOUCH_MS, MAX_PUBLIC_BUCKETS, type BoxmcpQueue } from "../src/queue";
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
          headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.210" },
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
          headers: {
            authorization: `Bearer not-a-token-${i}`,
            "content-type": "application/json",
            "cf-connecting-ip": `198.51.100.${100 + i}`,
          },
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
              "cf-connecting-ip": `198.51.100.${i + 1}`,
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
    let postN = 0;
    const post = (path: string, authorization?: string) => {
      postN += 1;
      return exports.default.fetch(
        new Request(base + path, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            // Distinct address so these few calls do not share the test IP budget with each other.
            "cf-connecting-ip": `198.51.100.${150 + postN}`,
            ...(authorization ? { authorization } : {}),
          },
          body: "{}",
        }),
      );
    };
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

  it("refunds a slot in the same window, and a trickle admission is not a refundable slot", async () => {
    const stub = queueStub(env as never);
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue) => {
      const view = inst as unknown as { forgeTrickleAt: number };
      const first = await inst.reserveForge("a".repeat(16), 2, 60_000);
      if (first.action !== "reserved" || !first.refundable) return { ok: false as const };
      await inst.releaseForge(first.resetAt);
      const afterRefund = trustedOf(inst).get("mcp:forge")?.count ?? -1;
      await inst.reserveForge("b".repeat(16), 2, 60_000);
      await inst.reserveForge("c".repeat(16), 2, 60_000);
      const atCap = trustedOf(inst).get("mcp:forge")?.count ?? -1;
      view.forgeTrickleAt = 0;
      const trickle = await inst.reserveForge("d".repeat(16), 2, 60_000);
      return {
        ok: true as const,
        afterRefund,
        atCap,
        trickleAction: trickle.action,
        trickleRefundable: trickle.action === "reserved" ? trickle.refundable : null,
        afterTrickle: trustedOf(inst).get("mcp:forge")?.count ?? -1,
      };
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.afterRefund).toBe(0);
    expect(result.atCap).toBe(2);
    expect(result.trickleAction).toBe("reserved");
    expect(result.trickleRefundable).toBe(false);
    expect(result.afterTrickle).toBe(2);
  });

  it("the 33rd accepted grant evicts the oldest", async () => {
    const stub = queueStub(env as never);
    const oldest = ("o" + "1".padStart(15, "0")).slice(0, 16);
    const newest = ("n" + "0".repeat(15)).slice(0, 16);
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue, state) => {
      const now = Date.now();
      for (let i = 1; i <= 32; i++) {
        const id = ("o" + String(i).padStart(15, "0")).slice(0, 16);
        // Recent enough to survive the 30-day prune, and strictly ordered so i=1 is the oldest.
        state.storage.sql.exec(`INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`, id, now - 120_000 + i);
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

  it("keeps the row just written when every seen_at ties, including an updated low rowid", async () => {
    const stub = queueStub(env as never);
    const keep = ("k" + "0".repeat(15)).slice(0, 16);
    const oldestOther = ("n" + "0".padStart(15, "0")).slice(0, 16);
    const frozen = 1_700_000_000_000;
    const realNow = Date.now;
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue, state) => {
      // Freeze the clock so the rewrite lands on the same seen_at as the other rows. No wall clock.
      Date.now = () => frozen;
      try {
        state.storage.sql.exec(`INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`, keep, frozen - GRANT_TOUCH_MS);
        for (let i = 0; i < 32; i++) {
          const id = ("n" + String(i).padStart(15, "0")).slice(0, 16);
          state.storage.sql.exec(`INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`, id, frozen);
        }
        await inst.rememberOwnerGrant(keep);
        const rows = state.storage.sql.exec<{ grant_id: string }>(`SELECT grant_id FROM accepted_grants`).toArray();
        return {
          count: rows.length,
          hasKeep: rows.some((r) => r.grant_id === keep),
          hasOldestOther: rows.some((r) => r.grant_id === oldestOther),
        };
      } finally {
        Date.now = realNow;
      }
    });
    expect(result.count).toBe(32);
    expect(result.hasKeep).toBe(true);
    expect(result.hasOldestOther).toBe(false);
  });

  it("skips the grant write inside 60s and writes again at the boundary", async () => {
    const stub = queueStub(env as never);
    const id = ("b" + "1".repeat(15)).slice(0, 16);
    const frozen = 1_700_000_000_000;
    const realNow = Date.now;
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue, state) => {
      Date.now = () => frozen;
      try {
        const seenOf = () =>
          state.storage.sql.exec<{ seen_at: number }>(`SELECT seen_at FROM accepted_grants WHERE grant_id = ?`, id).one().seen_at;
        state.storage.sql.exec(
          `INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`,
          id,
          frozen - (GRANT_TOUCH_MS - 1),
        );
        await inst.rememberOwnerGrant(id);
        const skipped = seenOf();
        state.storage.sql.exec(`UPDATE accepted_grants SET seen_at = ? WHERE grant_id = ?`, frozen - GRANT_TOUCH_MS, id);
        await inst.rememberOwnerGrant(id);
        return { skipped, written: seenOf() };
      } finally {
        Date.now = realNow;
      }
    });
    expect(result.skipped).toBe(frozen - (GRANT_TOUCH_MS - 1));
    expect(result.written).toBe(frozen);
  });

  it("drops grant rows older than the refresh lifetime when a row is written", async () => {
    expect(GRANT_TTL_MS).toBe(REFRESH_TOKEN_TTL * 1000);
    const stub = queueStub(env as never);
    const expired = ("e" + "1".padStart(15, "0")).slice(0, 16);
    const boundary = ("d" + "2".padStart(15, "0")).slice(0, 16);
    const fresh = ("f" + "3".padStart(15, "0")).slice(0, 16);
    const frozen = 1_800_000_000_000;
    const realNow = Date.now;
    const ids = await runInDurableObject(stub, async (inst: BoxmcpQueue, state) => {
      Date.now = () => frozen;
      try {
        state.storage.sql.exec(`INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`, expired, frozen - GRANT_TTL_MS - 1);
        state.storage.sql.exec(`INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`, boundary, frozen - GRANT_TTL_MS);
        await inst.rememberOwnerGrant(fresh);
        return state.storage.sql.exec<{ grant_id: string }>(`SELECT grant_id FROM accepted_grants`).toArray().map((r) => r.grant_id);
      } finally {
        Date.now = realNow;
      }
    });
    expect(ids).toContain(fresh);
    expect(ids).toContain(boundary);
    expect(ids).not.toContain(expired);
  });

  it("an expired grant is dropped when it is read, so it no longer skips forge", async () => {
    const stub = queueStub(env as never);
    const id = ("e" + "9".padStart(15, "0")).slice(0, 16);
    const frozen = 1_800_000_000_000;
    const realNow = Date.now;
    const result = await runInDurableObject(stub, async (inst: BoxmcpQueue, state) => {
      Date.now = () => frozen;
      try {
        state.storage.sql.exec(
          `INSERT INTO accepted_grants (grant_id, seen_at) VALUES (?, ?)`,
          id,
          frozen - GRANT_TTL_MS - 1,
        );
        const slot = await inst.reserveForge(id, 10, 60_000);
        const left = state.storage.sql.exec(`SELECT grant_id FROM accepted_grants WHERE grant_id = ?`, id).toArray().length;
        return { action: slot.action, left };
      } finally {
        Date.now = realNow;
      }
    });
    expect(result.action).not.toBe("known");
    expect(result.left).toBe(0);
  });

  it("a thrown rateLimit or reserveForge is 429 with WWW-Authenticate, not 500", async () => {
    const stub = queueStub(env as never);
    const post = (ip: string, authorization: string) =>
      exports.default.fetch(new Request("https://chief-bridge.test/mcp", {
        method: "POST",
        headers: {
          authorization,
          "content-type": "application/json",
          "cf-connecting-ip": ip,
        },
        body: "{}",
      }));
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      inst.__testFaultOnce = "rateLimit";
    });
    const unauth = await post("198.51.100.220", "Bearer not-a-token");
    const unauthBody = await unauth.text();
    expect(unauth.status).toBe(429);
    expect(unauthBody).not.toContain("do-fault");
    expect(unauth.headers.get("www-authenticate") ?? "").toContain("resource_metadata=");
    expect(unauth.headers.get("retry-after")).toBe("60");

    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      inst.__testFaultOnce = "reserveForge";
    });
    const forged = await post("198.51.100.221", `Bearer github-12345:${"q".repeat(16)}:${"s".repeat(32)}`);
    const forgedBody = await forged.text();
    expect(forged.status).toBe(429);
    expect(forgedBody).not.toContain("do-fault");
    expect(forged.headers.get("www-authenticate") ?? "").toContain("resource_metadata=");
    expect(forged.headers.get("retry-after")).toBe("60");
  });

  it("a thrown registration or chief limit is 429, then the next call succeeds", async () => {
    const stub = queueStub(env as never);
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    const logged = (event: string) =>
      logs
        .map((line) => {
          try {
            return JSON.parse(line) as { event?: string; error_class?: string };
          } catch {
            return null;
          }
        })
        .filter((line) => line?.event === event);
    try {
      await runInDurableObject(stub, (inst: BoxmcpQueue) => {
        inst.__testFaultOnce = "rateLimitPublic";
      });
      const denied = await exports.default.fetch(new Request("https://chief-bridge.test/oauth/register", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.230" },
        body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "none" }),
      }));
      const deniedBody = await denied.text();
      expect(denied.status).toBe(429);
      expect(denied.headers.get("retry-after")).toBe("60");
      expect(deniedBody).not.toContain("do-fault");
      const registerLog = logged("req").find((line) => line?.error_class === "Error");
      expect(registerLog?.error_class).toBe("Error");
      expect(JSON.stringify(registerLog)).not.toContain("do-fault");

      const next = await exports.default.fetch(new Request("https://chief-bridge.test/oauth/register", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.230" },
        body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "none" }),
      }));
      expect(next.status).toBe(201);

      logs.length = 0;
      await runInDurableObject(stub, (inst: BoxmcpQueue) => {
        inst.__testFaultOnce = "rateLimit";
      });
      const chiefDenied = await exports.default.fetch(new Request("https://chief-bridge.test/chief/health", {
        headers: { authorization: `Bearer ${KEY}` },
      }));
      const chiefBody = await chiefDenied.text();
      expect(chiefDenied.status).toBe(429);
      expect(chiefDenied.headers.get("retry-after")).toBe("60");
      expect(chiefBody).not.toContain("do-fault");
      const chiefLog = logged("chief").find((line) => line?.error_class === "Error");
      expect(chiefLog?.error_class).toBe("Error");
      expect(JSON.stringify(chiefLog)).not.toContain("do-fault");

      const chiefNext = await exports.default.fetch(new Request("https://chief-bridge.test/chief/health", {
        headers: { authorization: `Bearer ${KEY}` },
      }));
      expect(chiefNext.status).toBe(200);
    } finally {
      spy.mockRestore();
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
