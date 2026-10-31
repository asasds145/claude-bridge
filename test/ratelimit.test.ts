import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const KEY = "test-chief-key-not-a-secret";
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
});
void env;
