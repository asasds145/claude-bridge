import { createExecutionContext, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CLAUDE_REDIRECT_URI } from "../src/auth-github";
import { queueStub } from "../src/env";
import worker, { MCP_FORGE_PER_MIN, MCP_PREAUTH_PER_MIN, MCP_RATE_PER_MIN } from "../src/index";
import type { BoxmcpQueue } from "../src/queue";

// 테스트 전용 가짜 값 (실제 secret/토큰 아님)
const BASE = "https://chief-bridge.test";
const CIMD_ID = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const E = { ...(env as object), GITHUB_CLIENT_SECRET: "fake-github-secret-for-test" } as never;

afterEach(() => vi.restoreAllMocks());

beforeEach(async () => {
  // These counters live on the shared Durable Object and would otherwise leak between tests.
  await runInDurableObject(queueStub(env as never), (inst: BoxmcpQueue) => {
    const buckets = (inst as unknown as { buckets: Map<string, unknown> }).buckets;
    buckets.delete("mcp:unauth");
    buckets.delete("mcp:forge");
  });
});

/** 브라우저 쿠키 흉내: __Host- 규칙(Secure, Path=/, Domain 없음), Max-Age=0 삭제, SameSite=Lax(top-level GET·same-site POST 전송) */
class Jar {
  m = new Map<string, string>();
  take(res: Response) {
    for (const sc of res.headers.getSetCookie()) {
      const [nv, ...attrs] = sc.split(";").map((s) => s.trim());
      const i = nv.indexOf("=");
      const name = nv.slice(0, i), value = nv.slice(i + 1);
      const a = attrs.map((x) => x.toLowerCase());
      if (name.startsWith("__Host-") && (!a.includes("secure") || !a.includes("path=/") || a.some((x) => x.startsWith("domain=")))) continue;
      if (a.includes("max-age=0")) this.m.delete(name);
      else this.m.set(name, value);
    }
  }
  header() { return [...this.m].map(([k, v]) => `${k}=${v}`).join("; "); }
}

async function call(req: Request) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, E, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

let lastTokenBody = "";

function mockUpstream(githubId: number) {
  lastTokenBody = "";
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input as RequestInfo, init as RequestInit);
    const url = req.url;
    if (url === CIMD_ID)
      return Response.json({
        client_id: CIMD_ID, client_name: "Claude (claude.ai)", redirect_uris: [CLAUDE_REDIRECT_URI],
        grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none",
      }, { headers: { "cache-control": "max-age=300" } });
    if (url === "https://github.com/login/oauth/access_token") {
      // .text() warns and may mis-decode this form body. Read the bytes instead.
      lastTokenBody = new TextDecoder().decode(await req.arrayBuffer());
      return Response.json({ access_token: "gho_fake_test_token" });
    }
    if (url === "https://api.github.com/user") return Response.json({ id: githubId, login: "x" });
    return new Response("unexpected " + url, { status: 599 });
  });
}

async function s256(verifier: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  let s = "";
  for (const b of digest) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function flow(githubId: number) {
  mockUpstream(githubId);
  const jar = new Jar();
  const q = new URLSearchParams({
    response_type: "code", client_id: CIMD_ID, redirect_uri: CLAUDE_REDIRECT_URI, scope: "mcp offline_access",
    state: "client-state-1", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256",
    resource: `${BASE}/mcp`,
  });
  const g = await call(new Request(`${BASE}/authorize?${q}`));
  const page = await g.text();
  expect(g.status, page).toBe(200);
  expect(page).toContain("claude.ai");
  expect(page).toContain("<title>chief-bridge 연결 승인</title>");
  jar.take(g);
  const handle = /name="handle" value="([^"]+)"/.exec(page)![1];
  const p = await call(new Request(`${BASE}/authorize`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie: jar.header(), origin: BASE },
    body: new URLSearchParams({ handle, action: "approve" }).toString(),
  }));
  expect(p.status, await p.clone().text()).toBe(302);
  const gh = new URL(p.headers.get("location")!);
  expect(gh.origin + gh.pathname).toBe("https://github.com/login/oauth/authorize");
  expect(gh.searchParams.get("redirect_uri")).toBe(`${BASE}/callback`);
  expect(gh.searchParams.get("code_verifier")).toBeNull();
  expect(gh.searchParams.get("code_challenge_method")).toBe("S256");
  const challenge = gh.searchParams.get("code_challenge");
  expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
  jar.take(p);
  const done = await call(new Request(`${BASE}/callback?code=fake-gh-code&state=${encodeURIComponent(gh.searchParams.get("state")!)}`, {
    redirect: "manual", headers: { cookie: jar.header() },
  }));
  const sent = new URLSearchParams(lastTokenBody);
  const verifier = sent.get("code_verifier") ?? "";
  expect(verifier).not.toBe("");
  expect(await s256(verifier)).toBe(challenge);
  return done;
}

describe("OAuth full flow (CIMD Claude client, scope mcp offline_access)", () => {
  it("owner: authorize → approve → github callback → 302 to Claude with code", async () => {
    const c = await flow(12345);
    const body = await c.clone().text();
    expect(c.status, body).toBe(302);
    const loc = new URL(c.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe(CLAUDE_REDIRECT_URI);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("client-state-1");
  });
  it("non-owner → 403", async () => {
    const c = await flow(99999);
    expect(c.status).toBe(403);
  });
});

describe("auth helpers", () => {
  it("ownerUserId has no ':' (library rule)", async () => {
    const { ownerUserId } = await import("../src/auth-github");
    expect(ownerUserId(12345678)).toBe("github-12345678");
    expect(ownerUserId(12345678).includes(":")).toBe(false);
  });
  it("mcp user id must match the current owner", async () => {
    const { mcpUserMatchesOwner, mcpActorId } = await import("../src/auth-github");
    expect(mcpUserMatchesOwner("github-12345678", "12345678")).toBe(true);
    expect(mcpUserMatchesOwner("github-12345678", " 12345678 ")).toBe(true);
    expect(mcpUserMatchesOwner("github-1", "12345678")).toBe(false);
    expect(mcpUserMatchesOwner("github-12345678", "0")).toBe(false);
    expect(mcpUserMatchesOwner(undefined, "12345678")).toBe(false);
    expect(mcpUserMatchesOwner("github-12345678", undefined)).toBe(false);
    expect(mcpUserMatchesOwner("github-123", "0123")).toBe(false);
    const { validOwnerId } = await import("../src/auth-github");
    expect(validOwnerId("12345678")).toBe("12345678");
    expect(validOwnerId(" 12345678 ")).toBe("12345678");
    expect(validOwnerId("0")).toBeNull();
    expect(validOwnerId("0123")).toBeNull();
    expect(validOwnerId("12a")).toBeNull();
    expect(mcpActorId({ auth: { userId: "github-12345" }, props: { githubId: 12345 } })).toBe("github-12345");
    expect(mcpActorId({ props: { githubId: 12345 } })).toBe("github-12345");
    expect(mcpActorId({ auth: { userId: "github-12345" } })).toBe("github-12345");
    expect(mcpActorId({ auth: { userId: "github-1" }, props: { githubId: 12345 } })).toBeUndefined();
  });
  it("a leading-zero owner id fails closed and the value is not logged", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(
      new Request(`${BASE}/authorize?response_type=code&client_id=x`),
      { ...(env as object), GITHUB_CLIENT_SECRET: "fake-github-secret-for-test", BOXMCP_OWNER_GITHUB_ID: "012345" } as never,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    const joined = logs.join("\n");
    expect(joined).toContain("bad_owner_id");
    expect(joined).not.toContain("012345");
  });
  it("errorClass logs the class only, never the message", async () => {
    const { errorClass } = await import("../src/util");
    const e = new TypeError("boom Bearer abc.def relayed message text " + "m".repeat(500));
    expect(errorClass(e)).toBe("TypeError");
    expect(errorClass(e)).not.toContain("abc.def");
    expect(errorClass(e)).not.toContain("relayed");
    const named = new Error("secret message body");
    named.name = "secret message body";
    expect(errorClass(named)).toBe("Error");
    expect(errorClass("plain secret")).toBe("string");
  });
});

describe("strings that deploy/verify-chief-bridge.sh greps for", () => {
  it("www-authenticate, PRM, AS metadata, error page title", async () => {
    const m = await call(new Request(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }));
    expect(m.status).toBe(401);
    expect(m.headers.get("www-authenticate")).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`);
    const prm = await (await call(new Request(`${BASE}/.well-known/oauth-protected-resource/mcp`))).text();
    expect(prm).toContain(`"resource":"${BASE}/mcp"`);
    expect(prm).toContain(`"resource_name":"chief-bridge"`);
    const as = await (await call(new Request(`${BASE}/.well-known/oauth-authorization-server`))).text();
    for (const k of [`"issuer":"${BASE}"`, '"S256"', '"client_id_metadata_document_supported":true', '"none"', '"offline_access"']) expect(as).toContain(k);
    const h = await (await call(new Request(`${BASE}/health`))).json();
    expect(h).toMatchObject({ ok: true, service: "chief-bridge" });
    const a = await call(new Request(`${BASE}/authorize?response_type=code&client_id=x`));
    expect(a.status).toBe(400);
    expect(await a.text()).toContain("<title>chief-bridge</title>");
  });
});

/** RFC 7636 appendix B sample. Matches the code_challenge used in flow(). Not a secret. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

function mcpInit(token: string): Request {
  return new Request(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      host: "chief-bridge.test",
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": "2025-06-18",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    }),
  });
}

async function exchange(code: string): Promise<string> {
  const res = await call(new Request(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: CLAUDE_REDIRECT_URI,
      client_id: CIMD_ID,
      code_verifier: CODE_VERIFIER,
      resource: `${BASE}/mcp`,
    }),
  }));
  const text = await res.text();
  expect(res.status, text).toBe(200);
  const token = (JSON.parse(text) as { access_token?: string }).access_token;
  expect(token).toBeTruthy();
  return token as string;
}

function parseMcp(body: string): { error?: unknown; result?: { protocolVersion?: string; serverInfo?: { name?: string; version?: string } } } {
  const dataLine = body.split("\n").find((l) => l.startsWith("data:"));
  return JSON.parse(dataLine ? dataLine.slice(5).trim() : body) as { error?: unknown; result?: { protocolVersion?: string; serverInfo?: { name?: string; version?: string } } };
}

function expectInitialized(status: number, body: string) {
  expect(status, body).toBe(200);
  const msg = parseMcp(body);
  expect(msg.error).toBeUndefined();
  expect(msg.result?.protocolVersion).toBeTruthy();
  expect(msg.result?.serverInfo).toMatchObject({ name: "chief-bridge", version: "1.0.0" });
}

describe("authenticated /mcp", () => {
  it("code exchange then /mcp initialize is 200, and a full unauth bucket does not block it or a headerless probe", async () => {
    const c = await flow(12345);
    const loc = new URL(c.headers.get("location")!);
    const code = loc.searchParams.get("code");
    expect(code).toBeTruthy();
    const token = await exchange(code as string);
    const ok = await call(mcpInit(token));
    expectInitialized(ok.status, await ok.text());

    const stub = queueStub(env as never);
    const bucketMap = (inst: BoxmcpQueue) => (inst as unknown as { buckets: Map<string, { count: number; resetAt: number }> }).buckets;
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      bucketMap(inst).set("mcp:unauth", { count: MCP_PREAUTH_PER_MIN, resetAt: Date.now() + 60_000 });
    });
    try {
      const anon = await call(new Request(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }));
      expect(anon.status).toBe(401);
      expect(anon.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`);
      const junk = await call(new Request(`${BASE}/mcp`, {
        method: "POST",
        headers: { authorization: "Bearer not-a-token", "content-type": "application/json" },
        body: "{}",
      }));
      expect(junk.status).toBe(429);
      const still = await call(mcpInit(token));
      expectInitialized(still.status, await still.text());
    } finally {
      await runInDurableObject(stub, (inst: BoxmcpQueue) => {
        bucketMap(inst).delete("mcp:unauth");
      });
    }

    const forged = "github-12345:forged-grant:forged-secret";
    const keys = () => runInDurableObject(stub, (inst: BoxmcpQueue) => [...bucketMap(inst).keys()]);
    const before = new Set(await keys());
    const forgedRes = await call(new Request(`${BASE}/mcp`, {
      method: "POST",
      headers: { authorization: `Bearer ${forged}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: "{}",
    }));
    expect(forgedRes.status).toBe(401);
    const added = (await keys()).filter((k) => !before.has(k));
    expect(added.every((k) => k === "mcp:forge")).toBe(true);
    expect(added.join(" ")).not.toContain("forged");
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      bucketMap(inst).set("mcp:forge", { count: MCP_FORGE_PER_MIN, resetAt: Date.now() + 60_000 });
    });
    const forgedAgain = await call(new Request(`${BASE}/mcp`, {
      method: "POST",
      headers: { authorization: "Bearer github-12345:other-grant:other-secret", "content-type": "application/json" },
      body: "{}",
    }));
    expect(forgedAgain.status).toBe(429);
    const ownerStill = await call(mcpInit(token));
    expectInitialized(ownerStill.status, await ownerStill.text());
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      bucketMap(inst).delete("mcp:forge");
    });

    const ctx = createExecutionContext();
    const denied = await worker.fetch(mcpInit(token), { ...(E as object), BOXMCP_OWNER_GITHUB_ID: "999" } as never, ctx);
    await waitOnExecutionContext(ctx);
    expect(denied.status).toBe(401);
    const www = denied.headers.get("www-authenticate") ?? "";
    expect(www).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`);
    expect(www).toContain("invalid_token");

    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      (inst as unknown as { buckets: Map<string, unknown> }).buckets.delete("mcp:github-12345");
    });
    const statuses: number[] = [];
    for (let i = 0; i < MCP_RATE_PER_MIN + 1; i++) {
      statuses.push((await call(mcpInit(token))).status);
    }
    expect(statuses.slice(0, MCP_RATE_PER_MIN).every((s) => s === 200)).toBe(true);
    expect(statuses[MCP_RATE_PER_MIN]).toBe(429);
  }, 30_000);
});

describe("consent POST body limit", () => {
  it("oversized body without a trustworthy Content-Length is 413, not parsed", async () => {
    const { CONSENT_MAX_BODY } = await import("../src/auth-github");
    const payload = "x".repeat(CONSENT_MAX_BODY + 64);
    let sent = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent) {
          controller.close();
          return;
        }
        sent = true;
        controller.enqueue(new TextEncoder().encode(payload));
      },
    });
    const req = new Request(`${BASE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    // The bug was trusting a missing or small Content-Length and then calling formData() unbounded.
    expect(Number(req.headers.get("content-length") ?? "0")).toBeLessThanOrEqual(CONSENT_MAX_BODY);
    const res = await call(req);
    expect(res.status).toBe(413);
    expect(await res.text()).toContain("too large");
  });

  it("Content-Length under the cap does not allow a larger body", async () => {
    const { CONSENT_MAX_BODY } = await import("../src/auth-github");
    const payload = "y".repeat(CONSENT_MAX_BODY + 32);
    const req = new Request(`${BASE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "content-length": "16" },
      body: payload,
    });
    const res = await call(req);
    expect(res.status).toBe(413);
  });

  it("a body stream error is 400 and the error text is not returned", async () => {
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error("secret relayed message must not leak"));
      },
    });
    const res = await call(new Request(`${BASE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }));
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).not.toContain("secret");
    expect(text).not.toContain("relayed");
    expect(text).not.toContain("must not leak");
  });

  it("a body of exactly the cap is accepted and a split overflow is 413", async () => {
    const { CONSENT_MAX_BODY } = await import("../src/auth-github");
    const exact = await call(new Request(`${BASE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "a".repeat(CONSENT_MAX_BODY),
    }));
    expect(exact.status).not.toBe(413);
    expect(exact.status).toBeGreaterThanOrEqual(400);
    expect(exact.status).toBeLessThan(500);

    const first = new Uint8Array(4000).fill(0x61);
    const second = new Uint8Array(CONSENT_MAX_BODY).fill(0x61);
    let n = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (n === 0) controller.enqueue(first);
        else if (n === 1) controller.enqueue(second);
        else controller.close();
        n++;
      },
    });
    const overflow = await call(new Request(`${BASE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }));
    expect(overflow.status).toBe(413);
  });

  it("malformed percent-encoding is 400", async () => {
    const res = await call(new Request(`${BASE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "handle=%ZZ&action=approve",
    }));
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain("%ZZ");
  });
});
