import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { CLAUDE_REDIRECT_URI } from "../src/auth-github";

// 테스트 전용 가짜 값 (실제 secret/토큰 아님)
const BASE = "https://chief-bridge.test";
const CIMD_ID = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const E = { ...(env as object), GITHUB_CLIENT_SECRET: "fake-github-secret-for-test" } as never;

afterEach(() => vi.restoreAllMocks());

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

function mockUpstream(githubId: number) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = new Request(input as RequestInfo, init as RequestInit).url;
    if (url === CIMD_ID)
      return Response.json({
        client_id: CIMD_ID, client_name: "Claude (claude.ai)", redirect_uris: [CLAUDE_REDIRECT_URI],
        grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none",
      }, { headers: { "cache-control": "max-age=300" } });
    if (url === "https://github.com/login/oauth/access_token") return Response.json({ access_token: "gho_fake_test_token" });
    if (url === "https://api.github.com/user") return Response.json({ id: githubId, login: "x" });
    return new Response("unexpected " + url, { status: 599 });
  });
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
  jar.take(p);
  return call(new Request(`${BASE}/callback?code=fake-gh-code&state=${encodeURIComponent(gh.searchParams.get("state")!)}`, {
    redirect: "manual", headers: { cookie: jar.header() },
  }));
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
  it("errorSummary: name + truncated message/stack, secrets redacted", async () => {
    const { errorSummary } = await import("../src/auth-github");
    const e = new TypeError("boom Bearer abc.def code=xyz123&x=1 " + "A".repeat(40) + " " + "m".repeat(500));
    const s = errorSummary(e);
    expect(s.err_name).toBe("TypeError");
    expect(s.err_message.length).toBeLessThanOrEqual(200);
    expect(s.err_message).not.toContain("abc.def");
    expect(s.err_message).not.toContain("xyz123");
    expect(s.err_message).not.toContain("A".repeat(40));
    expect(s.err_stack.length).toBeLessThanOrEqual(800);
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

describe("errorSummary extra redaction forms", () => {
  it("JSON, url-encoded, __Host- cookie, stack path", async () => {
    const { errorSummary } = await import("../src/auth-github");
    const e = new Error('x {"code":"abc123","access_token":"tok1"} y code%3Dsecret9 z __Host-oauth-c=short.v+1/2');
    e.stack = "Error: refresh_token=rt1 at f (__Host-x=yy)\n at g";
    const s = errorSummary(e);
    const all = s.err_message + s.err_stack;
    for (const leak of ["abc123", "tok1", "secret9", "short.v", "rt1", "yy"]) expect(all).not.toContain(leak);
  });
});
