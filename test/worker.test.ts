import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { queueStub } from "../src/env";
import { wrapForClaude } from "../src/util";
import { allowedErrorRedirect, pkceOk, CLAUDE_REDIRECT_URI } from "../src/auth-github";

const E = env as unknown as Env;
const BASE = "https://chief-bridge.test";
const KEY = "test-chief-key-not-a-secret";
const fetchW = (path: string, init?: RequestInit) => exports.default.fetch(new Request(BASE + path, init));
const chief = (path: string, init: RequestInit = {}) =>
  fetchW(path, { ...init, headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json", ...(init.headers ?? {}) } });

describe("/chief auth", () => {
  it("no key → 401", async () => {
    const r = await fetchW("/chief/health");
    expect(r.status).toBe(401);
  });
  it("wrong key → 401", async () => {
    const r = await fetchW("/chief/health", { headers: { authorization: "Bearer wrong" } });
    expect(r.status).toBe(401);
  });
  it("right key → 200", async () => {
    const r = await chief("/chief/health");
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true });
  });
});

describe("OAuth / MCP discovery", () => {
  it("/mcp without token → 401 with resource_metadata", async () => {
    const r = await fetchW("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(401);
    const www = r.headers.get("www-authenticate") ?? "";
    expect(www).toContain("resource_metadata=");
    expect(www).toContain(`${BASE}/.well-known/oauth-protected-resource/mcp`);
  });
  it("PRM resource === https://<host>/mcp", async () => {
    const r = await fetchW("/.well-known/oauth-protected-resource/mcp");
    expect(r.status).toBe(200);
    const j = (await r.json()) as { resource: string; authorization_servers?: string[] };
    expect(j.resource).toBe(`${BASE}/mcp`);
    expect(j.authorization_servers).toEqual([BASE]);
  });
  it("AS metadata advertises S256", async () => {
    const r = await fetchW("/.well-known/oauth-authorization-server");
    expect(r.status).toBe(200);
    const j = (await r.json()) as Record<string, unknown>;
    expect(j.code_challenge_methods_supported).toContain("S256");
    expect(j.registration_endpoint).toBe(`${BASE}/oauth/register`);
    expect(j.scopes_supported).toEqual(expect.arrayContaining(["mcp", "offline_access"]));
    expect(j.client_id_metadata_document_supported).toBe(true);
    expect(j.issuer).toBe(BASE);
    expect(j.token_endpoint).toBe(`${BASE}/oauth/token`);
  });
  it("/authorize without GITHUB_CLIENT_SECRET → 503", async () => {
    const r = await fetchW("/authorize?response_type=code&client_id=x");
    expect(r.status).toBe(503);
  });
  it("auth pages: CSP form-action allows only self, github.com, claude.ai", async () => {
    const r = await fetchW("/authorize?response_type=code&client_id=x");
    const csp = r.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("form-action 'self' https://github.com https://claude.ai;");
  });
  it("error redirect only to the fixed Claude callback", () => {
    expect(allowedErrorRedirect(CLAUDE_REDIRECT_URI, CLAUDE_REDIRECT_URI + "?error=x")).toBe(true);
    expect(allowedErrorRedirect("https://evil.example/cb", "https://evil.example/cb?error=x")).toBe(false);
    expect(allowedErrorRedirect(undefined, "https://evil.example/cb?error=x")).toBe(false);
    expect(allowedErrorRedirect(CLAUDE_REDIRECT_URI, undefined)).toBe(false);
  });
  it("PKCE S256 required", () => {
    expect(pkceOk({ codeChallenge: "abc", codeChallengeMethod: "S256" })).toBe(true);
    expect(pkceOk({ codeChallenge: "abc", codeChallengeMethod: "plain" })).toBe(false);
    expect(pkceOk({ codeChallenge: undefined, codeChallengeMethod: undefined })).toBe(false);
  });
  it("wrong origin → 421", async () => {
    const r = await exports.default.fetch(new Request("https://other.example/.well-known/oauth-authorization-server"));
    expect(r.status).toBe(421);
  });
});

describe("DO queue", () => {
  it("send → inbox → ack → reply → read", async () => {
    const stub = queueStub(E);
    const sent = (await stub.sendToChief("hello <chief>\u0007")) as { id: number; thread_id: string };
    expect(sent.thread_id).toMatch(/^[0-9a-f-]{36}$/);

    const inbox = (await (await chief("/chief/inbox?limit=20")).json()) as { items: any[] };
    const item = inbox.items.find((i) => i.id === sent.id);
    expect(item).toMatchObject({ untrusted: true, from: "claude", thread_id: sent.thread_id, text: "hello <chief>" });

    const ack = await chief("/chief/ack", { method: "POST", body: JSON.stringify({ ids: [sent.id] }) });
    expect(await ack.json()).toEqual({ acked: 1 });
    const inbox2 = (await (await chief("/chief/inbox")).json()) as { items: any[] };
    expect(inbox2.items.find((i) => i.id === sent.id)).toBeUndefined();

    const rep = await chief("/chief/reply", { method: "POST", body: JSON.stringify({ thread_id: sent.thread_id, text: "<b>hi</b>" }) });
    expect(rep.status).toBe(200);
    const { id: replyId } = (await rep.json()) as { id: number };

    const replies = await stub.readReplies({ threadId: sent.thread_id, since: sent.id, limit: 20 });
    expect(replies.map((m) => m.id)).toEqual([replyId]);
    const wrapped = wrapForClaude(replies[0]);
    expect(wrapped).toContain('<chief_message untrusted="true"');
    expect(wrapped).toContain("&lt;b&gt;hi&lt;/b&gt;");
    expect(wrapped).not.toContain("<b>");

    const thread = await stub.getThread(sent.thread_id);
    expect(thread.map((m) => m.direction)).toEqual(["to_chief", "to_claude"]);
  });

  it("wait_for_reply: returns existing reply immediately, wakes on new reply, times out", async () => {
    const stub = queueStub(E);
    const { thread_id, id } = (await stub.sendToChief("q")) as { id: number; thread_id: string };
    const timedOut = await stub.waitForReply(thread_id, id, 1);
    expect(timedOut.messages).toEqual([]);

    const waiting = stub.waitForReply(thread_id, id, 10);
    await new Promise((r) => setTimeout(r, 100));
    await stub.chiefReply(thread_id, "answer");
    const got = await waiting;
    expect(got.messages.map((m) => m.text)).toEqual(["answer"]);

    const again = await stub.waitForReply(thread_id, id, 5);
    expect(again.messages.length).toBe(1);
  });

  it("a new waiter on the same thread supersedes a stale one (client gave up), others capped at 3 by evicting oldest", async () => {
    const stub = queueStub(E);
    const a = (await stub.sendToChief("w")) as { id: number; thread_id: string };
    const stale = stub.waitForReply(a.thread_id, a.id, 30);
    await new Promise((r) => setTimeout(r, 50));
    const fresh = stub.waitForReply(a.thread_id, a.id, 30);
    const s1 = await stale;
    expect(s1.messages).toEqual([]);
    expect(s1.superseded).toBe(true);
    await stub.chiefReply(a.thread_id, "x");
    expect((await fresh).messages.map((m) => m.text)).toEqual(["x"]);

    const { MAX_WAITERS } = await import("../src/queue");
    const ts = await Promise.all(
      Array.from({ length: MAX_WAITERS + 1 }, (_, i) => stub.sendToChief(`t${i}`) as Promise<{ id: number; thread_id: string }>),
    );
    const ws = ts.slice(0, MAX_WAITERS).map((t) => stub.waitForReply(t.thread_id, t.id, 30));
    await new Promise((r) => setTimeout(r, 50));
    const extra = stub.waitForReply(ts[MAX_WAITERS].thread_id, ts[MAX_WAITERS].id, 30);
    const first = await ws[0];
    expect(first.superseded).toBe(true);
    expect((await stub.status()).waiters).toBe(MAX_WAITERS);
    for (const t of ts.slice(1)) await stub.chiefReply(t.thread_id, "ok");
    for (const w of [...ws.slice(1), extra]) expect((await w).messages.length).toBe(1);
  });

  it("cancelWait frees the waiter slot immediately", async () => {
    const stub = queueStub(E);
    const a = (await stub.sendToChief("c")) as { id: number; thread_id: string };
    const w = stub.waitForReply(a.thread_id, a.id, 30, "tok-1");
    await new Promise((r) => setTimeout(r, 50));
    expect((await stub.status()).waiters).toBe(1);
    expect(await stub.cancelWait("tok-1")).toBe(true);
    expect((await w).messages).toEqual([]);
    expect((await stub.status()).waiters).toBe(0);
    expect(await stub.cancelWait("tok-1")).toBe(false);
  });

  it("unknown thread on reply → 404", async () => {
    const r = await chief("/chief/reply", { method: "POST", body: JSON.stringify({ thread_id: "nope", text: "x" }) });
    expect(r.status).toBe(404);
  });

  it("no webhook URL → nothing scheduled", async () => {
    const s = await queueStub(E).status();
    expect(s.webhook_configured).toBe(false);
    expect(s.webhook_scheduled).toBe(false);
  });
});

describe("input limits", () => {
  it("text > 8000 → 400", async () => {
    const r = await chief("/chief/send", { method: "POST", body: JSON.stringify({ text: "a".repeat(8001) }) });
    expect(r.status).toBe(400);
  });
  it("text = 8000 → 200", async () => {
    const r = await chief("/chief/send", { method: "POST", body: JSON.stringify({ text: "a".repeat(8000) }) });
    expect(r.status).toBe(200);
  });
  it("body > 64KB → 413", async () => {
    const r = await chief("/chief/send", { method: "POST", body: JSON.stringify({ text: "a".repeat(70000) }) });
    expect(r.status).toBe(413);
  });
  it("invalid thread_id → 400", async () => {
    const r = await chief("/chief/reply", { method: "POST", body: JSON.stringify({ thread_id: "../x", text: "x" }) });
    expect(r.status).toBe(400);
  });
  it("invalid ack ids → 400", async () => {
    const r = await chief("/chief/ack", { method: "POST", body: JSON.stringify({ ids: ["1"] }) });
    expect(r.status).toBe(400);
  });
  it("inbox limit out of range → 400", async () => {
    const r = await chief("/chief/inbox?limit=0");
    expect(r.status).toBe(400);
  });
  it("invalid json → 400", async () => {
    const r = await chief("/chief/send", { method: "POST", body: "{" });
    expect(r.status).toBe(400);
  });
});
