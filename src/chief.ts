import { type Env, queueStub } from "./env";
import { HttpError, MAX_TEXT, THREAD_ID_RE, json, logLine, readJsonLimited, safeEqual, type StoredMessage } from "./util";

export const CHIEF_RATE_PER_MIN = 60;

/** Authorization: Bearer <key> 를 BOXMCP_CHIEF_API_KEY / _NEXT 와 상수시간 비교 */
export async function checkChiefKey(req: Request, env: Env): Promise<boolean> {
  const h = req.headers.get("authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return false;
  const presented = m[1].trim();
  const keys = [env.BOXMCP_CHIEF_API_KEY, env.BOXMCP_CHIEF_API_KEY_NEXT].filter((k): k is string => !!k);
  let ok = false;
  for (const k of keys) {
    // 단락평가 없이 모두 비교
    const r = await safeEqual(presented, k);
    ok = ok || r;
  }
  return ok;
}

function toInboxItem(m: StoredMessage) {
  return { untrusted: true, from: "claude", id: m.id, thread_id: m.thread_id, text: m.text, created_at: new Date(m.created_at).toISOString() };
}

function validText(v: unknown): string {
  if (typeof v !== "string" || v.length === 0) throw new HttpError(400, "text required");
  if (v.length > MAX_TEXT) throw new HttpError(400, `text exceeds ${MAX_TEXT} chars`);
  return v;
}

export async function handleChief(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  if (!(await checkChiefKey(req, env))) {
    logLine("chief", { path, status: 401 });
    return json({ error: "unauthorized" }, 401, { "www-authenticate": 'Bearer realm="chief-bridge-chief"' });
  }
  const stub = queueStub(env);
  const rl = await stub.rateLimit("chief", CHIEF_RATE_PER_MIN, 60_000);
  if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });

  try {
    if (path === "/chief/health" && req.method === "GET") {
      const s = await stub.status();
      return json({ ok: true, pending: s.pending_to_chief, webhook_configured: s.webhook_configured, webhook_url_valid: s.webhook_url_valid });
    }
    if (path === "/chief/inbox" && req.method === "GET") {
      const raw = url.searchParams.get("limit");
      const limit = raw === null ? 20 : Number(raw);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new HttpError(400, "limit must be 1..100");
      const items = await stub.chiefInbox(limit);
      return json({ items: items.map(toInboxItem) });
    }
    if (path === "/chief/reply" && req.method === "POST") {
      const body = (await readJsonLimited(req)) as Record<string, unknown>;
      const tid = body?.thread_id;
      if (typeof tid !== "string" || !THREAD_ID_RE.test(tid)) throw new HttpError(400, "invalid thread_id");
      const text = validText(body.text);
      const r = await stub.chiefReply(tid, text);
      if ("error" in r) throw new HttpError(404, "unknown thread_id");
      return json(r);
    }
    if (path === "/chief/ack" && req.method === "POST") {
      const body = (await readJsonLimited(req)) as Record<string, unknown>;
      const ids = body?.ids;
      if (!Array.isArray(ids) || ids.length === 0 || ids.length > 200 || !ids.every((x) => Number.isInteger(x) && x > 0)) {
        throw new HttpError(400, "ids must be 1..200 positive integers");
      }
      return json({ acked: await stub.chiefAck(ids as number[]) });
    }
    if (path === "/chief/send" && req.method === "POST") {
      const body = (await readJsonLimited(req)) as Record<string, unknown>;
      return json(await stub.chiefSend(validText(body?.text)));
    }
    return json({ error: "not_found" }, 404);
  } catch (e) {
    if (e instanceof HttpError) {
      logLine("chief", { path, status: e.status });
      return json({ error: e.message }, e.status);
    }
    logLine("chief", { path, status: 500 });
    return json({ error: "internal_error" }, 500);
  }
}
