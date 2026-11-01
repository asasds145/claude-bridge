import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";
import { errorClass, logLine, stripControl, type StoredMessage } from "./util";

export const RETENTION_MS = 30 * 24 * 3600 * 1000;
export const MAX_PER_THREAD = 200;
export const MAX_TOTAL = 5000;
/** debounce 없음: 조용한 상태에서 온 첫 메시지는 즉시 webhook. */
export const WEBHOOK_DEBOUNCE_MS = 0;
/** 연속 발사 사이 최소 간격. 이 창 안에 온 메시지는 창이 끝나는 시각으로 예약되어 버려지지 않음. */
export const WEBHOOK_MIN_GAP_MS = 5 * 1000;
/** 안전 상한(재시도 포함). send_to_chief 30/h 보다 넉넉하게. */
export const WEBHOOK_MAX_PER_HOUR = 60;
export const WEBHOOK_RETRY_MS = [1, 5, 15].map((m) => m * 60 * 1000);
export const CLEANUP_INTERVAL_MS = 6 * 3600 * 1000;
export const MAX_WAITERS = 10;
/**
 * Cap for outsider-creatable buckets only (registration shards).
 * Trusted keys live in a different map, so filling this one cannot refuse them.
 */
export const MAX_PUBLIC_BUCKETS = 256;
/** Registration is one bucket per hash shard, not per raw address. 2 hex chars = 256 shards. */
export const REGISTER_SHARD_HEX = 2;
const HOUR = 3600 * 1000;

export type WebhookBlockReason = "non_https" | "invalid_url" | "missing_key";

/**
 * Why a webhook must not be sent, or null when it is safe to send.
 * An unset URL is "not configured" (null), not an error: nothing is woken and nothing is logged.
 * Non-https is refused so the bearer key is never sent in cleartext. Embedded userinfo is refused
 * because it is another credential on the request line.
 */
export function webhookBlockReason(url: string | undefined, key: string | undefined): WebhookBlockReason | null {
  if (!url) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "invalid_url";
  }
  if (parsed.protocol !== "https:") return "non_https";
  if (parsed.username !== "" || parsed.password !== "" || parsed.hostname === "") return "invalid_url";
  if (!key?.trim()) return "missing_key";
  return null;
}

type Waiter = {
  token?: string;
  threadId: string;
  afterId: number;
  resolve: (m: StoredMessage[], superseded?: boolean) => void;
  timer: ReturnType<typeof setTimeout>;
};

export interface WaitResult {
  messages: StoredMessage[];
  /** 새 waiter에 밀려 조기 종료됨 (클라이언트가 끊고 다시 호출한 경우 등) */
  superseded?: boolean;
}

/**
 * 단일 인스턴스("main") SQLite DO. 메시지 큐 + webhook 스케줄 + 메모리 rate limit.
 * webhook 스케줄은 SQLite meta 테이블에 저장하고 alarm은 하나만 사용.
 */
export class BoxmcpQueue extends DurableObject<Env> {
  private sql: SqlStorage;
  private waiters = new Set<Waiter>();
  /** Server-chosen keys only: chief, send_to_chief, mcp user, shared unauth/forge buckets. */
  private buckets = new Map<string, { count: number; resetAt: number }>();
  /** Fingerprints of access tokens the provider has already accepted. Fixed size, not one per attacker. */
  private validTokenFps: string[] = [];
  /** Keys an unauthenticated caller can multiply (registration shards). Capped separately. */
  private publicBuckets = new Map<string, { count: number; resetAt: number }>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id TEXT NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('to_chief','to_claude')),
        text TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        acked INTEGER NOT NULL DEFAULT 0
      )`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_thread ON messages(thread_id, id)`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_dir ON messages(direction, acked, id)`);
      this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`);
      if (this.getMeta("cleanup_due") === null) {
        this.setMeta("cleanup_due", String(Date.now() + CLEANUP_INTERVAL_MS));
      }
      await this.rearm();
    });
  }

  // ---------- meta ----------
  private getMeta(k: string): string | null {
    const rows = this.sql.exec<{ v: string }>(`SELECT v FROM meta WHERE k = ?`, k).toArray();
    return rows.length ? rows[0].v : null;
  }
  private setMeta(k: string, v: string | null): void {
    if (v === null) this.sql.exec(`DELETE FROM meta WHERE k = ?`, k);
    else this.sql.exec(`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v);
  }

  private async rearm(): Promise<void> {
    const times = [this.getMeta("wh_due"), this.getMeta("cleanup_due")]
      .filter((x): x is string => x !== null)
      .map(Number);
    if (times.length === 0) return;
    const next = Math.min(...times);
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || cur !== next) await this.ctx.storage.setAlarm(next);
  }

  // ---------- rate limit (DO 메모리; eviction 시 초기화) ----------
  // Trusted keys are not capped by the public map. Outsider-creatable keys use rateLimitPublic.
  async rateLimit(key: string, limit: number, windowMs: number): Promise<{ ok: boolean; retryAfter: number }> {
    return this.limitIn(this.buckets, key, limit, windowMs, Number.POSITIVE_INFINITY);
  }

  async rateLimitPublic(key: string, limit: number, windowMs: number): Promise<{ ok: boolean; retryAfter: number }> {
    return this.limitIn(this.publicBuckets, key, limit, windowMs, MAX_PUBLIC_BUCKETS);
  }

  /**
   * Owner-shaped bearers that this isolate has not accepted yet.
   * `known` skips the failure budget (a real token already worked).
   * `deny` means forged lookups have filled the budget: do not call the provider.
   * `allow` means the caller may look the token up, and should charge mcp:forge only if that lookup fails.
   */
  async mcpForgeAdmit(fp: string, limit: number): Promise<"known" | "allow" | "deny"> {
    if (this.validTokenFps.includes(fp)) return "known";
    const b = this.buckets.get("mcp:forge");
    if (b && b.resetAt > Date.now() && b.count >= limit) return "deny";
    return "allow";
  }

  async noteValidMcpToken(fp: string): Promise<void> {
    this.validTokenFps = this.validTokenFps.filter((x) => x !== fp);
    this.validTokenFps.push(fp);
    if (this.validTokenFps.length > 8) this.validTokenFps.shift();
  }

  private limitIn(
    map: Map<string, { count: number; resetAt: number }>,
    key: string,
    limit: number,
    windowMs: number,
    maxKeys: number,
  ): { ok: boolean; retryAfter: number } {
    const now = Date.now();
    const existing = map.get(key);
    if (!existing || existing.resetAt <= now) {
      const reusesSlot = existing !== undefined && existing.resetAt <= now;
      if (!reusesSlot && map.size >= maxKeys) {
        for (const [k, v] of map) if (v.resetAt <= now) map.delete(k);
      }
      if (!map.has(key) && map.size >= maxKeys) {
        let soonest = now + windowMs;
        for (const v of map.values()) if (v.resetAt < soonest) soonest = v.resetAt;
        return { ok: false, retryAfter: Math.max(1, Math.ceil((soonest - now) / 1000)) };
      }
      map.set(key, { count: 1, resetAt: now + windowMs });
      return { ok: true, retryAfter: 0 };
    }
    if (existing.count >= limit) return { ok: false, retryAfter: Math.ceil((existing.resetAt - now) / 1000) };
    existing.count++;
    return { ok: true, retryAfter: 0 };
  }

  // ---------- 메시지 ----------
  private insert(threadId: string, direction: StoredMessage["direction"], text: string): StoredMessage {
    const now = Date.now();
    const clean = stripControl(text);
    const row = this.sql
      .exec<{ id: number }>(
        `INSERT INTO messages (thread_id, direction, text, created_at) VALUES (?, ?, ?, ?) RETURNING id`,
        threadId,
        direction,
        clean,
        now,
      )
      .one();
    this.enforceRetention(threadId);
    return { id: row.id, thread_id: threadId, direction, text: clean, created_at: now };
  }

  private enforceRetention(threadId?: string): void {
    this.sql.exec(`DELETE FROM messages WHERE created_at < ?`, Date.now() - RETENTION_MS);
    if (threadId !== undefined) {
      this.sql.exec(
        `DELETE FROM messages WHERE thread_id = ? AND id NOT IN (SELECT id FROM messages WHERE thread_id = ? ORDER BY id DESC LIMIT ?)`,
        threadId,
        threadId,
        MAX_PER_THREAD,
      );
    }
    this.sql.exec(`DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY id DESC LIMIT ?)`, MAX_TOTAL);
  }

  private threadExists(threadId: string): boolean {
    return this.sql.exec(`SELECT 1 FROM messages WHERE thread_id = ? LIMIT 1`, threadId).toArray().length > 0;
  }

  /** Claude → chief */
  async sendToChief(text: string, threadId?: string): Promise<{ id: number; thread_id: string } | { error: "unknown_thread" }> {
    let tid = threadId;
    if (tid !== undefined && !this.threadExists(tid)) return { error: "unknown_thread" };
    if (tid === undefined) tid = crypto.randomUUID();
    const m = this.insert(tid, "to_chief", text);
    await this.scheduleWebhook();
    return { id: m.id, thread_id: tid };
  }

  /** chief inbox: 미확인 to_chief 메시지 */
  async chiefInbox(limit: number): Promise<StoredMessage[]> {
    return this.sql
      .exec<StoredMessage & { acked: number }>(
        `SELECT id, thread_id, direction, text, created_at FROM messages WHERE direction = 'to_chief' AND acked = 0 ORDER BY id ASC LIMIT ?`,
        limit,
      )
      .toArray();
  }

  async chiefAck(ids: number[]): Promise<number> {
    let n = 0;
    for (const id of ids) {
      n += this.sql.exec(`UPDATE messages SET acked = 1 WHERE id = ? AND direction = 'to_chief' AND acked = 0 RETURNING id`, id).toArray().length;
    }
    return n;
  }

  /** chief → Claude (기존 thread). 기록 후 waiter 깨움 */
  async chiefReply(threadId: string, text: string): Promise<{ id: number; thread_id: string } | { error: "unknown_thread" }> {
    if (!this.threadExists(threadId)) return { error: "unknown_thread" };
    const m = this.insert(threadId, "to_claude", text);
    this.wake(threadId);
    return { id: m.id, thread_id: threadId };
  }

  /** chief → Claude (새 thread) */
  async chiefSend(text: string): Promise<{ id: number; thread_id: string }> {
    const tid = crypto.randomUUID();
    const m = this.insert(tid, "to_claude", text);
    this.wake(tid);
    return { id: m.id, thread_id: tid };
  }

  async readReplies(opts: { since?: number; threadId?: string; limit: number }): Promise<StoredMessage[]> {
    const since = opts.since ?? 0;
    if (opts.threadId !== undefined) {
      return this.sql
        .exec<StoredMessage>(
          `SELECT id, thread_id, direction, text, created_at FROM messages WHERE direction = 'to_claude' AND thread_id = ? AND id > ? ORDER BY id ASC LIMIT ?`,
          opts.threadId,
          since,
          opts.limit,
        )
        .toArray();
    }
    return this.sql
      .exec<StoredMessage>(
        `SELECT id, thread_id, direction, text, created_at FROM messages WHERE direction = 'to_claude' AND id > ? ORDER BY id ASC LIMIT ?`,
        since,
        opts.limit,
      )
      .toArray();
  }

  async getThread(threadId: string): Promise<StoredMessage[]> {
    return this.sql
      .exec<StoredMessage>(
        `SELECT id, thread_id, direction, text, created_at FROM messages WHERE thread_id = ? ORDER BY id ASC`,
        threadId,
      )
      .toArray();
  }

  /** waiter 등록 전에 먼저 id > after_id 조회 → 경쟁 상태 방지 */
  async waitForReply(threadId: string, afterId: number, timeoutS: number, token?: string): Promise<WaitResult> {
    const existing = await this.readReplies({ threadId, since: afterId, limit: 20 });
    if (existing.length > 0) return { messages: existing };
    // MCP 클라이언트가 끊어도 DO 쪽 RPC는 취소되지 않아 waiter가 timeout까지 남음.
    // 그대로 두면 재시도가 'busy'로 막히므로: 같은 thread의 이전 waiter는 대체하고,
    // 그래도 상한이면 가장 오래된 waiter를 빈 결과로 끝냄.
    for (const old of [...this.waiters]) if (old.threadId === threadId) old.resolve([], true);
    while (this.waiters.size >= MAX_WAITERS) {
      const oldest = this.waiters.values().next().value as Waiter;
      oldest.resolve([], true);
    }
    return new Promise<WaitResult>((resolve) => {
      const w: Waiter = {
        token,
        threadId,
        afterId,
        resolve: (messages, superseded) => {
          clearTimeout(w.timer);
          this.waiters.delete(w);
          resolve(superseded ? { messages, superseded: true } : { messages });
        },
        timer: setTimeout(() => w.resolve([]), timeoutS * 1000),
      };
      this.waiters.add(w);
    });
  }

  /** MCP 요청이 abort되면 해당 waiter를 즉시 해제 (슬롯 반환) */
  async cancelWait(token: string): Promise<boolean> {
    for (const w of [...this.waiters]) {
      if (w.token === token) {
        w.resolve([], true);
        return true;
      }
    }
    return false;
  }

  private wake(threadId: string): void {
    for (const w of [...this.waiters]) {
      if (w.threadId !== threadId) continue;
      const rows = this.sql
        .exec<StoredMessage>(
          `SELECT id, thread_id, direction, text, created_at FROM messages WHERE direction = 'to_claude' AND thread_id = ? AND id > ? ORDER BY id ASC LIMIT 20`,
          threadId,
          w.afterId,
        )
        .toArray();
      if (rows.length) w.resolve(rows);
    }
  }

  async status(): Promise<{
    pending_to_chief: number;
    total_messages: number;
    last_to_chief_at: number | null;
    last_to_claude_at: number | null;
    waiters: number;
    webhook_configured: boolean; webhook_url_valid: boolean;
    webhook_scheduled: boolean;
  }> {
    const pending = this.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM messages WHERE direction='to_chief' AND acked=0`).one().n;
    const total = this.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM messages`).one().n;
    const lastC = this.sql.exec<{ t: number | null }>(`SELECT MAX(created_at) AS t FROM messages WHERE direction='to_chief'`).one().t;
    const lastR = this.sql.exec<{ t: number | null }>(`SELECT MAX(created_at) AS t FROM messages WHERE direction='to_claude'`).one().t;
    return {
      pending_to_chief: pending,
      total_messages: total,
      last_to_chief_at: lastC,
      last_to_claude_at: lastR,
      waiters: this.waiters.size,
      webhook_configured: webhookBlockReason(this.env.CHIEF_WEBHOOK_URL, this.env.CHIEF_WEBHOOK_KEY) === null && Boolean(this.env.CHIEF_WEBHOOK_URL),
      // A placeholder key so "missing key" is not reported as an invalid URL.
      webhook_url_valid: webhookBlockReason(this.env.CHIEF_WEBHOOK_URL, "set") === null && Boolean(this.env.CHIEF_WEBHOOK_URL),
      webhook_scheduled: this.getMeta("wh_due") !== null,
    };
  }

  // ---------- webhook ----------
  private recentSends(now: number): number[] {
    const raw = this.getMeta("wh_sends");
    const arr: number[] = raw ? JSON.parse(raw) : [];
    return arr.filter((t) => t > now - HOUR);
  }

  /** base 이후 가장 이른 발사 허용 시각: 직전 발사 + MIN_GAP, 시간당 상한. 조용했으면 base 그대로. */
  private earliestAllowed(now: number, base: number): number {
    const sends = this.recentSends(now);
    let t = base;
    if (sends.length > 0) t = Math.max(t, Math.max(...sends) + WEBHOOK_MIN_GAP_MS);
    if (sends.length >= WEBHOOK_MAX_PER_HOUR) t = Math.max(t, Math.min(...sends) + HOUR);
    return t;
  }

  /** Drop wh_due / wh_attempt / wh_chain_wm and keep the cleanup alarm. No-op if nothing is scheduled. */
  private async dropWebhookSchedule(): Promise<void> {
    if (this.getMeta("wh_due") === null && this.getMeta("wh_attempt") === null && this.getMeta("wh_chain_wm") === null) return;
    this.clearWebhook();
    await this.rearm();
  }

  private async scheduleWebhook(): Promise<void> {
    // Unset URL is "webhooks off", not a bad URL. Still drop a schedule left over from a previous config.
    if (!this.env.CHIEF_WEBHOOK_URL) {
      await this.dropWebhookSchedule();
      return;
    }
    const blocked = webhookBlockReason(this.env.CHIEF_WEBHOOK_URL, this.env.CHIEF_WEBHOOK_KEY);
    if (blocked) {
      // Reason code only. The URL and key are operator secrets and must not be logged.
      logLine("webhook_skipped", { reason: blocked });
      await this.dropWebhookSchedule();
      return;
    }
    if (this.getMeta("wh_due") !== null) {
      // 이미 예약됨(또는 발사 중) → 합침. 발사 중에 도착한 메시지는 runWebhook이 id watermark로 감지해 후속 예약.
      return;
    }
    const now = Date.now();
    this.setMeta("wh_due", String(this.earliestAllowed(now, now + WEBHOOK_DEBOUNCE_MS)));
    this.setMeta("wh_attempt", "0");
    await this.rearm();
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    const cleanupDue = Number(this.getMeta("cleanup_due") ?? 0);
    if (cleanupDue <= now) {
      this.enforceRetention();
      this.setMeta("cleanup_due", String(now + CLEANUP_INTERVAL_MS));
    }
    const whDue = this.getMeta("wh_due");
    if (whDue !== null && Number(whDue) <= now) {
      await this.runWebhook(now);
    }
    await this.rearm();
  }

  private async runWebhook(now: number): Promise<void> {
    const blocked = webhookBlockReason(this.env.CHIEF_WEBHOOK_URL, this.env.CHIEF_WEBHOOK_KEY);
    if (blocked) {
      logLine("webhook_skipped", { reason: blocked });
      this.clearWebhook();
      return;
    }
    const url = this.env.CHIEF_WEBHOOK_URL;
    const pending = this.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM messages WHERE direction='to_chief' AND acked=0`).one().n;
    if (!url || pending === 0) {
      this.clearWebhook();
      return;
    }
    const allowed = this.earliestAllowed(now, now);
    if (allowed > now) {
      this.setMeta("wh_due", String(allowed));
      return;
    }
    const sends = this.recentSends(now);
    sends.push(now);
    this.setMeta("wh_sends", JSON.stringify(sends));
    // 이번 발사가 다루는 메시지의 상한 id. 이후 id는 '늦게 도착' (시계 대신 단조 증가 id 사용)
    const wm = this.sql.exec<{ m: number | null }>(`SELECT MAX(id) AS m FROM messages WHERE direction='to_chief'`).one().m ?? 0;
    const attempt = Number(this.getMeta("wh_attempt") ?? 0);
    if (attempt === 0) this.setMeta("wh_chain_wm", String(wm));

    let ok = false;
    try {
      const headers = new Headers({ "content-type": "application/json" });
      // webhookBlockReason already required a non-empty key. Unset scheme defaults to Bearer;
      // an explicit empty scheme sends the raw key (wrangler.jsonc sets Bearer).
      const key = this.env.CHIEF_WEBHOOK_KEY as string;
      const name = this.env.CHIEF_WEBHOOK_AUTH_HEADER || "Authorization";
      const scheme = this.env.CHIEF_WEBHOOK_AUTH_SCHEME ?? "Bearer";
      headers.set(name, scheme ? `${scheme} ${key}` : key);
      const res = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify({ source: "chief-bridge", pending }),
        signal: AbortSignal.timeout(25_000),
        redirect: "manual",
      });
      ok = res.status >= 200 && res.status < 300;
      await res.body?.cancel();
      logLine("webhook", { status: res.status });
    } catch (e) {
      // Fetch errors often embed the destination URL in the message. Log the class only.
      logLine("webhook", { status: "error", err_name: errorClass(e) });
    }

    if (ok) {
      // fetch를 기다리는 동안(입력 게이트 열림) 도착한 메시지는 scheduleWebhook이 wh_due를 보고 건너뛰었음.
      // Chief가 이미 inbox를 읽었을 수 있으므로 후속 webhook을 예약해 버려지지 않게 함.
      if (this.unackedAbove(wm) > 0) this.restartChain(Date.now(), 0);
      else this.clearWebhook();
      return;
    }
    if (attempt < WEBHOOK_RETRY_MS.length) {
      this.setMeta("wh_attempt", String(attempt + 1));
      const t = Date.now(); // fetch(최대 25s) 이후 시각 기준
      this.setMeta("wh_due", String(this.earliestAllowed(t, t + WEBHOOK_RETRY_MS[attempt])));
      return;
    }
    // 재시도 소진. 체인 도중(대기 중 합쳐진) 새 메시지가 있으면 그들만을 위해 체인을 한 번 새로 시작
    const chainWm = Number(this.getMeta("wh_chain_wm") ?? wm);
    const stranded = this.unackedAbove(chainWm);
    logLine("webhook_gave_up", { attempts: attempt + 1, restarted: stranded > 0 });
    if (stranded > 0) this.restartChain(Date.now(), WEBHOOK_RETRY_MS[0]);
    else this.clearWebhook();
  }

  private unackedAbove(id: number): number {
    return this.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM messages WHERE direction='to_chief' AND acked=0 AND id > ?`, id).one().n;
  }

  private restartChain(now: number, delay: number): void {
    this.setMeta("wh_due", String(this.earliestAllowed(now, now + delay)));
    this.setMeta("wh_attempt", "0");
  }

  private clearWebhook(): void {
    this.setMeta("wh_due", null);
    this.setMeta("wh_attempt", null);
    this.setMeta("wh_chain_wm", null);
  }
}
