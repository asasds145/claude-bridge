export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_TEXT = 8000;
export const THREAD_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

// C0/C1 제어문자(\t \n \r 제외)와 bidi override 문자 제거
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;
export function stripControl(s: string): string {
  return s.replace(CONTROL_RE, "");
}

export function escapeAngle(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function escapeAttr(s: string): string {
  return escapeAngle(s).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export type StoredMessage = {
  id: number;
  thread_id: string;
  direction: "to_chief" | "to_claude";
  text: string;
  created_at: number;
};

/** Claude로 가는 텍스트: untrusted 태그로 감싸고 <,> 이스케이프 */
export function wrapForClaude(m: StoredMessage): string {
  return (
    `<chief_message untrusted="true" id="${m.id}" thread_id="${escapeAttr(m.thread_id)}" ` +
    `created_at="${new Date(m.created_at).toISOString()}">` +
    escapeAngle(stripControl(m.text)) +
    `</chief_message>`
  );
}

const enc = new TextEncoder();
async function sha256(s: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", enc.encode(s));
}

/** 상수시간 비교: 양쪽 SHA-256 후 timingSafeEqual (길이 노출 방지) */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

export async function sha256Hex(s: string): Promise<string> {
  const h = new Uint8Array(await sha256(s));
  return [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** 64KB 상한으로 body를 읽어 JSON 파싱 */
export async function readJsonLimited(req: Request, max = MAX_BODY_BYTES): Promise<unknown> {
  const cl = req.headers.get("content-length");
  if (cl !== null && Number(cl) > max) throw new HttpError(413, "body too large");
  if (!req.body) throw new HttpError(400, "missing body");
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new HttpError(413, "body too large");
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(buf));
  } catch {
    throw new HttpError(400, "invalid json");
  }
}

export function json(data: unknown, status = 200, headers?: HeadersInit): Response {
  const h = new Headers(headers);
  h.set("content-type", "application/json; charset=utf-8");
  h.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { status, headers: h });
}

export function clientIp(req: Request): string {
  return req.headers.get("cf-connecting-ip") ?? "unknown";
}

/** 로그: 경로/상태만. body·헤더·토큰·URL query 미포함 */
export function logLine(event: string, fields: Record<string, string | number | boolean> = {}): void {
  console.log(JSON.stringify({ event, ...fields }));
}
