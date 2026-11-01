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

function ipv4Key(s: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map((p) => Number(p));
  if (parts.some((n) => !Number.isInteger(n) || n > 255)) return null;
  return parts.join(".");
}

/** Expand an IPv6 address to 8 groups, or null when it is not one. */
function expandIpv6(text: string): number[] | null {
  if (text.includes(":::")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const parts = side.split(":");
    if (parts.some((p) => !/^[0-9a-f]{1,4}$/.test(p))) return null;
    return parts.map((p) => Number.parseInt(p, 16));
  };
  if (halves.length === 1) {
    const groups = parseSide(halves[0]);
    if (!groups || groups.length !== 8) return null;
    return groups;
  }
  const left = parseSide(halves[0]);
  const right = parseSide(halves[1]);
  if (!left || !right || left.length + right.length > 7) return null;
  return [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
}

/**
 * What we hash for the IP limiter. IPv4 uses the whole address. IPv6 uses the /64,
 * so a client cannot mint a new budget by rotating the host bits. An IPv4-mapped
 * IPv6 address uses the embedded IPv4 address. Unparseable input is kept distinct.
 */
export function ipRateLimitMaterial(ip: string): string {
  let text = ip.trim().toLowerCase();
  const zone = text.indexOf("%");
  if (zone >= 0) text = text.slice(0, zone);
  const v4 = ipv4Key(text);
  if (v4) return `4:${v4}`;
  const dotted = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (dotted) {
    const embedded = ipv4Key(dotted[2]);
    if (!embedded) return `raw:${text}`;
    const [a, b, c, d] = embedded.split(".").map(Number);
    text = `${dotted[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const groups = text.includes(":") ? expandIpv6(text) : null;
  if (!groups) return `raw:${text}`;
  // ::ffff:0:0/96, whether written as ::ffff:192.0.2.1 or ::ffff:c000:201.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const hi = groups[6];
    const lo = groups[7];
    return `4:${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return `6:${groups.slice(0, 4).map((g) => g.toString(16)).join(":")}`;
}

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/**
 * Read the body up to `max` bytes.
 * Content-Length is only an early reject: a missing or understated length still stops at `max`.
 * Stream errors become a generic 400 so the original message (which may quote user input) is not surfaced.
 */
export async function readBodyLimited(req: Request, max: number): Promise<Uint8Array> {
  const cl = req.headers.get("content-length");
  if (cl !== null && /^\d+$/.test(cl) && Number(cl) > max) throw new HttpError(413, "body too large");
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel().catch(() => {});
        throw new HttpError(413, "body too large");
      }
      chunks.push(value);
    }
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, "bad body");
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return buf;
}

/** 64KB 상한으로 body를 읽어 JSON 파싱 */
export async function readJsonLimited(req: Request, max = MAX_BODY_BYTES): Promise<unknown> {
  if (!req.body) throw new HttpError(400, "missing body");
  const buf = await readBodyLimited(req, max);
  try {
    return JSON.parse(new TextDecoder().decode(buf));
  } catch (e) {
    if (e instanceof HttpError) throw e;
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

/** Names we are willing to log. Anything else collapses to "Error" so a custom name cannot carry message text. */
const LOG_ERROR_NAMES = new Set([
  "Error",
  "TypeError",
  "RangeError",
  "SyntaxError",
  "ReferenceError",
  "URIError",
  "EvalError",
  "AbortError",
  "TimeoutError",
  "DOMException",
]);

/** Error class only. Message and stack are omitted: they can contain relayed message text or a URL. */
export function errorClass(e: unknown): string {
  if (e instanceof Error) return LOG_ERROR_NAMES.has(e.name) ? e.name : "Error";
  return typeof e;
}

const CHIEF_ROUTES = new Set(["/chief/health", "/chief/inbox", "/chief/reply", "/chief/ack", "/chief/send"]);

/** Fixed log label. Never the raw path: it is attacker-controlled and may contain a token or key. */
export function routeLabel(pathname: string): string {
  if (pathname === "/" || pathname === "/health") return pathname;
  if (pathname === "/mcp" || pathname.startsWith("/mcp/")) return "/mcp";
  if (pathname === "/authorize" || pathname === "/callback" || pathname === "/oauth/token" || pathname === "/oauth/register") return pathname;
  if (CHIEF_ROUTES.has(pathname)) return pathname;
  if (pathname.startsWith("/.well-known/")) return "/.well-known";
  return "unknown_route";
}

/** Logs: event, route label, status, counts, error class/code. No message body, stack, header, token, URL, raw path, or query. */
export function logLine(event: string, fields: Record<string, string | number | boolean> = {}): void {
  console.log(JSON.stringify({ event, ...fields }));
}
