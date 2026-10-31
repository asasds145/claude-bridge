import { AuthorizationError, type AuthRequest } from "@cloudflare/workers-oauth-provider";
import type { Env } from "./env";
import { escapeAttr, logLine } from "./util";

export const CLAUDE_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN = "https://github.com/login/oauth/access_token";
const GITHUB_USER = "https://api.github.com/user";

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://github.com https://claude.ai; frame-ancestors 'none'; base-uri 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
};

function page(title: string, body: string, status = 200, extra?: Headers): Response {
  const h = new Headers(PAGE_HEADERS);
  extra?.forEach((v, k) => h.append(k, v));
  return new Response(
    `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeAttr(title)}</title>` +
      `<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem}.host{font-size:1.6rem;font-weight:700;padding:.6rem;border:2px solid #c00;border-radius:.4rem;word-break:break-all}button{font-size:1rem;padding:.5rem 1.2rem;margin-right:.6rem}</style>` +
      `</head><body>${body}</body></html>`,
    { status, headers: h },
  );
}

function errorPage(status: number, msg: string): Response {
  return page("chief-bridge", `<h1>chief-bridge</h1><p>${escapeAttr(msg)}</p>`, status);
}

function configured(env: Env): boolean {
  return Boolean(env.GITHUB_CLIENT_SECRET && env.GITHUB_CLIENT_ID && env.BOXMCP_OWNER_GITHUB_ID && env.BOXMCP_OWNER_GITHUB_ID !== "0");
}

/** 오류 리다이렉트는 고정된 Claude callback으로만 (DCR/CIMD로 등록된 임의 URI로의 오류 리다이렉트 차단) */
export function allowedErrorRedirect(redirectUri: string | undefined, redirectTo: string | undefined): boolean {
  return Boolean(redirectTo) && redirectUri === CLAUDE_REDIRECT_URI;
}

/** PKCE S256 필수 (기밀 클라이언트 포함) */
export function pkceOk(r: Pick<AuthRequest, "codeChallenge" | "codeChallengeMethod">): boolean {
  return Boolean(r.codeChallenge) && r.codeChallengeMethod === "S256";
}

/** OAuth userId (":" 금지, workers-oauth-provider completeAuthorization 규칙) */
export function ownerUserId(githubId: number): string {
  return `github-${githubId}`;
}

/** 디버깅용 오류 요약: name, 잘린 message/stack만. 토큰·코드·쿠키·Bearer 값처럼 보이는 부분은 가림 */
export function errorSummary(e: unknown): Record<string, string> {
  const scrub = (t: string) =>
    t
      .replace(/(bearer|basic)\s+[^\s"']+/gi, "$1 [redacted]")
      .replace(/%3D/gi, "=")
      .replace(/\b(code|state|token|access_token|refresh_token|client_secret|handle|cookie)=([^&\s"']+)/gi, "$1=[redacted]")
      .replace(/"(code|state|token|access_token|refresh_token|client_secret|handle)"\s*:\s*"[^"]*"/gi, '"$1":"[redacted]"')
      .replace(/__Host-[^=;\s]+=[^;\s]+/g, "__Host-[redacted]")
      .replace(/[A-Za-z0-9_\-]{32,}/g, "[redacted]");
  if (e instanceof Error) {
    return {
      err_name: e.name.slice(0, 64),
      err_message: scrub(String(e.message)).slice(0, 200),
      err_stack: scrub(String(e.stack ?? "")).split("\n").slice(0, 6).join(" | ").slice(0, 800),
    };
  }
  return { err_name: typeof e, err_message: "" };
}

function handleAuthError(e: unknown, where: string): Response {
  if (e instanceof AuthorizationError) {
    logLine("oauth_error", { where, code: e.code });
    if (e.redirectTo && allowedErrorRedirect(e.redirectUri, e.redirectTo)) return Response.redirect(e.redirectTo, 302);
    return errorPage(400, `요청 오류: ${e.code}`);
  }
  logLine("oauth_error", { where, code: "internal", ...errorSummary(e) });
  return errorPage(500, "내부 오류");
}

/** GET /authorize: 요청 검증 → 동의 페이지 */
async function authorizeGet(req: Request, env: Env): Promise<Response> {
  let authReq: AuthRequest;
  try {
    authReq = await env.OAUTH_PROVIDER.parseAuthRequest(req);
  } catch (e) {
    return handleAuthError(e, "parse");
  }
  // parseAuthRequest 이후 redirect URI 고정 검사 (리다이렉트하지 않고 로컬 오류)
  if (authReq.redirectUri !== CLAUDE_REDIRECT_URI) {
    logLine("oauth_error", { where: "redirect_uri", code: "mismatch" });
    return errorPage(400, "허용되지 않은 redirect_uri");
  }
  if (!pkceOk(authReq)) {
    logLine("oauth_error", { where: "pkce", code: "missing_s256" });
    return errorPage(400, "PKCE(S256) 필요");
  }
  let d: Awaited<ReturnType<typeof env.OAUTH_PROVIDER.describeConsent>>;
  let handle: string, headers: Headers;
  try {
    d = await env.OAUTH_PROVIDER.describeConsent(authReq);
    ({ handle, headers } = await env.OAUTH_PROVIDER.beginConsent(authReq));
  } catch (e) {
    return handleAuthError(e, "consent_page");
  }
  const body =
    `<h1>chief-bridge 연결 승인</h1>` +
    `<p>토큰이 전달될 곳:</p><div class="host">${escapeAttr(d.redirectHost)}</div>` +
    (d.redirectIsLoopback ? `<p><strong>경고: 로컬 주소로 전달됩니다.</strong></p>` : "") +
    `<p>클라이언트: ${escapeAttr(d.clientName ?? "")}${d.clientDomain ? ` (${escapeAttr(d.clientDomain)})` : ""}</p>` +
    `<p>scope: ${escapeAttr(d.scope.join(" "))}</p>` +
    `<p>승인하면 GitHub 로그인으로 소유자 확인을 합니다 (GitHub scope 요청 없음).</p>` +
    `<form method="post" action="/authorize"><input type="hidden" name="handle" value="${escapeAttr(handle)}">` +
    `<button type="submit" name="action" value="approve">승인</button>` +
    `<button type="submit" name="action" value="deny">거부</button></form>`;
  return page("chief-bridge 연결 승인", body, 200, headers);
}

/** POST /authorize: 동의 처리 → GitHub로 */
async function authorizePost(req: Request, env: Env): Promise<Response> {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.startsWith("application/x-www-form-urlencoded")) return errorPage(415, "unsupported content-type");
  const cl = Number(req.headers.get("content-length") ?? "0");
  if (cl > 8192) return errorPage(413, "too large");
  const form = await req.formData();
  const handle = String(form.get("handle") ?? "");
  const action = String(form.get("action") ?? "");
  try {
    if (action !== "approve") {
      const denied = await env.OAUTH_PROVIDER.denyConsent(req, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    // scope 미지정 = 클라이언트가 요청한 scope (scopesSupported 안에서 라이브러리가 검증)
    const approved = await env.OAUTH_PROVIDER.approveConsent(req, handle);
    const { state, headers } = await env.OAUTH_PROVIDER.beginUpstream(approved.request, { headers: approved.headers });
    const origin = new URL(req.url).origin;
    const gh = new URL(GITHUB_AUTHORIZE);
    gh.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    gh.searchParams.set("redirect_uri", `${origin}/callback`);
    gh.searchParams.set("state", state);
    gh.searchParams.set("allow_signup", "false");
    // scope 파라미터 없음: 공개 프로필(id)만 필요
    headers.set("location", gh.toString());
    return new Response(null, { status: 302, headers });
  } catch (e) {
    return handleAuthError(e, "consent");
  }
}

/** GET /callback: GitHub code → numeric id 확인 → 토큰 폐기 → completeAuthorization */
async function callback(req: Request, env: Env): Promise<Response> {
  let resumed;
  try {
    resumed = await env.OAUTH_PROVIDER.finishUpstream(req);
  } catch (e) {
    return handleAuthError(e, "callback_state");
  }
  const url = new URL(req.url);
  const fail = (why: string) => {
    logLine("oauth_error", { where: "callback", code: why });
    return errorPage(403, "소유자 확인 실패");
  };
  if (url.searchParams.get("error")) return fail("upstream_denied");
  const code = url.searchParams.get("code");
  if (!code) return fail("no_code");

  let githubId: number;
  try {
    const tokRes = await fetch(GITHUB_TOKEN, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET ?? "",
        code,
        redirect_uri: `${url.origin}/callback`,
      }),
    });
    const tok = (await tokRes.json()) as { access_token?: string; error?: unknown };
    if (!tokRes.ok || !tok.access_token) {
      // GitHub은 bad_verification_code 등을 200 + error 필드로 돌려줌. 짧은 식별자만 로그.
      const ge = typeof tok.error === "string" && /^[a-z_]{1,40}$/.test(tok.error) ? tok.error : undefined;
      if (ge) logLine("oauth_error", { where: "callback", code: "token_exchange", gh_error: ge, status: String(tokRes.status) });
      return fail("token_exchange");
    }
    let accessToken: string | undefined = tok.access_token;
    const userRes = await fetch(GITHUB_USER, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/vnd.github+json", "user-agent": "chief-bridge" },
    });
    accessToken = undefined; // GitHub 토큰은 저장/props에 넣지 않음
    if (!userRes.ok) return fail("user_fetch");
    const user = (await userRes.json()) as { id?: unknown };
    if (typeof user.id !== "number") return fail("user_shape");
    githubId = user.id;
  } catch (e) {
    logLine("oauth_error", { where: "callback", code: "upstream_error", ...errorSummary(e) });
    return fail("upstream_error");
  }

  if (String(githubId) !== env.BOXMCP_OWNER_GITHUB_ID.trim()) return fail("not_owner");

  try {
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: resumed.request,
      // 라이브러리는 userId에 ":"를 금지함 (grant 키 `grant:${userId}:${grantId}` 구분자). 위반 시 TypeError → 500.
      userId: ownerUserId(githubId),
      metadata: { idp: "github" },
      scope: resumed.request.scope,
      props: { githubId },
    });
    const h = new Headers(resumed.headers);
    h.set("location", redirectTo);
    logLine("oauth_complete", {});
    return new Response(null, { status: 302, headers: h });
  } catch (e) {
    return handleAuthError(e, "complete");
  }
}

/** OAuthProvider defaultHandler 중 인증 UI 부분 */
export async function handleAuthUi(req: Request, env: Env): Promise<Response | null> {
  const { pathname } = new URL(req.url);
  if (pathname !== "/authorize" && pathname !== "/callback") return null;
  if (!configured(env)) return errorPage(503, "GitHub 로그인이 설정되지 않았습니다");
  if (pathname === "/authorize" && req.method === "GET") return authorizeGet(req, env);
  if (pathname === "/authorize" && req.method === "POST") return authorizePost(req, env);
  if (pathname === "/callback" && req.method === "GET") return callback(req, env);
  return errorPage(405, "method not allowed");
}
