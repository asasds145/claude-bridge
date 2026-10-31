import { AuthorizationError, type AuthRequest } from "@cloudflare/workers-oauth-provider";
import type { Env } from "./env";
import { errorClass, escapeAttr, HttpError, logLine, readBodyLimited } from "./util";

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

/**
 * Error redirects may only go to the fixed Claude callback.
 * Check the actual destination (origin + path), not only the associated redirectUri:
 * a truthy redirectTo paired with the right redirectUri would otherwise be trusted blindly.
 */
export function allowedErrorRedirect(redirectUri: string | undefined, redirectTo: string | undefined): boolean {
  if (redirectUri !== CLAUDE_REDIRECT_URI || !redirectTo) return false;
  try {
    const dest = new URL(redirectTo);
    const allowed = new URL(CLAUDE_REDIRECT_URI);
    return (
      dest.protocol === "https:" &&
      dest.origin === allowed.origin &&
      dest.pathname === allowed.pathname &&
      dest.username === "" &&
      dest.password === ""
    );
  } catch {
    return false;
  }
}

/** PKCE S256 필수 (기밀 클라이언트 포함) */
export function pkceOk(r: Pick<AuthRequest, "codeChallenge" | "codeChallengeMethod">): boolean {
  return Boolean(r.codeChallenge) && r.codeChallengeMethod === "S256";
}

/** OAuth userId (":" 금지, workers-oauth-provider completeAuthorization 규칙) */
export function ownerUserId(githubId: number): string {
  return `github-${githubId}`;
}

/**
 * True when the validated token subject is the GitHub user currently configured as owner.
 * Checked on each MCP call so a previous owner's access token stops working after the id changes.
 */
export function mcpUserMatchesOwner(userId: string | undefined, ownerGithubId: string | undefined): userId is string {
  const owner = ownerGithubId?.trim() ?? "";
  if (!/^\d+$/.test(owner) || owner === "0") return false;
  return userId === `github-${owner}`;
}

function handleAuthError(e: unknown, where: string): Response {
  if (e instanceof AuthorizationError) {
    logLine("oauth_error", { where, code: e.code });
    if (e.redirectTo && allowedErrorRedirect(e.redirectUri, e.redirectTo)) return Response.redirect(e.redirectTo, 302);
    return errorPage(400, `요청 오류: ${e.code}`);
  }
  logLine("oauth_error", { where, code: "internal", err_name: errorClass(e) });
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

/** POST /authorize body cap. Enforced by reading the stream, not by trusting Content-Length. */
export const CONSENT_MAX_BODY = 8192;

function bytesToBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** GitHub login leg PKCE. The verifier stays in the upstream transaction, not on the redirect URL. */
async function githubPkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  return { verifier, challenge: bytesToBase64Url(digest) };
}

/** POST /authorize: 동의 처리 → GitHub로 */
async function authorizePost(req: Request, env: Env): Promise<Response> {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.startsWith("application/x-www-form-urlencoded")) return errorPage(415, "unsupported content-type");
  let handle: string;
  let action: string;
  try {
    // Cap the bytes actually read. A missing or small Content-Length must not unlock a larger body.
    const bytes = await readBodyLimited(req, CONSENT_MAX_BODY);
    const form = new URLSearchParams(new TextDecoder().decode(bytes));
    handle = form.get("handle") ?? "";
    action = form.get("action") ?? "";
  } catch (e) {
    const status = e instanceof HttpError && (e.status === 400 || e.status === 413) ? e.status : 400;
    if (!(e instanceof HttpError)) logLine("oauth_error", { where: "consent_body", code: "bad_body", err_name: errorClass(e) });
    return errorPage(status, status === 413 ? "too large" : "bad request");
  }
  try {
    if (action !== "approve") {
      const denied = await env.OAUTH_PROVIDER.denyConsent(req, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    // scope 미지정 = 클라이언트가 요청한 scope (scopesSupported 안에서 라이브러리가 검증)
    const approved = await env.OAUTH_PROVIDER.approveConsent(req, handle);
    const pkce = await githubPkce();
    const { state, headers } = await env.OAUTH_PROVIDER.beginUpstream(approved.request, {
      headers: approved.headers,
      data: { codeVerifier: pkce.verifier },
    });
    const origin = new URL(req.url).origin;
    const gh = new URL(GITHUB_AUTHORIZE);
    gh.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    gh.searchParams.set("redirect_uri", `${origin}/callback`);
    gh.searchParams.set("state", state);
    gh.searchParams.set("code_challenge", pkce.challenge);
    gh.searchParams.set("code_challenge_method", "S256");
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
    resumed = await env.OAUTH_PROVIDER.finishUpstream<{ codeVerifier?: string }>(req);
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
    const tokenBody = new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET ?? "",
      code,
      redirect_uri: `${url.origin}/callback`,
    });
    // Present only when this login started with a challenge. In-flight logins from before that have neither.
    if (resumed.data?.codeVerifier) tokenBody.set("code_verifier", resumed.data.codeVerifier);
    const tokRes = await fetch(GITHUB_TOKEN, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: tokenBody,
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
    logLine("oauth_error", { where: "callback", code: "upstream_error", err_name: errorClass(e) });
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
