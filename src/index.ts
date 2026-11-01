import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { handleAuthUi, mcpActorId, mcpUserMatchesOwner, validOwnerId } from "./auth-github";
import { handleChief } from "./chief";
import { type Env, queueStub } from "./env";
import { createServer } from "./mcp";
import { REGISTER_SHARD_HEX } from "./queue";
import { MAX_BODY_BYTES, clientIp, json, logLine, routeLabel, sha256Hex } from "./util";

export { BoxmcpQueue } from "./queue";

export const MCP_RATE_PER_MIN = 20;
/**
 * Shared limit for /mcp bearers that are not the owner's token shape.
 * Requests with no Authorization header are not charged: the provider rejects them before KV.
 */
export const MCP_PREAUTH_PER_MIN = 120;
/**
 * Owner-shaped bearers whose grant is not already stored. A slot is reserved before KV lookup
 * and released if the provider accepts the token. Stored grants skip this budget.
 */
export const MCP_FORGE_PER_MIN = 60;
export const REGISTER_RATE_PER_HOUR = 5;
export const ACCESS_TOKEN_TTL = 3600;
/** 30 days. Matches workers-oauth-provider's default, set explicitly so a grant cannot live forever. Refresh does not extend it. */
export const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60;

const defaultHandler: ExportedHandler<Env> = {
  async fetch(req, env) {
    const res = await handleAuthUi(req, env);
    if (res) return res;
    const { pathname } = new URL(req.url);
    if (pathname === "/" || pathname === "/health") return json({ ok: true, service: "chief-bridge" });
    return json({ error: "not_found" }, 404);
  },
};

const providers = new Map<string, OAuthProvider<Env>>();

function getProvider(origin: string): OAuthProvider<Env> {
  let p = providers.get(origin);
  if (p) return p;
  const host = new URL(origin).hostname;
  const mcp = createMcpHandler(createServer, {
      route: "/mcp",
      allowedHostnames: [host],
      corsOptions: false,
      maxRequestBodySize: MAX_BODY_BYTES,
      onerror: () => logLine("mcp_error", {}),
  });
  p = new OAuthProvider<Env>({
    apiRoute: "/mcp",
    // OAuthProvider는 fetch 메서드를 가진 객체를 요구 (함수 단독 불가)
    // apiHandler runs only after the provider has accepted the access token.
    // Rate-limit by that validated user id. Do not key buckets by the raw header.
    apiHandler: {
      fetch: async (req, env, ctx) => {
        const origin = new URL(req.url).origin;
        // The provider only calls this after KV accepts the token. Remember the grant only if it is the current owner.
        const presented = providerBearer(req.headers.get("authorization"));
        const grantId = presented ? ownerGrantId(presented, env) : null;
        if (!validOwnerId(env.BOXMCP_OWNER_GITHUB_ID)) {
          logLine("mcp_auth", { status: 401, code: "bad_owner_id" });
          return markAuth(mcpUnauthorized(origin), "mismatch");
        }
        const userId = mcpActorId(ctx as ExecutionContext & { auth?: { userId?: string }; props?: { githubId?: number } });
        if (!mcpUserMatchesOwner(userId, env.BOXMCP_OWNER_GITHUB_ID)) {
          logLine("mcp_auth", { status: 401, code: "owner_mismatch" });
          return markAuth(mcpUnauthorized(origin), "mismatch");
        }
        if (grantId) await queueStub(env).rememberOwnerGrant(grantId);
        const rl = await queueStub(env).rateLimit(`mcp:${userId}`, MCP_RATE_PER_MIN, 60_000);
        if (!rl.ok) return markAuth(mcpLimited(origin, rl.retryAfter), "owner");
        return markAuth(await mcp(req, env, ctx), "owner");
      },
    },
    defaultHandler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
    clientRegistrationEndpoint: "/oauth/register",
    accessTokenTTL: ACCESS_TOKEN_TTL,
    refreshTokenTTL: REFRESH_TOKEN_TTL,
    // Runs on authorization_code and refresh_token issuance, before the client can call /mcp.
    tokenExchangeCallback: async (options) => {
      if (options.grantType !== "authorization_code" && options.grantType !== "refresh_token") return;
      const owner = expectedOwnerUser(options.env);
      if (!owner || options.userId !== owner) return;
      await queueStub(options.env).rememberOwnerGrant(options.grantId);
    },
    scopesSupported: ["mcp", "offline_access"],
    requiredScopes: ["mcp"],
    clientIdMetadataDocumentEnabled: true,
    resourceMetadata: { resource: `${origin}/mcp`, resource_name: "chief-bridge" },
    onError: ({ status, code }) => logLine("oauth_error_response", { status, code }),
  });
  providers.set(origin, p);
  return p;
}

function publicOrigin(req: Request, env: Env): { origin: string } | { error: Response } {
  const reqOrigin = new URL(req.url).origin;
  const configured = env.BOXMCP_PUBLIC_ORIGIN?.trim().replace(/\/+$/, "");
  if (configured) {
    if (configured !== reqOrigin) return { error: json({ error: "misdirected" }, 421) };
    return { origin: configured };
  }
  return { origin: reqOrigin };
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/chief" || path.startsWith("/chief/")) return handleChief(req, env);

    const o = publicOrigin(req, env);
    if ("error" in o) return o.error;

    if (path === "/oauth/register" && req.method === "POST") {
      // Fixed shard, public map. One address cannot mint a key, and these keys cannot fill the trusted map.
      const shard = (await sha256Hex(clientIp(req))).slice(0, REGISTER_SHARD_HEX);
      const rl = await queueStub(env).rateLimitPublic(`register:${shard}`, REGISTER_RATE_PER_HOUR, 3600_000);
      if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });
    }

    // workers-oauth-provider 1.2.4 matchApiRoute: exact "/mcp" or a descendant "/mcp/...". "/mcpx" is not an API route.
    const mcpPath = path === "/mcp" || path.startsWith("/mcp/");
    let forgeReleaseAt: number | null = null;
    if (mcpPath) {
      const cls = classifyMcpAuth(req, env);
      if (cls.kind === "unauth") {
        const rl = await queueStub(env).rateLimit("mcp:unauth", MCP_PREAUTH_PER_MIN, 60_000);
        if (!rl.ok) {
          logLine("req", { route: routeLabel(path), status: 429 });
          return mcpLimited(o.origin, rl.retryAfter);
        }
      } else if (cls.kind === "forge") {
        // One DO call reserves the slot before KV. A stored owner grant skips the budget.
        const slot = await queueStub(env).reserveForge(cls.grantId, MCP_FORGE_PER_MIN, 60_000);
        if (slot.action === "deny") {
          logLine("req", { route: routeLabel(path), status: 429 });
          return mcpLimited(o.origin, slot.retryAfter);
        }
        if (slot.action === "reserved" && slot.refundable) forgeReleaseAt = slot.resetAt;
      }
    }

    const raw = await getProvider(o.origin).fetch(req, env, ctx);
    const { res, mark } = stripAuthMark(raw);
    // Provider accepted the token (current owner or a previous owner). Release only this window's slot.
    if (forgeReleaseAt !== null && (mark === "owner" || mark === "mismatch")) await queueStub(env).releaseForge(forgeReleaseAt);
    logLine("req", { route: routeLabel(path), status: res.status });
    return res;
  },
} satisfies ExportedHandler<Env>;

/** Same challenge shape as workers-oauth-provider buildWwwAuthenticateHeader (realm, resource_metadata, scope). */
function oauthChallenge(origin: string, error?: "invalid_token"): string {
  const metadata = `${origin}/.well-known/oauth-protected-resource/mcp`;
  const base = `Bearer realm="OAuth", resource_metadata="${metadata}", scope="mcp"`;
  return error ? `${base}, error="${error}"` : base;
}

function mcpUnauthorized(origin: string): Response {
  return json({ error: "unauthorized" }, 401, { "www-authenticate": oauthChallenge(origin, "invalid_token") });
}

function mcpLimited(origin: string, retryAfter: number): Response {
  return json({ error: "rate_limited" }, 429, {
    "retry-after": String(Math.max(1, retryAfter)),
    "www-authenticate": oauthChallenge(origin),
  });
}

const AUTH_MARK = "x-chief-auth";

function markAuth(res: Response, mark: "owner" | "mismatch"): Response {
  const headers = new Headers(res.headers);
  headers.set(AUTH_MARK, mark);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function stripAuthMark(res: Response): { res: Response; mark: string | null } {
  const mark = res.headers.get(AUTH_MARK);
  if (!mark) return { res, mark: null };
  const headers = new Headers(res.headers);
  headers.delete(AUTH_MARK);
  return { res: new Response(res.body, { status: res.status, statusText: res.statusText, headers }), mark };
}

/** Provider 1.2.4 handleApiRequest: `^Bearer[\\t ]+([^\\s,]+)$`. Anything else is not a token lookup. */
function providerBearer(header: string | null): string | null {
  if (!header) return null;
  return /^Bearer[\t ]+([^\s,]+)$/i.exec(header)?.[1] ?? null;
}

function expectedOwnerUser(env: Env): string | null {
  const owner = validOwnerId(env.BOXMCP_OWNER_GITHUB_ID);
  return owner ? `github-${owner}` : null;
}

/** Middle segment of an owner-shaped token, or null. userId is `github-<id>` and contains no colon. */
function ownerGrantId(token: string, env: Env): string | null {
  const owner = expectedOwnerUser(env);
  if (!owner) return null;
  const parts = token.split(":");
  if (parts.length !== 3 || parts[0] !== owner || parts[1].length === 0 || parts[2].length === 0) return null;
  return parts[1];
}

type McpAuthClass = { kind: "none" } | { kind: "unauth" } | { kind: "forge"; grantId: string };

function classifyMcpAuth(req: Request, env: Env): McpAuthClass {
  const header = req.headers.get("authorization");
  // Absent header: provider returns 401 before KV. Do not charge.
  if (header === null) return { kind: "none" };
  const token = providerBearer(header);
  const grantId = token ? ownerGrantId(token, env) : null;
  if (!grantId) return { kind: "unauth" };
  return { kind: "forge", grantId };
}
