import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { handleAuthUi, mcpActorId, mcpUserMatchesOwner } from "./auth-github";
import { handleChief } from "./chief";
import { type Env, queueStub } from "./env";
import { createServer } from "./mcp";
import { REGISTER_SHARD_HEX } from "./queue";
import { MAX_BODY_BYTES, clientIp, json, logLine, routeLabel, sha256Hex } from "./util";

export { BoxmcpQueue } from "./queue";

export const MCP_RATE_PER_MIN = 20;
/**
 * Shared limit for /mcp requests that are not the configured owner's token shape.
 * One bucket. A valid owner token is not charged to it, so this budget cannot 429 the owner.
 * Arbitrary Authorization values do not get their own buckets.
 */
export const MCP_PREAUTH_PER_MIN = 120;
export const REGISTER_RATE_PER_HOUR = 5;
export const ACCESS_TOKEN_TTL = 3600;

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
        const userId = mcpActorId(ctx as ExecutionContext & { auth?: { userId?: string }; props?: { githubId?: number } });
        if (!mcpUserMatchesOwner(userId, env.BOXMCP_OWNER_GITHUB_ID)) {
          logLine("mcp_auth", { status: 401, code: "owner_mismatch" });
          return mcpUnauthorized(new URL(req.url).origin);
        }
        const rl = await queueStub(env).rateLimit(`mcp:${userId}`, MCP_RATE_PER_MIN, 60_000);
        if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });
        return mcp(req, env, ctx);
      },
    },
    defaultHandler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
    clientRegistrationEndpoint: "/oauth/register",
    accessTokenTTL: ACCESS_TOKEN_TTL,
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

    if (path === "/mcp" || path.startsWith("/mcp/")) {
      // Owner-shaped tokens skip this bucket so junk traffic cannot 429 them.
      // Every other request, including a random Authorization header, shares mcp:unauth.
      if (!ownerShapedBearer(req, env)) {
        const rl = await queueStub(env).rateLimit("mcp:unauth", MCP_PREAUTH_PER_MIN, 60_000);
        if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });
      }
    }

    const res = await getProvider(o.origin).fetch(req, env, ctx);
    logLine("req", { route: routeLabel(path), status: res.status });
    return res;
  },
} satisfies ExportedHandler<Env>;

/** Bearer challenge matching the provider's 401s, so Claude.ai starts a new login. */
function mcpUnauthorized(origin: string): Response {
  const metadata = `${origin}/.well-known/oauth-protected-resource/mcp`;
  return json({ error: "unauthorized" }, 401, {
    "www-authenticate": `Bearer realm="OAuth", error="invalid_token", scope="mcp", resource_metadata="${metadata}"`,
  });
}

function bearerToken(req: Request): string | null {
  const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "");
  return m ? m[1] : null;
}

/** Library access tokens are `userId:grantId:secret` with userId `github-<digits>`. */
function tokenUserHint(token: string): string | null {
  const parts = token.split(":");
  if (parts.length !== 3 || !/^github-\d+$/.test(parts[0]) || parts[1].length === 0 || parts[2].length === 0) return null;
  return parts[0];
}

function expectedOwnerUser(env: Env): string | null {
  const owner = env.BOXMCP_OWNER_GITHUB_ID?.trim() ?? "";
  if (!/^\d+$/.test(owner) || owner === "0") return null;
  return `github-${owner}`;
}

function ownerShapedBearer(req: Request, env: Env): boolean {
  const token = bearerToken(req);
  const owner = expectedOwnerUser(env);
  return token !== null && owner !== null && tokenUserHint(token) === owner;
}
