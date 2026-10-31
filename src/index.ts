import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { handleAuthUi } from "./auth-github";
import { handleChief } from "./chief";
import { type Env, queueStub } from "./env";
import { createServer } from "./mcp";
import { MAX_BODY_BYTES, clientIp, json, logLine, sha256Hex } from "./util";

export { BoxmcpQueue } from "./queue";

export const MCP_RATE_PER_MIN = 20;
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
    apiHandler: { fetch: (req, env, ctx) => mcp(req, env, ctx) },
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
      const rl = await queueStub(env).rateLimit(`register:${clientIp(req)}`, REGISTER_RATE_PER_HOUR, 3600_000);
      if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });
    }

    if (path === "/mcp" || path.startsWith("/mcp/")) {
      const auth = req.headers.get("authorization");
      if (auth) {
        const key = `mcp:${(await sha256Hex(auth)).slice(0, 32)}`;
        const rl = await queueStub(env).rateLimit(key, MCP_RATE_PER_MIN, 60_000);
        if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });
      }
    }

    const res = await getProvider(o.origin).fetch(req, env, ctx);
    logLine("req", { path: path.length > 64 ? path.slice(0, 64) : path, status: res.status });
    return res;
  },
} satisfies ExportedHandler<Env>;
