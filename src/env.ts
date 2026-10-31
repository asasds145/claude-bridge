import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { BoxmcpQueue } from "./queue";

export interface Env {
  QUEUE: DurableObjectNamespace<BoxmcpQueue>;
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers; // OAuthProvider가 defaultHandler/apiHandler env에 주입

  // vars
  BOXMCP_OWNER_GITHUB_ID: string;
  GITHUB_CLIENT_ID: string;
  CHIEF_WEBHOOK_AUTH_HEADER?: string;
  CHIEF_WEBHOOK_AUTH_SCHEME?: string;
  BOXMCP_PUBLIC_ORIGIN?: string;

  // secrets (optional: 미설정 시 해당 기능 비활성/503)
  GITHUB_CLIENT_SECRET?: string;
  CHIEF_WEBHOOK_URL?: string;
  CHIEF_WEBHOOK_KEY?: string;
  BOXMCP_CHIEF_API_KEY?: string;
  BOXMCP_CHIEF_API_KEY_NEXT?: string;
}

export const QUEUE_NAME = "main";
export function queueStub(env: Env) {
  return env.QUEUE.get(env.QUEUE.idFromName(QUEUE_NAME));
}
