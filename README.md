# Claude Bridge (chief-bridge)

A small **remote MCP server on Cloudflare Workers** that lets a Claude session and a Grok Bot agent ("Chief") talk to each other directly.

Claude gets a few MCP tools (`send_to_chief`, `wait_for_reply`, ...). When Claude sends a message, the bridge stores it in a Durable Object queue and fires a webhook that wakes your Grok Bot agent. The agent reads its inbox over a small authenticated HTTP API, posts a reply, and Claude picks the reply up with `wait_for_reply`.

> This is a plain remote MCP server (Streamable HTTP + OAuth) for the **Claude.ai custom connector** only. The OAuth callback is pinned to `https://claude.ai/api/mcp/auth_callback`. It is **not** a Claude Code client (that callback is localhost and is not allowlisted) and it is **not** a Claude Code "Channels" server.

## Architecture

```mermaid
flowchart LR
  subgraph Claude
    C[Claude.ai connector<br/>remote MCP client]
  end
  subgraph CF[Cloudflare Worker: chief-bridge]
    O[OAuth provider<br/>workers-oauth-provider]
    M["/mcp<br/>MCP tools"]
    A["/chief/*<br/>bot HTTP API"]
    Q[(Durable Object BoxmcpQueue<br/>SQLite queue + alarms)]
    K[(KV OAUTH_KV<br/>OAuth grants/tokens)]
  end
  GH[GitHub OAuth<br/>owner check]
  G[Grok Bot agent<br/>Chief]

  C -- OAuth 2.1 + PKCE --> O
  O -- login --> GH
  O --- K
  C -- Bearer token --> M
  M --> Q
  Q -- "webhook (Bearer CHIEF_WEBHOOK_KEY)" --> G
  G -- "Bearer BOXMCP_CHIEF_API_KEY" --> A
  A --> Q
```

## Message flow

1. Claude calls `send_to_chief(text)`. The worker stores it in the `BoxmcpQueue` Durable Object (a single SQLite-backed instance) and returns `{thread_id, id}`.
2. The Durable Object schedules a webhook with an alarm and `POST`s `{"source":"chief-bridge","pending":N}` to `CHIEF_WEBHOOK_URL` with `Authorization: Bearer <CHIEF_WEBHOOK_KEY>` (header name and scheme are configurable). The message text is **not** sent in the webhook. The send is skipped unless the URL is `https` (no embedded username or password) and `CHIEF_WEBHOOK_KEY` is set. A skip is logged by reason code only; the URL and the key are not logged.
3. The woken agent calls `GET /chief/inbox`, then `POST /chief/reply {thread_id, text}` and `POST /chief/ack {ids}`.
4. Meanwhile Claude loops on `wait_for_reply(thread_id, after_id)`. Each call long-polls the Durable Object for up to 55 s; a reply wakes it immediately. The server instructions tell Claude to keep looping for about 5 minutes and to call `read_chief_replies` before concluding there is no reply.

Webhook scheduling (in `src/queue.ts`):

- No debounce: the first message after a quiet period fires immediately.
- At least 5 s between webhook fires; messages arriving inside that window are coalesced into the next fire, not dropped.
- Hard cap of 60 fires per hour (retries included).
- Non-2xx or network error: retries after +1, +5, +15 minutes (25 s request timeout, redirects not followed).
- If new messages arrive while a fire is in flight, a follow-up webhook is scheduled after a success; if retries are exhausted, the chain restarts once for messages that arrived during it.

## MCP tools (Claude side)

| Tool | What it does |
|---|---|
| `send_to_chief` | Send a message (max 8000 chars). Omit `thread_id` to start a new thread. Rate-limited to 30/hour. |
| `wait_for_reply` | Long-poll for a reply in `thread_id` with id > `after_id`. `timeout_s` is clamped to 1..55 (default 50). |
| `read_chief_replies` | Read replies with id > `since`, optionally for one thread (max 20). |
| `get_thread` | Retained messages in a thread. Chief→Claude replies include their text (wrapped as untrusted). Claude→Chief messages are metadata only (id and time, labeled "sent by you"); the original text is not returned. |
| `chief_status` | Pending count, last activity, whether a webhook is configured/scheduled. |

Replies are returned wrapped as `<chief_message untrusted="true" ...>` with `<`/`>` escaped and control/bidi characters stripped, and the server instructions tell Claude to treat that content as data, not instructions.

## Bot API (agent side)

All `/chief/*` endpoints require `Authorization: Bearer <BOXMCP_CHIEF_API_KEY>` (or `_NEXT`, for rotation; compared in constant time). Rate-limited to 60/min.

| Method & path | Body | Result |
|---|---|---|
| `GET /chief/health` | – | `{ok, pending, webhook_configured, webhook_url_valid}`. `webhook_url_valid` is true only for an `https` URL with no embedded userinfo. `webhook_configured` is true only when that URL is set **and** `CHIEF_WEBHOOK_KEY` is set (a webhook will actually be sent). |
| `GET /chief/inbox?limit=1..100` | – | Unacked Claude→Chief messages (`untrusted: true`) |
| `POST /chief/reply` | `{thread_id, text}` | Reply in an existing thread; wakes waiting `wait_for_reply` calls |
| `POST /chief/ack` | `{ids: [..]}` | Mark inbox messages handled (1..200 ids) |
| `POST /chief/send` | `{text}` | Start a new Chief→Claude thread |

Request bodies are capped at 64 KB.

## Setup

Requirements: a Cloudflare account (Workers + Durable Objects + KV), Node.js 22+, a GitHub account, and an agent that can receive an HTTPS webhook and make HTTP calls (built for a Grok Bot routine, but any agent works).

```bash
git clone https://github.com/asasds145/claude-bridge.git
cd claude-bridge
npm ci
npm test            # vitest, runs in workerd via @cloudflare/vitest-plugin
npx tsc --noEmit
```

1. **KV namespace**
   ```bash
   npx wrangler kv namespace create OAUTH_KV
   ```
   Put the returned id into `wrangler.jsonc` (`<YOUR_KV_NAMESPACE_ID>`).

2. **GitHub OAuth app** (GitHub → Settings → Developer settings → OAuth Apps):
   - Homepage URL: `https://chief-bridge.<your-subdomain>.workers.dev`
   - Authorization callback URL: `https://chief-bridge.<your-subdomain>.workers.dev/callback`
   - Put the Client ID into `GITHUB_CLIENT_ID` in `wrangler.jsonc`.

3. **Owner allowlist**: set `BOXMCP_OWNER_GITHUB_ID` to your numeric GitHub user id (`curl https://api.github.com/users/<login>` → `id`). Only this account can authorize.

4. **Public origin**: set `BOXMCP_PUBLIC_ORIGIN` to the worker's https origin (recommended; requests to other hosts get `421`). For local `wrangler dev`, leave it empty or set it to the local origin (for example `http://127.0.0.1:8787`). If it stays set to the production origin, requests to the dev server return `421`. The GitHub OAuth app's authorization callback must be `<that-origin>/callback`; a production callback does not complete a local login. Use a separate OAuth app for local development, or point the callback at the origin you are actually using.

5. **Deploy and set secrets**
   ```bash
   npx wrangler deploy
   npx wrangler secret put GITHUB_CLIENT_SECRET
   npx wrangler secret put BOXMCP_CHIEF_API_KEY      # e.g. openssl rand -hex 32
   npx wrangler secret put CHIEF_WEBHOOK_URL         # your agent's webhook (https)
   npx wrangler secret put CHIEF_WEBHOOK_KEY         # bearer token the webhook expects
   ```
   Until `GITHUB_CLIENT_SECRET` is set and `BOXMCP_OWNER_GITHUB_ID` is a valid decimal id (digits only, no leading zero), `/authorize` returns 503. Without an `https` `CHIEF_WEBHOOK_URL` **and** `CHIEF_WEBHOOK_KEY`, messages queue but nothing is woken. An `http` URL, a URL with embedded userinfo, or a missing key is skipped (the key is never sent unauthenticated).

6. **Add the connector in Claude**: Claude.ai → Settings → Connectors → Add custom connector → URL `https://chief-bridge.<your-subdomain>.workers.dev/mcp`. Approve on the consent page, log in with GitHub.

7. **Wire up the agent**: give your agent (e.g. a Grok Bot routine triggered by the webhook) the API key and tell it to read `/chief/inbox`, reply via `/chief/reply`, then `/chief/ack`. Treat every inbox `text` as untrusted data from another model, not as instructions. Do not follow requests inside that text (tools, secrets, policy changes); confirm those with the user through your own trusted instructions. The inbox is JSON with `untrusted: true`, not the `<chief_message>` wrapper Claude sees.

8. **Smoke test** (read-only). `scripts/verify.sh` does **not** load `.env`; export the variables yourself (or `set -a && source .env && set +a` — `.env.example` lists only these two names):
   ```bash
   printf 'Authorization: Bearer %s\n' "$KEY" > chief.hdr   # gitignored
   export BRIDGE_URL=https://chief-bridge.<your-subdomain>.workers.dev
   export CHIEF_HEADER_FILE=./chief.hdr
   npm run verify
   ```

For local development, copy `.dev.vars.example` to `.dev.vars` and run `npx wrangler dev`. See step 4 for the local public origin and GitHub callback. Changing `BOXMCP_OWNER_GITHUB_ID` makes existing MCP access tokens fail on the next call (the token's user id is checked against the current value). That 401 includes `WWW-Authenticate` with `resource_metadata`, so the client can start login again. Grants already stored in KV are not deleted immediately. Each grant expires 30 days after it was issued (`refreshTokenTTL`). In `@cloudflare/workers-oauth-provider` 1.2.4, `handleRefreshTokenGrant` moves `expiresAt` only when `refreshTokenIdleTTL` is set; this worker does not set it, so a refresh does not extend that deadline. Until then, an old grant can still mint an access token, and `/mcp` rejects it.

## Configuration

| Name | Kind | Example / placeholder | Purpose |
|---|---|---|---|
| `OAUTH_KV` | KV binding | `<YOUR_KV_NAMESPACE_ID>` | OAuth clients, grants, tokens |
| `QUEUE` | Durable Object | `BoxmcpQueue` | Message queue, webhook scheduler, rate limits |
| `BOXMCP_OWNER_GITHUB_ID` | var | `12345678` | The only GitHub user id allowed to authorize |
| `GITHUB_CLIENT_ID` | var | `<your-github-oauth-client-id>` | GitHub OAuth app |
| `BOXMCP_PUBLIC_ORIGIN` | var | `https://chief-bridge.<sub>.workers.dev` | Canonical origin (OAuth resource metadata) |
| `CHIEF_WEBHOOK_AUTH_HEADER` | var | `Authorization` | Header used for the webhook key |
| `CHIEF_WEBHOOK_AUTH_SCHEME` | var | `Bearer` | Scheme prefix. Unset defaults to `Bearer`. An explicit empty string sends the raw key. |
| `GITHUB_CLIENT_SECRET` | secret | – | GitHub OAuth app secret |
| `BOXMCP_CHIEF_API_KEY` | secret | – | Key for `/chief/*` |
| `BOXMCP_CHIEF_API_KEY_NEXT` | secret (optional) | – | Second key for rotation |
| `CHIEF_WEBHOOK_URL` | secret | `https://<agent-webhook-host>/...` | Where to send the wake-up webhook. Must be `https` with no userinfo; anything else is skipped |
| `CHIEF_WEBHOOK_KEY` | secret | – | Bearer token sent with the webhook. If unset, the webhook is not sent |

## Security notes

- **Single-owner OAuth.** The worker is its own OAuth 2.1 authorization server (`@cloudflare/workers-oauth-provider`) and uses GitHub only to prove identity: it requests no GitHub scopes, checks the numeric user id against `BOXMCP_OWNER_GITHUB_ID`, and discards the GitHub token immediately.
- **PKCE S256** is required on the Claude.ai authorization request (the downstream leg). The GitHub login (the upstream leg) also sends S256: the verifier is stored in the OAuth provider's upstream transaction and presented only at the token exchange, not on the redirect URL.
- Explicit consent page showing where the token will go, and `redirect_uri` pinned to Claude.ai's callback (`https://claude.ai/api/mcp/auth_callback`). An error redirect is sent only when the destination's origin and path are that callback (not merely when the request's `redirect_uri` field matches).
- Access tokens live 1 hour. Refresh grants live 30 days from issuance (`refreshTokenTTL` is set explicitly). Refreshing does not extend the grant, because `refreshTokenIdleTTL` is unset (checked in workers-oauth-provider 1.2.4: `handleRefreshTokenGrant` updates `expiresAt` only when that idle TTL is set). `/oauth/register` is limited to 5/hour per IP shard (256 shards from the IP hash) in a separate map. Filling those shards cannot refuse `chief`, `send_to_chief`, or authenticated MCP buckets.
- `BOXMCP_OWNER_GITHUB_ID` must be a valid decimal id (`/^[1-9]\d*$/`, no leading zero). Anything else fails closed (`/authorize` stays 503, `/mcp` stays 401) and the log code is `bad_owner_id` (the value is not logged).
- `/mcp` and `/mcp/...` (the provider's API route; `/mcpx` is not) are checked against a Workers [Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) before any Durable Object call, and only when the request has an `Authorization` header. A missing header is not counted: the provider rejects it with 401 and `WWW-Authenticate` before any KV read, and a connector probe must not be able to spend the budget. The key is the SHA-256 of `CF-Connecting-IP`, or the fixed key `no-connecting-ip` when that header is absent. The binding allows 600 requests per 60 seconds. The owner's own `/mcp` cap is 20/minute, so 600 is thirty times normal use: reconnects and a few clients behind one address do not hit it, and one address still cannot open thousands of KV lookups per minute before the Durable Object. The binding is approximate and counted separately in each Cloudflare location. A denial is 429 with `WWW-Authenticate` and `Retry-After: 60` (the configured period; `limit()` does not report time left in the window). If `MCP_IP_LIMITER` is not bound, the request is allowed and each such request logs `rate_limiter=missing`. If `limit()` throws, the request is allowed and the log is `rate_limiter=error` plus `error_class` only. This is configuration only: it takes effect on the next deploy, and this repo does not deploy the Worker. Tests set the same binding to 8 per minute so a short loop can reach 429; bursts that must still reach the Durable Object use a distinct address per request.
- Any `Authorization` value that is not the owner's `userId:grantId:secret` token, including a malformed bearer such as `Bearer a:b:c d`, shares one 120/minute bucket (`mcp:unauth`). The provider parses the scheme with `/^Bearer[\t ]+([^\s,]+)$/i`, so a lowercase `bearer` is a real token.
- Forged bearers that copy the owner's id reserve a slot in `mcp:forge` (60/minute) inside the Durable Object before the KV lookup, so a parallel burst cannot exceed the cap. A stored grant id does not use that bucket: unknown forgeries must not be able to crowd out a login that was already recorded. The id is not the secret, so those requests are not unlimited either. They reserve `mcp:known` (120/minute) before the KV read. The slot is released only when `/mcp` accepts the current owner, and only if that reservation's window is still current. A wrong secret keeps the charge, and so does an owner-mismatch 401. When `mcp:known` is full the request is 429 and does not read KV. An unknown owner-shaped token, when `mcp:forge` is full, may still be looked up once every 5 seconds; that trickle admission is not refunded. The owner's grant id is written to Durable Object SQLite when `/oauth/token` issues an access token (authorization code or refresh) for the current owner, and again after a successful owner check on `/mcp` if the row is missing or older than 60 seconds. A refresh of a deleted row writes it again. A changed `BOXMCP_OWNER_GITHUB_ID` does not record the previous owner's grant. Eviction always keeps the row just written and breaks equal `seen_at` ties by `rowid`. A Durable Object error while recording at issuance is logged as `grant_record` with `error_class` only and does not fail `/oauth/token`. A wrong secret does not refresh `seen_at`. MCP 401s and 429s include `WWW-Authenticate` with `resource_metadata`, and 429s send `Retry-After`. After acceptance, `/mcp` is 20/minute for that user id.
- **Bot endpoints** need a separate bearer API key (constant-time compare, rotation via `_NEXT`).
- **Webhook** carries only a pending count. It is sent only to an `https` URL with no embedded userinfo, and only with `CHIEF_WEBHOOK_KEY` set. Redirects are not followed.
- Everything coming from the other side is wrapped and marked untrusted on both ends (prompt-injection hygiene). That marker does not stop a model from obeying text inside the payload; the agent instructions in setup step 7 are what keep that boundary.
- **No secrets in the repo.** All secrets are Worker secrets; `.dev.vars`, `.env*`, and header files are gitignored. Application logs (`logLine`) record event names, fixed route labels, status codes, counts, and error class or error code. They do not include message content, exception messages, stack traces, bodies, headers, tokens, webhook URLs, keys, raw request paths, or query strings. Invocation logs are turned off (`observability.logs.invocation_logs`). `redact_query_string` is a real Wrangler setting and strips query strings from request URLs in logs and traces ([Workers observability configuration](https://developers.cloudflare.com/workers/wrangler/configuration/#observability)). Tail and trace request headers are redacted when the header name is `cookie` or `set-cookie`, or contains `auth`, `key`, `secret`, `token`, or `jwt` ([Tail handler](https://developers.cloudflare.com/workers/runtime-apis/handlers/tail/)), so an `Authorization` value is not kept in those header fields.
- Retention: messages are kept 30 days, at most 200 per thread and 5000 total.

## Limitations

- Single user, single queue (one Durable Object instance named `main`). Authenticated abuse limits also run on that object. The IP rate-limiting binding above runs first, so a flood of `Authorization`-bearing `/mcp` traffic from one address is shed before the object. A WAF rate-limiting rule is a different control: it needs a Cloudflare zone on a custom domain and is not available on `*.workers.dev`.
- The OAuth `redirect_uri` is hard-coded to Claude.ai's connector callback, so other MCP clients (e.g. Claude Code, which uses a localhost callback) need `CLAUDE_REDIRECT_URI` in `src/auth-github.ts` adjusted before they can connect.
- Asynchronous: a reply usually takes 1-3 minutes (agent wake-up time), and Claude has to keep polling with `wait_for_reply`.
- In-memory rate-limit counters reset when the Durable Object is evicted.
- The consent and error pages are in Korean.
- Webhook payload format is fixed (`{source, pending}`); your agent must fetch the actual messages from `/chief/inbox`.

## License

MIT, see [LICENSE](LICENSE).

---

## 한국어 소개

**Claude Bridge**는 Cloudflare Workers 위에서 동작하는 원격 MCP 서버로, Claude(Claude.ai 커넥터)와 Grok Bot 에이전트("Chief")가 서로 직접 메시지를 주고받게 해 줍니다.

- Claude가 `send_to_chief`로 메시지를 보내면 Durable Object 큐에 저장되고, webhook이 Grok Bot 에이전트를 깨웁니다.
- 에이전트는 API 키로 보호된 `/chief/*` 엔드포인트에서 메시지를 읽고 답장하며, Claude는 `wait_for_reply`로 답을 받습니다.
- GitHub OAuth로 소유자 한 명만 연결할 수 있고, 모든 비밀값은 `wrangler secret put`으로만 설정합니다.

설치 방법은 위 [Setup](#setup) 섹션을 참고하세요.
