import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // 테스트 전용 값. 실제 secret 아님.
        bindings: {
          BOXMCP_PUBLIC_ORIGIN: "https://chief-bridge.test",
          BOXMCP_CHIEF_API_KEY: "test-chief-key-not-a-secret",
          BOXMCP_OWNER_GITHUB_ID: "12345",
          GITHUB_CLIENT_ID: "test-client-id",
        },
        // Same binding as wrangler, with a small limit so a short loop can reach 429.
        // Bursts that must still reach the Durable Object use a distinct address per request.
        ratelimits: {
          MCP_IP_LIMITER: {
            namespace_id: "739184625",
            simple: { limit: 8, period: 60 },
          },
        },
      },
    }),
  ],
});
