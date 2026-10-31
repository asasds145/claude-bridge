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
      },
    }),
  ],
});
