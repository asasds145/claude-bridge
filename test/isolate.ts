import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { queueStub } from "../src/env";
import type { BoxmcpQueue } from "../src/queue";

/** Drop shared in-memory limits and accepted grants so tests do not leak 429s into each other. */
export async function resetSharedDurableState(): Promise<void> {
  await runInDurableObject(queueStub(env as never), (inst: BoxmcpQueue, state) => {
    const buckets = (inst as unknown as { buckets: Map<string, unknown>; forgeTrickleAt: number }).buckets;
    for (const key of [...buckets.keys()]) {
      if (key === "chief" || key === "mcp:unauth" || key === "mcp:forge" || key.startsWith("mcp:github-")) buckets.delete(key);
    }
    (inst as unknown as { forgeTrickleAt: number }).forgeTrickleAt = Date.now();
    state.storage.sql.exec(`DELETE FROM accepted_grants`);
  });
}
