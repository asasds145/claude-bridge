/** Miniflare's rate limiter uses a wall-clock window. Wait if this window is about to roll. */
export async function waitForFreshRateWindow(periodSec = 60, needMs = 2_500): Promise<void> {
  const periodMs = periodSec * 1000;
  const left = periodMs - (Date.now() % periodMs);
  if (left < needMs) await new Promise((r) => setTimeout(r, left + 50));
}
