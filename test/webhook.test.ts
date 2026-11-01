import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env";
import { queueStub } from "../src/env";
import { WEBHOOK_DEBOUNCE_MS, WEBHOOK_MIN_GAP_MS, webhookBlockReason, type BoxmcpQueue } from "../src/queue";
import { resetSharedDurableState } from "./isolate";

const E = env as unknown as Env;
type Call = { url: string; body: string; auth: string | null; redirect: string | null };

async function until(pred: () => boolean | Promise<boolean>, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!(await pred())) {
    if (Date.now() > end) throw new Error("timeout waiting for condition");
    await new Promise((r) => setTimeout(r, 25));
  }
}
const meta = (k: string) =>
  runInDurableObject(queueStub(E), (_i: BoxmcpQueue, state) => {
    const rows = state.storage.sql.exec<{ v: string }>(`SELECT v FROM meta WHERE k = ?`, k).toArray();
    return rows.length ? rows[0].v : null;
  });

let calls: Call[];
function mockFetch(impl: () => Promise<Response> | Response) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input as RequestInfo, init as RequestInit);
    calls.push({
      url: req.url,
      body: await req.text(),
      auth: req.headers.get("authorization"),
      redirect: (init as RequestInit | undefined)?.redirect ?? null,
    });
    return impl();
  });
}

beforeEach(async () => {
  await resetSharedDurableState();
  calls = [];
  // 테스트 전용 가짜 webhook 설정 (실제 URL/secret 아님) + 깨끗한 webhook 상태
  await runInDurableObject(queueStub(E), (inst: BoxmcpQueue, state) => {
    (inst as unknown as { env: Env }).env = { ...E, CHIEF_WEBHOOK_URL: "https://hook.invalid/x", CHIEF_WEBHOOK_KEY: "fake-key" };
    state.storage.sql.exec(`UPDATE messages SET acked = 1 WHERE direction = 'to_chief'`);
    state.storage.sql.exec(`DELETE FROM meta WHERE k IN ('wh_due','wh_attempt','wh_sends','wh_chain_wm')`);
  });
});
afterEach(async () => {
  vi.restoreAllMocks();
  await runInDurableObject(queueStub(E), (inst: BoxmcpQueue) => {
    (inst as unknown as { env: Env }).env = E;
  });
});

function setWebhookEnv(url: string | undefined, key: string | undefined, scheme?: string) {
  return runInDurableObject(queueStub(E), (inst: BoxmcpQueue) => {
    const next: Env = { ...E, CHIEF_WEBHOOK_URL: url, CHIEF_WEBHOOK_KEY: key };
    if (scheme !== undefined) next.CHIEF_WEBHOOK_AUTH_SCHEME = scheme;
    (inst as unknown as { env: Env }).env = next;
  });
}

describe("webhook destination guards", () => {
  it("classifies https, non-https, userinfo, and a missing key without echoing them", () => {
    expect(webhookBlockReason(undefined, undefined)).toBeNull();
    expect(webhookBlockReason("https://hook.invalid/x", "fake-key")).toBeNull();
    expect(webhookBlockReason("http://hook.invalid/x", "fake-key")).toBe("non_https");
    expect(webhookBlockReason("https://user:pass@hook.invalid/x", "fake-key")).toBe("invalid_url");
    expect(webhookBlockReason("not a url", "fake-key")).toBe("invalid_url");
    expect(webhookBlockReason("https://hook.invalid/x", undefined)).toBe("missing_key");
    expect(webhookBlockReason("https://hook.invalid/x", "  ")).toBe("missing_key");
  });

  it("does not send when the URL is not https, including an already-due alarm", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    mockFetch(() => new Response("ok", { status: 200 }));
    const stub = queueStub(E);
    await setWebhookEnv("http://hook.invalid/x", "fake-key");
    await stub.sendToChief("nope-http");
    expect(calls).toHaveLength(0);
    expect(await meta("wh_due")).toBeNull();
    await runInDurableObject(stub, (_inst: BoxmcpQueue, state) => {
      state.storage.sql.exec(
        `INSERT INTO meta (k, v) VALUES ('wh_due', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
        String(Date.now() - 1),
      );
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(calls).toHaveLength(0);
    expect(await meta("wh_due")).toBeNull();
    const joined = logs.join("\n");
    expect(joined).toContain("non_https");
    expect(joined).not.toContain("hook.invalid");
    expect(joined).not.toContain("fake-key");
    expect(joined).not.toContain("nope-http");
  });

  it("does not send when CHIEF_WEBHOOK_KEY is unset", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    mockFetch(() => new Response("ok", { status: 200 }));
    const stub = queueStub(E);
    await setWebhookEnv("https://hook.invalid/x", undefined);
    await stub.sendToChief("nope-key");
    expect(calls).toHaveLength(0);
    expect(await meta("wh_due")).toBeNull();
    const status = await stub.status();
    expect(status.webhook_configured).toBe(false);
    expect(status.webhook_url_valid).toBe(true);
    const joined = logs.join("\n");
    expect(joined).toContain("missing_key");
    expect(joined).not.toContain("hook.invalid");
    expect(joined).not.toContain("nope-key");
  });

  it("does not send an https URL that embeds userinfo", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    mockFetch(() => new Response("ok", { status: 200 }));
    await setWebhookEnv("https://user:pass@hook.invalid/x", "fake-key");
    await queueStub(E).sendToChief("nope-userinfo");
    expect(calls).toHaveLength(0);
    const joined = logs.join("\n");
    expect(joined).toContain("invalid_url");
    expect(joined).not.toContain("hook.invalid");
    expect(joined).not.toContain("pass");
    expect(joined).not.toContain("fake-key");
  });

  it("clears a future webhook schedule when the config becomes invalid", async () => {
    const stub = queueStub(E);
    const future = Date.now() + 60_000;
    await runInDurableObject(stub, (_inst: BoxmcpQueue, state) => {
      state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_due', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, String(future));
      state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_attempt', '2') ON CONFLICT(k) DO UPDATE SET v = excluded.v`);
      state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_chain_wm', '9') ON CONFLICT(k) DO UPDATE SET v = excluded.v`);
    });
    await setWebhookEnv("http://hook.invalid/x", "fake-key");
    await stub.sendToChief("stale-schedule");
    expect(await meta("wh_due")).toBeNull();
    expect(await meta("wh_attempt")).toBeNull();
    expect(await meta("wh_chain_wm")).toBeNull();
    expect(await meta("cleanup_due")).not.toBeNull();
    const alarm = await runInDurableObject(stub, async (_inst: BoxmcpQueue, state) => state.storage.getAlarm());
    expect(alarm).toBe(Number(await meta("cleanup_due")));
  });

  it("clears a schedule when the webhook URL is removed", async () => {
    mockFetch(() => new Response("ok", { status: 200 }));
    const stub = queueStub(E);
    await runInDurableObject(stub, (_inst: BoxmcpQueue, state) => {
      state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_due', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, String(Date.now() + 60_000));
      state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_attempt', '2') ON CONFLICT(k) DO UPDATE SET v = excluded.v`);
      state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_chain_wm', '4') ON CONFLICT(k) DO UPDATE SET v = excluded.v`);
    });
    await setWebhookEnv(undefined, undefined);
    await stub.sendToChief("url-removed");
    expect(await meta("wh_due")).toBeNull();
    expect(await meta("wh_attempt")).toBeNull();
    expect(await meta("wh_chain_wm")).toBeNull();
    expect(await meta("cleanup_due")).not.toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("a due alarm with a missing key or userinfo URL does not fetch", async () => {
    mockFetch(() => new Response("ok", { status: 200 }));
    const stub = queueStub(E);
    const arm = async (url: string, key: string | undefined) => {
      await setWebhookEnv(url, key);
      await runInDurableObject(stub, (_inst: BoxmcpQueue, state) => {
        state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_due', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, String(Date.now() - 1));
        state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_attempt', '1') ON CONFLICT(k) DO UPDATE SET v = excluded.v`);
        state.storage.sql.exec(`INSERT INTO meta (k, v) VALUES ('wh_chain_wm', '3') ON CONFLICT(k) DO UPDATE SET v = excluded.v`);
      });
      expect(await runDurableObjectAlarm(stub)).toBe(true);
    };
    await arm("https://hook.invalid/x", undefined);
    await arm("https://user:pass@hook.invalid/x", "fake-key");
    expect(calls).toHaveLength(0);
    expect(await meta("wh_due")).toBeNull();
    expect(await meta("wh_attempt")).toBeNull();
    expect(await meta("wh_chain_wm")).toBeNull();
  });

  it("does not follow webhook redirects", async () => {
    mockFetch(() => new Response(null, { status: 302, headers: { location: "https://hook.invalid/other" } }));
    const stub = queueStub(E);
    await stub.sendToChief("redir");
    await until(() => calls.length === 1);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://hook.invalid/x");
    expect(calls[0].redirect).toBe("manual");
    await until(async () => (await meta("wh_attempt")) === "1");
    expect(calls).toHaveLength(1);
  });

  it("unset scheme defaults to Bearer and an empty scheme sends the raw key", async () => {
    mockFetch(() => new Response("ok", { status: 200 }));
    const stub = queueStub(E);
    await runInDurableObject(stub, (inst: BoxmcpQueue) => {
      const next: Env = { ...E, CHIEF_WEBHOOK_URL: "https://hook.invalid/x", CHIEF_WEBHOOK_KEY: "fake-key" };
      delete next.CHIEF_WEBHOOK_AUTH_SCHEME;
      (inst as unknown as { env: Env }).env = next;
    });
    await stub.sendToChief("scheme-default");
    await until(() => calls.length === 1);
    expect(calls[0].auth).toBe("Bearer fake-key");
    await until(async () => (await stub.status()).webhook_scheduled === false);
    await setWebhookEnv("https://hook.invalid/x", "fake-key", "");
    await stub.sendToChief("scheme-empty");
    await until(() => calls.length === 2, WEBHOOK_MIN_GAP_MS + 4000);
    expect(calls[1].auth).toBe("fake-key");
  }, 20_000);

  it("a fetch exception does not log the URL", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line) => {
      logs.push(String(line));
    });
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new TypeError("connect failed https://hook.invalid/secret-path");
    });
    await queueStub(E).sendToChief("boom-url");
    await until(() => logs.some((l) => l.includes("webhook")));
    const joined = logs.join("\n");
    expect(joined).toContain("TypeError");
    expect(joined).not.toContain("hook.invalid");
    expect(joined).not.toContain("secret-path");
    expect(joined).not.toContain("boom-url");
  });
});

describe("webhook (immediate / spacing / retry / no stranding)", () => {
  it("has no debounce", () => {
    expect(WEBHOOK_DEBOUNCE_MS).toBe(0);
  });

  it("fires immediately after a quiet period, then spaces a rapid second send without stranding it", async () => {
    mockFetch(() => new Response("ok", { status: 200 }));
    const stub = queueStub(E);
    const t0 = Date.now();
    await stub.sendToChief("one");
    await until(() => calls.length === 1);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(JSON.parse(calls[0].body)).toEqual({ source: "chief-bridge", pending: 1 });
    expect(calls[0].auth).toBe("Bearer fake-key");
    await until(async () => (await stub.status()).webhook_scheduled === false);

    // 직후 두 번째 메시지: MIN_GAP 만큼 뒤로 예약되고, 그 시각에 실제로 발사됨
    await stub.sendToChief("two");
    const due = Number(await meta("wh_due"));
    expect(due).toBeGreaterThan(Date.now() + 500);
    expect(due).toBeLessThanOrEqual(Date.now() + WEBHOOK_MIN_GAP_MS + 100);
    expect(calls.length).toBe(1);
    await until(() => calls.length === 2, WEBHOOK_MIN_GAP_MS + 4000);
    expect(JSON.parse(calls[1].body).pending).toBe(2);
    await until(async () => (await stub.status()).webhook_scheduled === false);
  }, 20_000);

  it("retries after 1 min on failure", async () => {
    mockFetch(() => new Response("fail", { status: 500 }));
    const stub = queueStub(E);
    await stub.sendToChief("r");
    await until(() => calls.length === 1);
    await until(async () => (await meta("wh_attempt")) === "1");
    const due = Number(await meta("wh_due"));
    expect(due - Date.now()).toBeGreaterThanOrEqual(55_000);
    expect(due - Date.now()).toBeLessThanOrEqual(61_000);
    // wh_due만 과거로 당기고, 알람 자체는 미래에 둔 채 runDurableObjectAlarm으로 즉시 실행
    await runInDurableObject(stub, (_inst: BoxmcpQueue, state) => {
      state.storage.sql.exec(`UPDATE meta SET v = ? WHERE k = 'wh_due'`, String(Date.now() - 1));
      // 1분이 지난 것처럼 직전 발사 기록도 과거로 (MIN_GAP에 걸리지 않게)
      state.storage.sql.exec(`UPDATE meta SET v = ? WHERE k = 'wh_sends'`, JSON.stringify([Date.now() - 60_000]));
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(calls.length).toBe(2);
    const due2 = Number(await meta("wh_due"));
    expect(due2 - Date.now()).toBeGreaterThanOrEqual(4 * 60_000);
    expect(await meta("wh_attempt")).toBe("2");
  });

  it("a message arriving while a webhook is in flight gets a follow-up webhook", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let n = 0;
    mockFetch(async () => {
      if (n++ === 0) await gate;
      return new Response("ok", { status: 200 });
    });
    const stub = queueStub(E);
    await stub.sendToChief("first");
    await until(() => calls.length === 1);
    await stub.sendToChief("during"); // wh_due가 아직 설정돼 있어 합쳐짐
    const tRelease = Date.now();
    release();
    // 후속 webhook이 attempt 0으로 MIN_GAP 뒤에 예약됨
    await until(async () => Number(await meta("wh_due")) > tRelease);
    expect(await meta("wh_attempt")).toBe("0");
    expect(calls.length).toBe(1);
    await until(() => calls.length === 2, WEBHOOK_MIN_GAP_MS + 4000);
    expect(Date.now() - tRelease).toBeGreaterThanOrEqual(WEBHOOK_MIN_GAP_MS - 500);
    await until(async () => (await stub.status()).webhook_scheduled === false);
  }, 20_000);

  it("after retries are exhausted, messages that joined the chain get a fresh chain; otherwise it stops", async () => {
    mockFetch(() => new Response("fail", { status: 500 }));
    const stub = queueStub(E);
    await stub.sendToChief("a");
    await until(async () => (await meta("wh_attempt")) === "1");
    await stub.sendToChief("joined"); // 재시도 대기 중 합쳐짐
    const fire = async () => {
      await runInDurableObject(stub, (_inst: BoxmcpQueue, state) => {
        state.storage.sql.exec(`UPDATE meta SET v = ? WHERE k = 'wh_due'`, String(Date.now() - 1));
        state.storage.sql.exec(`UPDATE meta SET v = '[]' WHERE k = 'wh_sends'`);
      });
      expect(await runDurableObjectAlarm(stub)).toBe(true);
    };
    for (let i = 0; i < 3; i++) await fire(); // 재시도 1..3
    expect(calls.length).toBe(4);
    expect(await meta("wh_attempt")).toBe("0"); // 'joined' 때문에 새 체인
    expect(await meta("wh_due")).not.toBeNull();
    for (let i = 0; i < 4; i++) await fire(); // 새 체인 0..3, 그 사이 새 메시지 없음
    expect(calls.length).toBe(8);
    expect(await meta("wh_due")).toBeNull();
  });
});
