// OAuth를 거치지 않고 MCP 핸들러(같은 createServer)를 직접 호출해 tool 동작/입력 제한 확인
import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createMcpHandler } from "agents/mcp/server";
import { beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/mcp";
import { resetSharedDurableState } from "./isolate";

const handler = createMcpHandler(createServer, { route: "/mcp", allowedHostnames: ["chief-bridge.test"], corsOptions: false });
let n = 0;
async function rpc(method: string, params: unknown) {
  const res = await handler(
    new Request("https://chief-bridge.test/mcp", {
      method: "POST",
      headers: { host: "chief-bridge.test", "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++n, method, params }),
    }),
    env,
    createExecutionContext(),
  );
  const body = await res.text();
  const dataLine = body.split("\n").find((l) => l.startsWith("data:"));
  return { status: res.status, json: JSON.parse(dataLine ? dataLine.slice(5) : body) };
}
const call = (name: string, args: unknown) => rpc("tools/call", { name, arguments: args });

beforeEach(() => resetSharedDurableState());

describe("MCP tools", () => {
  it("tools/list has the 5 tools with annotations", async () => {
    const r = await rpc("tools/list", {});
    expect(r.status).toBe(200);
    const tools = r.json.result.tools as { name: string; annotations?: Record<string, boolean> }[];
    expect(tools.map((t) => t.name).sort()).toEqual(["chief_status", "get_thread", "read_chief_replies", "send_to_chief", "wait_for_reply"]);
    expect(tools.find((t) => t.name === "send_to_chief")?.annotations?.openWorldHint).toBe(true);
    for (const n of ["read_chief_replies", "wait_for_reply", "get_thread", "chief_status"]) {
      expect(tools.find((t) => t.name === n)?.annotations?.readOnlyHint).toBe(true);
    }
  });
  it("send_to_chief + chief_status", async () => {
    const r = await call("send_to_chief", { text: "hi" });
    const out = JSON.parse(r.json.result.content[0].text);
    expect(out.thread_id).toBeTruthy();
    const s = await call("chief_status", {});
    expect(JSON.parse(s.json.result.content[0].text).pending_to_chief).toBeGreaterThan(0);
  });
  it("send_to_chief rejects text > 8000", async () => {
    const r = await call("send_to_chief", { text: "a".repeat(8001) });
    const isErr = r.json.error !== undefined || r.json.result?.isError === true;
    expect(isErr).toBe(true);
  });
  it("read_chief_replies rejects limit > 20", async () => {
    const r = await call("read_chief_replies", { limit: 21 });
    expect(r.json.error !== undefined || r.json.result?.isError === true).toBe(true);
  });
  it("wait_for_reply clamps timeout_s > 55 instead of rejecting it", async () => {
    const s = JSON.parse((await call("send_to_chief", { text: "clamp" })).json.result.content[0].text);
    const { queueStub } = await import("../src/env");
    await queueStub(env as never).chiefReply(s.thread_id, "clamped-ok");
    const r = await call("wait_for_reply", { thread_id: s.thread_id, after_id: s.id, timeout_s: 100 });
    expect(r.json.error).toBeUndefined();
    expect(r.json.result.isError).not.toBe(true);
    expect(r.json.result.content[0].text).toContain("clamped-ok");
  });
  it("wait_for_reply times out → 'no reply yet'", async () => {
    const s = JSON.parse((await call("send_to_chief", { text: "q" })).json.result.content[0].text);
    const r = await call("wait_for_reply", { thread_id: s.thread_id, after_id: s.id, timeout_s: 1 });
    expect(r.json.result.content[0].text).toContain("no reply yet");
    expect(r.json.result.content[0].text).toContain("Call wait_for_reply again");
  });
  it("initialize returns loop instructions; send_to_chief result tells Claude to keep waiting", async () => {
    const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    expect(init.json.result.serverInfo.version).toBe("1.0.0");
    const ins = init.json.result.instructions as string;
    expect(ins).toContain("wait_for_reply");
    expect(ins).toContain("read_chief_replies");
    const s = JSON.parse((await call("send_to_chief", { text: "loop" })).json.result.content[0].text);
    expect(s.next).toContain(`after_id=${s.id}`);
    expect(s.next).toContain("read_chief_replies");
    const tools = (await rpc("tools/list", {})).json.result.tools as { name: string; description: string; inputSchema: { properties: Record<string, { maximum?: number; default?: number }> } }[];
    const w = tools.find((t) => t.name === "wait_for_reply")!;
    expect(w.description).toContain("again");
    expect(w.inputSchema.properties.timeout_s.maximum).toBeUndefined();
    expect(w.description).toContain("max 55");
    expect(JSON.stringify(w)).not.toContain("100");
  });
  it("wait_for_reply returns a reply posted while waiting, and read_chief_replies still returns it afterwards", async () => {
    const s = JSON.parse((await call("send_to_chief", { text: "ping" })).json.result.content[0].text);
    const waiting = call("wait_for_reply", { thread_id: s.thread_id, after_id: s.id, timeout_s: 10 });
    await new Promise((r) => setTimeout(r, 200));
    const { queueStub } = await import("../src/env");
    const stub = queueStub(env as never);
    await stub.chiefAck([s.id]);
    await stub.chiefReply(s.thread_id, "pong");
    const r = await waiting;
    expect(r.json.result.content[0].text).toContain("pong");
    const again = await call("read_chief_replies", { thread_id: s.thread_id });
    expect(again.json.result.content[0].text).toContain("pong");
  });
  it("a superseded wait tells Claude to call again", async () => {
    const s = JSON.parse((await call("send_to_chief", { text: "sup" })).json.result.content[0].text);
    const first = call("wait_for_reply", { thread_id: s.thread_id, after_id: s.id, timeout_s: 10 });
    await new Promise((r) => setTimeout(r, 200));
    const second = call("wait_for_reply", { thread_id: s.thread_id, after_id: s.id, timeout_s: 1 });
    const t = (await first).json.result.content[0].text as string;
    expect(t).toContain("replaced by a newer wait_for_reply");
    await second;
  });
});
