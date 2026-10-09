/**
 * createServer end to end (in-memory transport): TAILSCALE_APPROVAL_EXEMPT only works because
 * createServer sets the exemptions BEFORE registering tools, and tailscale_server_info must keep
 * reporting the gate its own tools were registered with. Nothing here runs the CLI.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { createServer } from "../src/server.js";
import { loadConfig } from "../src/config.js";
import { FORCED_APPROVAL_TOOLS, setApprovalExemptions } from "../src/meta/approval.js";

process.env.TAILSCALE_LOG_LEVEL = "error"; // keep startup info/warn lines out of the test output

const GATE = "anthropic/requiresUserInteraction";

async function start(exempt?: string) {
  const env: NodeJS.ProcessEnv = { TAILSCALE_RISK_LEVEL: "write", TAILSCALE_CLI_PATH: "/nonexistent/tailscale" };
  if (exempt !== undefined) env.TAILSCALE_APPROVAL_EXEMPT = exempt;
  const server = createServer(loadConfig(env));
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  const tools = (await client.listTools()).tools;
  const forcedApproval = async (): Promise<Map<string, boolean>> => {
    const r = (await client.callTool({ name: "tailscale_server_info", arguments: {} })) as CallToolResult;
    const first = r.content[0];
    const info = JSON.parse(first?.type === "text" ? first.text : "{}") as {
      tools: { name: string; forcedApproval: boolean }[];
    };
    return new Map(info.tools.map((t) => [t.name, t.forcedApproval]));
  };
  return { tools, forcedApproval, close: async () => (await client.close(), await server.close()) };
}

function gated(t: Tool): boolean {
  return t._meta?.[GATE] === true;
}

test("createServer applies TAILSCALE_APPROVAL_EXEMPT before registering tools", async () => {
  const a = await start("tailscale_disconnect,tailscale_logout");
  try {
    const byName = new Map(a.tools.map((t) => [t.name, t]));
    const disconnect = byName.get("tailscale_disconnect");
    assert.ok(disconnect, "tailscale_disconnect should be registered at write level");
    assert.equal(disconnect._meta?.[GATE], undefined, "exempted tool must lose the gate");
    assert.match(disconnect.description ?? "", /TAILSCALE_APPROVAL_EXEMPT/);
    assert.equal(disconnect.annotations?.destructiveHint, true, "exemption does not change annotations");

    const stillGated = a.tools.filter((t) => FORCED_APPROVAL_TOOLS.has(t.name) && t.name !== "tailscale_disconnect");
    assert.ok(stillGated.length >= 4, "the other write-tier host tools should be registered");
    for (const t of stillGated) {
      assert.equal(gated(t), true, `${t.name} must stay gated`);
      assert.match(t.description ?? "", /requires user approval/, t.name);
    }

    // server_info matches _meta for every registered tool...
    const reported = await a.forcedApproval();
    for (const t of a.tools) assert.equal(reported.get(t.name), gated(t), t.name);

    // ...and keeps matching it after another server in this process registers with different exemptions.
    const b = await start();
    try {
      assert.equal(gated(b.tools.find((t) => t.name === "tailscale_disconnect") as Tool), true);
      assert.equal((await a.forcedApproval()).get("tailscale_disconnect"), false);
      assert.equal((await b.forcedApproval()).get("tailscale_disconnect"), true);
    } finally {
      await b.close();
    }
  } finally {
    await a.close();
    setApprovalExemptions([]);
  }
});
