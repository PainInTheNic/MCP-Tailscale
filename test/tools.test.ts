/**
 * Tool-layer tests through a real MCP client/server pair (in-memory transport).
 * The REST client and host backend are fakes: nothing here touches the network,
 * the Tailscale API or the local daemon.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig } from "../src/config.js";
import { registerAllTools } from "../src/tools/index.js";
import { TailscaleService } from "../src/service/tailscale-service.js";
import type { TailscaleApiClient } from "../src/backends/api/client.js";
import type { CliResult, HostBackend, HostStatus } from "../src/backends/host/types.js";
import { FORCED_APPROVAL_TOOLS, LARGE_RESULT_TOOLS } from "../src/meta/approval.js";
import { redact, registerSecret } from "../src/util/redact.js";

const API_KEY = "tskey-api-HELDAPIKEY0001";
const OAUTH_SECRET = "tskey-client-HELDOAUTH0002";
const MINTED_TOKEN = "minted-access-token-HELD0003";
const NEW_KEY = "tskey-auth-kNEW123CNTRL-ONETIMESECRET0004";

// ---- fakes ------------------------------------------------------------------
let nextGet: unknown = {};
let nextPost: unknown = {};
const fakeApi = {
  tnet: (suffix: string) => `/api/v2/tailnet/-${suffix}`,
  describeAuth: () => "fake",
  get: async () => ({ data: nextGet, status: 200 }),
  post: async () => ({ data: nextPost, status: 200 }),
  patch: async () => ({ data: {}, status: 200 }),
  put: async () => ({ data: {}, status: 200 }),
  del: async () => ({ data: {}, status: 200 }),
} as unknown as TailscaleApiClient;

let hostStatus: HostStatus;
const okCli: CliResult = { stdout: "", stderr: "", code: 0 };
const fakeHost: HostBackend = {
  status: async () => hostStatus,
  getPrefs: async () => ({}),
  connectBare: async () => okCli,
  connectWithAuthKeyFile: async () => okCli,
  beginInteractiveLogin: async () => undefined,
  disconnect: async () => okCli,
  exec: async () => okCli,
};

// ---- harness ----------------------------------------------------------------
let client: Client;
let server: McpServer;
let tools: Tool[];

before(async () => {
  // admin + credentials = every tool registered. loadConfig registers API_KEY as a held secret;
  // the OAuth secret and a minted token are registered the way auth.ts would.
  const config = loadConfig({ TAILSCALE_RISK_LEVEL: "admin", TAILSCALE_API_KEY: API_KEY });
  registerSecret(OAUTH_SECRET);
  registerSecret(MINTED_TOKEN);

  server = new McpServer({ name: "test-server", version: "0.0.0" });
  registerAllTools(server, new TailscaleService(fakeHost), config, { cliBinary: "tailscale", apiClient: fakeApi });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  tools = (await client.listTools()).tools;
});

after(async () => {
  await client.close();
  await server.close();
});

async function call(name: string, args: Record<string, unknown> = {}): Promise<CallToolResult> {
  return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

function text(r: CallToolResult): string {
  return r.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
}

function tool(name: string): Tool {
  const t = tools.find((x) => x.name === name);
  assert.ok(t, `${name} should be registered`);
  return t;
}

// ---- item 1: create_auth_key one-time reveal -----------------------------------
test("create_auth_key returns the new key once, unredacted, with a warning; other secrets stay redacted", async () => {
  nextPost = {
    id: "kNEW123CNTRL",
    key: NEW_KEY,
    created: "2026-10-07T00:00:00Z",
    capabilities: { devices: { create: { reusable: false, ephemeral: false, preauthorized: false, tags: [] } } },
    description: `echo ${API_KEY} ${OAUTH_SECRET} ${MINTED_TOKEN} tskey-auth-SOMEOTHERKEY0005`,
  };
  const r = await call("tailscale_create_auth_key", {});
  const out = text(r);
  assert.ok(!r.isError);
  assert.ok(out.includes(NEW_KEY), "the newly created key must be shown in full");
  assert.match(out, /ONE-TIME SECRET/);
  assert.match(out, /kNEW123CNTRL/, "warning names the key id for revocation");
  for (const held of ["HELDAPIKEY0001", "HELDOAUTH0002", "HELD0003", "SOMEOTHERKEY0005"]) {
    assert.ok(!out.includes(held), `${held} must stay redacted`);
  }

  // Shown once: the key is now a held secret, scrubbed from any later output.
  assert.ok(!redact(`later ${NEW_KEY}`).includes("ONETIMESECRET0004"));
  nextGet = { id: "1", name: NEW_KEY };
  assert.ok(!text(await call("tailscale_get_device", { deviceId: "1" })).includes("ONETIMESECRET0004"));
});

test("create_webhook returns its signing secret once, unredacted, with a warning; other secrets stay redacted", async () => {
  const SIGNING = "tskey-webhook-kWH123CNTRL-SIGNINGSECRET0009";
  nextPost = {
    endpointId: "wh123",
    endpointUrl: "https://example.com/hook",
    subscriptions: ["nodeCreated"],
    secret: SIGNING,
    note: `echo ${API_KEY} ${OAUTH_SECRET} tskey-webhook-OTHERSECRET0010`,
  };
  const out = text(await call("tailscale_create_webhook", { endpointUrl: "https://example.com/hook", subscriptions: ["nodeCreated"] }));
  assert.ok(out.includes(SIGNING), "the signing secret must be shown in full");
  assert.match(out, /ONE-TIME SECRET/);
  assert.match(out, /wh123/, "warning names the endpoint id for deletion");
  for (const held of ["HELDAPIKEY0001", "HELDOAUTH0002", "OTHERSECRET0010"]) {
    assert.ok(!out.includes(held), `${held} must stay redacted`);
  }
  assert.ok(!redact(`later ${SIGNING}`).includes("SIGNINGSECRET0009"), "scrubbed from later output");

  // A secret that is not tskey-shaped is revealed the same way, and also scrubbed afterwards.
  nextPost = { endpointId: "wh124", secret: "plainSigningSecret0011" };
  const out2 = text(await call("tailscale_create_webhook", { endpointUrl: "https://example.com/hook", subscriptions: ["nodeCreated"] }));
  assert.ok(out2.includes("plainSigningSecret0011"));
  assert.ok(!redact("later plainSigningSecret0011").includes("plainSigningSecret0011"));
});

test("create_auth_key without a key in the response falls back to full redaction", async () => {
  nextPost = { id: "k2", note: "tskey-auth-UNEXPECTED0006" };
  const out = text(await call("tailscale_create_auth_key", {}));
  assert.doesNotMatch(out, /ONE-TIME SECRET/);
  assert.ok(!out.includes("UNEXPECTED0006"));
});

// ---- item 2: structuredContent redaction ---------------------------------------------
test("ok() redacts structuredContent and the result still satisfies the outputSchema", async () => {
  hostStatus = {
    state: "needs_login",
    backendState: "NeedsLogin",
    selfOnline: false,
    haveNodeKey: true,
    keyExpired: false,
    tailscaleIPs: ["100.64.0.1"],
    hostName: "mac",
    authURL: "https://login.tailscale.com/a/abc123",
    health: ["ok", "leaked tskey-auth-HEALTHLEAK0007 here", `held ${API_KEY}`],
    version: "1.102.4",
  };
  const r = await call("tailscale_status", {});
  assert.ok(!r.isError, text(r)); // the client validated structuredContent against the outputSchema
  const sc = r.structuredContent as { health: string[]; authURL: string; tailscaleIPs: string[]; connected: boolean };
  assert.equal(sc.health.length, 3);
  assert.equal(sc.health[0], "ok");
  assert.ok(!JSON.stringify(sc).includes("HEALTHLEAK0007"));
  assert.ok(!JSON.stringify(sc).includes("HELDAPIKEY0001"));
  assert.equal(sc.authURL, "https://login.tailscale.com/a/abc123", "login URLs are not over-redacted");
  assert.deepEqual(sc.tailscaleIPs, ["100.64.0.1"]);
  assert.equal(sc.connected, false);
  assert.ok(!text(r).includes("HEALTHLEAK0007"));
});

// ---- item 4: annotations + forced approval -------------------------------------------
test("server_info's catalog lists exactly the registered tools (48)", async () => {
  const info = JSON.parse(text(await call("tailscale_server_info"))) as { tools: Array<{ name: string }> };
  const catalog = info.tools.map((t) => t.name).sort();
  assert.deepEqual(catalog, tools.map((t) => t.name).sort());
  assert.equal(tools.length, 48);
});

test("tools that can cut connectivity or remove access force approval and are annotated destructive", () => {
  for (const name of [
    "tailscale_set_prefs",
    "tailscale_authorize_device",
    "tailscale_set_device_tags",
    "tailscale_set_device_routes",
    "tailscale_set_dns_config",
    "tailscale_suspend_user",
    "tailscale_set_device_key_expiry",
  ]) {
    const t = tool(name);
    assert.equal(t._meta?.["anthropic/requiresUserInteraction"], true, `${name} should force approval`);
    assert.equal(t.annotations?.destructiveHint, true, `${name} should be destructiveHint:true`);
  }
});

test("secret-minting creates force approval but stay non-destructive (they only add)", () => {
  for (const name of ["tailscale_create_auth_key", "tailscale_create_webhook"]) {
    const t = tool(name);
    assert.equal(t._meta?.["anthropic/requiresUserInteraction"], true, `${name} should force approval`);
    assert.equal(t.annotations?.destructiveHint, false, name);
  }
});

test("every forced-approval tool is marked destructive, except secret minting", () => {
  const minting = new Set(["tailscale_create_auth_key", "tailscale_create_webhook"]);
  for (const t of tools.filter((x) => FORCED_APPROVAL_TOOLS.has(x.name))) {
    assert.equal(t._meta?.["anthropic/requiresUserInteraction"], true, t.name);
    if (!minting.has(t.name)) assert.equal(t.annotations?.destructiveHint, true, t.name);
  }
});

test("reads and additive/restorative writes are not gated", () => {
  for (const t of tools.filter((x) => x.annotations?.readOnlyHint)) {
    assert.ok(!FORCED_APPROVAL_TOOLS.has(t.name), `${t.name} is read-only and must not force approval`);
  }
  for (const name of ["tailscale_connect", "tailscale_approve_user", "tailscale_restore_user"]) {
    const t = tool(name);
    assert.equal(t._meta?.["anthropic/requiresUserInteraction"], undefined, name);
    assert.equal(t.annotations?.destructiveHint, false, name);
  }
});

test("approval/large-result sets only name real tools (bar the pre-gated, planned delete_user)", () => {
  const names = new Set(tools.map((t) => t.name));
  for (const n of [...FORCED_APPROVAL_TOOLS, ...LARGE_RESULT_TOOLS]) {
    if (n === "tailscale_delete_user") continue;
    assert.ok(names.has(n), `${n} is not a registered tool`);
  }
});
