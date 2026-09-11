import { test } from "node:test";
import assert from "node:assert/strict";
import { buildToolMeta, FORCED_APPROVAL_TOOLS, LARGE_RESULT_TOOLS } from "../src/meta/approval.js";
import { allows } from "../src/meta/risk.js";
import { loadConfig, hasApiCredentials } from "../src/config.js";

test("forced-approval meta only on the narrow high-impact set", () => {
  assert.deepEqual(buildToolMeta("tailscale_disconnect"), { "anthropic/requiresUserInteraction": true });
  assert.equal(buildToolMeta("tailscale_status"), undefined);
  assert.equal(buildToolMeta("tailscale_connect"), undefined); // connect is NOT forced
});

test("large-result hint on tailnet-scaled reads", () => {
  const m = buildToolMeta("tailscale_list_devices");
  assert.equal(m?.["anthropic/maxResultSizeChars"], 500_000);
});

test("forced-approval set includes traffic-redirection + destructive tools", () => {
  for (const n of ["tailscale_set_exit_node", "tailscale_set_routes", "tailscale_logout", "tailscale_delete_device", "tailscale_update_policy_file"]) {
    assert.ok(FORCED_APPROVAL_TOOLS.has(n), `${n} should be forced-approval`);
  }
  assert.ok(!FORCED_APPROVAL_TOOLS.has("tailscale_status"));
  assert.ok(LARGE_RESULT_TOOLS.has("tailscale_get_policy_file"));
});

test("risk gating: read < write < admin", () => {
  assert.ok(allows("read", "read"));
  assert.ok(!allows("read", "write"));
  assert.ok(allows("write", "write"));
  assert.ok(!allows("write", "admin"));
  assert.ok(allows("admin", "admin"));
  assert.ok(allows("admin", "read"));
});

test("config: defaults and OAuth pair validation", () => {
  const def = loadConfig({});
  assert.equal(def.riskLevel, "write");
  assert.equal(def.tailnet, "-");
  assert.equal(hasApiCredentials(def), false);

  assert.throws(() => loadConfig({ TAILSCALE_OAUTH_CLIENT_ID: "id-only" }), /must be set together/);

  const oauth = loadConfig({ TAILSCALE_OAUTH_CLIENT_ID: "id", TAILSCALE_OAUTH_CLIENT_SECRET: "secret" });
  assert.ok(hasApiCredentials(oauth));

  const key = loadConfig({ TAILSCALE_API_KEY: "tskey-api-x" });
  assert.ok(hasApiCredentials(key));
});

test("config: base URL must be https except loopback", () => {
  assert.throws(() => loadConfig({ TAILSCALE_API_BASE_URL: "http://evil.example.com" }), /https/);
  assert.doesNotThrow(() => loadConfig({ TAILSCALE_API_BASE_URL: "http://localhost:8080" }));
});
