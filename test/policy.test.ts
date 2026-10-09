import { test } from "node:test";
import assert from "node:assert/strict";
import {
  approvalClause,
  buildToolMeta,
  EXEMPTABLE_TOOLS,
  FORCED_APPROVAL_TOOLS,
  LARGE_RESULT_TOOLS,
  requiresApproval,
  setApprovalExemptions,
} from "../src/meta/approval.js";
import { allows } from "../src/meta/risk.js";
import { loadConfig, hasApiCredentials } from "../src/config.js";

test("forced-approval meta only on the narrow high-impact set", () => {
  assert.deepEqual(buildToolMeta("tailscale_disconnect"), { "anthropic/requiresUserInteraction": true });
  assert.equal(buildToolMeta("tailscale_status"), undefined);
  assert.equal(buildToolMeta("tailscale_connect"), undefined); // connect is NOT forced
});

test("forced approval covers connectivity-cutting / access-removing writes, not routine edits", () => {
  for (const n of [
    "tailscale_set_prefs",
    "tailscale_authorize_device",
    "tailscale_set_device_tags",
    "tailscale_set_device_routes",
    "tailscale_set_device_key_expiry",
    "tailscale_set_dns_config",
    "tailscale_suspend_user",
    "tailscale_create_auth_key",
    "tailscale_create_webhook",
    "tailscale_update_tailnet_settings",
  ]) {
    assert.deepEqual(buildToolMeta(n), { "anthropic/requiresUserInteraction": true }, `${n} should be forced-approval`);
  }
  for (const n of ["tailscale_set_device_name", "tailscale_approve_user", "tailscale_restore_user"]) {
    assert.equal(buildToolMeta(n), undefined, `${n} is a routine edit`);
  }
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

test("TAILSCALE_APPROVAL_EXEMPT lifts forced approval only for the named gated tools", () => {
  try {
    const ignored = setApprovalExemptions(["tailscale_disconnect", "tailscale_status", "not_a_tool"]);
    assert.deepEqual(ignored, ["tailscale_status", "not_a_tool"]); // only gated tools can be exempted
    assert.equal(requiresApproval("tailscale_disconnect"), false);
    assert.equal(buildToolMeta("tailscale_disconnect"), undefined);
    assert.equal(requiresApproval("tailscale_logout"), true); // everything else stays gated
    assert.deepEqual(buildToolMeta("tailscale_set_exit_node"), { "anthropic/requiresUserInteraction": true });
  } finally {
    setApprovalExemptions([]);
  }
  assert.equal(requiresApproval("tailscale_disconnect"), true);
});

test("TAILSCALE_APPROVAL_EXEMPT can never lift the gate on tailnet-wide, irreversible or unregistered tools", () => {
  const never = [...FORCED_APPROVAL_TOOLS].filter((n) => !EXEMPTABLE_TOOLS.has(n));
  assert.ok(never.includes("tailscale_logout") && never.includes("tailscale_delete_user"));
  for (const n of EXEMPTABLE_TOOLS) assert.ok(FORCED_APPROVAL_TOOLS.has(n), `${n} must be a gated tool`);
  try {
    assert.deepEqual(setApprovalExemptions(never), never); // every one ignored
    for (const n of never) assert.equal(requiresApproval(n), true, n);
  } finally {
    setApprovalExemptions([]);
  }
});

test("approvalClause matches the gate", () => {
  try {
    assert.equal(approvalClause("tailscale_disconnect"), "requires user approval");
    setApprovalExemptions(["tailscale_disconnect"]);
    assert.match(approvalClause("tailscale_disconnect"), /TAILSCALE_APPROVAL_EXEMPT/);
    assert.doesNotMatch(approvalClause("tailscale_disconnect"), /^requires user approval/);
    assert.equal(approvalClause("tailscale_set_routes"), "requires user approval");
  } finally {
    setApprovalExemptions([]);
  }
});

test("loadConfig parses TAILSCALE_APPROVAL_EXEMPT as a trimmed comma list", () => {
  assert.deepEqual(loadConfig({}).approvalExempt, []);
  assert.deepEqual(loadConfig({ TAILSCALE_APPROVAL_EXEMPT: " , " }).approvalExempt, []);
  assert.deepEqual(
    loadConfig({ TAILSCALE_APPROVAL_EXEMPT: " tailscale_disconnect , tailscale_set_routes," }).approvalExempt,
    ["tailscale_disconnect", "tailscale_set_routes"],
  );
});
