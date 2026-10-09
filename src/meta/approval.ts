/**
 * Client-enforced approval + large-result hints, expressed as tool `_meta`.
 *
 * `_meta["anthropic/requiresUserInteraction"] = true` forces the HOST to prompt
 * a human before the tool runs. This is the real gate for high-impact / irreversible
 * actions — a `confirm: true` *input* is not, because the model fills its own inputs.
 *
 * Criterion: anything that can CUT CONNECTIVITY or REMOVE ACCESS (for this host or
 * the tailnet), redirect traffic (an exit-node/route change can silently MITM all
 * host traffic; a webhook streams tailnet events to any URL), change identity, mint a
 * credential or one-time secret, or cannot be undone. Routine additive / restorative
 * edits (connect, rename a device, approve or restore a user) stay ungated, so
 * operators don't learn to click through it. Every tool here except the two that mint
 * a secret (create_auth_key, create_webhook — additive) is also destructiveHint:true.
 *
 * IMPORTANT: `_meta` only reaches the client when the tool is registered via
 * `server.registerTool(...)`. The legacy `server.tool(...)` API silently drops it.
 */

export const FORCED_APPROVAL_TOOLS: ReadonlySet<string> = new Set([
  // Host — traffic-redirection / identity / connectivity-severing / key-expiring
  "tailscale_disconnect",
  "tailscale_logout",
  "tailscale_set_prefs", // shields-up, accept-dns, ssh, hostname
  "tailscale_set_exit_node",
  "tailscale_set_routes",
  "tailscale_switch_profile",
  // REST — access-removing / connectivity-cutting tailnet writes (write tier)
  "tailscale_authorize_device", // authorized=false de-authorizes
  "tailscale_set_device_tags", // tags are the ACL identity
  "tailscale_set_device_routes", // dropping a route cuts the subnet tailnet-wide
  "tailscale_set_device_key_expiry", // re-enabling can expire the key at once
  "tailscale_set_dns_config", // replaces tailnet-wide resolvers
  "tailscale_suspend_user",
  "tailscale_create_webhook", // mints a signing secret; sends tailnet events to a model-chosen URL
  // REST — irreversible / tailnet-wide / credential-minting (admin tier)
  "tailscale_delete_device",
  "tailscale_expire_device_key",
  "tailscale_create_auth_key",
  "tailscale_delete_auth_key",
  "tailscale_update_policy_file",
  "tailscale_update_tailnet_settings",
  "tailscale_delete_webhook",
  // Planned (PLAN.md) but not registered yet: pre-gated so it can never ship without approval.
  "tailscale_delete_user",
]);

/**
 * The only forced-approval tools an operator may exempt: host-level changes to this machine
 * that another call here can undo. Tailnet-wide REST writes, logout (expires the node key) and
 * anything irreversible or not registered yet (delete_user) always keep the gate.
 */
export const EXEMPTABLE_TOOLS: ReadonlySet<string> = new Set([
  "tailscale_disconnect",
  "tailscale_set_prefs",
  "tailscale_set_exit_node",
  "tailscale_set_routes",
  "tailscale_switch_profile",
]);

/**
 * Forced-approval tools the operator has exempted (TAILSCALE_APPROVAL_EXEMPT), e.g. so a
 * maintenance routine can toggle the connection unattended. Set once at startup, before
 * any tool is registered; names outside EXEMPTABLE_TOOLS are ignored.
 */
let approvalExempt: ReadonlySet<string> = new Set();

/** Set the exemptions; returns the requested names that cannot be exempted (ignored). */
export function setApprovalExemptions(names: Iterable<string>): string[] {
  const requested = [...names];
  approvalExempt = new Set(requested.filter((n) => EXEMPTABLE_TOOLS.has(n)));
  return requested.filter((n) => !EXEMPTABLE_TOOLS.has(n));
}

/** True when the host must ask a human before `toolName` runs. */
export function requiresApproval(toolName: string): boolean {
  return FORCED_APPROVAL_TOOLS.has(toolName) && !approvalExempt.has(toolName);
}

/**
 * The approval clause for an exemptable tool's description ("..., so it <clause>."), so the
 * text the model reads matches the gate. Call it at registration, like buildToolMeta.
 */
export function approvalClause(toolName: string): string {
  return requiresApproval(toolName)
    ? "requires user approval"
    : "would normally require user approval, but TAILSCALE_APPROVAL_EXEMPT lifts that on this server, so it runs " +
        "without a prompt";
}

/** Client-side ceiling; larger values are ignored, so this is a cap not a preference. */
export const MAX_RESULT_SIZE_CHARS = 500_000;

/**
 * Tools whose response size scales with tailnet size (not with the request), so a
 * large-but-legitimate result should stay inline instead of being truncated to a
 * file reference the agent must read back mid-task. Deliberately not every read tool.
 */
export const LARGE_RESULT_TOOLS: ReadonlySet<string> = new Set([
  "tailscale_list_devices",
  "tailscale_list_users",
  "tailscale_get_policy_file",
  "tailscale_get_audit_log",
]);

/**
 * Build the `_meta` object for a tool, or undefined when it carries none.
 * Returns a fresh object per call (the SDK holds `_meta` by reference and echoes
 * it into every tools/list, so a shared literal could leak a mutation across tools).
 */
export function buildToolMeta(toolName: string): Record<string, unknown> | undefined {
  const meta: Record<string, unknown> = {};
  if (requiresApproval(toolName)) {
    meta["anthropic/requiresUserInteraction"] = true;
  }
  if (LARGE_RESULT_TOOLS.has(toolName)) {
    meta["anthropic/maxResultSizeChars"] = MAX_RESULT_SIZE_CHARS;
  }
  return Object.keys(meta).length > 0 ? meta : undefined;
}
