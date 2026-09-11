/**
 * Client-enforced approval + large-result hints, expressed as tool `_meta`.
 *
 * `_meta["anthropic/requiresUserInteraction"] = true` forces the HOST to prompt
 * a human before the tool runs. This is the real gate for high-impact / irreversible
 * actions — a `confirm: true` *input* is not, because the model fills its own inputs.
 *
 * The set is deliberately NARROW: irreversible tailnet writes, traffic-redirection
 * (an exit-node/route change can silently MITM all host traffic), identity changes,
 * and node logout. Keeping it small means operators don't learn to click through it.
 *
 * IMPORTANT: `_meta` only reaches the client when the tool is registered via
 * `server.registerTool(...)`. The legacy `server.tool(...)` API silently drops it.
 */

export const FORCED_APPROVAL_TOOLS: ReadonlySet<string> = new Set([
  // Host — traffic-redirection / identity / connectivity-severing / key-expiring
  "tailscale_disconnect",
  "tailscale_logout",
  "tailscale_set_exit_node",
  "tailscale_set_routes",
  "tailscale_switch_profile",
  // REST — irreversible tailnet writes
  "tailscale_delete_device",
  "tailscale_expire_device_key",
  "tailscale_delete_auth_key",
  "tailscale_update_policy_file",
  "tailscale_delete_webhook",
  "tailscale_delete_user",
]);

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
  "tailscale_diff_acl_access",
  "tailscale_get_audit_log",
  "tailscale_get_network_flow_logs",
]);

/**
 * Build the `_meta` object for a tool, or undefined when it carries none.
 * Returns a fresh object per call (the SDK holds `_meta` by reference and echoes
 * it into every tools/list, so a shared literal could leak a mutation across tools).
 */
export function buildToolMeta(toolName: string): Record<string, unknown> | undefined {
  const meta: Record<string, unknown> = {};
  if (FORCED_APPROVAL_TOOLS.has(toolName)) {
    meta["anthropic/requiresUserInteraction"] = true;
  }
  if (LARGE_RESULT_TOOLS.has(toolName)) {
    meta["anthropic/maxResultSizeChars"] = MAX_RESULT_SIZE_CHARS;
  }
  return Object.keys(meta).length > 0 ? meta : undefined;
}
