/**
 * Meta tool: server_info. Reports version, live backends, effective tailnet,
 * risk level, and a CAPABILITIES CATALOG so an agent that doesn't see a tool can
 * tell "gated by risk level" from "needs credentials" from "not built".
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Config, RiskLevel } from "../config.js";
import { hasApiCredentials } from "../config.js";
import { allows } from "../meta/risk.js";
import { FORCED_APPROVAL_TOOLS } from "../meta/approval.js";
import { jsonResult, fail } from "./_shared.js";
import { SERVER_NAME, SERVER_VERSION } from "../constants.js";

interface Descriptor {
  name: string;
  group: string;
  backend: "cli" | "api" | "meta";
  level: RiskLevel;
}

/** Static registry of every tool this server can expose (kept in sync with registrations). */
const CATALOG: Descriptor[] = [
  { name: "tailscale_status", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_get_prefs", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_connect", group: "host", backend: "cli", level: "write" },
  { name: "tailscale_disconnect", group: "host", backend: "cli", level: "write" },
  { name: "tailscale_list_exit_nodes", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_ping", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_netcheck", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_version", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_whois", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_whoami", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_dns_status", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_get_syspolicy", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_list_profiles", group: "host", backend: "cli", level: "read" },
  { name: "tailscale_set_prefs", group: "host", backend: "cli", level: "write" },
  { name: "tailscale_set_exit_node", group: "host", backend: "cli", level: "write" },
  { name: "tailscale_set_routes", group: "host", backend: "cli", level: "write" },
  { name: "tailscale_switch_profile", group: "host", backend: "cli", level: "write" },
  { name: "tailscale_logout", group: "host", backend: "cli", level: "admin" },
  { name: "tailscale_server_info", group: "meta", backend: "meta", level: "read" },
  // REST (P2)
  { name: "tailscale_list_devices", group: "devices", backend: "api", level: "read" },
  { name: "tailscale_get_device", group: "devices", backend: "api", level: "read" },
  { name: "tailscale_authorize_device", group: "devices", backend: "api", level: "write" },
  { name: "tailscale_set_device_name", group: "devices", backend: "api", level: "write" },
  { name: "tailscale_set_device_tags", group: "devices", backend: "api", level: "write" },
  { name: "tailscale_get_device_routes", group: "devices", backend: "api", level: "read" },
  { name: "tailscale_set_device_routes", group: "devices", backend: "api", level: "write" },
  { name: "tailscale_expire_device_key", group: "devices", backend: "api", level: "admin" },
  { name: "tailscale_delete_device", group: "devices", backend: "api", level: "admin" },
  { name: "tailscale_get_dns_config", group: "dns", backend: "api", level: "read" },
  { name: "tailscale_set_dns_config", group: "dns", backend: "api", level: "write" },
  { name: "tailscale_get_policy_file", group: "policy", backend: "api", level: "read" },
  { name: "tailscale_validate_policy_file", group: "policy", backend: "api", level: "read" },
  { name: "tailscale_update_policy_file", group: "policy", backend: "api", level: "admin" },
  { name: "tailscale_list_auth_keys", group: "keys", backend: "api", level: "read" },
  { name: "tailscale_create_auth_key", group: "keys", backend: "api", level: "admin" },
  { name: "tailscale_delete_auth_key", group: "keys", backend: "api", level: "admin" },
  { name: "tailscale_get_tailnet_settings", group: "settings", backend: "api", level: "read" },
  { name: "tailscale_update_tailnet_settings", group: "settings", backend: "api", level: "admin" },
  { name: "tailscale_list_webhooks", group: "webhooks", backend: "api", level: "read" },
  { name: "tailscale_create_webhook", group: "webhooks", backend: "api", level: "write" },
  { name: "tailscale_delete_webhook", group: "webhooks", backend: "api", level: "admin" },
  { name: "tailscale_list_users", group: "users", backend: "api", level: "read" },
  { name: "tailscale_get_user", group: "users", backend: "api", level: "read" },
  { name: "tailscale_approve_user", group: "users", backend: "api", level: "write" },
  { name: "tailscale_suspend_user", group: "users", backend: "api", level: "write" },
  { name: "tailscale_restore_user", group: "users", backend: "api", level: "write" },
  { name: "tailscale_get_audit_log", group: "logs", backend: "api", level: "read" },
];

export function registerMetaTools(server: McpServer, config: Config, info: { cliBinary: string }): void {
  const apiConfigured = hasApiCredentials(config);

  server.registerTool(
    "tailscale_server_info",
    {
      title: "Server info & capability catalog",
      description:
        "Report this MCP server's version, live backends (CLI path, whether REST credentials are configured), the " +
        "effective tailnet, the risk level, and a catalog of every tool: whether each is available now or, if not, " +
        "WHY (risk_gated — raise TAILSCALE_RISK_LEVEL; or needs_credentials — set TAILSCALE_OAUTH_* / TAILSCALE_API_KEY). " +
        "Use this when a tool you expected is missing. Read-only.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const tools = CATALOG.map((d) => {
          const riskOk = allows(config.riskLevel, d.level);
          const credOk = d.backend !== "api" || apiConfigured;
          let reason: string;
          if (!credOk) reason = "needs_credentials (set TAILSCALE_OAUTH_CLIENT_ID/SECRET or TAILSCALE_API_KEY)";
          else if (!riskOk) reason = `risk_gated (set TAILSCALE_RISK_LEVEL>=${d.level})`;
          else reason = "available";
          return {
            name: d.name,
            group: d.group,
            backend: d.backend,
            requiredRiskLevel: d.level,
            forcedApproval: FORCED_APPROVAL_TOOLS.has(d.name),
            available: riskOk && credOk,
            reason,
          };
        });
        return jsonResult({
          server: { name: SERVER_NAME, version: SERVER_VERSION },
          riskLevel: config.riskLevel,
          tailnet: config.tailnet,
          backends: {
            cli: { binary: info.cliBinary },
            api: { configured: apiConfigured, tailnet: config.tailnet },
          },
          counts: {
            total: tools.length,
            available: tools.filter((t) => t.available).length,
          },
          tools,
        });
      } catch (e) {
        return fail(e);
      }
    },
  );
}
