/**
 * P1 host-management tools (CLI-backed). Registered subject to risk level:
 *   read  — list_exit_nodes, ping, netcheck, version, whois, whoami, dns_status,
 *           get_syspolicy, list_profiles
 *   write — set_prefs, set_exit_node (🔒), set_routes (🔒), switch_profile (🔒)
 *   admin — logout (🔒, destructive)
 * 🔒 = forced-approval via _meta (see meta/approval.ts).
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TailscaleService } from "../service/tailscale-service.js";
import type { Config, RiskLevel } from "../config.js";
import { buildToolMeta } from "../meta/approval.js";
import { allows } from "../meta/risk.js";
import { cidrArraySchema, exitNodeSchema, hostnameSchema, ipSchema } from "../validation/schemas.js";
import { fail, jsonResult, ok, statusShape, statusText, textResult, toStructured } from "./_shared.js";
import { redact } from "../util/redact.js";

export function registerHostTools(server: McpServer, service: TailscaleService, config: Config): void {
  const risk: RiskLevel = config.riskLevel;
  const reg: typeof server.registerTool = ((name, cfg, cb) => {
    // guarded by caller; kept typed for convenience
    return server.registerTool(name, cfg, cb);
  }) as typeof server.registerTool;
  const gate = (required: RiskLevel): boolean => allows(risk, required);

  // ---- read ---------------------------------------------------------------
  if (gate("read")) {
    reg(
      "tailscale_list_exit_nodes",
      {
        title: "List exit nodes",
        description:
          "List tailnet nodes advertising as exit nodes (`tailscale exit-node list`), optionally filtered by country, " +
          "or ask Tailscale to suggest the best one (`exit-node suggest`). Read-only. Select one with tailscale_set_exit_node.",
        inputSchema: {
          country: z.string().max(64).optional().describe("Filter list by country name."),
          suggest: z.boolean().default(false).describe("Return a single suggested exit node instead of the list."),
        },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_list_exit_nodes"),
      },
      async ({ country, suggest }) => {
        try {
          return textResult(await service.listExitNodes({ country, suggest }));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_ping",
      {
        title: "Tailscale ping",
        description:
          "Ping a peer at the Tailscale layer (`tailscale ping`) and report the path (DERP relay vs direct). Read-only.",
        inputSchema: {
          target: z.string().min(1).max(256).describe("Peer hostname, MagicDNS name, or Tailscale IP."),
          count: z.number().int().min(1).max(20).default(1).describe("Number of pings (default 1)."),
          untilDirect: z.boolean().default(false).describe("Keep pinging until a direct connection is established."),
        },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_ping"),
      },
      async ({ target, count, untilDirect }) => {
        try {
          return textResult(await service.ping(target, { count, untilDirect }));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_netcheck",
      {
        title: "Network conditions check",
        description:
          "Analyze local network conditions (`tailscale netcheck`): DERP relay reachability & latency, NAT type, UDP, " +
          "IPv6. Returns JSON. Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        _meta: buildToolMeta("tailscale_netcheck"),
      },
      async () => {
        try {
          return jsonResult(await service.netcheck());
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_version",
      {
        title: "Tailscale version",
        description: "Report client and daemon versions (`tailscale version --json`), optionally checking for updates. Read-only.",
        inputSchema: { checkUpstream: z.boolean().default(false).describe("Also check the latest available release.") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_version"),
      },
      async ({ checkUpstream }) => {
        try {
          return jsonResult(await service.version({ upstream: checkUpstream }));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_whois",
      {
        title: "Who-is a Tailscale IP",
        description: "Show the machine and user associated with a Tailscale IP (`tailscale whois --json`). Read-only.",
        inputSchema: { ip: ipSchema.describe("Tailscale IP, optionally with :port.") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_whois"),
      },
      async ({ ip }) => {
        try {
          return jsonResult(await service.whois(ip));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_whoami",
      {
        title: "Identity of this host",
        description: "Show the machine + user identity of this node (`tailscale whoami --json`). Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_whoami"),
      },
      async () => {
        try {
          return jsonResult(await service.whoami());
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_dns_status",
      {
        title: "MagicDNS / DNS status",
        description:
          "Report the internal DNS forwarder (100.100.100.100) / MagicDNS configuration: resolvers, split-DNS, cert " +
          "domains (`tailscale dns status`). Read-only.",
        inputSchema: { all: z.boolean().default(false).describe("Include the full DNS configuration detail.") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_dns_status"),
      },
      async ({ all }) => {
        try {
          const r = await service.dnsStatus({ all });
          return r.json !== undefined ? jsonResult(r.json) : textResult(r.text);
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_get_syspolicy",
      {
        title: "Effective system policy (local)",
        description:
          "List the effective LOCAL system policy applied to Tailscale on this host (MDM/GPO/registry) via " +
          "`tailscale syspolicy list`. Use it to explain a preference that a set/up change did not persist. " +
          "NOTE: this is local device policy, NOT Tailscale device posture. Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        _meta: buildToolMeta("tailscale_get_syspolicy"),
      },
      async () => {
        try {
          return textResult(await service.getSyspolicy());
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_list_profiles",
      {
        title: "List login profiles",
        description: "List the Tailscale account/login profiles on this machine (`tailscale switch --list`). Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_list_profiles"),
      },
      async () => {
        try {
          return jsonResult(await service.listProfiles());
        } catch (e) {
          return fail(e);
        }
      },
    );
  }

  // ---- write --------------------------------------------------------------
  if (gate("write")) {
    reg(
      "tailscale_set_prefs",
      {
        title: "Set Tailscale preferences",
        description:
          "Incrementally change one or more preferences via `tailscale set` (no connect/disconnect, no complete-flag-set " +
          "requirement). Only benign prefs — exit-node and routes have dedicated tools. Returns the resulting status.",
        inputSchema: {
          acceptDns: z.boolean().optional(),
          hostname: hostnameSchema.optional(),
          shieldsUp: z.boolean().optional().describe("Block incoming connections."),
          ssh: z.boolean().optional().describe("Enable/disable Tailscale SSH server on this node."),
          advertiseExitNode: z.boolean().optional().describe("Offer this node as an exit node (still needs approval in the admin console)."),
          autoUpdate: z.boolean().optional(),
          updateCheck: z.boolean().optional(),
          webclient: z.boolean().optional(),
          nickname: z.string().max(63).optional(),
          reportPosture: z.boolean().optional(),
          unattended: z.boolean().optional().describe("Windows: keep connected with no user logged in."),
        },
        outputSchema: statusShape,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_prefs"),
      },
      async (prefs) => {
        try {
          const s = await service.setPrefs(prefs);
          return ok(statusText("Preferences updated.", s), toStructured(s));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_set_exit_node",
      {
        title: "Set exit node",
        description:
          "Route this host's internet traffic through a tailnet exit node (`tailscale set --exit-node`). Pass an empty " +
          "string to CLEAR (stop using an exit node). ⚠ This redirects ALL of this host's traffic through the chosen " +
          "node, so it requires user approval. Returns the resulting status.",
        inputSchema: {
          exitNode: exitNodeSchema.describe('Exit node IP or MagicDNS name; "" to clear.'),
          allowLanAccess: z.boolean().optional().describe("Allow direct access to the local LAN while using the exit node."),
        },
        outputSchema: statusShape,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_exit_node"),
      },
      async ({ exitNode, allowLanAccess }) => {
        try {
          const { status, target } = await service.setExitNode(exitNode, allowLanAccess);
          return ok(statusText(`Exit node set to ${target}.`, status), toStructured(status));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_set_routes",
      {
        title: "Set advertised / accepted routes",
        description:
          "Advertise subnet routes from this host and/or toggle accepting routes advertised by others " +
          "(`tailscale set --advertise-routes / --accept-routes`). Advertised subnet routes still need approval in the " +
          "admin console. ⚠ Route changes alter connectivity, so this requires user approval. Pass an empty " +
          "advertiseRoutes array to withdraw all advertised routes. Returns the resulting status.",
        inputSchema: {
          advertiseRoutes: cidrArraySchema.optional().describe("CIDRs to advertise (e.g. 10.0.0.0/24); [] withdraws all."),
          acceptRoutes: z.boolean().optional().describe("Whether to accept subnet routes advertised by peers."),
        },
        outputSchema: statusShape,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_routes"),
      },
      async ({ advertiseRoutes, acceptRoutes }) => {
        try {
          const s = await service.setRoutes({ advertiseRoutes, acceptRoutes });
          return ok(statusText("Routes updated.", s), toStructured(s));
        } catch (e) {
          return fail(e);
        }
      },
    );

    reg(
      "tailscale_switch_profile",
      {
        title: "Switch login profile",
        description:
          "Switch the active Tailscale account/login profile on this machine (`tailscale switch <id>`). ⚠ This changes " +
          "which identity/tailnet controls this node, so it requires user approval. Use tailscale_list_profiles to see ids. " +
          "Returns the resulting status.",
        inputSchema: { id: z.string().min(1).max(128).describe("Profile id from tailscale_list_profiles.") },
        outputSchema: statusShape,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        _meta: buildToolMeta("tailscale_switch_profile"),
      },
      async ({ id }) => {
        try {
          const s = await service.switchProfile(id);
          return ok(statusText(`Switched to profile ${redact(id)}.`, s), toStructured(s));
        } catch (e) {
          return fail(e);
        }
      },
    );
  }

  // ---- admin --------------------------------------------------------------
  if (gate("admin")) {
    reg(
      "tailscale_logout",
      {
        title: "Log out (expire node key)",
        description:
          "Log this node out of its tailnet (`tailscale logout`). ⚠ DESTRUCTIVE: this EXPIRES the node key — the next " +
          "connect requires full re-authentication (browser). This is NOT the same as disconnect. Requires user approval " +
          "and admin risk level. Returns the resulting status.",
        inputSchema: { reason: z.string().max(200).optional().describe("Optional reason, if tailnet policy requires one.") },
        outputSchema: statusShape,
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_logout"),
      },
      async ({ reason }) => {
        try {
          const s = await service.logout(reason);
          return ok(statusText("Logged out. Node key expired; next connect needs re-authentication.", s), toStructured(s));
        } catch (e) {
          return fail(e);
        }
      },
    );
  }
}
