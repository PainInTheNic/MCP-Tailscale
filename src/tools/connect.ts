/**
 * P0 host tools: status, get_prefs, connect, disconnect.
 * CLI-only, credential-free — they prove the immediate requirement.
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TailscaleService } from "../service/tailscale-service.js";
import { buildToolMeta } from "../meta/approval.js";
import { allows } from "../meta/risk.js";
import type { RiskLevel } from "../config.js";
import { actionShape, fail, ok, statusShape, statusText, textResult, toStructured } from "./_shared.js";
import { redact } from "../util/redact.js";

export function registerConnectTools(server: McpServer, service: TailscaleService, risk: RiskLevel): void {
  // Reads are always available.
  server.registerTool(
    "tailscale_status",
    {
      title: "Tailscale status (this host)",
      description:
        "Report this host's Tailscale connection state, read from `tailscale status --json`.\n\n" +
        "Returns a normalized `state` and a `connected` boolean (true only when BackendState=Running AND Self.Online). " +
        "Assigned Tailscale IPs persist even while Stopped, so an IP alone does not mean connected. The plain-`status` " +
        "exit code is ignored (it is 1 when stopped); state comes from the JSON. Read-only.",
      inputSchema: { peers: z.boolean().default(false).describe("Include the peer list (larger output). Default false.") },
      outputSchema: statusShape,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
      _meta: buildToolMeta("tailscale_status"),
    },
    async ({ peers }) => {
      try {
        const s = await service.status(peers);
        return ok(statusText("Tailscale status:", s), toStructured(s));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "tailscale_get_prefs",
    {
      title: "Tailscale preferences (this host)",
      description:
        "Return this host's current effective Tailscale preferences via `tailscale get --json` (works even while " +
        "Stopped). Read-only. Shows AcceptRoutes, AcceptDNS, ExitNode, Hostname, RunSSH, ShieldsUp, etc.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
      _meta: buildToolMeta("tailscale_get_prefs"),
    },
    async () => {
      try {
        const prefs = await service.getPrefs();
        return textResult(JSON.stringify(prefs, null, 2));
      } catch (e) {
        return fail(e);
      }
    },
  );

  // connect/disconnect are state-changing: only at write level or above.
  if (!allows(risk, "write")) return;

  server.registerTool(
    "tailscale_connect",
    {
      title: "Connect this host to Tailscale",
      description:
        "Bring this host online on its tailnet (`tailscale up`). Connectivity only — it does not change preferences " +
        "(use tailscale_set_prefs).\n\n" +
        "If already Running, returns immediately; if Stopped with a valid key, runs a flag-free `up` (silent, no " +
        "browser) then polls until reachable; if login/re-auth is needed it does NOT block — it returns a login " +
        "`authURL` (or logs in headlessly if TAILSCALE_AUTH_KEY_FILE is set). action ∈ already_connected | reconnected " +
        "| needs_login. Success means state=running. No elevation needed on Windows.",
      inputSchema: {},
      outputSchema: actionShape,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
      _meta: buildToolMeta("tailscale_connect"),
    },
    async () => {
      try {
        const r = await service.connect();
        return ok(statusText(r.message, r.status), { ...toStructured(r.status), action: r.action, message: redact(r.message) });
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "tailscale_disconnect",
    {
      title: "Disconnect this host from Tailscale",
      description:
        "Disconnect this host (`tailscale down`): brings WireGuard down but STAYS LOGGED IN — fully reversible with " +
        "tailscale_connect and does NOT expire the node key (use tailscale_logout for that). Interrupts Tailscale " +
        "connectivity for every user of this machine, so it requires user approval. action ∈ already_disconnected | " +
        "disconnected. Success means state=stopped.",
      inputSchema: {
        reason: z.string().max(200).optional().describe("Optional reason, only if your tailnet policy requires one."),
      },
      outputSchema: actionShape,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
      _meta: buildToolMeta("tailscale_disconnect"),
    },
    async ({ reason }) => {
      try {
        const r = await service.disconnect(reason);
        return ok(statusText(r.message, r.status), { ...toStructured(r.status), action: r.action, message: redact(r.message) });
      } catch (e) {
        return fail(e);
      }
    },
  );
}
