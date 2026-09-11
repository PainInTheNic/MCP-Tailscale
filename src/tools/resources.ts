/**
 * MCP resources: browseable, read-only views the host can fetch without a tool call.
 *   tailscale://status  — this host's connection state (no credentials)
 *   tailscale://prefs   — this host's preferences (no credentials)
 *   tailscale://devices — tailnet device list (REST; only when configured)
 *   tailscale://acl     — current ACL policy as HuJSON (REST; only when configured)
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TailscaleService } from "../service/tailscale-service.js";
import type { TailscaleApiClient } from "../backends/api/client.js";
import { redact } from "../util/redact.js";

export function registerResources(server: McpServer, service: TailscaleService, api?: TailscaleApiClient): void {
  server.registerResource(
    "tailscale-status",
    "tailscale://status",
    { title: "Tailscale status (this host)", description: "Normalized connection state of this host.", mimeType: "application/json" },
    async (uri) => {
      const s = await service.status();
      return { contents: [{ uri: uri.href, mimeType: "application/json", text: redact(JSON.stringify(s, null, 2)) }] };
    },
  );

  server.registerResource(
    "tailscale-prefs",
    "tailscale://prefs",
    { title: "Tailscale preferences (this host)", description: "Current effective preferences.", mimeType: "application/json" },
    async (uri) => {
      const p = await service.getPrefs();
      return { contents: [{ uri: uri.href, mimeType: "application/json", text: redact(JSON.stringify(p, null, 2)) }] };
    },
  );

  if (api) {
    server.registerResource(
      "tailscale-devices",
      "tailscale://devices",
      { title: "Tailnet devices", description: "All devices in the tailnet (REST).", mimeType: "application/json" },
      async (uri) => {
        const res = await api.get(api.tnet("/devices"));
        return { contents: [{ uri: uri.href, mimeType: "application/json", text: redact(JSON.stringify(res.data, null, 2)) }] };
      },
    );

    server.registerResource(
      "tailscale-acl",
      "tailscale://acl",
      { title: "ACL policy file", description: "Current tailnet ACL policy as HuJSON.", mimeType: "application/hujson" },
      async (uri) => {
        const res = await api.get<string>(api.tnet("/acl"), undefined, { accept: "application/hujson", parse: "text" });
        return { contents: [{ uri: uri.href, mimeType: "application/hujson", text: redact(String(res.data)) }] };
      },
    );
  }
}
