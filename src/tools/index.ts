/** Tool registration entry point. Groups are gated by risk level and credentials. */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TailscaleService } from "../service/tailscale-service.js";
import type { Config } from "../config.js";
import type { TailscaleApiClient } from "../backends/api/client.js";
import { registerConnectTools } from "./connect.js";
import { registerHostTools } from "./host.js";
import { registerMetaTools } from "./meta.js";
import { registerRestTools } from "./rest.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

export interface ToolDeps {
  cliBinary: string;
  apiClient?: TailscaleApiClient;
}

export function registerAllTools(
  server: McpServer,
  service: TailscaleService,
  config: Config,
  deps: ToolDeps,
): void {
  // P0 + P1 — host (CLI). Always available (reads); writes gated by risk level.
  registerConnectTools(server, service, config.riskLevel);
  registerHostTools(server, service, config);

  // P2 — tailnet REST. Only when credentials are configured (server_info reports why not).
  if (deps.apiClient) {
    registerRestTools(server, deps.apiClient, config);
  }

  // Meta — capability catalog (always).
  registerMetaTools(server, config, { cliBinary: deps.cliBinary });

  // Resources + prompts (ergonomics). Resource set depends on API availability.
  registerResources(server, service, deps.apiClient);
  registerPrompts(server);
}
