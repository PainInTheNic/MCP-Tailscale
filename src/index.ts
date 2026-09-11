#!/usr/bin/env node
/**
 * tailscale-mcp-server — entry point.
 * Local stdio MCP server for controlling and managing Tailscale.
 * GOLDEN RULE: never write to stdout; all diagnostics go to stderr via logger.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig, type Config } from "./config.js";
import { createServer, SERVER_NAME, SERVER_VERSION } from "./server.js";
import { logger } from "./logger.js";

async function main(): Promise<void> {
  let config: Config;
  try {
    config = loadConfig();
  } catch (e) {
    logger.error("invalid configuration", { error: e instanceof Error ? e.message : String(e) });
    process.exit(1);
  }

  const server = createServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info(`${SERVER_NAME} v${SERVER_VERSION} running on stdio`, { riskLevel: config.riskLevel });
}

main().catch((e: unknown) => {
  logger.error("fatal startup error", { error: e instanceof Error ? (e.stack ?? e.message) : String(e) });
  process.exit(1);
});
