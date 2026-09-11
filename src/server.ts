/** McpServer factory: resolve the CLI, wire host + REST backends, register tools. */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { type Config, hasApiCredentials } from "./config.js";
import { resolveTailscaleBinary } from "./backends/host/binary-resolver.js";
import { CliHostBackend } from "./backends/host/cli-executor.js";
import { TailscaleService } from "./service/tailscale-service.js";
import { TailscaleApiClient } from "./backends/api/client.js";
import { OAuthClientCredentialsProvider, StaticApiKeyProvider, type TokenProvider } from "./backends/api/auth.js";
import { registerAllTools } from "./tools/index.js";
import { logger } from "./logger.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";

export { SERVER_NAME, SERVER_VERSION } from "./constants.js";

export function createServer(config: Config): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  const binary = resolveTailscaleBinary(config.cliPath);
  logger.info("resolved tailscale binary", { binary });

  const host = new CliHostBackend(binary);
  const service = new TailscaleService(host, { authKeyFile: config.authKeyFile });

  let apiClient: TailscaleApiClient | undefined;
  if (hasApiCredentials(config)) {
    let provider: TokenProvider;
    if (config.oauthClientId && config.oauthClientSecret) {
      provider = new OAuthClientCredentialsProvider(config.apiBaseUrl, config.oauthClientId, config.oauthClientSecret);
    } else {
      provider = new StaticApiKeyProvider(config.apiKey as string);
    }
    apiClient = new TailscaleApiClient(config.apiBaseUrl, provider, config.tailnet);
    logger.info("REST API configured", { auth: apiClient.describeAuth(), tailnet: config.tailnet });
  } else {
    logger.info("REST API not configured; host/CLI tools only");
  }

  registerAllTools(server, service, config, { cliBinary: binary, apiClient });
  return server;
}
