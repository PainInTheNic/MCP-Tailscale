/** MCP prompts: reusable workflows for common Tailscale tasks. */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerPrompts(server: McpServer): void {
  server.registerPrompt(
    "diagnose_connectivity",
    {
      title: "Diagnose Tailscale connectivity",
      description: "Guide a step-by-step diagnosis of this host's Tailscale connectivity.",
    },
    () => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text:
              "Diagnose this host's Tailscale connectivity. Work through these steps and report findings:\n" +
              "1. Call tailscale_status. If state is not `running`, note why (stopped → tailscale_connect; needs_login → surface the authURL; daemon_unreachable → the Tailscale service is off).\n" +
              "2. Review the `health` warnings in the status.\n" +
              "3. Call tailscale_netcheck and note NAT type, DERP relay latency, UDP and IPv6 availability.\n" +
              "4. If a specific peer is unreachable, call tailscale_ping <peer> (optionally untilDirect) and report whether the path is direct or via a DERP relay.\n" +
              "5. If name resolution is failing, call tailscale_dns_status and check MagicDNS and the resolvers.\n" +
              "6. Summarize the likely cause and the single best next action. Do not make changes without asking.",
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    "review_acl_change",
    {
      title: "Review an ACL policy change",
      description: "Safely propose and apply a tailnet ACL policy change using validate + ETag concurrency.",
      argsSchema: { intent: z.string().max(2000).optional().describe("What the policy change should accomplish.") },
    },
    ({ intent }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text:
              "Safely change the tailnet ACL policy" +
              (intent ? ` to: ${intent}` : "") +
              ".\n" +
              "1. Call tailscale_get_policy_file and capture BOTH the current HuJSON and its ETag.\n" +
              "2. Draft the minimal edit, preserving existing comments and structure.\n" +
              "3. Call tailscale_validate_policy_file on the draft; fix any errors before proceeding.\n" +
              "4. Show me the exact diff and wait for my confirmation.\n" +
              "5. Only then call tailscale_update_policy_file with the draft and ifMatch set to the captured ETag " +
              "(a 412 means someone else edited it — re-read and rebase). Never overwrite without the ETag.",
          },
        },
      ],
    }),
  );
}
