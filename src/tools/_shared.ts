/** Shared helpers for building tool results and describing host status. */
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { HostStatus } from "../backends/host/types.js";
import { HostError } from "../util/errors.js";
import { redact } from "../util/redact.js";
import { logger } from "../logger.js";

/** Output shape describing this host's connection state. */
export const statusShape = {
  state: z
    .string()
    .describe("running | running_local_only | stopped | needs_login | starting | no_state | daemon_unreachable | unknown"),
  connected: z.boolean().describe("True only when BackendState=Running AND Self.Online."),
  backendState: z.string(),
  selfOnline: z.boolean(),
  haveNodeKey: z.boolean(),
  keyExpired: z.boolean(),
  keyExpiry: z.string().optional(),
  tailscaleIPs: z.array(z.string()),
  currentTailnet: z.string().optional(),
  hostName: z.string().optional(),
  dnsName: z.string().optional(),
  os: z.string().optional(),
  authURL: z.string().optional(),
  health: z.array(z.string()),
  version: z.string().optional(),
};

export const actionShape = {
  ...statusShape,
  action: z.string().describe("What the tool did."),
  message: z.string().describe("Human-readable summary."),
};

export function toStructured(s: HostStatus): Record<string, unknown> {
  return {
    state: s.state,
    connected: s.state === "running",
    backendState: s.backendState,
    selfOnline: s.selfOnline,
    haveNodeKey: s.haveNodeKey,
    keyExpired: s.keyExpired,
    ...(s.keyExpiry ? { keyExpiry: s.keyExpiry } : {}),
    tailscaleIPs: s.tailscaleIPs,
    ...(s.currentTailnet ? { currentTailnet: s.currentTailnet } : {}),
    ...(s.hostName ? { hostName: s.hostName } : {}),
    ...(s.dnsName ? { dnsName: s.dnsName } : {}),
    ...(s.os ? { os: s.os } : {}),
    ...(s.authURL ? { authURL: s.authURL } : {}),
    health: s.health,
    ...(s.version ? { version: s.version } : {}),
  };
}

/** Success result with structured content (matches an outputSchema). */
export function ok(text: string, structured: Record<string, unknown>): CallToolResult {
  return { content: [{ type: "text", text: redact(text) }], structuredContent: structured };
}

/** Plain text result (no outputSchema). */
export function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text: redact(text) }] };
}

/** Pretty-printed JSON text result (no outputSchema). */
export function jsonResult(value: unknown): CallToolResult {
  return { content: [{ type: "text", text: redact(JSON.stringify(value, null, 2)) }] };
}

/** Turn a thrown error into a non-structured error result (skips output validation). */
export function fail(err: unknown): CallToolResult {
  if (err instanceof HostError) {
    logger.warn("tool error", { code: err.code, detail: err.detail });
    return { isError: true, content: [{ type: "text", text: redact(err.toText()) }] };
  }
  logger.error("unexpected tool error", { error: String(err) });
  return {
    isError: true,
    content: [{ type: "text", text: redact(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`) }],
  };
}

export function statusText(prefix: string, s: HostStatus): string {
  const lines = [prefix, `State: ${s.state}${s.state === "running" ? " (connected)" : ""}`];
  if (s.dnsName || s.hostName) lines.push(`Host: ${s.dnsName ?? s.hostName}`);
  if (s.tailscaleIPs.length) lines.push(`IPs: ${s.tailscaleIPs.join(", ")}`);
  if (s.currentTailnet) lines.push(`Tailnet: ${s.currentTailnet}`);
  if (s.keyExpired) lines.push("⚠ Node key expired — re-authentication required.");
  if (s.authURL) lines.push(`Login URL: ${s.authURL}`);
  if (s.health.length) lines.push(`Health: ${s.health.join("; ")}`);
  return lines.join("\n");
}
