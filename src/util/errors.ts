/**
 * Host-path error taxonomy. Every failure the CLI layer can produce is mapped to
 * a stable {code, message, remedy} so the agent gets an actionable next step
 * instead of a raw stderr dump.
 */
import { MACOS_APP_CLI } from "../backends/host/binary-resolver.js";

export type HostErrorCode =
  | "cli_not_found"
  | "daemon_unreachable"
  | "needs_login"
  | "permission_denied"
  | "syspolicy_locked"
  | "timeout"
  | "invalid_argument"
  | "cli_error"
  | "parse_error";

export class HostError extends Error {
  readonly code: HostErrorCode;
  readonly remedy: string;
  /** Raw CLI stderr, if any — redacted before it ever reaches output. */
  readonly detail?: string;

  constructor(code: HostErrorCode, message: string, remedy: string, detail?: string) {
    super(message);
    this.name = "HostError";
    this.code = code;
    this.remedy = remedy;
    this.detail = detail;
  }

  /** Human-readable one-liner for tool text content. */
  toText(): string {
    const base = `Tailscale error [${this.code}]: ${this.message}`;
    return this.remedy ? `${base}\nRemedy: ${this.remedy}` : base;
  }
}

/**
 * Classify a completed-but-failed CLI invocation (non-zero exit) or a spawn
 * error into a HostError. `stderr` is matched case-insensitively against known
 * signatures.
 */
export function classifyCliFailure(args: {
  stderr?: string;
  exitCode?: number | null;
  spawnCode?: string; // e.g. "ENOENT"
  killed?: boolean;
  binaryPath: string;
  /** Locations searched for the binary, listed in a cli_not_found message. */
  searched?: string[];
  platform?: NodeJS.Platform;
}): HostError {
  const stderr = (args.stderr ?? "").trim();
  const lower = stderr.toLowerCase();

  if (args.spawnCode === "ENOENT") {
    const searched = args.searched?.length ? ` Searched: ${args.searched.join(", ")}.` : "";
    return new HostError(
      "cli_not_found",
      `Could not find the Tailscale CLI at "${args.binaryPath}".${searched}`,
      `Install Tailscale from https://tailscale.com/download, or set TAILSCALE_CLI_PATH to ${cliPathHint(args.platform ?? process.platform)}.`,
      stderr || undefined,
    );
  }
  if (args.killed) {
    return new HostError(
      "timeout",
      "The Tailscale command timed out and was terminated.",
      "The Tailscale service may be busy or unreachable. Check that the Tailscale service is running, then retry.",
      stderr || undefined,
    );
  }

  // Daemon not reachable (service stopped, pipe unavailable, wrong user session).
  if (
    lower.includes("failed to connect to local tailscaled") ||
    lower.includes("is tailscaled running") ||
    lower.includes("connection refused") ||
    lower.includes("cannot connect to") ||
    lower.includes("the system cannot find the file specified") // pipe missing on win
  ) {
    return new HostError(
      "daemon_unreachable",
      "Cannot reach the Tailscale service (tailscaled).",
      "Start the Tailscale service or launch the Tailscale app, then retry. If the server runs under a different account than the Tailscale user, run it in that user's session.",
      stderr || undefined,
    );
  }

  if (
    lower.includes("access is denied") ||
    lower.includes("permission denied") ||
    lower.includes("operation not permitted") ||
    lower.includes("access denied")
  ) {
    return new HostError(
      "permission_denied",
      "Permission denied talking to the Tailscale service.",
      "Run this MCP server as the same user that owns the Tailscale session on this machine.",
      stderr || undefined,
    );
  }

  if (lower.includes("needs login") || lower.includes("not logged in") || lower.includes("logged out")) {
    return new HostError(
      "needs_login",
      "This node is not logged in to a tailnet.",
      "Use tailscale_connect, which returns a login URL (or configure TAILSCALE_AUTH_KEY_FILE for headless login).",
      stderr || undefined,
    );
  }

  if (lower.includes("syspolicy") || lower.includes("managed by your administrator")) {
    return new HostError(
      "syspolicy_locked",
      "A setting is locked by system policy (MDM/GPO/registry).",
      "Check effective policy with tailscale_get_syspolicy; the change may be overridden centrally.",
      stderr || undefined,
    );
  }

  return new HostError(
    "cli_error",
    stderr ? firstLine(stderr) : `Tailscale exited with code ${args.exitCode ?? "unknown"}.`,
    "Inspect the detail, verify the node state with tailscale_status, and retry.",
    stderr || undefined,
  );
}

function cliPathHint(platform: NodeJS.Platform): string {
  if (platform === "win32") return "the full path of tailscale.exe";
  if (platform === "darwin") {
    return `the Tailscale app's bundled CLI (${MACOS_APP_CLI}) or the full path of a standalone tailscale binary`;
  }
  return "the full path of the tailscale binary";
}

function firstLine(s: string): string {
  const idx = s.indexOf("\n");
  return idx === -1 ? s : s.slice(0, idx);
}
