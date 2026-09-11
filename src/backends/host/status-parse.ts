/** Normalize `tailscale status --json` into a single-meaning HostStatus. */
import type { ConnState, HostStatus, RawStatus } from "./types.js";

/** Build the sentinel status for "cannot reach tailscaled". */
export function daemonUnreachableStatus(): HostStatus {
  return {
    state: "daemon_unreachable",
    backendState: "Unreachable",
    selfOnline: false,
    haveNodeKey: false,
    keyExpired: false,
    tailscaleIPs: [],
    health: ["Cannot reach the Tailscale service (tailscaled)."],
  };
}

/** Coerce the polymorphic `Health` field into a flat list of message strings. */
function normalizeHealth(health: unknown): string[] {
  if (!health) return [];
  if (Array.isArray(health)) return health.map((h) => (typeof h === "string" ? h : safe(h)));
  if (typeof health === "object") return Object.values(health as Record<string, unknown>).map((v) => (typeof v === "string" ? v : safe(v)));
  return [String(health)];
}

function safe(x: unknown): string {
  try {
    return JSON.stringify(x);
  } catch {
    return String(x);
  }
}

function isExpired(keyExpiry?: string, expiredFlag?: boolean): boolean {
  if (expiredFlag === true) return true;
  if (!keyExpiry) return false;
  const t = Date.parse(keyExpiry);
  return Number.isFinite(t) && t < Date.now();
}

function deriveState(args: {
  backendState: string;
  selfOnline: boolean;
  keyExpired: boolean;
}): ConnState {
  const { backendState, selfOnline, keyExpired } = args;
  if (backendState === "NeedsLogin" || keyExpired) return "needs_login";
  if (backendState === "Running") return selfOnline ? "running" : "running_local_only";
  if (backendState === "Stopped") return "stopped";
  if (backendState === "Starting") return "starting";
  if (backendState === "NoState") return "no_state";
  return "unknown";
}

export function parseStatus(stdout: string): HostStatus {
  const raw = JSON.parse(stdout) as RawStatus;
  const self = raw.Self ?? undefined;

  const backendState = raw.BackendState ?? "unknown";
  const selfOnline = self?.Online === true;
  const haveNodeKey = raw.HaveNodeKey === true;
  const keyExpired = isExpired(self?.KeyExpiry, self?.Expired);
  const tailscaleIPs = raw.TailscaleIPs ?? self?.TailscaleIPs ?? [];

  return {
    state: deriveState({ backendState, selfOnline, keyExpired }),
    backendState,
    selfOnline,
    haveNodeKey,
    keyExpired,
    keyExpiry: self?.KeyExpiry,
    tailscaleIPs,
    currentTailnet: raw.CurrentTailnet?.Name,
    hostName: self?.HostName,
    dnsName: self?.DNSName?.replace(/\.$/, ""),
    os: self?.OS,
    authURL: raw.AuthURL || undefined,
    health: normalizeHealth(raw.Health),
    version: raw.Version,
  };
}
