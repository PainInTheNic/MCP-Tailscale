/** Types for the local host (tailscaled) backend. */
import type { ArgvSpec } from "./argv-allowlist.js";

/** Raw shape of the fields we read from `tailscale status --json`. */
export interface RawStatus {
  Version?: string;
  BackendState?: string;
  AuthURL?: string;
  TailscaleIPs?: string[];
  HaveNodeKey?: boolean;
  Health?: unknown;
  CurrentTailnet?: { Name?: string; MagicDNSSuffix?: string } | null;
  Self?: RawSelf | null;
}

export interface RawSelf {
  ID?: string;
  HostName?: string;
  DNSName?: string;
  OS?: string;
  Online?: boolean;
  TailscaleIPs?: string[];
  KeyExpiry?: string; // RFC3339
  Expired?: boolean;
  Tags?: string[];
}

/** Normalized, single-meaning connection state. */
export type ConnState =
  | "running" // BackendState=Running AND Self.Online — fully connected & reachable
  | "running_local_only" // Running but not yet reachable (settling)
  | "stopped" // BackendState=Stopped — logged in, WireGuard down
  | "needs_login" // NeedsLogin, or key expired — requires (re)authentication
  | "starting"
  | "no_state"
  | "daemon_unreachable" // cannot reach tailscaled (service off / wrong session)
  | "unknown";

export interface HostStatus {
  state: ConnState;
  backendState: string;
  selfOnline: boolean;
  haveNodeKey: boolean;
  keyExpired: boolean;
  keyExpiry?: string;
  tailscaleIPs: string[];
  currentTailnet?: string;
  hostName?: string;
  dnsName?: string;
  os?: string;
  authURL?: string;
  health: string[];
  version?: string;
}

export interface CliResult {
  stdout: string;
  stderr: string;
  /** Process exit code; null if terminated by signal. */
  code: number | null;
}

/**
 * The host backend contract. Concrete methods only — there is intentionally no
 * generic `raw(sub, args)` escape hatch, so every invocation flows through the
 * argv allow-list.
 */
export interface HostBackend {
  status(opts?: { peers?: boolean }): Promise<HostStatus>;
  getPrefs(): Promise<unknown>;
  /** Bring the node online. `up` with no flags = silent reconnect (no browser). */
  connectBare(): Promise<CliResult>;
  /** Headless login via an auth-key FILE (secret never enters argv). */
  connectWithAuthKeyFile(path: string): Promise<CliResult>;
  /** Trigger interactive login and return the AuthURL to complete it, if one appears. */
  beginInteractiveLogin(): Promise<string | undefined>;
  /** Disconnect (WireGuard down); node stays logged in. */
  disconnect(reason?: string): Promise<CliResult>;
  /**
   * Constrained execution used by P1 host tools. NOT a model-facing passthrough:
   * `subcommand` and flags are still validated by the argv allow-list, and no tool
   * lets the model choose the subcommand — handlers pass fixed subcommands only.
   * With `ensureOk`, a non-zero exit throws a classified HostError.
   */
  exec(
    subcommand: string,
    spec?: ArgvSpec,
    opts?: { timeoutMs?: number; ensureOk?: boolean },
  ): Promise<CliResult>;
}
