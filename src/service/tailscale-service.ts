/**
 * Facade the tools call. For P0 it wraps the host backend and implements the
 * connect/disconnect state machine with a single, reconciled definition of
 * "connected" (BackendState=Running AND Self.Online), bounded polling, and
 * correct routing of the needs-login / expired-key case to the auth-URL path.
 */
import type { HostBackend, HostStatus } from "../backends/host/types.js";
import { HostError } from "../util/errors.js";
import { logger } from "../logger.js";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export interface ConnectResult {
  action: "already_connected" | "reconnected" | "needs_login";
  status: HostStatus;
  message: string;
  authURL?: string;
}

export interface DisconnectResult {
  action: "already_disconnected" | "disconnected";
  status: HostStatus;
  message: string;
}

export interface ServiceOptions {
  authKeyFile?: string;
  /** How long to wait for Self.Online after bringing the link up. */
  onlineWaitMs?: number;
  /** How long to wait for BackendState=Stopped after `down`. */
  stopWaitMs?: number;
}

export class TailscaleService {
  private readonly host: HostBackend;
  private readonly onlineWaitMs: number;
  private readonly stopWaitMs: number;
  private readonly authKeyFile?: string;

  constructor(host: HostBackend, opts: ServiceOptions = {}) {
    this.host = host;
    this.authKeyFile = opts.authKeyFile;
    this.onlineWaitMs = opts.onlineWaitMs ?? 20_000;
    this.stopWaitMs = opts.stopWaitMs ?? 15_000;
  }

  status(peers = false): Promise<HostStatus> {
    return this.host.status({ peers });
  }

  getPrefs(): Promise<unknown> {
    return this.host.getPrefs();
  }

  async connect(): Promise<ConnectResult> {
    const s = await this.host.status();

    if (s.state === "daemon_unreachable") throw daemonError();

    if (s.state === "running") {
      return { action: "already_connected", status: s, message: describe(s) };
    }

    // Needs (re)authentication — do NOT run bare `up` (it would block on a browser login).
    if (s.state === "needs_login") {
      return this.handleNeedsLogin();
    }

    // Stopped / starting / no_state / running_local_only with a valid key: bring the link up.
    logger.info("connect: bringing link up via bare `up`", { from: s.state });
    await this.host.connectBare();
    const settled = await this.pollUntilOnline();

    if (settled.state === "needs_login") {
      // Rare: `up` revealed the node actually needs login.
      return this.handleNeedsLogin(settled);
    }
    return { action: "reconnected", status: settled, message: describe(settled) };
  }

  async disconnect(reason?: string): Promise<DisconnectResult> {
    const s = await this.host.status();
    if (s.state === "daemon_unreachable") throw daemonError();
    if (s.state === "stopped") {
      return {
        action: "already_disconnected",
        status: s,
        message: "Already disconnected. The node stays logged in; reconnect with tailscale_connect.",
      };
    }
    logger.info("disconnect: running `down`", { from: s.state });
    await this.host.disconnect(reason);
    const settled = await this.pollUntilState("stopped", this.stopWaitMs);
    const message =
      settled.state === "stopped"
        ? "Disconnected. The node stays logged in (key not expired); reconnect with tailscale_connect."
        : `Ran 'tailscale down' but the node is now '${settled.state}'. Check tailscale_status.`;
    return { action: "disconnected", status: settled, message };
  }

  // ---------------------------------------------------------------------------
  // P1 — host management
  // ---------------------------------------------------------------------------

  /** Incremental preference changes via `tailscale set` (no connect/disconnect, no complete-set rule). */
  async setPrefs(prefs: SetPrefsInput): Promise<HostStatus> {
    const flags = prefsToFlags(prefs);
    if (Object.keys(flags).length === 0) {
      throw new HostError("invalid_argument", "No preferences were provided to set.", "Pass at least one preference field.");
    }
    await this.host.exec("set", { flags }, { timeoutMs: 20_000, ensureOk: true });
    return this.host.status();
  }

  /** Set (or clear, with "") the exit node. Returns status plus who the exit node resolves to. */
  async setExitNode(exitNode: string, allowLanAccess?: boolean): Promise<{ status: HostStatus; target: string }> {
    const flags: Record<string, string | boolean> = { "exit-node": exitNode };
    if (allowLanAccess !== undefined) flags["exit-node-allow-lan-access"] = allowLanAccess;
    await this.host.exec("set", { flags }, { timeoutMs: 20_000, ensureOk: true });
    return { status: await this.host.status(), target: exitNode === "" ? "(cleared)" : exitNode };
  }

  /** Advertise subnet routes and/or toggle accepting routes. */
  async setRoutes(input: { advertiseRoutes?: string[]; acceptRoutes?: boolean }): Promise<HostStatus> {
    const flags: Record<string, string | boolean> = {};
    if (input.advertiseRoutes !== undefined) flags["advertise-routes"] = input.advertiseRoutes.join(",");
    if (input.acceptRoutes !== undefined) flags["accept-routes"] = input.acceptRoutes;
    if (Object.keys(flags).length === 0) {
      throw new HostError("invalid_argument", "Provide advertiseRoutes and/or acceptRoutes.", "Pass at least one.");
    }
    await this.host.exec("set", { flags }, { timeoutMs: 20_000, ensureOk: true });
    return this.host.status();
  }

  async listExitNodes(input: { country?: string; suggest?: boolean }): Promise<string> {
    const spec = input.suggest
      ? { positionals: ["suggest"] }
      : { flags: input.country ? { filter: input.country } : {}, positionals: ["list"] };
    const res = await this.host.exec("exit-node", spec, { timeoutMs: 15_000, ensureOk: true });
    return res.stdout.trim();
  }

  async ping(target: string, opts: { count?: number; untilDirect?: boolean } = {}): Promise<string> {
    const flags: Record<string, string | boolean> = {};
    if (opts.count !== undefined) flags.c = String(opts.count);
    if (opts.untilDirect) flags["until-direct"] = true;
    const res = await this.host.exec("ping", { flags, positionals: [target] }, { timeoutMs: 30_000 });
    return (res.stdout || res.stderr).trim();
  }

  async netcheck(): Promise<unknown> {
    const res = await this.host.exec("netcheck", { flags: { format: "json" } }, { timeoutMs: 25_000, ensureOk: true });
    return parseJson(res.stdout, "netcheck");
  }

  async version(opts: { upstream?: boolean } = {}): Promise<unknown> {
    const res = await this.host.exec(
      "version",
      { flags: { json: true, daemon: true, upstream: opts.upstream } },
      { timeoutMs: 15_000, ensureOk: true },
    );
    return parseJson(res.stdout, "version");
  }

  async whois(ip: string): Promise<unknown> {
    const res = await this.host.exec("whois", { flags: { json: true }, positionals: [ip] }, { timeoutMs: 15_000, ensureOk: true });
    return parseJson(res.stdout, "whois");
  }

  async whoami(): Promise<unknown> {
    const res = await this.host.exec("whoami", { flags: { json: true } }, { timeoutMs: 10_000, ensureOk: true });
    return parseJson(res.stdout, "whoami");
  }

  async dnsStatus(opts: { all?: boolean } = {}): Promise<{ json?: unknown; text: string }> {
    const res = await this.host.exec(
      "dns",
      { flags: { json: true, all: opts.all }, positionals: ["status"] },
      { timeoutMs: 15_000 },
    );
    // `dns status` may not honor --json on every build; return text and best-effort JSON.
    const text = (res.stdout || res.stderr).trim();
    try {
      return { json: JSON.parse(res.stdout), text };
    } catch {
      return { text };
    }
  }

  async getSyspolicy(): Promise<string> {
    const res = await this.host.exec("syspolicy", { positionals: ["list"] }, { timeoutMs: 15_000 });
    return (res.stdout || res.stderr).trim();
  }

  async listProfiles(): Promise<unknown> {
    const res = await this.host.exec("switch", { flags: { list: true, json: true } }, { timeoutMs: 10_000 });
    try {
      return parseJson(res.stdout, "switch --list");
    } catch {
      return { text: (res.stdout || res.stderr).trim() };
    }
  }

  async switchProfile(id: string): Promise<HostStatus> {
    await this.host.exec("switch", { positionals: [id] }, { timeoutMs: 20_000, ensureOk: true });
    return this.host.status();
  }

  async logout(reason?: string): Promise<HostStatus> {
    const spec = reason ? { flags: { reason } } : {};
    await this.host.exec("logout", spec, { timeoutMs: 20_000, ensureOk: true });
    return this.host.status();
  }

  private async handleNeedsLogin(current?: HostStatus): Promise<ConnectResult> {
    if (this.authKeyFile) {
      logger.info("connect: headless login via auth-key file");
      await this.host.connectWithAuthKeyFile(this.authKeyFile);
      const settled = await this.pollUntilOnline();
      return {
        action: "reconnected",
        status: settled,
        message: `Logged in headlessly via auth-key file. ${describe(settled)}`,
      };
    }
    const url = current?.authURL ?? (await this.resolveAuthUrl());
    const after = current ?? (await this.host.status());
    return {
      action: "needs_login",
      status: after,
      authURL: url,
      message: url
        ? `This node needs (re)authentication. Open this URL to finish login, then run tailscale_connect again:\n${url}`
        : "This node needs (re)authentication, but no login URL could be obtained. Open the Tailscale app to log in, then retry.",
    };
  }

  /** Get a login URL without blocking: try a short `up`, then poll status.AuthURL. */
  private async resolveAuthUrl(): Promise<string | undefined> {
    const fromUp = await this.host.beginInteractiveLogin().catch(() => undefined);
    if (fromUp) return fromUp;
    for (let i = 0; i < 5; i++) {
      await sleep(1000);
      const s = await this.host.status();
      if (s.authURL) return s.authURL;
      if (s.state === "running") return undefined; // login completed already
    }
    return undefined;
  }

  private async pollUntilOnline(): Promise<HostStatus> {
    const deadline = Date.now() + this.onlineWaitMs;
    let last = await this.host.status();
    while (Date.now() < deadline) {
      if (last.state === "running" || last.state === "needs_login") return last;
      await sleep(1000);
      last = await this.host.status();
    }
    return last; // may be running_local_only; the caller reports the true state
  }

  private async pollUntilState(target: HostStatus["state"], timeoutMs: number): Promise<HostStatus> {
    const deadline = Date.now() + timeoutMs;
    let last = await this.host.status();
    while (Date.now() < deadline && last.state !== target) {
      await sleep(1000);
      last = await this.host.status();
    }
    return last;
  }
}

/** Benign preferences settable via `tailscale set`. Traffic-redirection prefs
 * (exit-node, advertise/accept-routes) are intentionally excluded — they have
 * dedicated, forced-approval tools. */
export interface SetPrefsInput {
  acceptDns?: boolean;
  hostname?: string;
  shieldsUp?: boolean;
  ssh?: boolean;
  advertiseExitNode?: boolean;
  autoUpdate?: boolean;
  updateCheck?: boolean;
  webclient?: boolean;
  nickname?: string;
  reportPosture?: boolean;
  unattended?: boolean;
}

function prefsToFlags(p: SetPrefsInput): Record<string, string | boolean> {
  const f: Record<string, string | boolean> = {};
  if (p.acceptDns !== undefined) f["accept-dns"] = p.acceptDns;
  if (p.hostname !== undefined) f.hostname = p.hostname;
  if (p.shieldsUp !== undefined) f["shields-up"] = p.shieldsUp;
  if (p.ssh !== undefined) f.ssh = p.ssh;
  if (p.advertiseExitNode !== undefined) f["advertise-exit-node"] = p.advertiseExitNode;
  if (p.autoUpdate !== undefined) f["auto-update"] = p.autoUpdate;
  if (p.updateCheck !== undefined) f["update-check"] = p.updateCheck;
  if (p.webclient !== undefined) f.webclient = p.webclient;
  if (p.nickname !== undefined) f.nickname = p.nickname;
  if (p.reportPosture !== undefined) f["report-posture"] = p.reportPosture;
  if (p.unattended !== undefined) f.unattended = p.unattended;
  return f;
}

function parseJson(stdout: string, label: string): unknown {
  try {
    return JSON.parse(stdout);
  } catch (e) {
    throw new HostError(
      "parse_error",
      `Could not parse JSON output from \`tailscale ${label}\`.`,
      "Retry; if it persists, run the command manually to inspect its output.",
      String(e),
    );
  }
}

function daemonError(): HostError {
  return new HostError(
    "daemon_unreachable",
    "Cannot reach the Tailscale service (tailscaled).",
    "Start the Tailscale service or launch the Tailscale app, then retry.",
  );
}

function describe(s: HostStatus): string {
  if (s.state === "running") {
    const who = s.dnsName ?? s.hostName ?? "this host";
    return `Connected as ${who} (${s.tailscaleIPs.join(", ") || "no IP"}).`;
  }
  if (s.state === "running_local_only") {
    return `The Tailscale interface is up (${s.tailscaleIPs.join(", ")}) but not yet reachable by the control plane — this usually settles within a few seconds. Re-check with tailscale_status.`;
  }
  return `State is now '${s.state}'.`;
}
