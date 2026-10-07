/**
 * CLI-backed HostBackend. Spawns the tailscale binary via execFile (shell:false,
 * argv arrays, windowsHide) — the guaranteed, always-available host path.
 *
 * Child environment: the server's env MINUS its REST credentials (the CLI never
 * needs them), plus TAILSCALE_BE_CLI=true when the binary is the macOS app's
 * executable (without a TTY it would otherwise start the GUI, not act as the CLI).
 *
 * Failure policy:
 *   - Spawn ENOENT and process-timeout (SIGKILL) reject as HostError.
 *   - A non-zero exit RESOLVES with the exit code, because `tailscale status`
 *     returns exit 1 when stopped. "Action" methods then call ensureOk() to turn
 *     a non-zero exit into a classified HostError; status()/getPrefs() interpret
 *     it themselves.
 */
import { execFile } from "node:child_process";
import { buildArgv, type ArgvSpec } from "./argv-allowlist.js";
import { isMacAppCli } from "./binary-resolver.js";
import { classifyCliFailure, HostError } from "../../util/errors.js";
import { logger } from "../../logger.js";
import { parseStatus, daemonUnreachableStatus } from "./status-parse.js";
import type { CliResult, HostBackend, HostStatus } from "./types.js";

export interface Timeouts {
  read: number;
  connect: number;
  disconnect: number;
  login: number;
}

const DEFAULT_TIMEOUTS: Timeouts = {
  read: 10_000,
  connect: 60_000,
  disconnect: 20_000,
  login: 8_000,
};

const MAX_BUFFER = 10 * 1024 * 1024;
const AUTH_URL_RE = /https:\/\/[^\s"']*login[^\s"']*/i;

/** The server's own REST credentials — never handed to a spawned CLI. */
const CREDENTIAL_ENV_VARS: ReadonlySet<string> = new Set([
  "TAILSCALE_OAUTH_CLIENT_ID",
  "TAILSCALE_OAUTH_CLIENT_SECRET",
  "TAILSCALE_API_KEY",
]);

/** Environment for a spawned CLI (see the file header). Returns a new object. */
export function buildChildEnv(
  binary: string,
  parentEnv: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...parentEnv };
  // Case-insensitive: Windows env names are, and a copied env keeps the user's casing.
  for (const k of Object.keys(env)) {
    if (CREDENTIAL_ENV_VARS.has(k.toUpperCase())) delete env[k];
  }
  // execFile resolves a bare name on the child env's PATH, so detection searches the same one.
  if (isMacAppCli(binary, platform, env.PATH)) env.TAILSCALE_BE_CLI = "true";
  return env;
}

interface ExecOptions {
  timeoutMs: number;
  env: NodeJS.ProcessEnv;
  /** Searched locations, reported if the binary cannot be spawned. */
  searched: string[];
}

function execTailscale(binary: string, argv: string[], opts: ExecOptions): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      argv,
      {
        windowsHide: true,
        timeout: opts.timeoutMs,
        maxBuffer: MAX_BUFFER,
        killSignal: "SIGKILL",
        encoding: "utf8",
        env: opts.env,
      },
      (err, stdout, stderr) => {
        const out = { stdout: stdout ?? "", stderr: stderr ?? "" };
        if (err) {
          const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: string };
          if (e.code === "ENOENT") {
            reject(classifyCliFailure({ spawnCode: "ENOENT", binaryPath: binary, searched: opts.searched }));
            return;
          }
          if (e.killed || e.signal === "SIGKILL") {
            reject(classifyCliFailure({ killed: true, binaryPath: binary, stderr: out.stderr }));
            return;
          }
          const code = typeof e.code === "number" ? e.code : null;
          resolve({ ...out, code });
          return;
        }
        resolve({ ...out, code: 0 });
      },
    );
  });
}

export interface CliBackendOptions {
  timeouts?: Partial<Timeouts>;
  /** Locations searched for the binary (binary-resolver's searchedLocations()), for cli_not_found. */
  searched?: string[];
}

export class CliHostBackend implements HostBackend {
  private readonly binary: string;
  private readonly t: Timeouts;
  private readonly env: NodeJS.ProcessEnv;
  private readonly searched: string[];

  constructor(binary: string, opts: CliBackendOptions = {}) {
    this.binary = binary;
    this.t = { ...DEFAULT_TIMEOUTS, ...opts.timeouts };
    this.env = buildChildEnv(binary);
    this.searched = opts.searched ?? [];
  }

  private async run(subcommand: string, spec: ArgvSpec, timeoutMs: number): Promise<CliResult> {
    const argv = buildArgv(subcommand, spec);
    logger.debug("exec tailscale", { argv });
    return execTailscale(this.binary, argv, { timeoutMs, env: this.env, searched: this.searched });
  }

  private ensureOk(res: CliResult): void {
    if (res.code !== 0) {
      throw classifyCliFailure({ stderr: res.stderr, exitCode: res.code, binaryPath: this.binary });
    }
  }

  async status(opts: { peers?: boolean } = {}): Promise<HostStatus> {
    const flags: ArgvSpec["flags"] = { json: true };
    if (!opts.peers) flags.peers = "false";
    const res = await this.run("status", { flags }, this.t.read);

    if (!res.stdout.trim()) {
      const err = classifyCliFailure({ stderr: res.stderr, exitCode: res.code, binaryPath: this.binary });
      if (err.code === "daemon_unreachable") return daemonUnreachableStatus();
      throw err;
    }
    try {
      return parseStatus(res.stdout);
    } catch (e) {
      const err = classifyCliFailure({ stderr: res.stderr, exitCode: res.code, binaryPath: this.binary });
      if (err.code === "daemon_unreachable") return daemonUnreachableStatus();
      throw new HostError(
        "parse_error",
        "Could not parse `tailscale status --json` output.",
        "Retry; if it persists, run `tailscale status --json` manually to inspect.",
        res.stderr || String(e),
      );
    }
  }

  async getPrefs(): Promise<unknown> {
    const res = await this.run("get", { flags: { json: true } }, this.t.read);
    this.ensureOk(res);
    try {
      return JSON.parse(res.stdout);
    } catch (e) {
      throw new HostError(
        "parse_error",
        "Could not parse `tailscale get --json` output.",
        "Retry; if it persists, run `tailscale get --json` manually.",
        String(e),
      );
    }
  }

  async connectBare(): Promise<CliResult> {
    const res = await this.run("up", {}, this.t.connect);
    this.ensureOk(res);
    return res;
  }

  async connectWithAuthKeyFile(path: string): Promise<CliResult> {
    // `file:<path>` indirection keeps the secret out of argv and the process table.
    const res = await this.run("up", { flags: { "auth-key": `file:${path}` } }, this.t.connect);
    this.ensureOk(res);
    return res;
  }

  async beginInteractiveLogin(): Promise<string | undefined> {
    // Short CLI timeout so the process returns promptly after emitting the AuthURL,
    // instead of blocking forever (up defaults to --timeout 0s = block).
    const res = await this.run("up", { flags: { json: true, timeout: "1s" } }, this.t.login).catch(
      (e: unknown) => {
        // A timeout here is expected-ish; return empty output so the caller can poll status.
        if (e instanceof HostError && e.code === "timeout") return { stdout: "", stderr: "", code: null } as CliResult;
        throw e;
      },
    );
    return extractAuthUrl(res.stdout);
  }

  async disconnect(reason?: string): Promise<CliResult> {
    const spec: ArgvSpec = reason ? { flags: { reason } } : {};
    const res = await this.run("down", spec, this.t.disconnect);
    this.ensureOk(res);
    return res;
  }

  async exec(
    subcommand: string,
    spec: ArgvSpec = {},
    opts: { timeoutMs?: number; ensureOk?: boolean } = {},
  ): Promise<CliResult> {
    const res = await this.run(subcommand, spec, opts.timeoutMs ?? this.t.read);
    if (opts.ensureOk) this.ensureOk(res);
    return res;
  }
}

/** Extract an AuthURL from `up --json` output (JSON field or a login URL substring). */
export function extractAuthUrl(stdout: string): string | undefined {
  const trimmed = stdout.trim();
  if (!trimmed) return undefined;
  // Try structured first.
  for (const line of trimmed.split(/\r?\n/)) {
    try {
      const obj = JSON.parse(line) as { AuthURL?: string };
      if (obj && typeof obj.AuthURL === "string" && obj.AuthURL) return obj.AuthURL;
    } catch {
      // not JSON; fall through to regex
    }
  }
  const m = trimmed.match(AUTH_URL_RE);
  return m ? m[0] : undefined;
}
