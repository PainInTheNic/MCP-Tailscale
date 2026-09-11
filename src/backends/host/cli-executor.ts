/**
 * CLI-backed HostBackend. Spawns the tailscale binary via execFile (shell:false,
 * argv arrays, windowsHide) — the guaranteed, always-available host path.
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

function execTailscale(binary: string, argv: string[], timeoutMs: number): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      argv,
      { windowsHide: true, timeout: timeoutMs, maxBuffer: MAX_BUFFER, killSignal: "SIGKILL", encoding: "utf8" },
      (err, stdout, stderr) => {
        const out = { stdout: stdout ?? "", stderr: stderr ?? "" };
        if (err) {
          const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: string };
          if (e.code === "ENOENT") {
            reject(classifyCliFailure({ spawnCode: "ENOENT", binaryPath: binary }));
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

export class CliHostBackend implements HostBackend {
  private readonly binary: string;
  private readonly t: Timeouts;

  constructor(binary: string, timeouts: Partial<Timeouts> = {}) {
    this.binary = binary;
    this.t = { ...DEFAULT_TIMEOUTS, ...timeouts };
  }

  private async run(subcommand: string, spec: ArgvSpec, timeoutMs: number): Promise<CliResult> {
    const argv = buildArgv(subcommand, spec);
    logger.debug("exec tailscale", { argv });
    return execTailscale(this.binary, argv, timeoutMs);
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
