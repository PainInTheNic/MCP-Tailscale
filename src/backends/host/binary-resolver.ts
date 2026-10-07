/** Locate the tailscale CLI binary. */
import { existsSync, realpathSync } from "node:fs";
import { posix } from "node:path";

const WINDOWS_DEFAULT = "C:\\Program Files\\Tailscale\\tailscale.exe";
const UNIX_DEFAULTS = ["/usr/bin/tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"];

/**
 * macOS: the Tailscale app's own executable doubles as its CLI. When the app is
 * installed its network extension IS this machine's node, so the bundled CLI always
 * matches the daemon; a separately installed CLI (e.g. Homebrew's) talks to the same
 * daemon but warns about a version mismatch whenever the two drift. So on darwin the
 * app binary is searched FIRST.
 */
export const MACOS_APP_CLI = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";

/**
 * Any Tailscale app-bundle executable, wherever the app lives (e.g. ~/Applications). Case-
 * insensitive: macOS volumes are by default, so ".../MacOS/tailscale" runs the same binary.
 */
const MACOS_APP_CLI_RE = /\.app\/Contents\/MacOS\/Tailscale$/i;

export interface ResolveOptions {
  platform?: NodeJS.Platform;
  /** Existence check; injectable for tests. */
  exists?: (path: string) => boolean;
}

function defaultLocations(platform: NodeJS.Platform): string[] {
  if (platform === "win32") return [WINDOWS_DEFAULT];
  if (platform === "darwin") return [MACOS_APP_CLI, ...UNIX_DEFAULTS];
  return UNIX_DEFAULTS;
}

function bareName(platform: NodeJS.Platform): string {
  return platform === "win32" ? "tailscale.exe" : "tailscale";
}

/**
 * Resolve the binary path in priority order:
 *   1. explicit config (TAILSCALE_CLI_PATH)
 *   2. the platform default install locations, in order (verified to exist)
 *   3. bare command name, letting the OS resolve it via PATH at spawn time
 *
 * We do not hard-fail here when nothing exists on disk: a bare name may still be
 * on PATH, and if it truly is missing the executor surfaces a `cli_not_found`
 * HostError (with the searched locations) on first use.
 */
export function resolveTailscaleBinary(explicit?: string, opts: ResolveOptions = {}): string {
  const platform = opts.platform ?? process.platform;
  const exists = opts.exists ?? existsSync;
  if (explicit && exists(explicit)) return explicit;

  for (const p of defaultLocations(platform)) {
    if (exists(p)) return p;
  }
  return bareName(platform); // resolved via PATH by execFile
}

/** The locations we search, in order, for inclusion in a not-found error message. */
export function searchedLocations(explicit?: string, platform: NodeJS.Platform = process.platform): string[] {
  const locs: string[] = [];
  if (explicit) locs.push(`TAILSCALE_CLI_PATH=${explicit}`);
  locs.push(...defaultLocations(platform), `PATH (${bareName(platform)})`);
  return locs;
}

/**
 * True when `binary` is the macOS Tailscale app's executable (directly, through a
 * symlink, or — for a bare name — as found on `pathEnv`, the PATH the child is spawned
 * with). Spawned without a TTY — as execFile does — that executable starts the GUI app
 * instead of acting as the CLI unless TAILSCALE_BE_CLI=true is set.
 */
export function isMacAppCli(
  binary: string,
  platform: NodeJS.Platform = process.platform,
  pathEnv: string | undefined = process.env.PATH,
): boolean {
  if (platform !== "darwin") return false;
  if (MACOS_APP_CLI_RE.test(binary)) return true;
  const file = binary.includes("/") ? binary : findOnPath(binary, pathEnv);
  if (!file) return false;
  try {
    // .native is realpath(3): it follows symlinks AND returns the on-disk letter case.
    return MACOS_APP_CLI_RE.test(realpathSync.native(file));
  } catch {
    return false; // missing path: not resolvable here
  }
}

/** The first `pathEnv` entry holding `name` — the file execFile will spawn for a bare name. */
function findOnPath(name: string, pathEnv: string | undefined): string | undefined {
  for (const dir of (pathEnv ?? "").split(posix.delimiter)) {
    if (!dir) continue;
    const candidate = posix.join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}
