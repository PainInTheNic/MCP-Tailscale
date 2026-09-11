/** Locate the tailscale CLI binary. */
import { existsSync } from "node:fs";

const WINDOWS_DEFAULT = "C:\\Program Files\\Tailscale\\tailscale.exe";
const UNIX_DEFAULTS = ["/usr/bin/tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"];

/**
 * Resolve the binary path in priority order:
 *   1. explicit config (TAILSCALE_CLI_PATH)
 *   2. the platform default install location (verified to exist)
 *   3. bare command name, letting the OS resolve it via PATH at spawn time
 *
 * We do not hard-fail here when nothing exists on disk: a bare name may still be
 * on PATH, and if it truly is missing the executor surfaces a `cli_not_found`
 * HostError (with the searched locations) on first use.
 */
export function resolveTailscaleBinary(explicit?: string): string {
  if (explicit && existsSync(explicit)) return explicit;

  if (process.platform === "win32") {
    if (existsSync(WINDOWS_DEFAULT)) return WINDOWS_DEFAULT;
    return "tailscale.exe"; // resolved via PATH by execFile on Windows
  }

  for (const p of UNIX_DEFAULTS) {
    if (existsSync(p)) return p;
  }
  return "tailscale";
}

/** The locations we search, for inclusion in a not-found error message. */
export function searchedLocations(explicit?: string): string[] {
  const locs: string[] = [];
  if (explicit) locs.push(explicit);
  locs.push("TAILSCALE_CLI_PATH env");
  if (process.platform === "win32") locs.push(WINDOWS_DEFAULT, "PATH (tailscale.exe)");
  else locs.push(...UNIX_DEFAULTS, "PATH (tailscale)");
  return locs;
}
