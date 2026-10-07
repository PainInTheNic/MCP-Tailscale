import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MACOS_APP_CLI,
  isMacAppCli,
  resolveTailscaleBinary,
  searchedLocations,
} from "../src/backends/host/binary-resolver.js";
import { buildChildEnv, CliHostBackend } from "../src/backends/host/cli-executor.js";
import { classifyCliFailure, HostError } from "../src/util/errors.js";

const HOMEBREW = "/opt/homebrew/bin/tailscale";
const existing = (...paths: string[]) => (p: string) => paths.includes(p);

// ---- search order -----------------------------------------------------------------
test("darwin: the Tailscale app's bundled CLI wins over a Homebrew CLI", () => {
  assert.equal(resolveTailscaleBinary(undefined, { platform: "darwin", exists: existing(MACOS_APP_CLI, HOMEBREW) }), MACOS_APP_CLI);
});

test("darwin: falls back to Homebrew, then to PATH", () => {
  assert.equal(resolveTailscaleBinary(undefined, { platform: "darwin", exists: existing(HOMEBREW) }), HOMEBREW);
  assert.equal(resolveTailscaleBinary(undefined, { platform: "darwin", exists: existing() }), "tailscale");
});

test("explicit TAILSCALE_CLI_PATH wins when it exists", () => {
  const exists = existing("/custom/tailscale", MACOS_APP_CLI);
  assert.equal(resolveTailscaleBinary("/custom/tailscale", { platform: "darwin", exists }), "/custom/tailscale");
});

test("non-darwin platforms never pick the macOS app path", () => {
  const exists = existing(MACOS_APP_CLI, "/usr/bin/tailscale");
  assert.equal(resolveTailscaleBinary(undefined, { platform: "linux", exists }), "/usr/bin/tailscale");
  assert.equal(resolveTailscaleBinary(undefined, { platform: "win32", exists: existing() }), "tailscale.exe");
});

test("searchedLocations lists what was actually searched, in order, per platform", () => {
  const mac = searchedLocations("/nope/tailscale", "darwin");
  assert.equal(mac[0], "TAILSCALE_CLI_PATH=/nope/tailscale");
  assert.equal(mac[1], MACOS_APP_CLI);
  assert.ok(mac.includes(HOMEBREW));
  assert.equal(mac.at(-1), "PATH (tailscale)");
  assert.ok(!mac.join(" ").includes("tailscale.exe"));
  assert.ok(!searchedLocations(undefined, "linux").includes(MACOS_APP_CLI));
  assert.ok(searchedLocations(undefined, "win32").join(" ").includes("tailscale.exe"));
});

// ---- macOS app detection + child env -----------------------------------------------
let tmp: string;
let fakeAppCli: string;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), "ts-mcp-test-"));
  const macos = join(tmp, "Tailscale.app", "Contents", "MacOS");
  mkdirSync(macos, { recursive: true });
  fakeAppCli = join(macos, "Tailscale");
  // Stand-in for the app binary: prints its environment, whatever the argv.
  writeFileSync(fakeAppCli, "#!/bin/sh\nenv\n");
  chmodSync(fakeAppCli, 0o755);
});

after(() => rmSync(tmp, { recursive: true, force: true }));

test("isMacAppCli: app-bundle executable (anywhere, or via symlink) on darwin only", { skip: process.platform === "win32" }, () => {
  assert.ok(isMacAppCli(MACOS_APP_CLI, "darwin"));
  assert.ok(isMacAppCli("/Users/me/Applications/Tailscale.app/Contents/MacOS/Tailscale", "darwin"));
  assert.ok(!isMacAppCli(MACOS_APP_CLI, "linux"));
  assert.ok(!isMacAppCli(HOMEBREW, "darwin"));
  assert.ok(!isMacAppCli("tailscale", "darwin", ""), "a bare name that is not on PATH");
  const link = join(tmp, "tailscale");
  symlinkSync(fakeAppCli, link);
  assert.ok(isMacAppCli(link, "darwin"), "a `tailscale` symlink to the app binary still needs TAILSCALE_BE_CLI");
});

test("isMacAppCli: any letter case of the app path (macOS volumes are case-insensitive)", () => {
  assert.ok(isMacAppCli("/Applications/Tailscale.app/Contents/MacOS/tailscale", "darwin"));
  assert.ok(isMacAppCli("/applications/tailscale.app/contents/macos/tailscale", "darwin"));
  const env = buildChildEnv("/Applications/Tailscale.app/Contents/MacOS/tailscale", {}, "darwin");
  assert.equal(env.TAILSCALE_BE_CLI, "true", "TAILSCALE_CLI_PATH in lowercase still gets TAILSCALE_BE_CLI");
});

test("isMacAppCli: a bare name is looked up on the child's PATH", { skip: process.platform === "win32" }, () => {
  const bin = join(tmp, "path-bin");
  const elsewhere = join(tmp, "path-empty");
  mkdirSync(bin);
  mkdirSync(elsewhere);
  symlinkSync(fakeAppCli, join(bin, "tailscale"));
  assert.ok(isMacAppCli("tailscale", "darwin", `${elsewhere}:${bin}`));
  assert.ok(!isMacAppCli("tailscale", "darwin", elsewhere));
  assert.ok(!isMacAppCli("tailscale", "linux", bin));
  // buildChildEnv searches the PATH the child will be spawned with.
  assert.equal(buildChildEnv("tailscale", { PATH: bin }, "darwin").TAILSCALE_BE_CLI, "true");
  assert.equal(buildChildEnv("tailscale", { PATH: elsewhere }, "darwin").TAILSCALE_BE_CLI, undefined);
});

test("buildChildEnv sets TAILSCALE_BE_CLI for the app binary only, and strips REST credentials", () => {
  const parent = {
    PATH: "/usr/bin",
    HOME: "/Users/me",
    TAILSCALE_OAUTH_CLIENT_ID: "id",
    TAILSCALE_OAUTH_CLIENT_SECRET: "tskey-client-SECRET",
    tailscale_api_key: "tskey-api-SECRET", // any casing
    TAILSCALE_AUTH_KEY_FILE: "/keys/authkey",
  };
  const app = buildChildEnv(MACOS_APP_CLI, parent, "darwin");
  assert.equal(app.TAILSCALE_BE_CLI, "true");
  assert.equal(app.PATH, "/usr/bin");
  assert.equal(app.HOME, "/Users/me");
  assert.equal(app.TAILSCALE_AUTH_KEY_FILE, "/keys/authkey");
  for (const k of ["TAILSCALE_OAUTH_CLIENT_ID", "TAILSCALE_OAUTH_CLIENT_SECRET", "tailscale_api_key"]) {
    assert.ok(!(k in app), `${k} must not reach the CLI`);
  }

  const brew = buildChildEnv(HOMEBREW, parent, "darwin");
  assert.equal(brew.TAILSCALE_BE_CLI, undefined);
  assert.ok(!("TAILSCALE_OAUTH_CLIENT_SECRET" in brew));

  // A user-supplied TAILSCALE_BE_CLI (e.g. for a wrapper script) still passes through.
  assert.equal(buildChildEnv(HOMEBREW, { ...parent, TAILSCALE_BE_CLI: "1" }, "darwin").TAILSCALE_BE_CLI, "1");
  assert.equal(parent.TAILSCALE_OAUTH_CLIENT_SECRET, "tskey-client-SECRET", "parent env is not mutated");
});

test("the spawned CLI really gets the sanitized env", { skip: process.platform === "win32" }, async () => {
  const saved = { key: process.env.TAILSCALE_API_KEY, secret: process.env.TAILSCALE_OAUTH_CLIENT_SECRET };
  process.env.TAILSCALE_API_KEY = "tskey-api-SHOULDNOTLEAK";
  process.env.TAILSCALE_OAUTH_CLIENT_SECRET = "tskey-client-SHOULDNOTLEAK";
  try {
    const backend = new CliHostBackend(fakeAppCli);
    const res = await backend.exec("version", { flags: { json: true } });
    assert.equal(res.code, 0);
    assert.doesNotMatch(res.stdout, /SHOULDNOTLEAK/);
    assert.doesNotMatch(res.stdout, /^TAILSCALE_API_KEY=/m);
    if (process.platform === "darwin") assert.match(res.stdout, /^TAILSCALE_BE_CLI=true$/m);
  } finally {
    if (saved.key === undefined) delete process.env.TAILSCALE_API_KEY;
    else process.env.TAILSCALE_API_KEY = saved.key;
    if (saved.secret === undefined) delete process.env.TAILSCALE_OAUTH_CLIENT_SECRET;
    else process.env.TAILSCALE_OAUTH_CLIENT_SECRET = saved.secret;
  }
});

// ---- cli_not_found -----------------------------------------------------------------
test("cli_not_found names the searched locations and no tailscale.exe outside Windows", () => {
  const searched = searchedLocations(undefined, "darwin");
  const err = classifyCliFailure({ spawnCode: "ENOENT", binaryPath: "tailscale", searched, platform: "darwin" });
  assert.equal(err.code, "cli_not_found");
  assert.ok(err.toText().includes(MACOS_APP_CLI));
  assert.ok(err.toText().includes(HOMEBREW));
  assert.doesNotMatch(err.toText(), /tailscale\.exe/);
  assert.doesNotMatch(classifyCliFailure({ spawnCode: "ENOENT", binaryPath: "tailscale", platform: "linux" }).remedy, /\.exe/);
  assert.match(classifyCliFailure({ spawnCode: "ENOENT", binaryPath: "x", platform: "win32" }).remedy, /tailscale\.exe/);
});

test("a missing binary surfaces cli_not_found with the searched list end to end", async () => {
  const missing = join(tmp, "does-not-exist", "tailscale");
  const backend = new CliHostBackend(missing, { searched: [`TAILSCALE_CLI_PATH=${missing}`, "PATH (tailscale)"] });
  await assert.rejects(backend.exec("version"), (e: unknown) => {
    assert.ok(e instanceof HostError);
    assert.equal(e.code, "cli_not_found");
    assert.ok(e.message.includes(`TAILSCALE_CLI_PATH=${missing}`));
    return true;
  });
});
