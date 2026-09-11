import { test } from "node:test";
import assert from "node:assert/strict";
import { buildArgv, ArgvError } from "../src/backends/host/argv-allowlist.js";

test("bare up produces just the subcommand", () => {
  assert.deepEqual(buildArgv("up"), ["up"]);
});

test("status json + peers=false, flags after subcommand", () => {
  assert.deepEqual(buildArgv("status", { flags: { json: true, peers: "false" } }), ["status", "--json", "--peers=false"]);
});

test("value flags are single --flag=value tokens", () => {
  assert.deepEqual(buildArgv("down", { flags: { reason: "policy" } }), ["down", "--reason=policy"]);
  assert.deepEqual(buildArgv("set", { flags: { "exit-node": "100.64.0.1" } }), ["set", "--exit-node=100.64.0.1"]);
});

test("nested subcommands put the positional BEFORE flags (dns status --json)", () => {
  const argv = buildArgv("dns", { flags: { json: true }, positionals: ["status"] });
  assert.deepEqual(argv, ["dns", "status", "--json"]);
});

test("exit-node list --filter=X keeps positional first", () => {
  assert.deepEqual(buildArgv("exit-node", { flags: { filter: "US" }, positionals: ["list"] }), ["exit-node", "list", "--filter=US"]);
});

test("leaf commands keep flags before positionals (ping)", () => {
  assert.deepEqual(buildArgv("ping", { flags: { "until-direct": true }, positionals: ["host"] }), ["ping", "--until-direct", "host"]);
});

test("rejects unknown subcommand", () => {
  assert.throws(() => buildArgv("rm", { positionals: ["-rf"] }), ArgvError);
});

test("rejects a flag not on the allow-list", () => {
  assert.throws(() => buildArgv("up", { flags: { "evil-flag": "x" } }), ArgvError);
});

test("rejects flag-smuggling via a value that starts with '-'", () => {
  assert.throws(() => buildArgv("set", { flags: { hostname: "--advertise-exit-node" } }), ArgvError);
  assert.throws(() => buildArgv("up", { flags: { "login-server": "--foo" } }), ArgvError);
});

test("rejects control characters in values", () => {
  assert.throws(() => buildArgv("down", { flags: { reason: "a\nb" } }), ArgvError);
});

test("rejects a value on a boolean flag", () => {
  assert.throws(() => buildArgv("status", { flags: { json: "true" } }), ArgvError);
});

test("rejects positionals where unsupported, and dash-leading positionals", () => {
  assert.throws(() => buildArgv("status", { positionals: ["x"] }), ArgvError);
  assert.throws(() => buildArgv("ping", { positionals: ["--tsmp"] }), ArgvError);
});
