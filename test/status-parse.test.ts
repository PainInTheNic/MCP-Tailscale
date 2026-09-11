import { test } from "node:test";
import assert from "node:assert/strict";
import { parseStatus, daemonUnreachableStatus } from "../src/backends/host/status-parse.js";

const base = {
  Version: "1.102.4",
  TailscaleIPs: ["100.82.210.52"],
  HaveNodeKey: true,
  CurrentTailnet: { Name: "nicpierce.com" },
};

test("running + online => running (connected)", () => {
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "Running", Self: { Online: true, DNSName: "nuc.ts.net." } }));
  assert.equal(s.state, "running");
  assert.equal(s.selfOnline, true);
  assert.equal(s.dnsName, "nuc.ts.net"); // trailing dot stripped
});

test("running but not online => running_local_only", () => {
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "Running", Self: { Online: false } }));
  assert.equal(s.state, "running_local_only");
});

test("stopped => stopped, IPs still present", () => {
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "Stopped", Self: { Online: false } }));
  assert.equal(s.state, "stopped");
  assert.deepEqual(s.tailscaleIPs, ["100.82.210.52"]);
});

test("BackendState NeedsLogin => needs_login", () => {
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "NeedsLogin", Self: { Online: false } }));
  assert.equal(s.state, "needs_login");
});

test("expired key routes to needs_login even if BackendState=Stopped", () => {
  const past = "2000-01-01T00:00:00Z";
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "Stopped", Self: { Online: false, KeyExpiry: past } }));
  assert.equal(s.keyExpired, true);
  assert.equal(s.state, "needs_login");
});

test("Self.Expired flag also routes to needs_login", () => {
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "Stopped", Self: { Online: false, Expired: true } }));
  assert.equal(s.state, "needs_login");
});

test("health coerces to a string array", () => {
  const s = parseStatus(JSON.stringify({ ...base, BackendState: "Stopped", Health: ["a", "b"], Self: {} }));
  assert.deepEqual(s.health, ["a", "b"]);
});

test("daemonUnreachableStatus sentinel", () => {
  const s = daemonUnreachableStatus();
  assert.equal(s.state, "daemon_unreachable");
  assert.equal(s.selfOnline, false);
});
