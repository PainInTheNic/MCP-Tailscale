import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { redact, registerSecret, _clearSecrets } from "../src/util/redact.js";

beforeEach(() => _clearSecrets());

test("scrubs a registered secret in every encoding", () => {
  registerSecret("tskey-client-SUPERSECRETVALUE");
  const jsonForm = redact(JSON.stringify({ clientSecret: "tskey-client-SUPERSECRETVALUE" }));
  const formEnc = redact("client_secret=tskey-client-SUPERSECRETVALUE&grant_type=x");
  const header = redact("Authorization: Bearer tskey-client-SUPERSECRETVALUE");
  assert.ok(!jsonForm.includes("SUPERSECRETVALUE"));
  assert.ok(!formEnc.includes("SUPERSECRETVALUE"));
  assert.ok(!header.includes("SUPERSECRETVALUE"));
});

test("scrubs tskey-shaped tokens by pattern even if unregistered", () => {
  const out = redact("using tskey-api-abc123DEF456 now");
  assert.ok(!out.includes("abc123DEF456"));
});

test("scrubs client_secret= form field by pattern", () => {
  const out = redact("client_secret=notregistered12345&x=1");
  assert.ok(!out.includes("notregistered12345"));
});

test("does not over-redact short/empty secrets", () => {
  registerSecret("ab"); // too short, ignored
  assert.equal(redact("ab cd"), "ab cd");
});

test("leaves innocuous text untouched", () => {
  assert.equal(redact("connected as view-nuc (100.82.210.52)"), "connected as view-nuc (100.82.210.52)");
});
