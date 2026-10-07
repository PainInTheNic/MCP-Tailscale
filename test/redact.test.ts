import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { redact, redactExcept, redactObject, registerSecret, _clearSecrets } from "../src/util/redact.js";

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

test("redactExcept reveals only the named value; other secrets stay redacted", () => {
  registerSecret("tskey-client-OAUTHSECRET123");
  registerSecret("tskey-api-APIKEYSECRET456");
  const newKey = "tskey-auth-kNEW123CNTRL-REVEALME789";
  const out = redactExcept(
    JSON.stringify({
      key: newKey,
      note: "tskey-client-OAUTHSECRET123 tskey-api-APIKEYSECRET456 tskey-auth-OTHERKEY000",
      form: "client_secret=unregistered999",
    }),
    [newKey],
  );
  assert.ok(out.includes(newKey), "the one-time key must survive");
  for (const leaked of ["OAUTHSECRET123", "APIKEYSECRET456", "OTHERKEY000", "unregistered999"]) {
    assert.ok(!out.includes(leaked), `${leaked} must stay redacted`);
  }
  assert.ok(!out.includes("\u0000"), "no placeholder may leak");
});

test("redactExcept never reveals a held secret, even when asked to", () => {
  registerSecret("tskey-api-HELDSECRET111");
  assert.ok(!redactExcept("x tskey-api-HELDSECRET111 y", ["tskey-api-HELDSECRET111"]).includes("HELDSECRET111"));
  // A reveal value that merely CONTAINS a held secret is not a way around it either.
  const out = redactExcept("k=tskey-api-HELDSECRET111-suffix", ["tskey-api-HELDSECRET111-suffix"]);
  assert.ok(!out.includes("HELDSECRET111"));
});

test("redact() is unchanged by the reveal machinery", () => {
  assert.equal(redact("tskey-auth-abc123"), "«redacted»");
  assert.equal(redactExcept("tskey-auth-abc123", []), "«redacted»");
});

test("redactObject keeps shape and types, scrubs every string leaf, and does not mutate", () => {
  registerSecret("held-secret-value-xyz");
  const input = {
    state: "running",
    connected: true,
    count: 3,
    nothing: null,
    health: ["ok", "leaked tskey-auth-LEAK123 here", "held-secret-value-xyz"],
    nested: { clientSecret: "plain-looking-but-secret-field", apiKey: "another", deeper: [{ t: "tskey-api-DEEP" }] },
  };
  const before = JSON.stringify(input);
  const out = redactObject(input);
  assert.equal(JSON.stringify(input), before, "input must not be mutated");
  assert.equal(out.state, "running");
  assert.equal(out.connected, true);
  assert.equal(out.count, 3);
  assert.equal(out.nothing, null);
  assert.equal(out.health.length, 3);
  assert.equal(out.health[0], "ok");
  assert.ok(!out.health[1]!.includes("LEAK123"));
  assert.equal(out.health[2], "«redacted»");
  assert.equal(out.nested.clientSecret, "«redacted»");
  assert.equal(out.nested.apiKey, "«redacted»");
  assert.ok(!JSON.stringify(out).includes("DEEP"));
});

test("redactObject survives strings that would corrupt a JSON-text round-trip", () => {
  // A pattern match inside an escaped quote used to break JSON.parse and turn the object into a string.
  const out = redactObject({ msg: 'api_key="abc"', n: 1 });
  assert.equal(typeof out, "object");
  assert.equal(out.n, 1);
  assert.ok(!out.msg.includes("abc"));
});

test("redactExcept shields the exact token only, not a longer secret that starts or ends with it", () => {
  const key = "tskey-auth-kABC-123";
  const out = redactExcept(
    JSON.stringify({ key, longer: `${key}XYZsecretTail`, prefixed: `tskey-api-${key}` }),
    [key],
  );
  assert.equal(JSON.parse(out).key, key, "the exact value is still revealed");
  assert.ok(!out.includes("XYZsecretTail"), "a token extending the reveal value must be redacted");
  assert.equal(JSON.parse(out).prefixed, "«redacted»");
});

test("redactObject scrubs keys, any field ending in client secret / api key, and non-string secret values", () => {
  registerSecret("HELDSECRET123");
  const out = redactObject({
    "tskey-auth-kXYZ-abcdef": true,
    nested: { HELDSECRET123: 1 },
    oauthClientSecret: "plainsecretvalue",
    TAILSCALE_API_KEY: "plainapikeyvalue",
    "x-api-key": "plainheadervalue",
    apiKey: 12345678,
    client_secret: ["arr-secret"],
    clientSecret: { v: "obj-secret" },
    unsetApiKey: null,
    apiKeyId: "not-a-secret-id",
  }) as Record<string, unknown>;
  const json = JSON.stringify(out);
  for (const leaked of ["kXYZ", "HELDSECRET123", "plainsecretvalue", "plainapikeyvalue", "plainheadervalue", "12345678", "arr-secret", "obj-secret"]) {
    assert.ok(!json.includes(leaked), `${leaked} must be redacted`);
  }
  assert.equal(out.oauthClientSecret, "«redacted»");
  assert.equal(out.apiKey, "«redacted»");
  assert.equal(out.client_secret, "«redacted»");
  assert.equal(out.unsetApiKey, null, "null carries no secret and keeps its type");
  assert.equal(out.apiKeyId, "not-a-secret-id", "a name that merely contains api key is not over-redacted");
});
