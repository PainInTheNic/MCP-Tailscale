/**
 * Secret redaction. Two strategies, applied to EVERY string that could reach a
 * log or the model:
 *   1. Exact-value match of known held secrets (registered at startup) — this
 *      catches a secret in ANY encoding: form body, JSON, header, bare token.
 *   2. Pattern match for secret-shaped substrings we may not have registered.
 *
 * Used by the logger AND by the tool layer for tool text / structuredContent /
 * error envelopes — not just logs.
 */

import { randomUUID } from "node:crypto";

const REDACTED = "«redacted»";

/** Known secret VALUES to scrub verbatim wherever they appear. */
const secretValues = new Set<string>();

/**
 * Register a secret so it is scrubbed by exact-value match everywhere.
 * Short/empty values are ignored to avoid over-redacting incidental text.
 */
export function registerSecret(value: string | undefined | null): void {
  if (!value) return;
  const v = value.trim();
  if (v.length >= 6) secretValues.add(v);
}

/** For tests / teardown. */
export function _clearSecrets(): void {
  secretValues.clear();
}

const PATTERNS: Array<{ re: RegExp; replace: (m: string, ...g: string[]) => string }> = [
  // Tailscale auth keys & API access tokens: tskey-... (auth), tskey-api-...
  { re: /tskey-[A-Za-z0-9._-]+/g, replace: () => REDACTED },
  // OAuth client secrets in Tailscale form: tskey-client-... already covered; also generic secret fields
  { re: /(client_secret=)[^&\s"']+/gi, replace: (_m, p1) => `${p1}${REDACTED}` },
  { re: /("?client[_-]?secret"?\s*[:=]\s*"?)[^",\s}]+/gi, replace: (_m, p1) => `${p1}${REDACTED}` },
  { re: /("?api[_-]?key"?\s*[:=]\s*"?)[^",\s}]+/gi, replace: (_m, p1) => `${p1}${REDACTED}` },
  // Bearer tokens in an Authorization header
  { re: /(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, replace: (_m, p1) => `${p1}${REDACTED}` },
];

/** Characters a secret token is made of (the tskey pattern's class); bounds a reveal match. */
const TOKEN_CHARS = "A-Za-z0-9._-";

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Redact a string (or the JSON stringification of any value). */
export function redact(input: unknown): string {
  return redactExcept(input, []);
}

/**
 * redact(), except that each `reveal` value survives verbatim. This exists for the
 * deliberate one-time disclosures — a new auth key or webhook signing secret, which
 * the API returns exactly once and the user must capture. Held secrets are scrubbed
 * BEFORE the reveal values are shielded, so a reveal value that is (or contains) a
 * held credential still comes out redacted — this can never expose the OAuth secret,
 * API key or a minted access token.
 */
export function redactExcept(input: unknown, reveal: readonly string[]): string {
  let s = typeof input === "string" ? input : safeStringify(input);
  for (const secret of secretValues) {
    if (secret) s = s.split(secret).join(REDACTED);
  }
  // Swap reveal values for placeholders no pattern can match, then restore them. Only
  // whole tokens are shielded: a longer secret that merely starts or ends with a reveal
  // value is left for the patterns, so it cannot ride along unredacted.
  const nonce = randomUUID();
  const shields: Array<[string, string]> = [];
  reveal.forEach((value, i) => {
    if (!value) return;
    const token = `\u0000${nonce}:${i}\u0000`;
    const exact = new RegExp(`(?<![${TOKEN_CHARS}])${escapeRegExp(value)}(?![${TOKEN_CHARS}])`, "g");
    const shielded = s.replace(exact, () => token);
    if (shielded === s) return;
    s = shielded;
    shields.push([token, value]);
  });
  for (const { re, replace } of PATTERNS) {
    s = s.replace(re, replace as (substring: string, ...args: unknown[]) => string);
  }
  for (const [token, value] of shields) s = s.split(token).join(value);
  return s;
}

/**
 * Field names whose values are secrets no matter what they look like: any name ENDING in
 * client secret / api key (clientSecret, oauthClientSecret, TAILSCALE_API_KEY, x-api-key) —
 * the same names the text PATTERNS catch in `name: value` form.
 */
const SECRET_FIELD_RE = /(client[_-]?secret|api[_-]?key)$/i;

/**
 * Deep-redact a JSON-shaped value (e.g. a tool's structuredContent). Returns a NEW
 * value with the same shape and types for ordinary data — every string leaf AND every
 * key goes through redact() — so the result still satisfies the tool's outputSchema.
 * A secret-named field loses its whole value (string, number, array or object) to the
 * redaction marker. The input is not mutated.
 * A non-serializable value (cycle, BigInt) falls back to a redacted string.
 */
export function redactObject<T>(value: T): T {
  if (value === undefined) return value;
  let plain: unknown;
  try {
    plain = JSON.parse(JSON.stringify(value)); // detach from the input + normalize to JSON types
  } catch {
    return redact(value) as unknown as T;
  }
  return redactDeep(plain) as T;
}

function redactDeep(v: unknown, secretField = false): unknown {
  // null / booleans cannot carry a secret; anything else under a secret-named field goes.
  if (secretField && v !== null && typeof v !== "boolean") return REDACTED;
  if (typeof v === "string") return redact(v);
  if (Array.isArray(v)) return v.map((x) => redactDeep(x));
  if (v !== null && typeof v === "object") {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [redact(k), redactDeep(x, SECRET_FIELD_RE.test(k))]));
  }
  return v;
}

function safeStringify(x: unknown): string {
  try {
    return JSON.stringify(x) ?? String(x);
  } catch {
    return String(x);
  }
}
