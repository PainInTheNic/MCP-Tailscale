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

/** Redact a string (or the JSON stringification of any value). */
export function redact(input: unknown): string {
  let s = typeof input === "string" ? input : safeStringify(input);
  for (const secret of secretValues) {
    if (secret) s = s.split(secret).join(REDACTED);
  }
  for (const { re, replace } of PATTERNS) {
    s = s.replace(re, replace as (substring: string, ...args: unknown[]) => string);
  }
  return s;
}

/**
 * Deep-redact an object by round-tripping through redact() on its JSON form.
 * Returns a NEW object; the input is not mutated. Non-serializable values fall
 * back to a redacted string.
 */
export function redactObject<T>(value: T): T {
  try {
    return JSON.parse(redact(JSON.stringify(value))) as T;
  } catch {
    return redact(value) as unknown as T;
  }
}

function safeStringify(x: unknown): string {
  try {
    return JSON.stringify(x);
  } catch {
    return String(x);
  }
}
