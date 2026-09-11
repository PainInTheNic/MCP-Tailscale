/**
 * Environment configuration, parsed and validated once at startup.
 *
 * Design rule: the server must START even with no REST credentials — host/CLI
 * tools stay fully functional and API tools return a setup error. Only a
 * genuinely broken config (a half-configured OAuth pair, a non-https base URL)
 * is fatal, so the Claude host never enters a restart loop.
 */
import { z } from "zod";
import { registerSecret } from "./util/redact.js";

export type RiskLevel = "read" | "write" | "admin";

const RiskLevelSchema = z.enum(["read", "write", "admin"]);

const ConfigSchema = z
  .object({
    // Host / CLI
    cliPath: z.string().min(1).optional(),
    riskLevel: RiskLevelSchema.default("write"),
    localApi: z.boolean().default(false),
    authKeyFile: z.string().min(1).optional(),

    // REST (used by P2 tools; optional so the server still starts without them)
    oauthClientId: z.string().min(1).optional(),
    oauthClientSecret: z.string().min(1).optional(),
    apiKey: z.string().min(1).optional(),
    tailnet: z.string().min(1).default("-"),
    apiBaseUrl: z.string().url().default("https://api.tailscale.com"),
  })
  .strict()
  .superRefine((v, ctx) => {
    const hasId = Boolean(v.oauthClientId);
    const hasSecret = Boolean(v.oauthClientSecret);
    if (hasId !== hasSecret) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET must be set together (or both omitted).",
      });
    }
    // Authorization must never travel in cleartext: https only, except loopback.
    try {
      const u = new URL(v.apiBaseUrl);
      const isLoopback =
        u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "::1";
      if (u.protocol !== "https:" && !isLoopback) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["apiBaseUrl"],
          message: "TAILSCALE_API_BASE_URL must use https (except for loopback).",
        });
      }
    } catch {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["apiBaseUrl"], message: "Invalid URL." });
    }
  });

export type Config = z.infer<typeof ConfigSchema>;

function bool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  return v === "1" || v.toLowerCase() === "true" || v.toLowerCase() === "yes";
}

function trimmed(v: string | undefined): string | undefined {
  if (v === undefined) return undefined;
  const t = v.trim();
  return t.length ? t : undefined;
}

/** Parse and validate config from an env map (defaults to process.env). Throws on fatal misconfig. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const raw = {
    cliPath: trimmed(env.TAILSCALE_CLI_PATH),
    riskLevel: trimmed(env.TAILSCALE_RISK_LEVEL)?.toLowerCase(),
    localApi: bool(env.TS_LOCAL_API),
    authKeyFile: trimmed(env.TAILSCALE_AUTH_KEY_FILE),
    oauthClientId: trimmed(env.TAILSCALE_OAUTH_CLIENT_ID),
    oauthClientSecret: trimmed(env.TAILSCALE_OAUTH_CLIENT_SECRET),
    apiKey: trimmed(env.TAILSCALE_API_KEY),
    tailnet: trimmed(env.TAILSCALE_TAILNET),
    apiBaseUrl: trimmed(env.TAILSCALE_API_BASE_URL),
  };
  // Drop undefined keys so zod defaults apply.
  const cleaned = Object.fromEntries(Object.entries(raw).filter(([, v]) => v !== undefined));
  const cfg = ConfigSchema.parse(cleaned);

  // Register secrets so redact() scrubs them everywhere, in every encoding.
  registerSecret(cfg.oauthClientSecret);
  registerSecret(cfg.apiKey);

  return cfg;
}

/** True if REST credentials are present (either OAuth pair or a static API key). */
export function hasApiCredentials(cfg: Config): boolean {
  return Boolean((cfg.oauthClientId && cfg.oauthClientSecret) || cfg.apiKey);
}
