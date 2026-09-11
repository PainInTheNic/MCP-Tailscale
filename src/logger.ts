/**
 * stderr-only logger. The GOLDEN RULE for a stdio MCP server: never write to
 * stdout (that is the JSON-RPC channel). Every line is passed through redact().
 */
import { redact } from "./util/redact.js";

type Level = "debug" | "info" | "warn" | "error";

const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function threshold(): number {
  const raw = (process.env.TAILSCALE_LOG_LEVEL ?? "info").toLowerCase() as Level;
  return ORDER[raw] ?? ORDER.info;
}

function emit(level: Level, msg: string, meta?: unknown): void {
  if (ORDER[level] < threshold()) return;
  const suffix = meta === undefined ? "" : " " + safe(meta);
  const line = `${new Date().toISOString()} [${level}] ${msg}${suffix}`;
  process.stderr.write(redact(line) + "\n");
}

function safe(x: unknown): string {
  try {
    return typeof x === "string" ? x : JSON.stringify(x);
  } catch {
    return String(x);
  }
}

export const logger = {
  debug: (msg: string, meta?: unknown) => emit("debug", msg, meta),
  info: (msg: string, meta?: unknown) => emit("info", msg, meta),
  warn: (msg: string, meta?: unknown) => emit("warn", msg, meta),
  error: (msg: string, meta?: unknown) => emit("error", msg, meta),
};
