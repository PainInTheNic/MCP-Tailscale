/**
 * Tailscale REST client (native fetch). Security/robustness:
 *   - Authorization attached ONLY when the request host equals the configured base
 *     host; `redirect: "manual"` and any 3xx is refused (no auth leak on redirect).
 *   - 429 honored via Retry-After with exponential backoff + jitter, bounded by a
 *     per-request wall-clock budget.
 *   - One 401 retry after evicting the cached token.
 *   - Errors surface the JSON {message}.
 */
import { logger } from "../../logger.js";
import type { TokenProvider } from "./auth.js";

export class ApiError extends Error {
  readonly status: number;
  readonly body?: string;
  constructor(status: number, message: string, body?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
  toText(): string {
    const hint =
      this.status === 401
        ? " — check credentials (env in the Claude config block, not a shell profile)."
        : this.status === 403
          ? " — the credential's scopes/role are insufficient for this operation."
          : this.status === 412
            ? " — the policy changed since you read it (ETag mismatch); re-read and retry."
            : this.status === 429
              ? " — rate limited; retry later."
              : "";
    return `Tailscale API error ${this.status}: ${this.message}${hint}`;
  }
}

export interface ApiResponse<T> {
  data: T;
  etag?: string;
  status: number;
}

type Method = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function retryAfterMs(res: Response): number | undefined {
  const h = res.headers.get("retry-after");
  if (!h) return undefined;
  const secs = Number(h);
  return Number.isFinite(secs) ? secs * 1000 : undefined;
}

function backoffMs(attempt: number): number {
  const base = Math.min(30_000, 500 * 2 ** (attempt - 1));
  return base / 2 + Math.floor(Math.random() * (base / 2)); // jitter
}

function extractMessage(text: string): string | undefined {
  try {
    const j = JSON.parse(text) as { message?: string };
    return typeof j.message === "string" ? j.message : undefined;
  } catch {
    return undefined;
  }
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  /** Send as application/hujson instead of JSON (ACL policy). */
  hujson?: boolean;
  ifMatch?: string;
  accept?: string;
  timeoutMs?: number;
  /** "json" (default) or "text" (ACL raw HuJSON). */
  parse?: "json" | "text";
}

export class TailscaleApiClient {
  private readonly base: URL;
  private readonly allowedHost: string;
  private readonly tokens: TokenProvider;
  private readonly tailnet: string;

  constructor(baseUrl: string, tokens: TokenProvider, tailnet: string) {
    this.base = new URL(baseUrl);
    this.allowedHost = this.base.host;
    this.tokens = tokens;
    this.tailnet = tailnet;
  }

  describeAuth(): string {
    return this.tokens.describe();
  }

  /** Tailnet-scoped path: /api/v2/tailnet/{tailnet}{suffix}. */
  tnet(suffix: string): string {
    return `/api/v2/tailnet/${encodeURIComponent(this.tailnet)}${suffix}`;
  }

  async request<T = unknown>(method: Method, path: string, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    const url = new URL(this.base.toString());
    url.pathname = path.startsWith("/") ? path : `/${path}`;
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined) url.searchParams.set(k, String(v));
      }
    }

    const budgetMs = opts.timeoutMs ?? 30_000;
    const deadline = Date.now() + budgetMs;
    let attempt = 0;

    for (;;) {
      attempt++;
      const token = await this.tokens.getToken();
      const headers: Record<string, string> = { Accept: opts.accept ?? "application/json" };
      // Base-host pin: never attach the bearer to any host but the configured base.
      if (url.host === this.allowedHost) headers.Authorization = `Bearer ${token}`;
      if (opts.body !== undefined) headers["Content-Type"] = opts.hujson ? "application/hujson" : "application/json";
      if (opts.ifMatch) headers["If-Match"] = opts.ifMatch;

      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), Math.max(1, deadline - Date.now()));
      let res: Response;
      try {
        res = await fetch(url, {
          method,
          headers,
          body: opts.body !== undefined ? (opts.hujson ? String(opts.body) : JSON.stringify(opts.body)) : undefined,
          redirect: "manual",
          signal: ctrl.signal,
        });
      } catch (e) {
        clearTimeout(timer);
        if (e instanceof Error && e.name === "AbortError") {
          throw new ApiError(0, `Tailscale API request timed out after ${budgetMs}ms.`);
        }
        throw new ApiError(0, `Network error calling Tailscale API: ${e instanceof Error ? e.message : String(e)}`);
      }
      clearTimeout(timer);

      if (res.status >= 300 && res.status < 400) {
        throw new ApiError(res.status, `Refusing to follow a redirect from the Tailscale API (${res.status}).`);
      }
      if (res.status === 401 && attempt === 1) {
        this.tokens.invalidate(token);
        continue;
      }
      if (res.status === 429 && Date.now() < deadline) {
        const wait = retryAfterMs(res) ?? backoffMs(attempt);
        if (Date.now() + wait < deadline) {
          logger.warn("Tailscale API 429; backing off", { waitMs: wait, attempt });
          await sleep(wait);
          continue;
        }
      }

      const etag = res.headers.get("etag") ?? undefined;
      const text = await res.text();
      if (!res.ok) {
        throw new ApiError(res.status, extractMessage(text) ?? `${res.status} ${res.statusText}`, text);
      }
      let data: unknown;
      if (opts.parse === "text") data = text;
      else {
        try {
          data = text ? JSON.parse(text) : {};
        } catch {
          data = text;
        }
      }
      return { data: data as T, etag, status: res.status };
    }
  }

  get<T = unknown>(path: string, query?: RequestOptions["query"], opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.request<T>("GET", path, { ...opts, query });
  }
  post<T = unknown>(path: string, body?: unknown, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.request<T>("POST", path, { ...opts, body });
  }
  patch<T = unknown>(path: string, body?: unknown, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.request<T>("PATCH", path, { ...opts, body });
  }
  put<T = unknown>(path: string, body?: unknown, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.request<T>("PUT", path, { ...opts, body });
  }
  del<T = unknown>(path: string, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.request<T>("DELETE", path, opts);
  }
}
