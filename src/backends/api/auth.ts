/**
 * REST auth. Two credential types, both presented as `Authorization: Bearer <token>`:
 *   - Static API access token (tskey-api-…) — used directly.
 *   - OAuth client-credentials — mint a 1-hour token from client_id/client_secret,
 *     cache it, refresh ~60s before expiry, dedupe concurrent refreshes, evict on 401.
 */
import { logger } from "../../logger.js";
import { registerSecret } from "../../util/redact.js";

export interface TokenProvider {
  getToken(): Promise<string>;
  /** Drop a cached token (e.g. after a 401) so the next call re-mints. */
  invalidate(token?: string): void;
  describe(): string;
}

export class StaticApiKeyProvider implements TokenProvider {
  private readonly apiKey: string;
  constructor(apiKey: string) {
    this.apiKey = apiKey;
    registerSecret(apiKey);
  }
  async getToken(): Promise<string> {
    return this.apiKey;
  }
  invalidate(): void {
    /* static: nothing to evict */
  }
  describe(): string {
    return "api_key";
  }
}

export class OAuthClientCredentialsProvider implements TokenProvider {
  private readonly tokenUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private cached?: { token: string; expiresAt: number };
  private inflight?: Promise<string>;

  constructor(baseUrl: string, clientId: string, clientSecret: string) {
    this.tokenUrl = `${baseUrl.replace(/\/$/, "")}/api/v2/oauth/token`;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    registerSecret(clientSecret);
  }

  async getToken(): Promise<string> {
    if (this.cached && Date.now() < this.cached.expiresAt - 60_000) return this.cached.token;
    if (this.inflight) return this.inflight;
    this.inflight = this.mint().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  private async mint(): Promise<string> {
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });
    let res: Response;
    try {
      res = await fetch(this.tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body,
        redirect: "manual",
      });
    } catch (e) {
      throw new Error(`OAuth token request failed (network): ${e instanceof Error ? e.message : String(e)}`);
    }
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`OAuth token request failed (${res.status}). Check TAILSCALE_OAUTH_CLIENT_ID/SECRET and scopes.`);
    }
    let json: { access_token?: string; expires_in?: number };
    try {
      json = JSON.parse(text) as { access_token?: string; expires_in?: number };
    } catch {
      throw new Error("OAuth token response was not valid JSON.");
    }
    if (!json.access_token) throw new Error("OAuth token response missing access_token.");
    registerSecret(json.access_token);
    const ttlMs = (json.expires_in ?? 3600) * 1000;
    this.cached = { token: json.access_token, expiresAt: Date.now() + ttlMs };
    logger.info("minted OAuth access token", { expiresInSec: json.expires_in ?? 3600 });
    return json.access_token;
  }

  invalidate(token?: string): void {
    if (!token || this.cached?.token === token) this.cached = undefined;
  }

  describe(): string {
    return "oauth_client_credentials";
  }
}
