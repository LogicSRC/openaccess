/**
 * Two clients.
 *
 * OpenAccessApp is what an app holds: it sends a person to the hub, exchanges
 * the code, verifies tokens offline against the hub's keys, verifies webhook
 * signatures, and, with its own key, reports sales and checks standing.
 *
 * OpenAccessClient is what a person or agent holds: a token for the hub
 * itself, and the REST calls about what they hold.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { fromPrivateJwk, sha256url, signJwt, verifyBody, verifyJwt, type SigningKey } from "./jwt.ts";
import type { AccessClaims, AppRecord, Entitlement, Grant, HubDescriptor, Jwk, Limits, Principal } from "./spec.ts";
import type { ProbeJob } from "./db.ts";

export { verifyBody as verifyWebhookSignature, verifyJwt } from "./jwt.ts";

export type Fetcher = typeof fetch;

export class OpenAccessError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export interface Tokens {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
  grant: string;
  sub: string;
}

/** The hub's metadata and keys, fetched once and kept. */
export class HubInfo {
  readonly url: string;
  private readonly fetcher: Fetcher;
  private descriptor: HubDescriptor | null = null;
  private keys: { keys: Jwk[]; at: number } | null = null;

  constructor(url: string, fetcher: Fetcher = fetch) {
    this.url = url.replace(/\/+$/, "");
    this.fetcher = fetcher;
  }

  async metadata(): Promise<HubDescriptor> {
    if (this.descriptor) return this.descriptor;
    const response = await this.fetcher(`${this.url}/.well-known/openaccess.json`, { headers: { accept: "application/json" } });
    if (!response.ok) throw new OpenAccessError("no_hub", `${this.url} answered ${response.status} for its descriptor.`, 502);
    this.descriptor = (await response.json()) as HubDescriptor;
    return this.descriptor;
  }

  async jwks(maxAgeMs = 10 * 60_000): Promise<Jwk[]> {
    if (this.keys && Date.now() - this.keys.at < maxAgeMs) return this.keys.keys;
    const meta = await this.metadata();
    const response = await this.fetcher(meta.jwks_uri, { headers: { accept: "application/json" } });
    if (!response.ok) throw new OpenAccessError("no_jwks", `${meta.jwks_uri} answered ${response.status}.`, 502);
    const body = (await response.json()) as { keys: Jwk[] };
    this.keys = { keys: body.keys, at: Date.now() };
    return body.keys;
  }
}

export interface AppOptions {
  hub: string;
  /** The app's id at the hub: its host. */
  clientId: string;
  redirectUri?: string;
  /** The private JWK matching one in the app's descriptor, for calling the hub as itself. */
  key?: Jwk;
  fetch?: Fetcher;
}

export const pkce = (): { verifier: string; challenge: string } => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: sha256url(verifier) };
};

async function tokenCall(fetcher: Fetcher, endpoint: string, form: Record<string, string>): Promise<Tokens> {
  const response = await fetcher(endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: new URLSearchParams(form).toString() });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) throw new OpenAccessError(String(body.error ?? "token_error"), String(body.error_description ?? `token endpoint answered ${response.status}`), response.status);
  return body as unknown as Tokens;
}

export class OpenAccessApp {
  readonly info: HubInfo;
  readonly clientId: string;
  readonly redirectUri: string | undefined;
  private readonly key: SigningKey | null;
  private readonly fetcher: Fetcher;

  constructor(options: AppOptions) {
    this.fetcher = options.fetch ?? fetch;
    this.info = new HubInfo(options.hub, this.fetcher);
    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.key = options.key ? fromPrivateJwk(options.key) : null;
  }

  /** Where to send the person. Keep the verifier and state for the exchange. */
  async authorizeUrl(input: { scope: string; state?: string; redirectUri?: string }): Promise<{ url: string; verifier: string; state: string }> {
    const meta = await this.info.metadata();
    const { verifier, challenge } = pkce();
    const state = input.state ?? randomBytes(16).toString("base64url");
    const redirect = input.redirectUri ?? this.redirectUri;
    if (!redirect) throw new OpenAccessError("no_redirect", "A redirectUri is needed.");
    const url = new URL(meta.authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", redirect);
    url.searchParams.set("scope", input.scope);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    return { url: url.toString(), verifier, state };
  }

  async exchange(code: string, verifier: string, redirectUri?: string): Promise<Tokens> {
    const meta = await this.info.metadata();
    const redirect = redirectUri ?? this.redirectUri;
    if (!redirect) throw new OpenAccessError("no_redirect", "A redirectUri is needed.");
    return tokenCall(this.fetcher, meta.token_endpoint, { grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: redirect, client_id: this.clientId, ...(await this.assertionFields()) });
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    const meta = await this.info.metadata();
    return tokenCall(this.fetcher, meta.token_endpoint, { grant_type: "refresh_token", refresh_token: refreshToken, client_id: this.clientId, ...(await this.assertionFields()) });
  }

  /** Start the device flow: show user_code and verification_uri to the person, then poll. */
  async device(scope: string): Promise<{ device_code: string; user_code: string; verification_uri: string; verification_uri_complete: string; expires_in: number; interval: number }> {
    const meta = await this.info.metadata();
    const response = await this.fetcher(meta.device_authorization_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: new URLSearchParams({ client_id: this.clientId, scope }).toString() });
    const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) throw new OpenAccessError(String(body.error ?? "device_error"), String(body.error_description ?? `answered ${response.status}`), response.status);
    return body as never;
  }

  /** Poll until the person decides. Resolves with tokens, or throws access_denied / expired_token. */
  async pollDevice(deviceCode: string, intervalSec = 5, sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms))): Promise<Tokens> {
    const meta = await this.info.metadata();
    let wait = intervalSec;
    for (;;) {
      try {
        return await tokenCall(this.fetcher, meta.token_endpoint, { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: deviceCode, client_id: this.clientId });
      } catch (error) {
        const code = (error as OpenAccessError).code;
        if (code === "slow_down") wait += 5;
        else if (code !== "authorization_pending") throw error;
      }
      await sleep(wait * 1000);
    }
  }

  /** Verify one of the hub's access tokens offline. Checks the signature, the issuer and that it is for this app. */
  async verify(accessToken: string): Promise<AccessClaims> {
    const outcome = verifyJwt(accessToken, await this.info.jwks());
    if ("error" in outcome) throw new OpenAccessError("invalid_token", outcome.error, 401);
    const claims = outcome.claims as AccessClaims;
    if (claims.iss !== this.info.url) throw new OpenAccessError("invalid_token", `issued by ${claims.iss}, not ${this.info.url}`, 401);
    if (claims.aud !== this.clientId) throw new OpenAccessError("invalid_token", `for ${claims.aud}, not ${this.clientId}`, 401);
    return claims;
  }

  /** Verify a webhook delivery over its raw body, against the hub's keys. */
  async verifyWebhook(rawBody: string, signatureHeader: string | null | undefined): Promise<boolean> {
    return verifyBody(rawBody, signatureHeader, await this.info.jwks());
  }

  /** A client assertion (RFC 7523): this app, signed with its key, for the hub. */
  assertion(ttlSec = 300): string {
    if (!this.key) throw new OpenAccessError("no_key", "This app has no key; it cannot call the hub as itself.");
    const now = Math.floor(Date.now() / 1000);
    return signJwt({ iss: this.clientId, sub: this.clientId, aud: this.info.url, iat: now, exp: now + ttlSec, jti: randomUUID() }, this.key);
  }

  private async assertionFields(): Promise<Record<string, string>> {
    return this.key ? { client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: this.assertion() } : {};
  }

  /** Report a principal's standing with one of this app's own products. */
  async report(input: { sub: string; product: string; status: Entitlement["status"]; period?: { start?: string; end?: string }; receipt?: string }): Promise<{ entitlement: Entitlement; event: string | null; honouredBy: string[] }> {
    const response = await this.fetcher(`${this.info.url}/v1/entitlements`, { method: "POST", headers: { authorization: `Bearer ${this.assertion()}`, "content-type": "application/json" }, body: JSON.stringify(input) });
    const body = (await response.json()) as { ok: boolean; error?: string; message?: string; entitlement: Entitlement; event: string | null; honouredBy: string[] };
    if (!body.ok) throw new OpenAccessError(body.error ?? "report_failed", body.message ?? `answered ${response.status}`, response.status);
    return body;
  }

  /** Does a principal hold a product, as the hub sees it now. */
  async check(sub: string, product: string): Promise<{ held: boolean; status: string | null; entitlement: Entitlement | null }> {
    const response = await this.fetcher(`${this.info.url}/v1/check?product=${encodeURIComponent(product)}&sub=${encodeURIComponent(sub)}`, { headers: { authorization: `Bearer ${this.assertion()}` } });
    const body = (await response.json()) as { ok: boolean; error?: string; message?: string; held: boolean; status: string | null; entitlement: Entitlement | null };
    if (!body.ok) throw new OpenAccessError(body.error ?? "check_failed", body.message ?? `answered ${response.status}`, response.status);
    return body;
  }
}

export interface ClientOptions {
  hub: string;
  /** A bearer token from the hub, for the calls about the holder. */
  token?: string;
  /** The hub's admin token, for removing apps. */
  adminToken?: string;
  fetch?: Fetcher;
}

/** A person's or agent's view of the hub, over REST. */
export class OpenAccessClient {
  readonly url: string;
  private readonly token: string | undefined;
  private readonly adminToken: string | undefined;
  private readonly fetcher: Fetcher;

  constructor(options: ClientOptions) {
    this.url = options.hub.replace(/\/+$/, "");
    this.token = options.token;
    this.adminToken = options.adminToken;
    this.fetcher = options.fetch ?? fetch;
  }

  private async call<T>(method: string, path: string, body?: unknown, admin = false): Promise<T> {
    const token = admin ? this.adminToken : this.token;
    const response = await this.fetcher(`${this.url}${path}`, { method, headers: { accept: "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    const payload = (await response.json().catch(() => ({}))) as { ok?: boolean; error?: string; message?: string };
    if (!response.ok || payload.ok === false) throw new OpenAccessError(payload.error ?? "request_failed", payload.message ?? `${method} ${path} answered ${response.status}`, response.status);
    return payload as T;
  }

  me(): Promise<{ principal: Principal; links: Array<{ app: string; name: string; url: string | null; grant: Grant | null }>; grants: Grant[]; entitlements: Array<Entitlement & { links: Record<string, string>; honouredBy: string[] }> }> {
    return this.call("GET", "/v1/me");
  }
  grants(options: { app?: string; all?: boolean } = {}): Promise<{ grants: Grant[] }> {
    return this.call("GET", `/v1/grants?${new URLSearchParams({ ...(options.app ? { app: options.app } : {}), ...(options.all ? { all: "1" } : {}) })}`);
  }
  grant(id: string): Promise<{ grant: Grant; children: Grant[] }> {
    return this.call("GET", `/v1/grants/${encodeURIComponent(id)}`);
  }
  delegate(input: { grant?: string; for?: string; scope: string; limits?: Limits; expires_in?: number }): Promise<{ grant: Grant; refresh_token: string; token_endpoint: string; client_id: string }> {
    return this.call("POST", "/v1/grants", input);
  }
  revoke(id: string): Promise<{ revoked: Grant[] }> {
    return this.call("DELETE", `/v1/grants/${encodeURIComponent(id)}`);
  }
  unlink(app: string): Promise<{ ok: true }> {
    return this.call("DELETE", `/v1/links/${encodeURIComponent(app)}`);
  }
  entitlements(): Promise<{ entitlements: Array<Entitlement & { links: Record<string, string>; honouredBy: string[] }> }> {
    return this.call("GET", "/v1/entitlements");
  }
  cancel(id: string): Promise<{ entitlement: Entitlement; cancel: string | null }> {
    return this.call("POST", `/v1/entitlements/${encodeURIComponent(id)}/cancel`);
  }
  check(product: string): Promise<{ held: boolean; status: string | null }> {
    return this.call("GET", `/v1/check?product=${encodeURIComponent(product)}`);
  }
  apps(q?: string): Promise<{ apps: AppRecord[] }> {
    return this.call("GET", `/v1/apps${q ? `?q=${encodeURIComponent(q)}` : ""}`);
  }
  app(id: string): Promise<{ app: AppRecord }> {
    return this.call("GET", `/v1/apps/${encodeURIComponent(id)}`);
  }
  registerApp(url: string): Promise<{ app: AppRecord }> {
    return this.call("POST", "/v1/apps", { url });
  }
  /** Register many at once. Answers a job; poll it with bulkJob until finishedAt is set. */
  registerApps(urls: string[]): Promise<{ job: ProbeJob; rejected: string[]; page: string }> {
    return this.call("POST", "/v1/apps/bulk", { urls });
  }
  bulkJob(id: string): Promise<{ job: ProbeJob }> {
    return this.call("GET", `/v1/apps/bulk/${encodeURIComponent(id)}`);
  }
  refreshApp(id: string): Promise<{ app: AppRecord }> {
    return this.call("POST", `/v1/apps/${encodeURIComponent(id)}/refresh`);
  }
  removeApp(id: string): Promise<{ ok: boolean }> {
    return this.call("DELETE", `/v1/apps/${encodeURIComponent(id)}`, undefined, true);
  }
}

/** A descriptor to start from. */
export function descriptorTemplate(siteUrl: string, options: { name?: string; hub?: string; jwk?: Jwk } = {}): Record<string, unknown> {
  const origin = new URL(siteUrl).origin;
  const host = new URL(siteUrl).hostname.replace(/^www\./, "");
  return {
    openaccess: "0.1",
    name: options.name ?? host,
    url: origin,
    operator: "https://your.site/.well-known/openprofile.md",
    redirect_uris: [`${origin}/api/v1/openaccess/callback`],
    ...(options.jwk ? { jwks: { keys: [options.jwk] } } : {}),
    scopes: { "things:read": "See your things", "things:write": "Change your things" },
    offers: [{ product: `${host}/pro`, name: "Pro", price: "9 USD/month", links: { pay: `${origin}/pay/pro?principal={principal}`, cancel: `${origin}/me/billing`, manage: `${origin}/me/billing`, promote: `${origin}/?ref={principal}` } }],
    honours: [`${host}/pro`],
    webhooks: `${origin}/api/v1/openaccess/events`,
    hubs: [options.hub ?? "https://openaccess.logicsrc.com"],
  };
}
