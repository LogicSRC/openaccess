/**
 * What a hub does, with no HTTP in it: probe an app, link a principal, issue
 * tokens, delegate and revoke grants, record entitlements, and tell the apps.
 * The REST routes, the MCP tools and the dashboard all call this.
 */
import { signJwt, verifyJwt, type SigningKey } from "./jwt.ts";
import { Store } from "./db.ts";
import { fanOut, type Fetcher } from "./webhooks.ts";
import {
  appId,
  honouredBy,
  isProductOf,
  isSubset,
  narrowLimits,
  parseDescriptor,
  parseScope,
  unknownScopes,
  ENTITLEMENT_STATUSES,
  OPENACCESS_VERSION,
  WELL_KNOWN_PATH,
  type AccessClaims,
  type AppRecord,
  type Entitlement,
  type EntitlementStatus,
  type Grant,
  type HubEvent,
  type Limits,
  type Principal,
} from "./spec.ts";

export class HubError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export interface HubOptions {
  store: Store;
  /** The hub's public origin, no trailing slash. */
  url: string;
  key: SigningKey;
  name?: string;
  operator?: string;
  fetch?: Fetcher;
  log?: (line: string) => void;
  /** Access token lifetime. */
  accessTtlSec?: number;
}

export interface IssuedTokens {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
  grant: string;
  sub: string;
}

export class Hub {
  readonly store: Store;
  readonly url: string;
  readonly key: SigningKey;
  readonly name: string;
  readonly operator: string | undefined;
  readonly fetch: Fetcher | undefined;
  readonly log: (line: string) => void;
  readonly accessTtlSec: number;
  /** The hub is an app too: its own id, so a CLI can hold a token for it. */
  readonly selfId: string;

  constructor(options: HubOptions) {
    this.store = options.store;
    this.url = options.url.replace(/\/+$/, "");
    this.key = options.key;
    this.name = options.name ?? "OpenAccess hub";
    this.operator = options.operator;
    this.fetch = options.fetch;
    this.log = options.log ?? (() => {});
    this.accessTtlSec = options.accessTtlSec ?? 3600;
    this.selfId = appId(this.url);
    this.ensureSelf();
  }

  /** The hub's own app record: what a terminal links to with `openaccess login`. */
  private ensureSelf(): void {
    const existing = this.store.getApp(this.selfId);
    const at = new Date().toISOString();
    this.store.putApp({
      id: this.selfId,
      source: `${this.url}${WELL_KNOWN_PATH}`,
      descriptor: {
        openaccess: OPENACCESS_VERSION,
        name: this.name,
        url: this.url,
        ...(this.operator ? { operator: this.operator } : {}),
        scopes: { "hub:manage": "Manage your grants and subscriptions at this hub" },
        redirect_uris: ["http://127.0.0.1/callback", "http://localhost/callback"],
      },
      verified: true,
      seenAt: at,
      firstSeenAt: existing?.firstSeenAt ?? at,
      failures: 0,
      lastError: null,
      webhookFailures: 0,
    });
  }

  private events(event: HubEvent, payload: { sub: string; grant?: Grant; entitlement?: Entitlement; link?: { principal: string; app: string; createdAt: string } }): void {
    void fanOut(this.store, event, payload, { hub: this.url, key: this.key, fetch: this.fetch, log: this.log });
  }

  // --- apps ---------------------------------------------------------------

  /** Register or refresh an app from any URL on its origin. The descriptor decides what is listed. */
  async probeApp(given: string, previous: AppRecord | null = null): Promise<AppRecord> {
    let origin: string;
    try {
      origin = new URL(given).origin;
    } catch {
      throw new HubError("invalid_request", "That is not a URL.");
    }
    const source = `${origin}${WELL_KNOWN_PATH}`;
    const fetcher = this.fetch ?? fetch;
    const at = new Date().toISOString();
    let error: string | null = null;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10_000);
      const response = await fetcher(source, { headers: { accept: "application/json", "user-agent": "openaccess-hub" }, signal: controller.signal }).finally(() => clearTimeout(timer));
      if (!response.ok) error = `${source} answered ${response.status}`;
      else {
        const descriptor = parseDescriptor(await response.json().catch(() => null), source);
        if (!descriptor) error = `${source} is not an OpenAccess descriptor`;
        else {
          const record: AppRecord = { id: appId(origin), source, descriptor, verified: true, seenAt: at, firstSeenAt: previous?.firstSeenAt ?? at, failures: 0, lastError: null, webhookFailures: previous?.webhookFailures ?? 0 };
          this.store.putApp(record);
          this.log(`${previous ? "refreshed" : "registered"} ${record.id} (${Object.keys(descriptor.scopes ?? {}).length} scopes, ${(descriptor.offers ?? []).length} offers)`);
          return record;
        }
      }
    } catch (caught) {
      error = (caught as Error).name === "AbortError" ? `${source} timed out` : (caught as Error).message;
    }
    if (!previous) throw new HubError("not_an_app", `Nothing at ${origin} answered as an app: ${error}.`, 422);
    const kept: AppRecord = { ...previous, failures: previous.failures + 1, lastError: error };
    this.store.putApp(kept);
    return kept;
  }

  app(appIdOrUrl: string): AppRecord {
    const app = this.store.getApp(appIdOrUrl.includes("://") ? appId(appIdOrUrl) : appIdOrUrl);
    if (!app) throw new HubError("unknown_app", `No app ${appIdOrUrl}. Register it first.`, 404);
    return app;
  }

  /** The scopes an app understands, or a complaint naming the ones it does not. */
  checkScopes(app: AppRecord, requested: string[]): void {
    if (!requested.length) throw new HubError("invalid_scope", "Ask for at least one scope.");
    const unknown = unknownScopes(requested, app.descriptor);
    if (unknown.length) throw new HubError("invalid_scope", `${app.descriptor.name ?? app.id} does not understand: ${unknown.join(", ")}.`);
  }

  // --- linking and grants ---------------------------------------------------------------

  /**
   * The principal approved these scopes for this app: the root grant is
   * created or widened, and the link made. Answers the grant.
   */
  approve(principal: Principal, app: AppRecord, scope: string[]): Grant {
    this.checkScopes(app, scope);
    const link = this.store.link(principal.id, app.id);
    if (link.created) this.events("link.created", { sub: principal.id, link: link.link });
    const existing = this.store.rootGrant(principal.id, app.id);
    if (!existing) {
      const grant = this.store.createGrant({ principal: principal.id, app: app.id, scope });
      this.events("grant.created", { sub: principal.id, grant });
      return grant;
    }
    const widened = Array.from(new Set([...existing.scope, ...scope]));
    if (widened.length !== existing.scope.length) {
      existing.scope = widened;
      this.store.updateGrant(existing);
      this.events("grant.updated", { sub: principal.id, grant: existing });
    }
    return existing;
  }

  /** Tokens for a live grant. The refresh token is fresh; the caller rotates the old one. */
  issue(grant: Grant, refreshToken?: string): IssuedTokens {
    const principal = this.store.getPrincipal(grant.principal);
    if (!principal) throw new HubError("invalid_grant", "The principal is gone.");
    const app = this.store.getApp(grant.app);
    const now = Math.floor(Date.now() / 1000);
    const claims: AccessClaims = {
      iss: this.url,
      sub: principal.id,
      aud: grant.app,
      iat: now,
      exp: now + this.accessTtlSec,
      scope: grant.scope.join(" "),
      grant: grant.id,
      ...(grant.parent ? { parent: grant.parent } : {}),
      ...(grant.holder ? { holder: grant.holder } : {}),
      ...(Object.keys(grant.limits).length ? { limits: grant.limits } : {}),
      ...(grant.scope.includes("entitlements") && app ? { entitlements: this.store.heldProducts(principal.id, honouredBy(app)) } : {}),
      openaccess: OPENACCESS_VERSION,
    };
    return {
      access_token: signJwt(claims, this.key),
      token_type: "Bearer",
      expires_in: this.accessTtlSec,
      refresh_token: refreshToken ?? this.store.issueRefreshToken(grant.id),
      scope: claims.scope,
      grant: grant.id,
      sub: principal.id,
    };
  }

  /** Verify one of this hub's own access tokens and find the live grant behind it. */
  verifyAccess(token: string): { claims: AccessClaims; grant: Grant; principal: Principal } | null {
    const outcome = verifyJwt(token, [this.key.jwk]);
    if ("error" in outcome) return null;
    const claims = outcome.claims as AccessClaims;
    if (claims.iss !== this.url || typeof claims.grant !== "string") return null;
    const grant = this.store.liveGrant(claims.grant);
    if (!grant) return null;
    const principal = this.store.getPrincipal(grant.principal);
    return principal ? { claims, grant, principal } : null;
  }

  /** Hand a narrower grant down from a parent. Answers the child and its refresh token. */
  delegate(parent: Grant, input: { for?: string | null; scope: string[]; limits?: Limits; expiresIn?: number | null }): { grant: Grant; refreshToken: string } {
    if (parent.status !== "active") throw new HubError("invalid_grant", "The parent grant is revoked.");
    const scope = input.scope.filter((s) => s !== "grants:delegate" || parent.scope.includes("grants:delegate"));
    if (!scope.length) throw new HubError("invalid_scope", "A child grant needs at least one scope.");
    if (!isSubset(scope, parent.scope)) throw new HubError("invalid_scope", `Not in the parent: ${scope.filter((s) => !parent.scope.includes(s)).join(", ")}.`);
    const narrowed = narrowLimits(parent.limits, input.limits ?? {});
    if ("error" in narrowed) throw new HubError("invalid_request", narrowed.error);
    let expiresAt: string | null = parent.expiresAt;
    if (input.expiresIn) {
      const mine = new Date(Date.now() + input.expiresIn * 1000).toISOString();
      expiresAt = expiresAt && expiresAt < mine ? expiresAt : mine;
    }
    let holder: string | null = null;
    if (input.for) {
      try {
        holder = new URL(input.for).toString();
      } catch {
        throw new HubError("invalid_request", "`for` must be a URL: the agent's OpenProfile.md.");
      }
    }
    const grant = this.store.createGrant({ principal: parent.principal, app: parent.app, parent: parent.id, holder, scope, limits: narrowed.limits, expiresAt });
    this.events("grant.created", { sub: grant.principal, grant });
    return { grant, refreshToken: this.store.issueRefreshToken(grant.id) };
  }

  /** Revoke a grant and everything under it, telling the app about each. */
  revoke(grantId: string, principal: Principal): Grant[] {
    const grant = this.store.getGrant(grantId);
    if (!grant || grant.principal !== principal.id) throw new HubError("unknown_grant", "No such grant.", 404);
    const revoked = this.store.revokeGrant(grantId);
    for (const each of revoked) this.events("grant.revoked", { sub: principal.id, grant: each });
    return revoked;
  }

  unlink(principal: Principal, app: AppRecord): void {
    for (const grant of this.store.grantsOf(principal.id, { app: app.id })) this.revoke(grant.id, principal);
    if (this.store.unlink(principal.id, app.id)) this.events("link.removed", { sub: principal.id, link: { principal: principal.id, app: app.id, createdAt: "" } });
  }

  // --- entitlements ---------------------------------------------------------------

  /** A seller reports a principal's standing with one of its own products. */
  report(seller: AppRecord, input: { sub: string; product: string; status: string; period?: { start?: string | null; end?: string | null }; receipt?: string | null }): { entitlement: Entitlement; event: HubEvent | null } {
    const principal = this.store.getPrincipal(input.sub);
    if (!principal) throw new HubError("unknown_principal", `No principal ${input.sub} at this hub.`, 404);
    if (!seller.descriptor.url || !isProductOf(input.product, seller.descriptor.url)) throw new HubError("not_your_product", `${input.product} is not a product of ${seller.id}: a product is <your host>/<slug>.`, 403);
    if (!ENTITLEMENT_STATUSES.includes(input.status as EntitlementStatus)) throw new HubError("invalid_request", `status must be one of ${ENTITLEMENT_STATUSES.join(", ")}.`);
    for (const edge of ["start", "end"] as const) {
      const value = input.period?.[edge];
      if (value && Number.isNaN(Date.parse(value))) throw new HubError("invalid_request", `period.${edge} is not a date.`);
    }
    const outcome = this.store.putEntitlement({ principal: principal.id, product: input.product, seller: seller.id, status: input.status as EntitlementStatus, period: input.period, receipt: input.receipt });
    if (outcome.event) this.events(outcome.event, { sub: principal.id, entitlement: outcome.entitlement });
    return outcome;
  }

  /** The person asked to cancel. The seller hears; the standing stays until the seller says. */
  requestCancel(entitlementId: string, principal: Principal): { entitlement: Entitlement; cancel: string | null } {
    const entitlement = this.store.entitlementById(entitlementId);
    if (!entitlement || entitlement.principal !== principal.id) throw new HubError("unknown_entitlement", "No such entitlement.", 404);
    const marked = this.store.markCancelRequested(entitlementId) as Entitlement;
    this.events("entitlement.cancel_requested", { sub: principal.id, entitlement: marked });
    const seller = this.store.getApp(entitlement.seller);
    const offer = seller?.descriptor.offers?.find((candidate) => candidate.product === entitlement.product);
    return { entitlement: marked, cancel: offer?.links?.cancel ? offer.links.cancel.replaceAll("{principal}", encodeURIComponent(principal.id)) : null };
  }

  /** Does this principal hold this product, as far as the hub knows. */
  check(principalId: string, product: string): { held: boolean; status: EntitlementStatus | null; entitlement: Entitlement | null } {
    const entitlement = this.store.entitlementsOf(principalId).find((candidate) => candidate.product === product) ?? null;
    return { held: Boolean(entitlement && ["active", "trialing"].includes(entitlement.status)), status: entitlement?.status ?? null, entitlement };
  }

  /** Everything the hub holds for one principal, as the dashboard and `GET /v1/me` show it. */
  me(principal: Principal): { principal: Principal; links: Array<{ app: string; name: string; url: string | null; grant: Grant | null }>; grants: Grant[]; entitlements: Array<Entitlement & { links: Record<string, string>; honouredBy: string[] }> } {
    const links = this.store.linksOf(principal.id).map((link) => {
      const app = this.store.getApp(link.app);
      return { app: link.app, name: app?.descriptor.name ?? link.app, url: app?.descriptor.url ?? null, grant: this.store.rootGrant(principal.id, link.app) };
    });
    const entitlements = this.store.entitlementsOf(principal.id).map((entitlement) => {
      const seller = this.store.getApp(entitlement.seller);
      const offer = seller?.descriptor.offers?.find((candidate) => candidate.product === entitlement.product);
      const filled: Record<string, string> = {};
      for (const [key, href] of Object.entries(offer?.links ?? {})) if (href) filled[key] = href.replaceAll("{principal}", encodeURIComponent(principal.id));
      return { ...entitlement, links: filled, honouredBy: this.store.appsHonouring(entitlement.product).map((app) => app.id) };
    });
    return { principal, links, grants: this.store.grantsOf(principal.id), entitlements };
  }

  /** Re-read every app's descriptor. What the daemon does on its schedule. */
  async refreshAll(): Promise<{ probed: number; failed: number }> {
    let failed = 0;
    const apps = this.store.listApps().filter((app) => app.id !== this.selfId);
    for (const app of apps) {
      const record = await this.probeApp(app.source, app);
      if (record.lastError) failed++;
    }
    return { probed: apps.length, failed };
  }
}

export { parseScope };
