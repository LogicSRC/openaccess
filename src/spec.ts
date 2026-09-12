/**
 * OpenAccess, the records.
 *
 * A hub is an OAuth 2.1 authorization server that also keeps, for each
 * principal, the grants they gave apps and the entitlements they hold. An app
 * keeps its own users and links each to a principal once. Everything in this
 * file is the shape of what crosses the wire; the normative text is
 * docs/openaccess.md.
 *
 * The rule that shapes all of it: what a principal gave and what they paid
 * for is theirs. A grant hands down narrower, an entitlement is honoured
 * wherever the product is honoured, and a hub never narrows a request in
 * silence.
 */

export const OPENACCESS_VERSION = "0.1";
export const WELL_KNOWN_PATH = "/.well-known/openaccess.json";

/** Scopes every hub understands without an app listing them. */
export const RESERVED_SCOPES = ["openid", "profile", "email", "entitlements", "grants:delegate"] as const;

export type PrincipalKind = "person" | "agent" | "organization";

export interface Principal {
  /** Stable at this hub: `oa_` and random. */
  id: string;
  kind: PrincipalKind;
  email: string | null;
  /** An OpenProfile.md URL. */
  profile: string | null;
  createdAt: string;
}

export interface Offer {
  /** `<host>/<slug>`, host being the seller's own origin. */
  product: string;
  name?: string;
  /** `<amount> <currency>/<period>` or `free`. */
  price?: string;
  links?: Partial<Record<"pay" | "cancel" | "manage" | "upgrade" | "promote" | "support", string>>;
}

export interface Jwk {
  kty: string;
  crv?: string;
  kid?: string;
  x?: string;
  [key: string]: unknown;
}

/** What an app says about itself at /.well-known/openaccess.json on its own origin. */
export interface AppDescriptor {
  openaccess: string;
  name?: string;
  url?: string;
  operator?: string;
  redirect_uris?: string[];
  jwks?: { keys: Jwk[] };
  /** The registry: scope, one line a person can read. */
  scopes?: Record<string, string>;
  offers?: Offer[];
  honours?: string[];
  webhooks?: string;
  hubs?: string[];
}

/** An app as a hub holds it. */
export interface AppRecord {
  /** A slug of the app's host: its client_id. */
  id: string;
  /** The descriptor URL. */
  source: string;
  descriptor: AppDescriptor;
  verified: boolean;
  seenAt: string | null;
  firstSeenAt: string;
  failures: number;
  lastError: string | null;
  /** Consecutive failed webhook deliveries. */
  webhookFailures: number;
}

export type LimitKey = "per_call" | "per_day" | "lifetime";
export type Limits = Partial<Record<LimitKey, string>>;

export type GrantStatus = "active" | "revoked";

export interface Grant {
  id: string;
  principal: string;
  app: string;
  parent: string | null;
  /** Who holds a delegated grant: an OpenProfile URL, or null for a bare bearer or the principal themself. */
  holder: string | null;
  scope: string[];
  limits: Limits;
  expiresAt: string | null;
  status: GrantStatus;
  createdAt: string;
  revokedAt: string | null;
}

export type EntitlementStatus = "active" | "trialing" | "past_due" | "cancelled" | "expired";
export const ENTITLEMENT_STATUSES: EntitlementStatus[] = ["active", "trialing", "past_due", "cancelled", "expired"];
/** The statuses an app treats as paid. */
export const GOOD_STANDING: EntitlementStatus[] = ["active", "trialing"];

export interface Entitlement {
  id: string;
  principal: string;
  product: string;
  /** The app that sold it, by id. */
  seller: string;
  status: EntitlementStatus;
  period: { start: string | null; end: string | null };
  receipt: string | null;
  cancelRequestedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Link {
  principal: string;
  app: string;
  createdAt: string;
}

export type HubEvent =
  | "link.created"
  | "link.removed"
  | "grant.created"
  | "grant.updated"
  | "grant.revoked"
  | "entitlement.activated"
  | "entitlement.updated"
  | "entitlement.cancelled"
  | "entitlement.expired"
  | "entitlement.cancel_requested";

export const HUB_EVENTS: HubEvent[] = [
  "link.created",
  "link.removed",
  "grant.created",
  "grant.updated",
  "grant.revoked",
  "entitlement.activated",
  "entitlement.updated",
  "entitlement.cancelled",
  "entitlement.expired",
  "entitlement.cancel_requested",
];

export interface WebhookDelivery {
  id: string;
  event: HubEvent;
  at: string;
  hub: string;
  sub: string;
  grant?: Grant;
  entitlement?: Entitlement;
  link?: Link;
}

/** The claims an access token carries. */
export interface AccessClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  scope: string;
  grant: string;
  parent?: string;
  holder?: string;
  limits?: Limits;
  entitlements?: string[];
  openaccess: string;
  [key: string]: unknown;
}

/** What a hub says about itself: RFC 8414 metadata plus where the rest lives. */
export interface HubDescriptor {
  openaccess: string;
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  device_authorization_endpoint: string;
  introspection_endpoint: string;
  revocation_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  code_challenge_methods_supported: string[];
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  scopes_supported: string[];
  operator?: string;
  hub: { api: string; mcp: string; apps: number; principals: number };
}

/** A slug from an app's host, stable across probes: its client_id. */
export function appId(url: string): string {
  const parsed = new URL(url);
  return parsed.hostname
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/[^a-z0-9.-]+/g, "-")
    .slice(0, 120);
}

const SCOPE_RE = /^[a-z0-9_-]+(:[a-z0-9_-]+){0,2}$/;
export const isScopeName = (value: string): boolean => SCOPE_RE.test(value);

/** Read a descriptor out of whatever an app served. Never throws; a bad one is null. */
export function parseDescriptor(value: unknown, base: string): AppDescriptor | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  const origin = new URL(base).origin;
  const strings = (key: string): string[] | undefined =>
    Array.isArray(record[key]) ? (record[key] as unknown[]).filter((item): item is string => typeof item === "string").slice(0, 100) : undefined;
  const absolute = (raw: string): string | null => {
    try {
      const url = new URL(raw, base);
      return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
    } catch {
      return null;
    }
  };

  const scopes: Record<string, string> = {};
  if (typeof record.scopes === "object" && record.scopes !== null) {
    for (const [name, line] of Object.entries(record.scopes as Record<string, unknown>)) {
      if (isScopeName(name) && typeof line === "string") scopes[name] = line.slice(0, 200);
    }
  }

  const offers: Offer[] = [];
  if (Array.isArray(record.offers)) {
    for (const raw of record.offers as unknown[]) {
      if (typeof raw !== "object" || raw === null) continue;
      const offer = raw as Record<string, unknown>;
      if (typeof offer.product !== "string" || !isProductOf(offer.product, origin)) continue;
      const links: Record<string, string> = {};
      if (typeof offer.links === "object" && offer.links !== null) {
        for (const [key, href] of Object.entries(offer.links as Record<string, unknown>)) {
          if (["pay", "cancel", "manage", "upgrade", "promote", "support"].includes(key) && typeof href === "string" && absolute(href)) links[key] = href;
        }
      }
      offers.push({
        product: offer.product,
        ...(typeof offer.name === "string" ? { name: offer.name.slice(0, 120) } : {}),
        ...(typeof offer.price === "string" ? { price: offer.price.slice(0, 60) } : {}),
        ...(Object.keys(links).length ? { links: links as Offer["links"] } : {}),
      });
    }
  }

  const redirects = (strings("redirect_uris") ?? []).filter((uri) => {
    try {
      const url = new URL(uri);
      const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
      return (url.protocol === "https:" && url.origin === origin) || (loopback && url.protocol === "http:");
    } catch {
      return false;
    }
  });

  let jwks: { keys: Jwk[] } | undefined;
  if (typeof record.jwks === "object" && record.jwks !== null && Array.isArray((record.jwks as { keys?: unknown }).keys)) {
    const keys = ((record.jwks as { keys: unknown[] }).keys as unknown[]).filter((key): key is Jwk => typeof key === "object" && key !== null && typeof (key as Jwk).kty === "string");
    if (keys.length) jwks = { keys };
  }

  const site = typeof record.url === "string" ? absolute(record.url) : null;
  const webhooks = typeof record.webhooks === "string" ? absolute(record.webhooks) : null;
  return {
    openaccess: typeof record.openaccess === "string" ? record.openaccess : OPENACCESS_VERSION,
    ...(typeof record.name === "string" ? { name: record.name.slice(0, 120) } : {}),
    ...(site ? { url: site } : {}),
    ...(typeof record.operator === "string" ? { operator: record.operator } : {}),
    ...(redirects.length ? { redirect_uris: redirects } : {}),
    ...(jwks ? { jwks } : {}),
    scopes,
    ...(offers.length ? { offers } : {}),
    ...(strings("honours") ? { honours: strings("honours") } : {}),
    ...(webhooks ? { webhooks } : {}),
    ...(strings("hubs") ? { hubs: strings("hubs") } : {}),
  };
}

/** `<host>/<slug>` where host is the seller's origin host. */
export function isProductOf(product: string, origin: string): boolean {
  const slash = product.indexOf("/");
  if (slash <= 0) return false;
  const host = product.slice(0, slash).toLowerCase().replace(/^www\./, "");
  const slug = product.slice(slash + 1);
  return host === new URL(origin).hostname.toLowerCase().replace(/^www\./, "") && /^[a-z0-9][a-z0-9._-]{0,60}$/.test(slug);
}

/**
 * Which of the requested scopes an app does not understand. Empty means all
 * are fine. A hub reports these by name and refuses; it never drops them.
 */
export function unknownScopes(requested: string[], descriptor: AppDescriptor): string[] {
  const known = new Set<string>([...RESERVED_SCOPES, ...Object.keys(descriptor.scopes ?? {})]);
  return requested.filter((scope) => !known.has(scope));
}

export const parseScope = (value: string | undefined | null): string[] => Array.from(new Set((value ?? "").split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)));

/** `5 USD`, `100 calls`, `0.25 eip155:8453/erc20:0x833...`. */
export function parseLimit(value: string): { amount: number; unit: string } | null {
  const match = /^(\d+(?:\.\d+)?)\s+(\S+)$/.exec(value.trim());
  if (!match) return null;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount) || amount < 0) return null;
  return { amount, unit: match[2] as string };
}

/**
 * A child's limits against its parent's: every key the parent has, the child
 * keeps or tightens in the same unit; the child may add keys. Answers the
 * effective limits, or the first complaint.
 */
export function narrowLimits(parent: Limits, child: Limits): { limits: Limits } | { error: string } {
  const out: Limits = { ...parent };
  for (const [key, raw] of Object.entries(child) as Array<[LimitKey, string | undefined]>) {
    if (raw === undefined) continue;
    const mine = parseLimit(raw);
    if (!mine) return { error: `limits.${key}: "${raw}" is not "<amount> <unit>".` };
    const theirs = parent[key] ? parseLimit(parent[key] as string) : null;
    if (theirs) {
      if (theirs.unit !== mine.unit) return { error: `limits.${key}: the parent is in ${theirs.unit}, not ${mine.unit}.` };
      if (mine.amount > theirs.amount) return { error: `limits.${key}: ${raw} is more than the parent's ${parent[key]}.` };
    }
    out[key] = raw;
  }
  return { limits: out };
}

export const isSubset = (child: string[], parent: string[]): boolean => child.every((scope) => parent.includes(scope));

/** The products an app treats as paid: what it honours, and what it sells. */
export const honouredBy = (app: AppRecord): string[] => Array.from(new Set([...(app.descriptor.honours ?? []), ...(app.descriptor.offers ?? []).map((offer) => offer.product)]));
export const honours = (app: AppRecord, product: string): boolean => honouredBy(app).includes(product);

/** Fill `{principal}` in a link. */
export const fillLink = (href: string, principal: string): string => href.replaceAll("{principal}", encodeURIComponent(principal));
