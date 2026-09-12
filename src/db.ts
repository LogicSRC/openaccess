/**
 * The hub on disk: SQLite, built into Node, one file.
 *
 * Records are kept whole as JSON beside the few columns a query narrows on,
 * so a field added tomorrow needs no migration. Secrets (refresh tokens,
 * codes, magic links) are stored hashed; the plain value is shown once.
 */
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { sha256url } from "./jwt.ts";
import { honours, type AppRecord, type Entitlement, type EntitlementStatus, type Grant, type HubEvent, type Limits, type Link, type Principal, type PrincipalKind } from "./spec.ts";

const SCHEMA = `
create table if not exists settings (key text primary key, value text not null);
create table if not exists principals (
  id text primary key, kind text not null, email text unique, profile text, created_at text not null
);
create table if not exists magic (
  hash text primary key, email text not null, expires_at text not null, used integer not null default 0, next text
);
create table if not exists sessions (
  id text primary key, principal text not null references principals(id) on delete cascade, created_at text not null, expires_at text not null
);
create table if not exists apps (
  id text primary key, verified integer not null default 0, seen_at text, first_seen_at text not null, record text not null
);
create table if not exists links (
  principal text not null references principals(id) on delete cascade,
  app text not null references apps(id) on delete cascade,
  created_at text not null, primary key (principal, app)
);
create table if not exists grants (
  id text primary key, principal text not null references principals(id) on delete cascade,
  app text not null references apps(id) on delete cascade, parent text, status text not null,
  created_at text not null, record text not null
);
create index if not exists grants_principal_idx on grants(principal, status);
create index if not exists grants_parent_idx on grants(parent);
create table if not exists refresh_tokens (
  hash text primary key, grant_id text not null references grants(id) on delete cascade,
  created_at text not null, used integer not null default 0
);
create table if not exists auth_codes (
  hash text primary key, grant_id text not null references grants(id) on delete cascade, redirect_uri text not null,
  challenge text not null, expires_at text not null, used integer not null default 0
);
create table if not exists device_codes (
  hash text primary key, user_code text unique not null, app text not null references apps(id) on delete cascade,
  scope text not null, status text not null, grant_id text, expires_at text not null, created_at text not null, last_poll text
);
create table if not exists entitlements (
  id text primary key, principal text not null references principals(id) on delete cascade, product text not null,
  seller text not null references apps(id) on delete cascade, status text not null, updated_at text not null, record text not null,
  unique (principal, product)
);
create index if not exists entitlements_product_idx on entitlements(product, status);
create table if not exists deliveries (
  id text primary key, app text not null references apps(id) on delete cascade, event text not null, at text not null,
  status integer, error text, attempts integer not null default 0
);
create index if not exists deliveries_app_idx on deliveries(app, at desc);
create table if not exists probe_jobs (
  id text primary key, created_at text not null, finished_at text, total integer not null, done integer not null default 0, results text not null
);
`;

const now = (): string => new Date().toISOString();
export const token = (bytes = 32): string => randomBytes(bytes).toString("base64url");
export const id = (prefix: string, bytes = 9): string => `${prefix}_${randomBytes(bytes).toString("hex")}`;

export class Store {
  readonly db: DatabaseSync;

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    if (path !== ":memory:") this.db.exec("pragma journal_mode = wal;");
    this.db.exec("pragma foreign_keys = on;");
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  // --- settings ---------------------------------------------------------------

  getSetting(key: string): string | null {
    const row = this.db.prepare("select value from settings where key = ?").get(key) as { value: string } | undefined;
    return row ? row.value : null;
  }

  setSetting(key: string, value: string): void {
    this.db.prepare("insert into settings (key, value) values (?, ?) on conflict (key) do update set value = excluded.value").run(key, value);
  }

  // --- principals ---------------------------------------------------------------

  getPrincipal(principalId: string): Principal | null {
    const row = this.db.prepare("select * from principals where id = ?").get(principalId) as PrincipalRow | undefined;
    return row ? principalOf(row) : null;
  }

  principalByEmail(email: string): Principal | null {
    const row = this.db.prepare("select * from principals where email = ?").get(email.toLowerCase()) as PrincipalRow | undefined;
    return row ? principalOf(row) : null;
  }

  /** Find or create by email. Signing in is the only way a person appears. */
  ensurePrincipal(email: string, kind: PrincipalKind = "person"): Principal {
    const existing = this.principalByEmail(email);
    if (existing) return existing;
    const principal: Principal = { id: id("oa"), kind, email: email.toLowerCase(), profile: null, createdAt: now() };
    this.db.prepare("insert into principals (id, kind, email, profile, created_at) values (?, ?, ?, ?, ?)").run(principal.id, kind, principal.email, null, principal.createdAt);
    return principal;
  }

  setProfile(principalId: string, profile: string | null): void {
    this.db.prepare("update principals set profile = ? where id = ?").run(profile, principalId);
  }

  countPrincipals(): number {
    return Number((this.db.prepare("select count(*) as n from principals").get() as { n: number }).n);
  }

  // --- sign in ---------------------------------------------------------------

  /** A magic link: the plain token goes in the mail, the hash stays here. */
  createMagic(email: string, next: string | null, ttlMs = 15 * 60_000): string {
    const plain = token(24);
    this.db.prepare("insert into magic (hash, email, expires_at, next) values (?, ?, ?, ?)").run(sha256url(plain), email.toLowerCase(), new Date(Date.now() + ttlMs).toISOString(), next);
    return plain;
  }

  redeemMagic(plain: string): { email: string; next: string | null } | null {
    const row = this.db.prepare("select email, expires_at, used, next from magic where hash = ?").get(sha256url(plain)) as { email: string; expires_at: string; used: number; next: string | null } | undefined;
    if (!row || row.used || row.expires_at < now()) return null;
    this.db.prepare("update magic set used = 1 where hash = ?").run(sha256url(plain));
    return { email: row.email, next: row.next };
  }

  createSession(principalId: string, ttlMs = 30 * 24 * 3600_000): string {
    const sessionId = token(32);
    this.db.prepare("insert into sessions (id, principal, created_at, expires_at) values (?, ?, ?, ?)").run(sessionId, principalId, now(), new Date(Date.now() + ttlMs).toISOString());
    return sessionId;
  }

  sessionPrincipal(sessionId: string | undefined): Principal | null {
    if (!sessionId) return null;
    const row = this.db.prepare("select p.* from sessions s join principals p on p.id = s.principal where s.id = ? and s.expires_at > ?").get(sessionId, now()) as PrincipalRow | undefined;
    return row ? principalOf(row) : null;
  }

  endSession(sessionId: string): void {
    this.db.prepare("delete from sessions where id = ?").run(sessionId);
  }

  // --- apps ---------------------------------------------------------------

  listApps(q?: string): AppRecord[] {
    const rows = this.db.prepare("select record from apps order by verified desc, first_seen_at").all() as { record: string }[];
    let apps = rows.map((row) => JSON.parse(row.record) as AppRecord);
    if (q) {
      const needle = q.toLowerCase();
      apps = apps.filter((app) => `${app.id} ${app.descriptor.name ?? ""} ${app.descriptor.url ?? ""} ${(app.descriptor.honours ?? []).join(" ")}`.toLowerCase().includes(needle));
    }
    return apps;
  }

  getApp(appId: string): AppRecord | null {
    const row = this.db.prepare("select record from apps where id = ?").get(appId) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as AppRecord) : null;
  }

  putApp(record: AppRecord): { previous: AppRecord | null } {
    const previous = this.getApp(record.id);
    this.db
      .prepare("insert into apps (id, verified, seen_at, first_seen_at, record) values (?, ?, ?, ?, ?) on conflict (id) do update set verified = excluded.verified, seen_at = excluded.seen_at, record = excluded.record")
      .run(record.id, record.verified ? 1 : 0, record.seenAt, record.firstSeenAt, JSON.stringify(record));
    return { previous };
  }

  removeApp(appId: string): boolean {
    return this.db.prepare("delete from apps where id = ?").run(appId).changes > 0;
  }

  /** Apps that honour a product: those that say so, and the one that sells it. */
  appsHonouring(product: string): AppRecord[] {
    return this.listApps().filter((app) => honours(app, product));
  }

  countApps(): number {
    return Number((this.db.prepare("select count(*) as n from apps").get() as { n: number }).n);
  }

  // --- links ---------------------------------------------------------------

  link(principal: string, app: string): { created: boolean; link: Link } {
    const existing = this.db.prepare("select created_at from links where principal = ? and app = ?").get(principal, app) as { created_at: string } | undefined;
    if (existing) return { created: false, link: { principal, app, createdAt: existing.created_at } };
    const createdAt = now();
    this.db.prepare("insert into links (principal, app, created_at) values (?, ?, ?)").run(principal, app, createdAt);
    return { created: true, link: { principal, app, createdAt } };
  }

  unlink(principal: string, app: string): boolean {
    return this.db.prepare("delete from links where principal = ? and app = ?").run(principal, app).changes > 0;
  }

  linksOf(principal: string): Link[] {
    const rows = this.db.prepare("select * from links where principal = ? order by created_at").all(principal) as Array<{ principal: string; app: string; created_at: string }>;
    return rows.map((row) => ({ principal: row.principal, app: row.app, createdAt: row.created_at }));
  }

  // --- grants ---------------------------------------------------------------

  createGrant(input: { principal: string; app: string; parent?: string | null; holder?: string | null; scope: string[]; limits?: Limits; expiresAt?: string | null }): Grant {
    const grant: Grant = {
      id: id("g"),
      principal: input.principal,
      app: input.app,
      parent: input.parent ?? null,
      holder: input.holder ?? null,
      scope: input.scope,
      limits: input.limits ?? {},
      expiresAt: input.expiresAt ?? null,
      status: "active",
      createdAt: now(),
      revokedAt: null,
    };
    this.db.prepare("insert into grants (id, principal, app, parent, status, created_at, record) values (?, ?, ?, ?, ?, ?, ?)").run(grant.id, grant.principal, grant.app, grant.parent, grant.status, grant.createdAt, JSON.stringify(grant));
    return grant;
  }

  getGrant(grantId: string): Grant | null {
    const row = this.db.prepare("select record from grants where id = ?").get(grantId) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as Grant) : null;
  }

  /** A grant that can be used now: active and not past its expiry. */
  liveGrant(grantId: string): Grant | null {
    const grant = this.getGrant(grantId);
    if (!grant || grant.status !== "active") return null;
    if (grant.expiresAt && grant.expiresAt < now()) return null;
    return grant;
  }

  grantsOf(principal: string, options: { app?: string; includeRevoked?: boolean } = {}): Grant[] {
    const rows = this.db.prepare("select record from grants where principal = ? order by created_at desc").all(principal) as { record: string }[];
    return rows.map((row) => JSON.parse(row.record) as Grant).filter((grant) => (options.includeRevoked || grant.status === "active") && (!options.app || grant.app === options.app));
  }

  /** The principal's own (top-level) active grant for an app, if any. */
  rootGrant(principal: string, app: string): Grant | null {
    return this.grantsOf(principal, { app }).find((grant) => !grant.parent) ?? null;
  }

  updateGrant(grant: Grant): void {
    this.db.prepare("update grants set status = ?, record = ? where id = ?").run(grant.status, JSON.stringify(grant), grant.id);
  }

  /** Revoke a grant and everything delegated from it. Answers every grant revoked. */
  revokeGrant(grantId: string): Grant[] {
    const out: Grant[] = [];
    const queue = [grantId];
    while (queue.length) {
      const current = queue.shift() as string;
      const grant = this.getGrant(current);
      if (!grant || grant.status === "revoked") continue;
      grant.status = "revoked";
      grant.revokedAt = now();
      this.updateGrant(grant);
      this.db.prepare("delete from refresh_tokens where grant_id = ?").run(grant.id);
      out.push(grant);
      const children = this.db.prepare("select id from grants where parent = ?").all(current) as { id: string }[];
      queue.push(...children.map((child) => child.id));
    }
    return out;
  }

  // --- tokens and codes ---------------------------------------------------------------

  issueRefreshToken(grantId: string): string {
    const plain = token(32);
    this.db.prepare("insert into refresh_tokens (hash, grant_id, created_at) values (?, ?, ?)").run(sha256url(plain), grantId, now());
    return plain;
  }

  /**
   * Rotate: the old token is marked used and a new one issued. A token that
   * was already used is a replay, and the whole grant is revoked (OAuth 2.1).
   */
  rotateRefreshToken(plain: string): { grant: Grant; refreshToken: string } | { error: "unknown" | "replayed" | "dead" } {
    const row = this.db.prepare("select grant_id, used from refresh_tokens where hash = ?").get(sha256url(plain)) as { grant_id: string; used: number } | undefined;
    if (!row) return { error: "unknown" };
    if (row.used) {
      this.revokeGrant(row.grant_id);
      return { error: "replayed" };
    }
    const grant = this.liveGrant(row.grant_id);
    if (!grant) return { error: "dead" };
    this.db.prepare("update refresh_tokens set used = 1 where hash = ?").run(sha256url(plain));
    return { grant, refreshToken: this.issueRefreshToken(grant.id) };
  }

  createAuthCode(grantId: string, redirectUri: string, challenge: string, ttlMs = 5 * 60_000): string {
    const plain = token(24);
    this.db.prepare("insert into auth_codes (hash, grant_id, redirect_uri, challenge, expires_at) values (?, ?, ?, ?, ?)").run(sha256url(plain), grantId, redirectUri, challenge, new Date(Date.now() + ttlMs).toISOString());
    return plain;
  }

  redeemAuthCode(plain: string): { grantId: string; redirectUri: string; challenge: string } | null {
    const hash = sha256url(plain);
    const row = this.db.prepare("select grant_id, redirect_uri, challenge, expires_at, used from auth_codes where hash = ?").get(hash) as { grant_id: string; redirect_uri: string; challenge: string; expires_at: string; used: number } | undefined;
    if (!row) return null;
    if (row.used) {
      // A code presented twice: the grant it made is revoked, as OAuth 2.1 asks.
      this.revokeGrant(row.grant_id);
      return null;
    }
    if (row.expires_at < now()) return null;
    this.db.prepare("update auth_codes set used = 1 where hash = ?").run(hash);
    return { grantId: row.grant_id, redirectUri: row.redirect_uri, challenge: row.challenge };
  }

  createDeviceCode(app: string, scope: string[], ttlMs = 10 * 60_000): { deviceCode: string; userCode: string; expiresAt: string } {
    const deviceCode = token(32);
    // Eight letters from an alphabet without lookalikes, in two groups: what a person types.
    const alphabet = "BCDFGHJKLMNPQRSTVWXZ";
    const code = Array.from(randomBytes(8), (byte) => alphabet[byte % alphabet.length]).join("");
    const userCode = `${code.slice(0, 4)}-${code.slice(4)}`;
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();
    this.db.prepare("insert into device_codes (hash, user_code, app, scope, status, expires_at, created_at) values (?, ?, ?, ?, 'pending', ?, ?)").run(sha256url(deviceCode), userCode, app, scope.join(" "), expiresAt, now());
    return { deviceCode, userCode, expiresAt };
  }

  deviceByUserCode(userCode: string): DeviceRow | null {
    const row = this.db.prepare("select * from device_codes where user_code = ?").get(userCode.toUpperCase().replace(/[^A-Z]/g, "").replace(/^(.{4})(.{4})$/, "$1-$2")) as DeviceRow | undefined;
    return row && row.expires_at > now() ? row : null;
  }

  decideDevice(userCode: string, grantId: string | null): void {
    this.db.prepare("update device_codes set status = ?, grant_id = ? where user_code = ?").run(grantId ? "approved" : "denied", grantId, userCode);
  }

  /** What the terminal polling gets. `slow_down` when it polls within the interval. */
  pollDevice(deviceCode: string, intervalMs = 5000): { status: "pending" | "approved" | "denied" | "expired" | "unknown" | "slow_down"; grantId?: string } {
    const hash = sha256url(deviceCode);
    const row = this.db.prepare("select * from device_codes where hash = ?").get(hash) as DeviceRow | undefined;
    if (!row) return { status: "unknown" };
    if (row.expires_at < now()) return { status: "expired" };
    const last = row.last_poll ? Date.parse(row.last_poll) : 0;
    // A poll inside the interval is refused and does not count; the next one is measured from the last accepted poll.
    if (Date.now() - last < intervalMs) return { status: "slow_down" };
    this.db.prepare("update device_codes set last_poll = ? where hash = ?").run(now(), hash);
    if (row.status === "approved") {
      this.db.prepare("delete from device_codes where hash = ?").run(hash);
      return { status: "approved", grantId: row.grant_id as string };
    }
    return { status: row.status as "pending" | "denied" };
  }

  // --- entitlements ---------------------------------------------------------------

  /** Insert or update one principal's standing with one product. Answers what changed. */
  putEntitlement(input: { principal: string; product: string; seller: string; status: EntitlementStatus; period?: { start?: string | null; end?: string | null }; receipt?: string | null }): { entitlement: Entitlement; event: HubEvent | null } {
    const existing = this.entitlement(input.principal, input.product);
    const at = now();
    const entitlement: Entitlement = {
      id: existing?.id ?? id("e"),
      principal: input.principal,
      product: input.product,
      seller: input.seller,
      status: input.status,
      period: { start: input.period?.start ?? existing?.period.start ?? null, end: input.period?.end ?? existing?.period.end ?? null },
      receipt: input.receipt ?? existing?.receipt ?? null,
      cancelRequestedAt: input.status === "cancelled" ? null : (existing?.cancelRequestedAt ?? null),
      createdAt: existing?.createdAt ?? at,
      updatedAt: at,
    };
    this.db
      .prepare("insert into entitlements (id, principal, product, seller, status, updated_at, record) values (?, ?, ?, ?, ?, ?, ?) on conflict (principal, product) do update set seller = excluded.seller, status = excluded.status, updated_at = excluded.updated_at, record = excluded.record")
      .run(entitlement.id, entitlement.principal, entitlement.product, entitlement.seller, entitlement.status, at, JSON.stringify(entitlement));
    let event: HubEvent | null;
    if (!existing) event = "entitlement.activated";
    else if (existing.status === entitlement.status && JSON.stringify(existing.period) === JSON.stringify(entitlement.period)) event = null;
    else if (entitlement.status === "cancelled") event = "entitlement.cancelled";
    else if (entitlement.status === "expired") event = "entitlement.expired";
    else if (!["active", "trialing"].includes(existing.status) && ["active", "trialing"].includes(entitlement.status)) event = "entitlement.activated";
    else event = "entitlement.updated";
    return { entitlement, event };
  }

  entitlement(principal: string, product: string): Entitlement | null {
    const row = this.db.prepare("select record from entitlements where principal = ? and product = ?").get(principal, product) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as Entitlement) : null;
  }

  entitlementById(entitlementId: string): Entitlement | null {
    const row = this.db.prepare("select record from entitlements where id = ?").get(entitlementId) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as Entitlement) : null;
  }

  entitlementsOf(principal: string): Entitlement[] {
    const rows = this.db.prepare("select record from entitlements where principal = ? order by updated_at desc").all(principal) as { record: string }[];
    return rows.map((row) => JSON.parse(row.record) as Entitlement).map(expireIfPast);
  }

  /** The products a principal holds in good standing, out of a given list. */
  heldProducts(principal: string, products: string[]): string[] {
    if (!products.length) return [];
    return this.entitlementsOf(principal)
      .filter((entitlement) => products.includes(entitlement.product) && ["active", "trialing"].includes(entitlement.status))
      .map((entitlement) => entitlement.product);
  }

  markCancelRequested(entitlementId: string): Entitlement | null {
    const entitlement = this.entitlementById(entitlementId);
    if (!entitlement) return null;
    entitlement.cancelRequestedAt = now();
    entitlement.updatedAt = now();
    this.db.prepare("update entitlements set updated_at = ?, record = ? where id = ?").run(entitlement.updatedAt, JSON.stringify(entitlement), entitlement.id);
    return entitlement;
  }

  // --- bulk probe jobs ---------------------------------------------------------------

  createJob(jobId: string, total: number): ProbeJob {
    const job: ProbeJob = { id: jobId, createdAt: now(), finishedAt: null, total, done: 0, results: [] };
    this.db.prepare("insert into probe_jobs (id, created_at, finished_at, total, done, results) values (?, ?, ?, ?, ?, ?)").run(job.id, job.createdAt, null, total, 0, "[]");
    return job;
  }

  updateJob(job: ProbeJob): void {
    this.db.prepare("update probe_jobs set finished_at = ?, done = ?, results = ? where id = ?").run(job.finishedAt, job.done, JSON.stringify(job.results), job.id);
  }

  getJob(jobId: string): ProbeJob | null {
    const row = this.db.prepare("select * from probe_jobs where id = ?").get(jobId) as { id: string; created_at: string; finished_at: string | null; total: number; done: number; results: string } | undefined;
    return row ? { id: row.id, createdAt: row.created_at, finishedAt: row.finished_at, total: Number(row.total), done: Number(row.done), results: JSON.parse(row.results) as ProbeResult[] } : null;
  }

  // --- deliveries ---------------------------------------------------------------

  recordDelivery(input: { id: string; app: string; event: HubEvent; at: string; status: number | null; error: string | null; attempts: number }): void {
    this.db.prepare("insert into deliveries (id, app, event, at, status, error, attempts) values (?, ?, ?, ?, ?, ?, ?)").run(input.id, input.app, input.event, input.at, input.status, input.error, input.attempts);
    const app = this.getApp(input.app);
    if (!app) return;
    const ok = input.status !== null && input.status >= 200 && input.status < 300;
    app.webhookFailures = ok ? 0 : app.webhookFailures + 1;
    this.putApp(app);
  }

  listDeliveries(app: string, limit = 50): unknown[] {
    return this.db.prepare("select id, event, at, status, error, attempts from deliveries where app = ? order by at desc limit ?").all(app, limit);
  }
}

interface PrincipalRow {
  id: string;
  kind: PrincipalKind;
  email: string | null;
  profile: string | null;
  created_at: string;
}

export interface ProbeResult {
  url: string;
  ok: boolean;
  /** The app id when it was listed. */
  id?: string;
  verified?: boolean;
  name?: string;
  error?: string;
}

export interface ProbeJob {
  id: string;
  createdAt: string;
  finishedAt: string | null;
  total: number;
  done: number;
  results: ProbeResult[];
}

export interface DeviceRow {
  hash: string;
  user_code: string;
  app: string;
  scope: string;
  status: string;
  grant_id: string | null;
  expires_at: string;
  created_at: string;
  last_poll: string | null;
}

const principalOf = (row: PrincipalRow): Principal => ({ id: row.id, kind: row.kind, email: row.email, profile: row.profile, createdAt: row.created_at });

/** A period that ended is expired, whatever the seller last said. */
function expireIfPast(entitlement: Entitlement): Entitlement {
  if (["active", "trialing", "past_due"].includes(entitlement.status) && entitlement.period.end && entitlement.period.end < now()) return { ...entitlement, status: "expired" };
  return entitlement;
}
