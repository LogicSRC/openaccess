/**
 * The reference hub over HTTP.
 *
 * Four faces of one hub: the OAuth 2.1 endpoints an app uses to link a person
 * and get tokens; REST under /v1 and MCP at /mcp for a principal's own token;
 * signed webhooks out; and the pages a person sees, the dashboard where every
 * app, grant and subscription is in one place.
 */
import { Hono, type Context } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { serve as nodeServe } from "@hono/node-server";
import { timingSafeEqual, createHash } from "node:crypto";
import { Store } from "./db.ts";
import { Hub, HubError, type HubOptions } from "./hub.ts";
import { decodeJwt, exportPrivateJwk, fromPrivateJwk, generateSigningKey, sha256url, verifyJwt, type SigningKey } from "./jwt.ts";
import { logMailer, type Mailer } from "./mail.ts";
import { TOOLS, callTool } from "./mcp/tools.ts";
import { PROTOCOL_VERSION, failure, isNotification, isRequest, result, INVALID_PARAMS, METHOD_NOT_FOUND, PARSE_ERROR, INTERNAL_ERROR } from "./mcp/protocol.ts";
import { OPENACCESS_VERSION, RESERVED_SCOPES, parseScope, type AppRecord, type Grant, type HubDescriptor, type Principal } from "./spec.ts";
import { appPage, appsPage, consentPage, dashboardPage, devicePage, esc, layout, signInPage } from "./ui.ts";

export const VERSION = "0.1.0";
const SESSION_COOKIE = "oa_session";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface ServerOptions extends Omit<HubOptions, "key"> {
  key?: SigningKey;
  description?: string;
  /** Bearer token for removing apps and reading deliveries. Absent means those routes are off. */
  adminToken?: string;
  mailer?: Mailer;
  /** How often a device may poll the token endpoint. */
  devicePollIntervalMs?: number;
}

/** The hub's signing key, made once and kept in the store. */
export function loadKey(store: Store): SigningKey {
  const saved = store.getSetting("signing_key");
  if (saved) return fromPrivateJwk(JSON.parse(saved));
  const key = generateSigningKey();
  store.setSetting("signing_key", JSON.stringify(exportPrivateJwk(key)));
  return key;
}

const sameToken = (a: string, b: string): boolean => {
  const left = createHash("sha256").update(a).digest();
  const right = createHash("sha256").update(b).digest();
  return timingSafeEqual(left, right);
};

type Actor = { principal: Principal; grant: Grant; scope: string[]; via: "token" } | { principal: Principal; grant: null; scope: string[]; via: "session" };

export function createApp(options: ServerOptions): Hono & { hub: Hub } {
  const store = options.store;
  const key = options.key ?? loadKey(store);
  const hub = new Hub({ ...options, key });
  const url = hub.url;
  const secure = url.startsWith("https://");
  const log = options.log ?? (() => {});
  const mailer = options.mailer ?? logMailer(log);
  const app = new Hono() as Hono & { hub: Hub };
  app.hub = hub;

  const bearer = (c: Context): string => {
    const header = c.req.header("authorization") ?? "";
    return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  };
  const isAdmin = (c: Context): boolean => Boolean(options.adminToken) && sameToken(bearer(c), options.adminToken as string);
  const csrfOf = (session: string): string => sha256url(`${session}:csrf`);

  /** A person at the dashboard (cookie) or a program with the hub's own token. */
  const actorOf = (c: Context): Actor | null => {
    const token = bearer(c);
    if (token) {
      const verified = hub.verifyAccess(token);
      if (!verified) return null;
      return { principal: verified.principal, grant: verified.grant, scope: verified.grant.scope, via: "token" };
    }
    const principal = store.sessionPrincipal(getCookie(c, SESSION_COOKIE));
    return principal ? { principal, grant: null, scope: ["hub:manage"], via: "session" } : null;
  };
  /** The same, but a token must be for the hub itself: an app's token is not a key to the person's whole account. */
  const selfActor = (c: Context): Actor | null => {
    const actor = actorOf(c);
    if (actor?.via === "token" && actor.grant.app !== hub.selfId) return null;
    return actor;
  };

  /** An app calling as itself: a client assertion signed with a key its descriptor names. */
  const appFromAssertion = (assertion: string): AppRecord => {
    const decoded = decodeJwt(assertion);
    if (!decoded) throw new HubError("invalid_client", "The client assertion is not a JWT.", 401);
    const clientId = typeof decoded.claims.iss === "string" ? decoded.claims.iss : "";
    if (!clientId || decoded.claims.sub !== clientId) throw new HubError("invalid_client", "The assertion's iss and sub must both be the client_id.", 401);
    const record = store.getApp(clientId);
    if (!record) throw new HubError("invalid_client", `No app ${clientId}.`, 401);
    if (!record.descriptor.jwks?.keys.length) throw new HubError("invalid_client", `${clientId} names no jwks in its descriptor, so it cannot call as itself.`, 401);
    const outcome = verifyJwt(assertion, record.descriptor.jwks.keys);
    if ("error" in outcome) throw new HubError("invalid_client", `Bad client assertion: ${outcome.error}.`, 401);
    const aud = outcome.claims.aud;
    const audiences = Array.isArray(aud) ? aud : [aud];
    if (!audiences.some((a) => a === url || a === `${url}/token` || a === `${url}/v1`)) throw new HubError("invalid_client", `The assertion's aud must be ${url}.`, 401);
    if (typeof outcome.claims.exp !== "number") throw new HubError("invalid_client", "The assertion needs exp.", 401);
    return record;
  };

  const readBody = async (c: Context): Promise<Record<string, string>> => {
    const type = c.req.header("content-type") ?? "";
    if (type.includes("application/json")) {
      const parsed = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
      return Object.fromEntries(Object.entries(parsed).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]));
    }
    const form = await c.req.parseBody().catch(() => ({}));
    return Object.fromEntries(Object.entries(form).map(([k, v]) => [k, typeof v === "string" ? v : ""]));
  };

  const page = (c: Context, title: string, body: string, principal?: Principal | null): Response => {
    const session = getCookie(c, SESSION_COOKIE);
    return c.html(layout(title, body, { hubName: hub.name, principal, csrf: session ? csrfOf(session) : "" }));
  };
  const oauthError = (c: Context, error: HubError): Response => c.json({ error: error.code, error_description: error.message }, error.status as 400);
  const apiError = (c: Context, error: unknown): Response => {
    if (error instanceof HubError) return c.json({ ok: false, error: error.code, message: error.message }, error.status as 400);
    log(`error: ${(error as Error).stack ?? String(error)}`);
    return c.json({ ok: false, error: "internal", message: (error as Error).message }, 500);
  };

  const descriptor = (): HubDescriptor => ({
    openaccess: OPENACCESS_VERSION,
    issuer: url,
    authorization_endpoint: `${url}/authorize`,
    token_endpoint: `${url}/token`,
    device_authorization_endpoint: `${url}/device`,
    introspection_endpoint: `${url}/introspect`,
    revocation_endpoint: `${url}/revoke`,
    userinfo_endpoint: `${url}/userinfo`,
    jwks_uri: `${url}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
    token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
    scopes_supported: [...RESERVED_SCOPES, "hub:manage"],
    ...(hub.operator ? { operator: hub.operator } : {}),
    hub: { api: `${url}/v1`, mcp: `${url}/mcp`, apps: store.countApps(), principals: store.countPrincipals() },
  });

  // --- well-known and index ---------------------------------------------------------------

  app.get("/.well-known/openaccess.json", (c) => c.json(descriptor()));
  app.get("/.well-known/oauth-authorization-server", (c) => c.json(descriptor()));
  app.get("/.well-known/jwks.json", (c) => c.json({ keys: [key.jwk] }));
  app.get("/healthz", (c) => c.json({ ok: true, version: VERSION, apps: store.countApps(), principals: store.countPrincipals() }));

  app.get("/", (c) => {
    const actor = selfActor(c);
    if (!(c.req.header("accept") ?? "").includes("text/html")) {
      return c.json({
        name: hub.name,
        version: VERSION,
        openaccess: OPENACCESS_VERSION,
        spec: "https://logicsrc.com/openaccess",
        descriptor: `${url}/.well-known/openaccess.json`,
        endpoints: [
          "GET  /authorize (code + PKCE)",
          "POST /token (authorization_code | refresh_token | device_code)",
          "POST /device {client_id, scope}",
          "POST /introspect {token}",
          "POST /revoke {token}",
          "GET  /userinfo",
          "GET  /v1/me",
          "GET  /v1/grants | POST /v1/grants {scope, for?, limits?, expires_in?, grant?} | DELETE /v1/grants/:id",
          "GET  /v1/entitlements | POST /v1/entitlements (seller, private_key_jwt) | POST /v1/entitlements/:id/cancel",
          "GET  /v1/check?product=&sub=",
          "GET  /v1/apps?q= | POST /v1/apps {url} | GET /v1/apps/:id | POST /v1/apps/:id/refresh | DELETE /v1/apps/:id (admin)",
          "DELETE /v1/links/:app",
          "POST /mcp",
        ],
        mcp: { endpoint: `${url}/mcp`, transport: "streamable-http", tools: TOOLS.length },
      });
    }
    if (!actor) {
      return page(
        c,
        "OpenAccess",
        `<h1>${esc(hub.name)}</h1><p>OAuth 2.1 with a grant you can carry. Sign in to see every app you linked, revoke a grant, hand a narrower one to an agent, and pay or cancel a subscription from one page.</p><p><a class="btn" href="/auth">Sign in</a> <a class="btn quiet" href="/apps">The apps</a> <a class="btn quiet" href="https://logicsrc.com/openaccess">The spec</a></p><p class="mute">${store.countApps()} apps · ${store.countPrincipals()} principals · <a href="/.well-known/openaccess.json">descriptor</a></p>`,
      );
    }
    const me = hub.me(actor.principal);
    const apps = new Map(store.listApps().map((record) => [record.id, record]));
    const session = getCookie(c, SESSION_COOKIE) ?? "";
    const notice = c.req.query("notice");
    return page(c, "Dashboard", dashboardPage({ principal: actor.principal, links: me.links.map((l) => ({ principal: actor.principal.id, app: l.app, createdAt: "" })), apps, grants: me.grants, entitlements: me.entitlements, csrf: csrfOf(session), hubId: hub.selfId, ...(notice ? { notice: esc(notice) } : {}) }), actor.principal);
  });

  // --- sign in ---------------------------------------------------------------

  app.get("/auth", (c) => page(c, "Sign in", signInPage({ next: c.req.query("next") ?? null, ...(c.req.query("error") ? { error: c.req.query("error") } : {}) })));

  app.post("/auth/start", async (c) => {
    const body = await readBody(c);
    const email = (body.email ?? "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return page(c, "Sign in", signInPage({ next: body.next ?? null, error: "That is not an email address." }));
    const next = body.next && body.next.startsWith("/") ? body.next : null;
    const plain = store.createMagic(email, next);
    const link = `${url}/auth/verify?t=${plain}`;
    const sent = await mailer.send({ to: email, subject: `Sign in to ${hub.name}`, text: `Your sign-in link, good for fifteen minutes and one use:\n\n${link}\n\nIf you did not ask for this, ignore it.`, html: `<p>Your sign-in link, good for fifteen minutes and one use:</p><p><a href="${esc(link)}">${esc(link)}</a></p><p>If you did not ask for this, ignore it.</p>` });
    if (!sent.ok) {
      log(`mail failed: ${sent.error}`);
      return page(c, "Sign in", signInPage({ next, error: "The mail could not be sent. Try again in a minute." }));
    }
    return page(c, "Check your mail", signInPage({ next, sent: email }));
  });

  app.get("/auth/verify", (c) => {
    const redeemed = store.redeemMagic(c.req.query("t") ?? "");
    if (!redeemed) return page(c, "Sign in", signInPage({ next: null, error: "That link is used or expired. Ask for another." }));
    const principal = store.ensurePrincipal(redeemed.email);
    const session = store.createSession(principal.id);
    setCookie(c, SESSION_COOKIE, session, { httpOnly: true, secure, sameSite: "Lax", path: "/", maxAge: 30 * 24 * 3600 });
    return c.redirect(redeemed.next ?? "/");
  });

  const csrfOk = async (c: Context): Promise<{ principal: Principal; body: Record<string, string>; session: string } | null> => {
    const session = getCookie(c, SESSION_COOKIE);
    const principal = store.sessionPrincipal(session);
    if (!principal || !session) return null;
    const body = await readBody(c);
    if (!body.csrf || !sameToken(body.csrf, csrfOf(session))) return null;
    return { principal, body, session };
  };

  app.post("/auth/signout", async (c) => {
    const ok = await csrfOk(c);
    if (ok) store.endSession(ok.session);
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
    return c.redirect("/");
  });

  // --- OAuth: authorization code + PKCE ---------------------------------------------------------------

  /** Everything about an authorize request that must be right before a redirect is trusted. */
  const authorizeRequest = (params: Record<string, string | undefined>): { app: AppRecord; redirectUri: string; scope: string[]; state: string; challenge: string } => {
    const record = store.getApp(params.client_id ?? "");
    if (!record) throw new HubError("invalid_client", `Unknown client_id ${params.client_id ?? ""}. Register the app first.`);
    const redirectUri = params.redirect_uri ?? "";
    const allowed = record.descriptor.redirect_uris ?? [];
    const loopback = /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//.test(redirectUri) && allowed.some((u) => /^http:\/\/(127\.0\.0\.1|localhost)/.test(u));
    if (!allowed.includes(redirectUri) && !loopback) throw new HubError("invalid_request", `redirect_uri is not one the app's descriptor names.`);
    if (params.response_type !== "code") throw new HubError("unsupported_response_type", "Only response_type=code.");
    if (!params.code_challenge || (params.code_challenge_method ?? "S256") !== "S256") throw new HubError("invalid_request", "code_challenge with method S256 is required.");
    const scope = parseScope(params.scope);
    hub.checkScopes(record, scope);
    return { app: record, redirectUri, scope, state: params.state ?? "", challenge: params.code_challenge };
  };

  const redirectWith = (c: Context, redirectUri: string, params: Record<string, string>): Response => {
    const target = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v) target.searchParams.set(k, v);
    return c.redirect(target.toString());
  };

  app.get("/authorize", (c) => {
    const params = c.req.query();
    let request: ReturnType<typeof authorizeRequest>;
    try {
      request = authorizeRequest(params);
    } catch (error) {
      const hubError = error as HubError;
      // A bad client or redirect never redirects; anything after that goes back to the app.
      if (hubError.code === "invalid_client" || (hubError.code === "invalid_request" && /redirect_uri/.test(hubError.message))) return page(c, "Cannot continue", `<h1>Cannot continue</h1><p>${esc(hubError.message)}</p>`);
      return redirectWith(c, params.redirect_uri ?? "", { error: hubError.code, error_description: hubError.message, state: params.state ?? "" });
    }
    const principal = store.sessionPrincipal(getCookie(c, SESSION_COOKIE));
    if (!principal) return c.redirect(`/auth?next=${encodeURIComponent(`${new URL(c.req.url).pathname}?${new URL(c.req.url).searchParams.toString()}`)}`);
    const session = getCookie(c, SESSION_COOKIE) as string;
    const honoured = store.heldProducts(principal.id, [...(request.app.descriptor.honours ?? []), ...(request.app.descriptor.offers ?? []).map((o) => o.product)]);
    return page(c, `${request.app.descriptor.name ?? request.app.id} wants access`, consentPage({ app: request.app, scopes: request.scope, honoured, action: "/authorize/decision", csrf: csrfOf(session), fields: { client_id: request.app.id, redirect_uri: request.redirectUri, scope: request.scope.join(" "), state: request.state, code_challenge: request.challenge, response_type: "code" } }), principal);
  });

  app.post("/authorize/decision", async (c) => {
    const ok = await csrfOk(c);
    if (!ok) return page(c, "Cannot continue", "<h1>Cannot continue</h1><p>Sign in again and retry.</p>");
    let request: ReturnType<typeof authorizeRequest>;
    try {
      request = authorizeRequest(ok.body);
    } catch (error) {
      return page(c, "Cannot continue", `<h1>Cannot continue</h1><p>${esc((error as Error).message)}</p>`);
    }
    if (ok.body.decision !== "approve") return redirectWith(c, request.redirectUri, { error: "access_denied", error_description: "The person said no.", state: request.state });
    const grant = hub.approve(ok.principal, request.app, request.scope);
    const code = store.createAuthCode(grant.id, request.redirectUri, request.challenge);
    return redirectWith(c, request.redirectUri, { code, state: request.state });
  });

  // --- OAuth: token ---------------------------------------------------------------

  app.post("/token", async (c) => {
    const body = await readBody(c);
    try {
      let clientId = body.client_id ?? "";
      if (body.client_assertion) {
        if (body.client_assertion_type && body.client_assertion_type !== ASSERTION_TYPE) throw new HubError("invalid_client", `client_assertion_type must be ${ASSERTION_TYPE}.`, 401);
        clientId = appFromAssertion(body.client_assertion).id;
      }
      if (!clientId) throw new HubError("invalid_client", "client_id is required.", 401);
      const mustMatch = (grant: Grant): void => {
        if (grant.app !== clientId) throw new HubError("invalid_grant", "That grant is for another app.");
      };
      switch (body.grant_type) {
        case "authorization_code": {
          if (!body.code || !body.code_verifier || !body.redirect_uri) throw new HubError("invalid_request", "code, code_verifier and redirect_uri are required.");
          const redeemed = store.redeemAuthCode(body.code);
          if (!redeemed) throw new HubError("invalid_grant", "The code is unknown, used or expired.");
          if (redeemed.redirectUri !== body.redirect_uri) throw new HubError("invalid_grant", "redirect_uri does not match the one the code was issued to.");
          if (sha256url(body.code_verifier) !== redeemed.challenge) throw new HubError("invalid_grant", "code_verifier does not match code_challenge.");
          const grant = store.liveGrant(redeemed.grantId);
          if (!grant) throw new HubError("invalid_grant", "The grant behind the code is gone.");
          mustMatch(grant);
          return c.json(hub.issue(grant));
        }
        case "refresh_token": {
          if (!body.refresh_token) throw new HubError("invalid_request", "refresh_token is required.");
          const rotated = store.rotateRefreshToken(body.refresh_token);
          if ("error" in rotated) throw new HubError("invalid_grant", rotated.error === "replayed" ? "That refresh token was already used; the grant is revoked." : rotated.error === "dead" ? "The grant is revoked or expired." : "Unknown refresh token.");
          mustMatch(rotated.grant);
          return c.json(hub.issue(rotated.grant, rotated.refreshToken));
        }
        case "urn:ietf:params:oauth:grant-type:device_code": {
          if (!body.device_code) throw new HubError("invalid_request", "device_code is required.");
          const polled = store.pollDevice(body.device_code, options.devicePollIntervalMs);
          switch (polled.status) {
            case "approved": {
              const grant = store.liveGrant(polled.grantId as string);
              if (!grant) throw new HubError("invalid_grant", "The grant is gone.");
              mustMatch(grant);
              return c.json(hub.issue(grant));
            }
            case "pending":
              throw new HubError("authorization_pending", "Not approved yet.");
            case "slow_down":
              throw new HubError("slow_down", "Poll less often.");
            case "denied":
              throw new HubError("access_denied", "The person said no.");
            case "expired":
              throw new HubError("expired_token", "The code expired.");
            default:
              throw new HubError("invalid_grant", "Unknown device_code.");
          }
        }
        default:
          throw new HubError("unsupported_grant_type", "grant_type must be authorization_code, refresh_token or urn:ietf:params:oauth:grant-type:device_code.");
      }
    } catch (error) {
      if (error instanceof HubError) return oauthError(c, error);
      throw error;
    }
  });

  // --- OAuth: device ---------------------------------------------------------------

  app.post("/device", async (c) => {
    const body = await readBody(c);
    try {
      const record = store.getApp(body.client_id ?? "");
      if (!record) throw new HubError("invalid_client", `Unknown client_id ${body.client_id ?? ""}.`, 401);
      const scope = parseScope(body.scope);
      hub.checkScopes(record, scope);
      const made = store.createDeviceCode(record.id, scope);
      return c.json({ device_code: made.deviceCode, user_code: made.userCode, verification_uri: `${url}/device`, verification_uri_complete: `${url}/device/verify?user_code=${made.userCode}`, expires_in: 600, interval: 5 });
    } catch (error) {
      if (error instanceof HubError) return oauthError(c, error);
      throw error;
    }
  });

  app.get("/device", (c) => page(c, "Enter the code", devicePage({}), store.sessionPrincipal(getCookie(c, SESSION_COOKIE))));

  app.get("/device/verify", (c) => {
    const userCode = c.req.query("user_code") ?? "";
    const principal = store.sessionPrincipal(getCookie(c, SESSION_COOKIE));
    if (!principal) return c.redirect(`/auth?next=${encodeURIComponent(`/device/verify?user_code=${encodeURIComponent(userCode)}`)}`);
    const row = store.deviceByUserCode(userCode);
    if (!row || row.status !== "pending") return page(c, "Enter the code", devicePage({ userCode, error: "That code is unknown, used or expired." }), principal);
    const record = store.getApp(row.app);
    if (!record) return page(c, "Enter the code", devicePage({ userCode, error: "The app is gone." }), principal);
    const scope = parseScope(row.scope);
    const honoured = store.heldProducts(principal.id, [...(record.descriptor.honours ?? []), ...(record.descriptor.offers ?? []).map((o) => o.product)]);
    return page(c, `${record.descriptor.name ?? record.id} wants access`, consentPage({ app: record, scopes: scope, honoured, action: "/device/decision", csrf: csrfOf(getCookie(c, SESSION_COOKIE) as string), device: row.user_code, fields: { user_code: row.user_code } }), principal);
  });

  app.post("/device/decision", async (c) => {
    const ok = await csrfOk(c);
    if (!ok) return page(c, "Cannot continue", "<h1>Cannot continue</h1><p>Sign in again and retry.</p>");
    const row = store.deviceByUserCode(ok.body.user_code ?? "");
    if (!row || row.status !== "pending") return page(c, "Enter the code", devicePage({ error: "That code is unknown, used or expired." }), ok.principal);
    if (ok.body.decision !== "approve") {
      store.decideDevice(row.user_code, null);
      return page(c, "Denied", devicePage({ done: "denied" }), ok.principal);
    }
    const record = store.getApp(row.app);
    if (!record) return page(c, "Enter the code", devicePage({ error: "The app is gone." }), ok.principal);
    const grant = hub.approve(ok.principal, record, parseScope(row.scope));
    store.decideDevice(row.user_code, grant.id);
    return page(c, "Approved", devicePage({ done: "approved" }), ok.principal);
  });

  // --- OAuth: introspect, revoke, userinfo ---------------------------------------------------------------

  app.post("/introspect", async (c) => {
    const body = await readBody(c);
    const verified = body.token ? hub.verifyAccess(body.token) : null;
    return c.json(verified ? { active: true, ...verified.claims, token_type: "Bearer" } : { active: false });
  });

  app.post("/revoke", async (c) => {
    const body = await readBody(c);
    const token = body.token ?? "";
    const rotated = token ? store.rotateRefreshToken(token) : { error: "unknown" as const };
    if ("grant" in rotated) store.revokeGrant(rotated.grant.id);
    else {
      const verified = hub.verifyAccess(token);
      if (verified) store.revokeGrant(verified.grant.id);
    }
    return c.json({});
  });

  app.get("/userinfo", (c) => {
    const verified = hub.verifyAccess(bearer(c));
    if (!verified) return c.json({ error: "invalid_token" }, 401);
    const scope = verified.grant.scope;
    const p = verified.principal;
    return c.json({ sub: p.id, kind: p.kind, ...(scope.includes("email") && p.email ? { email: p.email, email_verified: true } : {}), ...(scope.includes("profile") && p.profile ? { profile: p.profile } : {}) });
  });

  // --- REST: the principal's own ---------------------------------------------------------------

  const needSelf = (c: Context): Actor => {
    const actor = selfActor(c);
    if (!actor) throw new HubError("unauthorized", "This needs your own hub token (openaccess login) or a signed-in session.", 401);
    return actor;
  };

  app.get("/v1/me", (c) => {
    try {
      return c.json({ ok: true, ...hub.me(needSelf(c).principal) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.get("/v1/grants", (c) => {
    try {
      const actor = needSelf(c);
      return c.json({ ok: true, grants: store.grantsOf(actor.principal.id, { app: c.req.query("app") || undefined, includeRevoked: c.req.query("all") === "1" }) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  /** Delegate. An app's token delegates from itself and needs grants:delegate; the person delegates from any of their grants. */
  app.post("/v1/grants", async (c) => {
    try {
      const actor = actorOf(c);
      if (!actor) throw new HubError("unauthorized", "A bearer token from this hub is required.", 401);
      const body = (await c.req.json().catch(() => ({}))) as { grant?: string; for?: string; scope?: string | string[]; limits?: Record<string, string>; expires_in?: number };
      let parent: Grant | null;
      if (actor.via === "token" && actor.grant.app !== hub.selfId) {
        if (body.grant && body.grant !== actor.grant.id) throw new HubError("forbidden", "An app's token delegates from its own grant only.", 403);
        if (!actor.scope.includes("grants:delegate")) throw new HubError("forbidden", "This token cannot delegate: it lacks grants:delegate.", 403);
        parent = actor.grant;
      } else {
        if (!body.grant) throw new HubError("invalid_request", "Say which grant to delegate from: {grant}.");
        parent = store.liveGrant(body.grant);
        if (!parent || parent.principal !== actor.principal.id) throw new HubError("unknown_grant", "No such grant of yours.", 404);
      }
      const scope = Array.isArray(body.scope) ? body.scope : parseScope(body.scope);
      const made = hub.delegate(parent, { for: body.for, scope, limits: body.limits, expiresIn: typeof body.expires_in === "number" ? body.expires_in : null });
      return c.json({ ok: true, grant: made.grant, refresh_token: made.refreshToken, token_endpoint: `${url}/token`, client_id: made.grant.app, note: "The refresh token is shown once. The agent redeems it at token_endpoint with grant_type=refresh_token and this client_id." }, 201);
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.get("/v1/grants/:id", (c) => {
    try {
      const actor = needSelf(c);
      const grant = store.getGrant(c.req.param("id"));
      if (!grant || grant.principal !== actor.principal.id) throw new HubError("unknown_grant", "No such grant.", 404);
      return c.json({ ok: true, grant, children: store.grantsOf(actor.principal.id, { includeRevoked: true }).filter((g) => g.parent === grant.id) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.delete("/v1/grants/:id", (c) => {
    try {
      const actor = needSelf(c);
      return c.json({ ok: true, revoked: hub.revoke(c.req.param("id"), actor.principal) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.delete("/v1/links/:app", (c) => {
    try {
      const actor = needSelf(c);
      hub.unlink(actor.principal, hub.app(c.req.param("app")));
      return c.json({ ok: true });
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.get("/v1/entitlements", (c) => {
    try {
      return c.json({ ok: true, entitlements: hub.me(needSelf(c).principal).entitlements });
    } catch (error) {
      return apiError(c, error);
    }
  });

  /** A seller reports. Authorization: Bearer <client assertion>, or client_assertion in the body. */
  app.post("/v1/entitlements", async (c) => {
    try {
      const body = (await c.req.json().catch(() => ({}))) as { client_assertion?: string; sub?: string; product?: string; status?: string; period?: { start?: string; end?: string }; receipt?: string };
      const seller = appFromAssertion(body.client_assertion ?? bearer(c));
      if (!body.sub || !body.product || !body.status) throw new HubError("invalid_request", "sub, product and status are required.");
      const outcome = hub.report(seller, { sub: body.sub, product: body.product, status: body.status, period: body.period, receipt: body.receipt ?? null });
      return c.json({ ok: true, ...outcome, honouredBy: store.appsHonouring(outcome.entitlement.product).map((a) => a.id) }, outcome.event === "entitlement.activated" ? 201 : 200);
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.post("/v1/entitlements/:id/cancel", (c) => {
    try {
      return c.json({ ok: true, ...hub.requestCancel(c.req.param("id"), needSelf(c).principal) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  /** A seller or an honouring app asks about a principal; a principal asks about themself. */
  app.get("/v1/check", (c) => {
    try {
      const product = c.req.query("product") ?? "";
      if (!product) throw new HubError("invalid_request", "product is required.");
      const token = bearer(c);
      const asApp = token && token.split(".").length === 3 && decodeJwt(token)?.claims.iss !== url ? appFromAssertion(token) : null;
      if (asApp) {
        const sub = c.req.query("sub") ?? "";
        if (!sub) throw new HubError("invalid_request", "sub is required.");
        return c.json({ ok: true, sub, product, ...hub.check(sub, product) });
      }
      const actor = needSelf(c);
      return c.json({ ok: true, sub: actor.principal.id, product, ...hub.check(actor.principal.id, product) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  // --- REST: apps ---------------------------------------------------------------

  app.get("/v1/apps", (c) => c.json({ ok: true, apps: store.listApps(c.req.query("q") || undefined) }));

  app.post("/v1/apps", async (c) => {
    try {
      const body = (await c.req.json().catch(() => ({}))) as { url?: string };
      const given = typeof body.url === "string" ? body.url.trim() : "";
      if (!/^https?:\/\//i.test(given)) throw new HubError("invalid_request", "Send {url}: any URL on the app's origin.");
      const previous = store.getApp(new URL(given).hostname.toLowerCase().replace(/^www\./, ""));
      const record = await hub.probeApp(given, previous);
      return c.json({ ok: true, app: record }, previous ? 200 : 201);
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.get("/v1/apps/:id", (c) => {
    const record = store.getApp(c.req.param("id"));
    return record ? c.json({ ok: true, app: record }) : c.json({ ok: false, error: "unknown_app" }, 404);
  });

  app.post("/v1/apps/:id/refresh", async (c) => {
    try {
      const previous = hub.app(c.req.param("id"));
      return c.json({ ok: true, app: await hub.probeApp(previous.source, previous) });
    } catch (error) {
      return apiError(c, error);
    }
  });

  app.delete("/v1/apps/:id", (c) => {
    if (!isAdmin(c)) return c.json({ ok: false, error: "Removing an app needs the admin token." }, 401);
    return c.json({ ok: store.removeApp(c.req.param("id")) });
  });

  app.get("/v1/apps/:id/deliveries", (c) => {
    if (!isAdmin(c)) return c.json({ ok: false, error: "Reading deliveries needs the admin token." }, 401);
    return c.json({ ok: true, deliveries: store.listDeliveries(c.req.param("id")) });
  });

  // --- MCP ---------------------------------------------------------------

  app.get("/mcp", (c) => c.json({ ok: false, note: "POST JSON-RPC 2.0 here, with your hub token as a bearer for the tools about you.", tools: TOOLS.map((t) => t.name) }, 405));

  app.post("/mcp", async (c) => {
    let message: unknown;
    try {
      message = await c.req.json();
    } catch {
      return c.json(failure(null, PARSE_ERROR, "Parse error"), 400);
    }
    if (!isRequest(message)) return c.json(failure(null, -32600, "Invalid request"), 400);
    if (isNotification(message)) return c.body(null, 202);
    const id = message.id ?? null;
    const actor = actorOf(c);
    const ctx = { hub, actor: actor?.via === "token" ? { principal: actor.principal, grant: actor.grant, scope: actor.scope } : actor ? { principal: actor.principal, grant: store.rootGrant(actor.principal.id, hub.selfId) ?? store.createGrant({ principal: actor.principal.id, app: hub.selfId, scope: ["hub:manage"] }), scope: ["hub:manage"] } : null };
    switch (message.method) {
      case "initialize":
        return c.json(result(id, { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: { name: hub.name, version: VERSION }, instructions: `An OpenAccess hub. whoami, my_grants and my_entitlements need a bearer token from this hub; list_apps does not.` }));
      case "ping":
        return c.json(result(id, {}));
      case "tools/list":
        return c.json(result(id, { tools: TOOLS }));
      case "tools/call": {
        const params = (message.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        if (!params.name) return c.json(failure(id, INVALID_PARAMS, "tools/call needs a name."));
        try {
          return c.json(result(id, await callTool(params.name, params.arguments ?? {}, ctx)));
        } catch (error) {
          return c.json(failure(id, INTERNAL_ERROR, (error as Error).message));
        }
      }
      default:
        return c.json(failure(id, METHOD_NOT_FOUND, `Method not found: ${message.method}`));
    }
  });

  // --- pages: apps, and the dashboard's forms ---------------------------------------------------------------

  app.get("/apps", (c) => {
    const session = getCookie(c, SESSION_COOKIE);
    return page(c, "Apps", appsPage(store.listApps(), { csrf: session ? csrfOf(session) : "", error: c.req.query("error") }), store.sessionPrincipal(session));
  });
  app.get("/apps/:id", (c) => {
    const record = store.getApp(c.req.param("id"));
    return record ? page(c, record.descriptor.name ?? record.id, appPage(record), store.sessionPrincipal(getCookie(c, SESSION_COOKIE))) : c.notFound();
  });

  const form = (path: string, handle: (ok: NonNullable<Awaited<ReturnType<typeof csrfOk>>>, c: Context) => Promise<string> | string): void => {
    app.post(path, async (c) => {
      const ok = await csrfOk(c);
      if (!ok) return c.redirect("/auth");
      try {
        return c.redirect(`/?notice=${encodeURIComponent(await handle(ok, c))}`);
      } catch (error) {
        return c.redirect(`/?notice=${encodeURIComponent((error as Error).message)}`);
      }
    });
  };

  form("/ui/grants/:id/revoke", (ok, c) => `Revoked ${hub.revoke(c.req.param("id") ?? "", ok.principal).length} grant(s).`);
  form("/ui/links/:app/remove", (ok, c) => {
    hub.unlink(ok.principal, hub.app(c.req.param("app") ?? ""));
    return `Unlinked ${c.req.param("app")}.`;
  });
  form("/ui/entitlements/:id/cancel", (ok, c) => {
    const outcome = hub.requestCancel(c.req.param("id") ?? "", ok.principal);
    return `Asked ${outcome.entitlement.seller} to cancel ${outcome.entitlement.product}.${outcome.cancel ? ` You can also cancel at ${outcome.cancel}` : ""}`;
  });
  form("/ui/profile", (ok) => {
    const profile = (ok.body.profile ?? "").trim();
    if (profile) new URL(profile);
    store.setProfile(ok.principal.id, profile || null);
    return profile ? "Profile saved." : "Profile cleared.";
  });
  form("/ui/grants/delegate", (ok) => {
    const parent = store.liveGrant(ok.body.grant ?? "");
    if (!parent || parent.principal !== ok.principal.id) throw new HubError("unknown_grant", "No such grant of yours.", 404);
    const limits = Object.fromEntries((["per_call", "per_day", "lifetime"] as const).filter((k) => ok.body[k]?.trim()).map((k) => [k, (ok.body[k] as string).trim()]));
    const days = Number(ok.body.days ?? "");
    const made = hub.delegate(parent, { for: ok.body.for?.trim() || null, scope: parseScope(ok.body.scope), limits, expiresIn: days > 0 ? days * 86400 : null });
    return `Delegated ${made.grant.id}. Refresh token, shown once: ${made.refreshToken} (redeem at ${url}/token with client_id=${made.grant.app})`;
  });
  app.post("/ui/apps", async (c) => {
    const ok = await csrfOk(c);
    if (!ok) return c.redirect("/auth");
    try {
      const given = (ok.body.url ?? "").trim();
      if (!/^https?:\/\//i.test(given)) throw new HubError("invalid_request", "Give the app's URL.");
      const record = await hub.probeApp(given, store.getApp(new URL(given).hostname.toLowerCase().replace(/^www\./, "")));
      return c.redirect(`/apps/${record.id}`);
    } catch (error) {
      return c.redirect(`/apps?error=${encodeURIComponent((error as Error).message)}`);
    }
  });

  app.notFound((c) => c.json({ ok: false, error: "Not found" }, 404));
  return app;
}

export interface ServeOptions extends ServerOptions {
  port: number;
  /** Re-read every app's descriptor this often. 0 turns the job off. */
  refreshEveryMs?: number;
}

/** Start listening, with the refresh job on its timer. Returns a stop function. */
export function serve(options: ServeOptions): { app: Hono & { hub: Hub }; stop: () => void } {
  const app = createApp(options);
  const server = nodeServe({ fetch: app.fetch, port: options.port });
  const timers: NodeJS.Timeout[] = [];
  if (options.refreshEveryMs) timers.push(setInterval(() => void app.hub.refreshAll().then((r) => options.log?.(`refresh: ${r.probed} apps, ${r.failed} failed`)), options.refreshEveryMs));
  return {
    app,
    stop: () => {
      for (const timer of timers) clearInterval(timer);
      server.close();
    },
  };
}
