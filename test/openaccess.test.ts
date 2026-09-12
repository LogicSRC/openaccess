/**
 * The hub end to end, against two fake apps and no network: every fetch is
 * routed by host to an in-process Hono app. One app sells a product, the
 * other honours it; a person links both, pays, delegates to an agent, and
 * cancels. Every webhook is captured and its signature checked.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Hono } from "hono";
import { Store } from "../src/db.ts";
import { createApp } from "../src/server.ts";
import { OpenAccessApp, OpenAccessClient, pkce } from "../src/client.ts";
import { exportPrivateJwk, generateSigningKey, signJwt, verifyBody, verifyJwt } from "../src/jwt.ts";
import { narrowLimits, parseDescriptor, isProductOf, unknownScopes, type Jwk } from "../src/spec.ts";
import type { Mailer } from "../src/mail.ts";

interface Captured {
  host: string;
  event: string | null;
  signature: string | null;
  body: string;
}

/** An app: a descriptor at its well-known path and a webhook receiver that captures. */
function fakeApp(host: string, descriptor: Record<string, unknown>, captured: Captured[]): Hono {
  const app = new Hono();
  app.get("/.well-known/openaccess.json", (c) => c.json({ openaccess: "0.1", url: `https://${host}`, ...descriptor }));
  app.post("/hooks", async (c) => {
    captured.push({ host, event: c.req.header("x-openaccess-event") ?? null, signature: c.req.header("x-openaccess-signature") ?? null, body: await c.req.text() });
    return c.json({ ok: true });
  });
  return app;
}

/** Route fetch by host to in-process apps. */
function router(apps: Record<string, Hono>): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const app = apps[url.host];
    if (!app) return new Response("no such host", { status: 502 });
    return app.request(url.toString(), { method: init?.method ?? "GET", headers: init?.headers as Record<string, string>, body: init?.body ?? undefined });
  }) as typeof fetch;
}

/** Webhooks go out after the response; give them a beat before reading what was captured. */
const settled = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 30));

const captureMailer = (links: string[]): Mailer => ({
  async send(input) {
    const match = /https?:\/\/\S+/.exec(input.text);
    if (match) links.push(match[0]);
    return { ok: true };
  },
});

const HUB = "https://hub.example";
const sellerKey = generateSigningKey();
const sellerDescriptor = {
  name: "Board",
  operator: "https://ada.example/.well-known/openprofile.md",
  redirect_uris: ["https://board.example/api/v1/openaccess/callback"],
  jwks: { keys: [sellerKey.jwk] },
  scopes: { "jobs:read": "See jobs", "jobs:apply": "Apply for you", "inbox:write": "Reply in your inbox" },
  offers: [{ product: "board.example/pro", name: "Pro", price: "9 USD/month", links: { pay: "https://board.example/pay?p={principal}", cancel: "https://board.example/billing", promote: "https://board.example/?ref={principal}" } }],
  webhooks: "https://board.example/hooks",
  hubs: [HUB],
};
const honourerDescriptor = {
  name: "Notes",
  redirect_uris: ["https://notes.example/api/v1/openaccess/callback"],
  scopes: { "notes:read": "See notes" },
  honours: ["board.example/pro"],
  webhooks: "https://notes.example/hooks",
  hubs: [HUB],
};

/** A hub with both apps registered and a person signed in. */
async function world() {
  const captured: Captured[] = [];
  const apps: Record<string, Hono> = { "board.example": fakeApp("board.example", sellerDescriptor, captured), "notes.example": fakeApp("notes.example", honourerDescriptor, captured) };
  const fetcher = router(apps);
  const links: string[] = [];
  const store = new Store();
  const hubApp = createApp({ store, url: HUB, fetch: fetcher, mailer: captureMailer(links), adminToken: "admin-secret", name: "Test hub", devicePollIntervalMs: 0 });
  apps["hub.example"] = hubApp;
  const client = new OpenAccessClient({ hub: HUB, fetch: fetcher });
  const board = (await client.registerApp("https://board.example/anything")).app;
  const notes = (await client.registerApp("https://notes.example")).app;

  // Sign in: the link arrives by mail, the cookie comes back.
  const start = await hubApp.request(`${HUB}/auth/start`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "email=Ada@Example.com" });
  assert.equal(start.status, 200);
  const verify = await hubApp.request(links[0] as string);
  assert.equal(verify.status, 302);
  const cookie = (verify.headers.get("set-cookie") as string).split(";")[0] as string;
  const csrf = async (): Promise<string> => {
    const html = await (await hubApp.request(`${HUB}/`, { headers: { cookie, accept: "text/html" } })).text();
    return /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
  };
  const jwks = ((await (await hubApp.request(`${HUB}/.well-known/jwks.json`)).json()) as { keys: Jwk[] }).keys;

  /** Link an app for the signed-in person with the code flow, and get tokens. */
  const link = async (appHost: string, scope: string) => {
    // The hub's own app lists only loopback redirects, as a CLI would use.
    const redirectUri = appHost === "hub.example" ? "http://127.0.0.1/callback" : `https://${appHost}/api/v1/openaccess/callback`;
    const app = new OpenAccessApp({ hub: HUB, clientId: appHost, redirectUri, fetch: fetcher });
    const started = await app.authorizeUrl({ scope });
    const consent = await hubApp.request(started.url, { headers: { cookie } });
    assert.equal(consent.status, 200, await consent.text());
    const decision = await hubApp.request(`${HUB}/authorize/decision`, {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: await csrf(), decision: "approve", client_id: appHost, redirect_uri: redirectUri, scope, state: started.state, code_challenge: new URL(started.url).searchParams.get("code_challenge") as string, response_type: "code" }).toString(),
    });
    assert.equal(decision.status, 302);
    const back = new URL(decision.headers.get("location") as string);
    assert.equal(back.searchParams.get("state"), started.state);
    const tokens = await app.exchange(back.searchParams.get("code") as string, started.verifier);
    return { app, tokens, claims: await app.verify(tokens.access_token) };
  };

  return { store, hubApp, fetcher, client, board, notes, cookie, csrf, captured, jwks, link, links };
}

test("descriptor parsing: scopes, offers of the app's own host, redirect uris on the origin, and the reserved scopes", () => {
  const parsed = parseDescriptor({ scopes: { "a:b": "A", "Bad Scope": "x" }, offers: [{ product: "x.example/pro" }, { product: "other.example/pro" }], redirect_uris: ["https://x.example/cb", "https://evil.example/cb", "http://127.0.0.1:9/cb"] }, "https://x.example/.well-known/openaccess.json");
  assert.deepEqual(parsed?.scopes, { "a:b": "A" });
  assert.deepEqual(parsed?.offers?.map((o) => o.product), ["x.example/pro"]);
  assert.deepEqual(parsed?.redirect_uris, ["https://x.example/cb", "http://127.0.0.1:9/cb"]);
  assert.equal(isProductOf("www.x.example/pro", "https://x.example"), true);
  assert.deepEqual(unknownScopes(["openid", "a:b", "z:z"], parsed as never), ["z:z"]);
  assert.equal(parseDescriptor("nope", "https://x.example/"), null);
});

test("limits narrow: a child keeps or tightens each key in the parent's unit, may add, never exceeds", () => {
  assert.deepEqual(narrowLimits({ per_day: "50 USD" }, { per_call: "5 USD" }), { limits: { per_day: "50 USD", per_call: "5 USD" } });
  assert.deepEqual(narrowLimits({ per_day: "50 USD" }, { per_day: "20 USD" }), { limits: { per_day: "20 USD" } });
  assert.match((narrowLimits({ per_day: "50 USD" }, { per_day: "60 USD" }) as { error: string }).error, /more than the parent/);
  assert.match((narrowLimits({ per_day: "50 USD" }, { per_day: "10 EUR" }) as { error: string }).error, /USD, not EUR/);
  assert.match((narrowLimits({}, { per_day: "lots" }) as { error: string }).error, /not "<amount> <unit>"/);
});

test("jwt: sign and verify with Ed25519, kid matching, expiry; a body signature verifies against the same key", () => {
  const key = generateSigningKey();
  const other = generateSigningKey();
  const token = signJwt({ sub: "x", exp: Math.floor(Date.now() / 1000) + 60 }, key);
  assert.deepEqual((verifyJwt(token, [other.jwk, key.jwk]) as { claims: { sub: string } }).claims.sub, "x");
  assert.equal((verifyJwt(token, [other.jwk]) as { error: string }).error, `no key ${key.kid}`);
  assert.equal((verifyJwt(signJwt({ exp: 1 }, key), [key.jwk]) as { error: string }).error, "expired");
  const restored = generateSigningKey();
  assert.equal(JSON.stringify(exportPrivateJwk(restored)).includes('"d"'), true);
});

test("registration reads the descriptor from the app's origin; an unknown scope is refused by name, never dropped", async () => {
  const w = await world();
  assert.equal(w.board.verified, true);
  assert.equal(w.board.id, "board.example");
  assert.deepEqual(Object.keys(w.board.descriptor.scopes ?? {}), ["jobs:read", "jobs:apply", "inbox:write"]);
  await assert.rejects(w.client.registerApp("https://nowhere.example"), /answered as an app/);

  const app = new OpenAccessApp({ hub: HUB, clientId: "board.example", redirectUri: "https://board.example/api/v1/openaccess/callback", fetch: w.fetcher });
  const started = await app.authorizeUrl({ scope: "jobs:read payments:write" });
  const response = await w.hubApp.request(started.url, { headers: { cookie: w.cookie } });
  assert.equal(response.status, 302);
  const back = new URL(response.headers.get("location") as string);
  assert.equal(back.searchParams.get("error"), "invalid_scope");
  assert.match(back.searchParams.get("error_description") as string, /payments:write/);

  // An unregistered redirect never redirects.
  const bad = await w.hubApp.request(`${HUB}/authorize?response_type=code&client_id=board.example&redirect_uri=https://evil.example/cb&scope=jobs:read&code_challenge=x`, { headers: { cookie: w.cookie } });
  assert.equal(bad.status, 200);
  assert.match(await bad.text(), /redirect_uri is not one/);
});

test("the code flow with PKCE links a person: tokens verify offline, aud is the app, userinfo obeys scope, refresh rotates and a replay revokes", async () => {
  const w = await world();
  const linked = await w.link("board.example", "openid email jobs:read jobs:apply entitlements");
  assert.equal(linked.claims.aud, "board.example");
  assert.equal(linked.claims.iss, HUB);
  assert.equal(linked.claims.scope, "openid email jobs:read jobs:apply entitlements");
  assert.deepEqual(linked.claims.entitlements, []);
  assert.match(linked.claims.sub, /^oa_/);
  const notes = new OpenAccessApp({ hub: HUB, clientId: "notes.example", fetch: w.fetcher });
  await assert.rejects(notes.verify(linked.tokens.access_token), /for board.example, not notes.example/);

  const info = (await (await w.hubApp.request(`${HUB}/userinfo`, { headers: { authorization: `Bearer ${linked.tokens.access_token}` } })).json()) as { sub: string; email?: string };
  assert.equal(info.email, "ada@example.com");

  // Webhooks: link.created then grant.created, both signed by the hub.
  await settled();
  const events = w.captured.filter((c) => c.host === "board.example").map((c) => c.event);
  assert.deepEqual(events, ["link.created", "grant.created"]);
  for (const delivery of w.captured) assert.equal(verifyBody(delivery.body, delivery.signature, w.jwks), true);

  // A wrong verifier fails; refresh rotates; the old one replayed revokes the grant.
  const rotated = await linked.app.refresh(linked.tokens.refresh_token);
  assert.notEqual(rotated.refresh_token, linked.tokens.refresh_token);
  await assert.rejects(linked.app.refresh(linked.tokens.refresh_token), /already used/);
  await assert.rejects(linked.app.refresh(rotated.refresh_token), /revoked|Unknown/);
  const introspected = (await (await w.hubApp.request(`${HUB}/introspect`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: rotated.access_token }) })).json()) as { active: boolean };
  assert.equal(introspected.active, false);

  // Asking again widens the same root grant rather than making a second.
  const again = await w.link("board.example", "jobs:read inbox:write");
  const grants = w.store.grantsOf(again.claims.sub, { app: "board.example" });
  assert.equal(grants.length, 1);
  assert.deepEqual(grants[0]?.scope.sort(), ["inbox:write", "jobs:read"]);
});

test("the device flow: a terminal gets a code, the person approves it, the poll answers with tokens", async () => {
  const w = await world();
  const app = new OpenAccessApp({ hub: HUB, clientId: "hub.example", fetch: w.fetcher });
  const started = await app.device("hub:manage");
  assert.match(started.user_code, /^[A-Z]{4}-[A-Z]{4}$/);
  const pending = w.hubApp.request(`${HUB}/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: started.device_code, client_id: "hub.example" }) });
  assert.equal(((await (await pending).json()) as { error: string }).error, "authorization_pending");

  const consent = await w.hubApp.request(started.verification_uri_complete, { headers: { cookie: w.cookie } });
  assert.match(await consent.text(), new RegExp(started.user_code));
  const decision = await w.hubApp.request(`${HUB}/device/decision`, { method: "POST", headers: { cookie: w.cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: await w.csrf(), decision: "approve", user_code: started.user_code }).toString() });
  assert.match(await decision.text(), /Approved/);

  const tokens = await app.pollDevice(started.device_code, 0, async () => {});
  assert.equal(tokens.scope, "hub:manage");
  const me = await new OpenAccessClient({ hub: HUB, token: tokens.access_token, fetch: w.fetcher }).me();
  assert.equal(me.principal.email, "ada@example.com");
  assert.equal(me.links.length, 1);
});

test("delegation: a child is narrower, its token names parent and holder, an over-limit child is refused, revoking the parent revokes the child, and an app's token needs grants:delegate", async () => {
  const w = await world();
  const linked = await w.link("board.example", "jobs:read jobs:apply grants:delegate");
  const holder = new OpenAccessClient({ hub: HUB, token: linked.tokens.access_token, fetch: w.fetcher });
  const child = await holder.delegate({ for: "https://bot.example/.well-known/openprofile.md", scope: "jobs:read", limits: { per_day: "50 USD" }, expires_in: 3600 });
  assert.equal(child.grant.parent, linked.claims.grant);
  assert.deepEqual(child.grant.scope, ["jobs:read"]);
  await assert.rejects(holder.delegate({ scope: "inbox:write" }), /Not in the parent: inbox:write/);

  const agentTokens = await linked.app.refresh(child.refresh_token);
  const agentClaims = await linked.app.verify(agentTokens.access_token);
  assert.equal(agentClaims.parent, linked.claims.grant);
  assert.equal(agentClaims.holder, "https://bot.example/.well-known/openprofile.md");
  assert.deepEqual(agentClaims.limits, { per_day: "50 USD" });
  assert.ok((agentClaims.exp - agentClaims.iat) <= 3600);

  // The agent, holding jobs:read only, cannot delegate further, and cannot go over its own limit anyway.
  const agent = new OpenAccessClient({ hub: HUB, token: agentTokens.access_token, fetch: w.fetcher });
  await assert.rejects(agent.delegate({ scope: "jobs:read" }), /lacks grants:delegate/);
  await assert.rejects(holder.delegate({ scope: "jobs:read", limits: { per_day: "60 USD" }, grant: child.grant.id }), /own grant only/);

  // The person, from the dashboard token, delegates from the child with a tighter limit; then revokes the root and everything goes.
  const me = await w.link("hub.example", "hub:manage");
  const person = new OpenAccessClient({ hub: HUB, token: me.tokens.access_token, fetch: w.fetcher });
  await assert.rejects(person.delegate({ grant: child.grant.id, scope: "jobs:read", limits: { per_day: "60 USD" } }), /more than the parent/);
  const grandchild = await person.delegate({ grant: child.grant.id, scope: "jobs:read", limits: { per_day: "10 USD", per_call: "1 USD" } });
  assert.deepEqual(grandchild.grant.limits, { per_day: "10 USD", per_call: "1 USD" });
  const revoked = await person.revoke(linked.claims.grant);
  assert.deepEqual(revoked.revoked.map((g) => g.id).sort(), [linked.claims.grant, child.grant.id, grandchild.grant.id].sort());
  await assert.rejects(linked.app.refresh(agentTokens.refresh_token), /revoked|Unknown/);
  await settled();
  assert.equal(w.captured.filter((c) => c.host === "board.example" && c.event === "grant.revoked").length, 3);
});

test("entitlements: the seller reports with its key, the honourer hears and its tokens carry the product, a cancel request reaches the seller, and the seller's word ends it", async () => {
  const w = await world();
  const atBoard = await w.link("board.example", "openid entitlements jobs:read");
  const atNotes = await w.link("notes.example", "openid entitlements notes:read");
  assert.deepEqual(atNotes.claims.entitlements, []);
  const sub = atBoard.claims.sub;

  const seller = new OpenAccessApp({ hub: HUB, clientId: "board.example", key: exportPrivateJwk(sellerKey), fetch: w.fetcher });
  const impostor = new OpenAccessApp({ hub: HUB, clientId: "board.example", key: exportPrivateJwk(generateSigningKey()), fetch: w.fetcher });
  await assert.rejects(impostor.report({ sub, product: "board.example/pro", status: "active" }), /Bad client assertion/);
  await assert.rejects(seller.report({ sub, product: "notes.example/pro", status: "active" }), /not a product of board.example/);

  const reported = await seller.report({ sub, product: "board.example/pro", status: "active", period: { end: "2099-01-01T00:00:00Z" }, receipt: "https://board.example/r/1" });
  assert.equal(reported.event, "entitlement.activated");
  assert.deepEqual(reported.honouredBy.sort(), ["board.example", "notes.example"]);
  await settled();
  const activated = w.captured.filter((c) => c.event === "entitlement.activated").map((c) => c.host).sort();
  assert.deepEqual(activated, ["board.example", "notes.example"]);

  // The honourer's next token carries the product it did not sell.
  const refreshed = await atNotes.app.refresh(atNotes.tokens.refresh_token);
  assert.deepEqual((await atNotes.app.verify(refreshed.access_token)).entitlements, ["board.example/pro"]);
  assert.equal((await seller.check(sub, "board.example/pro")).held, true);

  // Reporting the same standing again is not an event.
  assert.equal((await seller.report({ sub, product: "board.example/pro", status: "active", period: { end: "2099-01-01T00:00:00Z" } })).event, null);

  // The person sees it with links filled in, and asks to cancel.
  const me = await w.link("hub.example", "hub:manage");
  const person = new OpenAccessClient({ hub: HUB, token: me.tokens.access_token, fetch: w.fetcher });
  const mine = (await person.entitlements()).entitlements;
  assert.equal(mine[0]?.links.pay, `https://board.example/pay?p=${sub}`);
  assert.equal(mine[0]?.links.promote, `https://board.example/?ref=${sub}`);
  const asked = await person.cancel(mine[0]?.id as string);
  assert.equal(asked.cancel, "https://board.example/billing");
  assert.equal(asked.entitlement.status, "active");
  await settled();
  const requests = w.captured.filter((c) => c.event === "entitlement.cancel_requested");
  assert.deepEqual(requests.map((c) => c.host), ["board.example"]);

  // The seller confirms; the honourer's next token drops it.
  assert.equal((await seller.report({ sub, product: "board.example/pro", status: "cancelled" })).event, "entitlement.cancelled");
  const after = await atNotes.app.refresh(refreshed.refresh_token);
  assert.deepEqual((await atNotes.app.verify(after.access_token)).entitlements, []);
  assert.equal((await person.check("board.example/pro")).held, false);
});

test("the MCP door: list_apps needs no token; whoami and my_entitlements need one; delegate_grant answers a refresh token", async () => {
  const w = await world();
  const me = await w.link("hub.example", "hub:manage");
  await w.link("board.example", "jobs:read");
  const rpc = async (method: string, params: unknown, token?: string) => (await w.hubApp.request(`${HUB}/mcp`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) })).json() as Promise<{ result?: { tools?: unknown[]; structuredContent?: Record<string, unknown>; isError?: boolean; content: { text: string }[] } }>;
  assert.equal((await rpc("tools/list", {})).result?.tools?.length, 10);
  const anonymous = await rpc("tools/call", { name: "whoami", arguments: {} });
  assert.equal(anonymous.result?.isError, true);
  const apps = await rpc("tools/call", { name: "list_apps", arguments: {} });
  assert.equal((apps.result?.structuredContent?.apps as unknown[]).length, 3);
  const who = await rpc("tools/call", { name: "whoami", arguments: {} }, me.tokens.access_token);
  assert.equal((who.result?.structuredContent?.principal as { email: string }).email, "ada@example.com");
  const grants = await rpc("tools/call", { name: "my_grants", arguments: { app: "board.example" } }, me.tokens.access_token);
  const [root] = grants.result?.structuredContent?.grants as { id: string }[];
  const delegated = await rpc("tools/call", { name: "delegate_grant", arguments: { grant: root?.id, scope: "jobs:read", per_day: "5 USD" } }, me.tokens.access_token);
  assert.equal(typeof delegated.result?.structuredContent?.refresh_token, "string");
});

test("the dashboard renders subscriptions, links, agents and the forms; admin removes an app", async () => {
  const w = await world();
  await w.link("board.example", "jobs:read");
  const html = await (await w.hubApp.request(`${HUB}/`, { headers: { cookie: w.cookie, accept: "text/html" } })).text();
  assert.match(html, /Apps you linked/);
  assert.match(html, /Board/);
  assert.match(html, /Hand a narrower grant/);
  const revoke = await w.hubApp.request(`${HUB}/ui/grants/nope/revoke`, { method: "POST", headers: { cookie: w.cookie, "content-type": "application/x-www-form-urlencoded" }, body: `csrf=${await w.csrf()}` });
  assert.match(decodeURIComponent(revoke.headers.get("location") as string), /No such grant/);
  const noCsrf = await w.hubApp.request(`${HUB}/ui/grants/nope/revoke`, { method: "POST", headers: { cookie: w.cookie, "content-type": "application/x-www-form-urlencoded" }, body: "csrf=wrong" });
  assert.equal(noCsrf.headers.get("location"), "/auth");
  assert.equal((await w.hubApp.request(`${HUB}/v1/apps/notes.example`, { method: "DELETE" })).status, 401);
  assert.equal((await w.hubApp.request(`${HUB}/v1/apps/notes.example`, { method: "DELETE", headers: { authorization: "Bearer admin-secret" } })).status, 200);
  assert.equal(w.store.getApp("notes.example"), null);
});

test("bulk registration: a pasted list is normalised and probed in the background; the ones that answer are listed, the rest reported", async () => {
  const w = await world();
  const parsed = (await import("../src/hub.ts")).Hub.parseBulk("board.example\nhttps://notes.example/anything, www.board.example\nnowhere.example\nnot a url\n");
  assert.deepEqual(parsed.urls, ["https://board.example", "https://notes.example", "https://nowhere.example"]);
  assert.deepEqual(parsed.rejected, []);
  const started = await w.hubApp.request(`${HUB}/v1/apps/bulk`, { method: "POST", headers: { "content-type": "text/plain" }, body: "board.example\nnotes.example\nnowhere.example" });
  assert.equal(started.status, 202);
  const { job } = (await started.json()) as { job: { id: string; total: number } };
  assert.equal(job.total, 3);
  let finished: { finishedAt: string | null; results: Array<{ url: string; ok: boolean; error?: string }> } = { finishedAt: null, results: [] };
  for (let i = 0; i < 50 && !finished.finishedAt; i++) {
    await settled();
    finished = ((await (await w.hubApp.request(`${HUB}/v1/apps/bulk/${job.id}`)).json()) as { job: typeof finished }).job;
  }
  assert.ok(finished.finishedAt);
  assert.deepEqual(finished.results.filter((r) => r.ok).map((r) => r.url).sort(), ["https://board.example", "https://notes.example"]);
  assert.match(finished.results.find((r) => !r.ok)?.error ?? "", /nowhere.example/);
  const html = await (await w.hubApp.request(`${HUB}/apps/bulk/${job.id}`, { headers: { accept: "text/html" } })).text();
  assert.match(html, /2 listed, 1 without a descriptor/);
  assert.equal((await w.hubApp.request(`${HUB}/v1/apps/bulk/nope`)).status, 404);
});
