# OpenAccess

OAuth 2.1 with a grant you can carry. A person, an agent or an organisation keeps one account at a **hub**; every app they use keeps its own users and links each one to that account once. What the hub holds for them is theirs: the permissions they gave each app hand down to agents narrower than they were received, and a subscription bought in one app is honoured in every app that says it honours that product. A reference hub, and a client and CLI for apps and terminals.

The specification is at [logicsrc.com/openaccess](https://logicsrc.com/openaccess); this repository is the reference implementation, and `docs/openaccess.md` is a copy of the spec. A hub runs at [openaccess.logicsrc.com](https://openaccess.logicsrc.com).

## What it is

- An app serves `/.well-known/openaccess.json`: the scopes it understands (each with a line a person can read), the products it sells with their pay, cancel, manage, upgrade and promote links, the products it honours, the key it signs with, and where it takes webhooks.
- A hub registers an app by reading that file from the app's own origin. It links a person to an app with plain OAuth 2.1 (authorization code with PKCE, or the device flow for a terminal), and refuses any scope the descriptor does not name, by name. It never narrows a request in silence.
- Tokens are Ed25519 JWTs an app verifies offline against the hub's JWKS. They carry the scopes, the grant, the limits, and the honoured products the person holds.
- A grant delegates: a token with `grants:delegate` mints a child for an agent with a subset of scopes, limits no larger and an expiry no later. Revoking a grant revokes every child. Every token names its parent, so an app always sees the path back to the person.
- A seller reports a sale or a cancellation as itself, signed with the key its descriptor names. Every app that honours the product hears by webhook, and every token it is issued from then on carries the product. The hub records standing; it moves no money.
- The hub has a dashboard: sign in by magic link, see every app you linked, revoke a grant, hand a narrower one to an agent, pay or cancel a subscription from one page. The same over REST and MCP with your own hub token.

## Run a hub

```sh
npx @logicsrc/openaccess serve --port 8791 --url https://hub.example --admin-token <token>
```

Node 24 or later, one SQLite file (`--db`), no build step. `OPENACCESS_URL`, `OPENACCESS_DB`, `OPENACCESS_ADMIN_TOKEN`, `OPENACCESS_NAME`, `OPENACCESS_OPERATOR` (an OpenProfile.md URL), `RESEND_API_KEY` and `MAIL_FROM` (sign-in mail; without a key the link is logged), and `OPENACCESS_REFRESH_MINUTES` (30) do the same from the environment. The signing key is made on first run and kept in the database.

`PROFULLSTACK_FOOTER=1` adds the Profullstack network footer ([@profullstack/footer](https://github.com/profullstack/footer): webring row, built.indie and pwamart badges) to every HTML page and serves `/.well-known/openwebring.json`. Off by default; leave it off on a hub that is not part of that network.

The `Dockerfile` and `railway.json` deploy it as one service with a volume at `/data`.

## Use one from a terminal

```sh
openaccess login --hub https://openaccess.logicsrc.com   # a code to confirm in the browser
openaccess me                                            # apps, grants, entitlements
openaccess delegate --grant g_… --scope "jobs:read" --for https://bot.example/.well-known/openprofile.md --per-day "50 USD" --days 7
openaccess revoke g_…                                    # and every child under it
openaccess cancel e_…                                    # the seller hears; its cancel link comes back
openaccess app add https://agenticjobs.work              # register by any URL on the app
```

## Adopt it in an app

1. `openaccess keygen` and keep the private half. `openaccess descriptor https://your.site --jwk key.json` prints a descriptor to start from; serve it at `/.well-known/openaccess.json`.
2. Register: `openaccess app add https://your.site`, or `POST /v1/apps {url}` on any hub.
3. Link people and verify tokens:

```ts
import { OpenAccessApp } from "@logicsrc/openaccess/client";

const oa = new OpenAccessApp({ hub: "https://openaccess.logicsrc.com", clientId: "your.site", redirectUri: "https://your.site/api/v1/openaccess/callback", key: privateJwk });

// Send the person to the hub; keep verifier and state in the session.
const { url, verifier, state } = await oa.authorizeUrl({ scope: "openid email entitlements things:read" });

// Back at the callback:
const tokens = await oa.exchange(code, verifier);
const claims = await oa.verify(tokens.access_token);   // iss, aud and signature checked against the hub's JWKS
// claims.sub is the link: store it beside your own user id.
// claims.scope, claims.limits and claims.entitlements are yours to enforce.

// When someone pays, or cancels:
await oa.report({ sub: claims.sub, product: "your.site/pro", status: "active", period: { end }, receipt });

// In the webhook receiver:
if (!(await oa.verifyWebhook(rawBody, request.headers.get("x-openaccess-signature")))) return 401;
```

An app with no key is a public client: it links people with PKCE and reads entitlements from the token, but cannot report sales.

## Test

```sh
npm test
```

The suite runs the hub against two fake apps in process, one selling a product and one honouring it, through the code flow, the device flow, delegation, entitlement reporting, cancellation, webhooks and the MCP door, with no network.
