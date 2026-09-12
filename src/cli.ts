/**
 * `openaccess`: the hub from a terminal.
 *
 *   openaccess serve [--port 8791] [--db openaccess.db] [--url https://...]
 *   openaccess login [--hub url] [--scope "hub:manage"]   device flow; the token is kept in ~/.config/openaccess
 *   openaccess logout | whoami | me
 *   openaccess grants | grant <id> | revoke <id>
 *   openaccess delegate --grant <id> --scope "a b" [--for url] [--per-call "5 USD"] [--per-day ..] [--lifetime ..] [--days 7]
 *   openaccess entitlements | cancel <id> | check <product>
 *   openaccess apps [q] | app add <url> | app show <id> | app refresh <id> | app rm <id> --token <admin>
 *   openaccess keygen                       an Ed25519 key: private half to keep, public half for the descriptor
 *   openaccess descriptor <site url> [--name n] [--jwk file]
 *   openaccess report --key file --client-id id --sub oa_.. --product host/slug --status active [--end date] [--receipt url]
 *   openaccess verify-webhook --hub url --signature "ed25519=..." < body
 *   openaccess token                        print a live access token for scripts
 *
 * The hub is --hub, else $OPENACCESS_HUB, else the one you logged in to, else http://127.0.0.1:8791.
 * --json prints the payload and nothing else.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { OpenAccessApp, OpenAccessClient, descriptorTemplate } from "./client.ts";
import { Store } from "./db.ts";
import { exportPrivateJwk, generateSigningKey, verifyBody } from "./jwt.ts";
import { resendMailer } from "./mail.ts";
import { serve, VERSION } from "./server.ts";
import { appId, parseScope, type Jwk } from "./spec.ts";

type Flags = Record<string, string | boolean>;

function parse(argv: string[]): { positional: string[]; flags: Flags } {
  const positional: string[] = [];
  const flags: Flags = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index] as string;
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const [key, inline] = arg.slice(2).split("=", 2);
    const name = (key as string).replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
    if (inline !== undefined) flags[name] = inline;
    else if (index + 1 < argv.length && !(argv[index + 1] as string).startsWith("--")) flags[name] = argv[++index] as string;
    else flags[name] = true;
  }
  return { positional, flags };
}

const out = (line = ""): void => {
  process.stdout.write(`${line}\n`);
};
const str = (flags: Flags, key: string): string | undefined => (typeof flags[key] === "string" ? (flags[key] as string) : undefined);

const CONFIG_DIR = process.env.OPENACCESS_CONFIG_DIR ?? join(homedir(), ".config", "openaccess");
const CREDENTIALS = join(CONFIG_DIR, "credentials.json");

interface Credentials {
  hub: string;
  client_id: string;
  access_token: string;
  refresh_token: string;
  expires_at: number;
  sub: string;
}

const readCredentials = (): Credentials | null => (existsSync(CREDENTIALS) ? (JSON.parse(readFileSync(CREDENTIALS, "utf8")) as Credentials) : null);
const writeCredentials = (value: Credentials): void => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CREDENTIALS, JSON.stringify(value, null, 2), { mode: 0o600 });
};

const HELP = `openaccess ${VERSION}: OAuth 2.1 with a grant you can carry.

  serve [--port 8791] [--db openaccess.db] [--url https://hub.example] [--admin-token t]
  login [--hub url] [--scope "hub:manage"]      sign in from a terminal (device flow)
  logout | whoami | me                          who you are; everything the hub holds for you
  grants | grant <id> | revoke <id>             what you gave each app; revoke one and every child
  delegate --grant <id> --scope "a b" [--for <openprofile url>] [--per-call "5 USD"] [--per-day ..] [--lifetime ..] [--days 7]
  entitlements | cancel <id> | check <product>  what you pay for, wherever it is honoured
  apps [q] | app add <url> | app show <id> | app refresh <id> | app rm <id> --token <admin>
  keygen                                        an Ed25519 key for an app's descriptor
  descriptor <site url> [--name n] [--jwk file] a /.well-known/openaccess.json to start from
  report --key file --client-id id --sub oa_.. --product host/slug --status active [--end date] [--receipt url]
  verify-webhook --hub url --signature sig < body
  token                                         a live access token, for scripts

  --hub <url>   the hub (or $OPENACCESS_HUB; default: where you logged in, else http://127.0.0.1:8791)
  --json        print the payload and nothing else

Spec: https://logicsrc.com/openaccess`;

export async function main(argv: string[]): Promise<number> {
  const { positional, flags } = parse(argv);
  const [command, ...rest] = positional;
  const json = flags.json === true;
  const print = (value: unknown, lines: () => void): void => (json ? out(JSON.stringify(value, null, 2)) : lines());

  if (!command || command === "help" || flags.help === true) {
    out(HELP);
    return 0;
  }

  if (command === "serve") {
    const port = Number(flags.port ?? process.env.PORT ?? 8791);
    const url = String(flags.url ?? process.env.OPENACCESS_URL ?? `http://127.0.0.1:${port}`);
    const store = new Store(String(flags.db ?? process.env.OPENACCESS_DB ?? "openaccess.db"));
    const adminToken = str(flags, "adminToken") ?? process.env.OPENACCESS_ADMIN_TOKEN;
    const log = (line: string): void => out(`${new Date().toISOString()}  ${line}`);
    const resend = process.env.RESEND_API_KEY;
    const running = serve({
      store,
      url,
      port,
      adminToken,
      name: process.env.OPENACCESS_NAME,
      operator: process.env.OPENACCESS_OPERATOR,
      log,
      ...(resend ? { mailer: resendMailer(resend, process.env.MAIL_FROM ?? "OpenAccess <openaccess@localhost>") } : {}),
      refreshEveryMs: Number(process.env.OPENACCESS_REFRESH_MINUTES ?? 30) * 60_000,
    });
    log(`openaccess hub ${VERSION} on :${port} as ${url} (${store.countApps()} apps, ${store.countPrincipals()} principals${resend ? "" : ", no RESEND_API_KEY: sign-in links are logged here"}${adminToken ? "" : ", no admin token: app removal is off"})`);
    const stop = (): void => {
      running.stop();
      store.close();
      process.exit(0);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    await new Promise(() => {});
    return 0;
  }

  if (command === "keygen") {
    const key = generateSigningKey();
    const priv = exportPrivateJwk(key);
    print({ private: priv, public: key.jwk }, () => {
      out("Private JWK, keep it (this is the app's credential):");
      out(JSON.stringify(priv));
      out("");
      out("Public JWK, put it in the descriptor's jwks.keys:");
      out(JSON.stringify(key.jwk));
    });
    return 0;
  }

  if (command === "descriptor") {
    const site = rest[0];
    if (!site) throw new Error("Usage: openaccess descriptor <site url> [--name n] [--jwk file]");
    const jwkFile = str(flags, "jwk");
    const jwk = jwkFile ? (JSON.parse(readFileSync(jwkFile, "utf8")) as { public?: Jwk } & Jwk) : undefined;
    out(JSON.stringify(descriptorTemplate(site, { name: str(flags, "name"), hub: str(flags, "hub"), jwk: jwk?.public ?? (jwk?.x ? { kty: jwk.kty, crv: jwk.crv, kid: jwk.kid, x: jwk.x, alg: "EdDSA", use: "sig" } : undefined) }), null, 2));
    return 0;
  }

  if (command === "verify-webhook") {
    const hubUrl = str(flags, "hub") ?? process.env.OPENACCESS_HUB;
    const signature = str(flags, "signature");
    if (!hubUrl || !signature) throw new Error("Usage: openaccess verify-webhook --hub url --signature sig < body");
    const keys = ((await (await fetch(`${hubUrl.replace(/\/+$/, "")}/.well-known/jwks.json`)).json()) as { keys: Jwk[] }).keys;
    const good = verifyBody(readFileSync(0, "utf8"), signature, keys);
    out(good ? "Signature matches." : "Signature does NOT match.");
    return good ? 0 : 1;
  }

  if (command === "report") {
    const keyFile = str(flags, "key");
    const clientId = str(flags, "clientId");
    const hubUrl = str(flags, "hub") ?? process.env.OPENACCESS_HUB ?? readCredentials()?.hub;
    if (!keyFile || !clientId || !hubUrl || !str(flags, "sub") || !str(flags, "product") || !str(flags, "status")) throw new Error("Usage: openaccess report --key file --client-id id --sub oa_.. --product host/slug --status active [--end date] [--receipt url] [--hub url]");
    const parsed = JSON.parse(readFileSync(keyFile, "utf8")) as { private?: Jwk } & Jwk;
    const app = new OpenAccessApp({ hub: hubUrl, clientId, key: parsed.private ?? parsed });
    const outcome = await app.report({ sub: str(flags, "sub") as string, product: str(flags, "product") as string, status: str(flags, "status") as never, period: { ...(str(flags, "start") ? { start: str(flags, "start") } : {}), ...(str(flags, "end") ? { end: str(flags, "end") } : {}) }, receipt: str(flags, "receipt") });
    print(outcome, () => out(`${outcome.entitlement.product} for ${outcome.entitlement.principal}: ${outcome.entitlement.status}${outcome.event ? ` (${outcome.event}, told ${outcome.honouredBy.join(", ")})` : " (no change)"}`));
    return 0;
  }

  const saved = readCredentials();
  const hubUrl = (str(flags, "hub") ?? process.env.OPENACCESS_HUB ?? saved?.hub ?? "http://127.0.0.1:8791").replace(/\/+$/, "");

  if (command === "login") {
    const clientId = appId(hubUrl);
    const app = new OpenAccessApp({ hub: hubUrl, clientId });
    const started = await app.device(str(flags, "scope") ?? "hub:manage");
    out(`Open ${started.verification_uri_complete}`);
    out(`and confirm the code ${started.user_code}. Waiting...`);
    const tokens = await app.pollDevice(started.device_code, started.interval);
    writeCredentials({ hub: hubUrl, client_id: clientId, access_token: tokens.access_token, refresh_token: tokens.refresh_token, expires_at: Date.now() + tokens.expires_in * 1000, sub: tokens.sub });
    out(`Signed in as ${tokens.sub} at ${hubUrl}.`);
    return 0;
  }

  if (command === "logout") {
    if (existsSync(CREDENTIALS)) unlinkSync(CREDENTIALS);
    out("Signed out.");
    return 0;
  }

  /** A live access token: refresh it when it is within a minute of expiry. */
  const accessToken = async (): Promise<string | undefined> => {
    const explicit = str(flags, "token") ?? process.env.OPENACCESS_TOKEN;
    if (explicit) return explicit;
    if (!saved || saved.hub !== hubUrl) return undefined;
    if (saved.expires_at - Date.now() > 60_000) return saved.access_token;
    const app = new OpenAccessApp({ hub: hubUrl, clientId: saved.client_id });
    const tokens = await app.refresh(saved.refresh_token);
    writeCredentials({ ...saved, access_token: tokens.access_token, refresh_token: tokens.refresh_token, expires_at: Date.now() + tokens.expires_in * 1000 });
    return tokens.access_token;
  };

  if (command === "token") {
    const token = await accessToken();
    if (!token) throw new Error("Not signed in. openaccess login");
    out(token);
    return 0;
  }

  const client = new OpenAccessClient({ hub: hubUrl, token: await accessToken(), adminToken: str(flags, "token") ?? process.env.OPENACCESS_TOKEN });

  switch (command) {
    case "whoami":
    case "me": {
      const me = await client.me();
      print(me, () => {
        out(`${me.principal.email ?? me.principal.profile ?? me.principal.id}  (${me.principal.id}, ${me.principal.kind}) at ${hubUrl}`);
        out(`${me.links.length} apps linked, ${me.grants.length} grants, ${me.entitlements.length} entitlements`);
        for (const link of me.links) out(`  ${link.name.padEnd(28)} ${link.grant ? link.grant.scope.join(" ") : "no grant"}`);
        for (const e of me.entitlements) out(`  ${e.product.padEnd(28)} ${e.status.padEnd(9)} honoured by ${e.honouredBy.join(", ")}`);
      });
      return 0;
    }
    case "grants": {
      const { grants } = await client.grants({ app: str(flags, "app"), all: flags.all === true });
      print(grants, () => {
        if (!grants.length) out("No grants.");
        for (const g of grants) out(`${g.id}  ${g.status.padEnd(7)} ${g.app.padEnd(28)} ${g.parent ? `child of ${g.parent}` : "root".padEnd(22)}  ${g.scope.join(" ")}${g.holder ? `  held by ${g.holder}` : ""}`);
      });
      return 0;
    }
    case "grant": {
      if (!rest[0]) throw new Error("Usage: openaccess grant <id>");
      const shown = await client.grant(rest[0]);
      print(shown, () => {
        out(JSON.stringify(shown.grant, null, 2));
        for (const child of shown.children) out(`child ${child.id} ${child.status} ${child.scope.join(" ")}`);
      });
      return 0;
    }
    case "revoke": {
      if (!rest[0]) throw new Error("Usage: openaccess revoke <id>");
      const { revoked } = await client.revoke(rest[0]);
      print(revoked, () => out(`Revoked ${revoked.map((g) => g.id).join(", ")}.`));
      return 0;
    }
    case "delegate": {
      const scope = str(flags, "scope");
      if (!scope) throw new Error("Usage: openaccess delegate --grant <id> --scope \"a b\" [--for url] [--per-call ..] [--per-day ..] [--lifetime ..] [--days n]");
      const days = Number(str(flags, "days") ?? "0");
      const made = await client.delegate({ grant: str(flags, "grant"), for: str(flags, "for"), scope: parseScope(scope).join(" "), limits: { ...(str(flags, "perCall") ? { per_call: str(flags, "perCall") } : {}), ...(str(flags, "perDay") ? { per_day: str(flags, "perDay") } : {}), ...(str(flags, "lifetime") ? { lifetime: str(flags, "lifetime") } : {}) }, ...(days > 0 ? { expires_in: days * 86400 } : {}) });
      print(made, () => {
        out(`Delegated ${made.grant.id}: ${made.grant.scope.join(" ")}${Object.keys(made.grant.limits).length ? `  limits ${JSON.stringify(made.grant.limits)}` : ""}`);
        out(`Refresh token (shown once): ${made.refresh_token}`);
        out(`The agent redeems it: POST ${made.token_endpoint} grant_type=refresh_token&client_id=${made.client_id}&refresh_token=...`);
      });
      return 0;
    }
    case "entitlements": {
      const { entitlements } = await client.entitlements();
      print(entitlements, () => {
        if (!entitlements.length) out("No entitlements.");
        for (const e of entitlements) {
          out(`${e.id}  ${e.product.padEnd(28)} ${e.status.padEnd(9)} sold by ${e.seller}, honoured by ${e.honouredBy.join(", ")}`);
          for (const [k, v] of Object.entries(e.links)) out(`    ${k.padEnd(8)} ${v}`);
        }
      });
      return 0;
    }
    case "cancel": {
      if (!rest[0]) throw new Error("Usage: openaccess cancel <entitlement id>");
      const outcome = await client.cancel(rest[0]);
      print(outcome, () => out(`Asked ${outcome.entitlement.seller} to cancel ${outcome.entitlement.product}.${outcome.cancel ? ` Or cancel there: ${outcome.cancel}` : ""}`));
      return 0;
    }
    case "check": {
      if (!rest[0]) throw new Error("Usage: openaccess check <product>");
      const outcome = await client.check(rest[0]);
      print(outcome, () => out(outcome.held ? `Held (${outcome.status}).` : `Not held${outcome.status ? ` (${outcome.status})` : ""}.`));
      return outcome.held ? 0 : 1;
    }
    case "apps": {
      const { apps } = await client.apps(rest.join(" ") || undefined);
      print(apps, () => {
        if (!apps.length) out("No apps. openaccess app add <url> registers one.");
        for (const a of apps) out(`${a.verified ? "✓" : " "} ${a.id.padEnd(30)} ${Object.keys(a.descriptor.scopes ?? {}).length.toString().padStart(2)} scopes ${(a.descriptor.offers ?? []).length.toString().padStart(2)} offers  ${a.descriptor.name ?? ""}`);
      });
      return 0;
    }
    case "app": {
      const [sub, arg] = rest;
      if (!arg) throw new Error("Usage: openaccess app add|show|refresh|rm <url or id>");
      switch (sub) {
        case "add": {
          const { app } = await client.registerApp(arg);
          print(app, () => out(`${app.id}: ${app.verified ? "verified" : "unverified"}, ${Object.keys(app.descriptor.scopes ?? {}).length} scopes, ${(app.descriptor.offers ?? []).length} offers, honours ${(app.descriptor.honours ?? []).join(", ") || "nothing"}.`));
          return 0;
        }
        case "show": {
          const { app } = await client.app(arg);
          print(app, () => out(JSON.stringify(app, null, 2)));
          return 0;
        }
        case "refresh": {
          const { app } = await client.refreshApp(arg);
          print(app, () => out(`${app.id}: ${app.lastError ?? "refreshed"}`));
          return 0;
        }
        case "rm":
          await client.removeApp(arg);
          out(`Removed ${arg}.`);
          return 0;
        default:
          throw new Error("Usage: openaccess app add|show|refresh|rm <url or id>");
      }
    }
    default:
      out(HELP);
      return 1;
  }
}
