/**
 * The hub's pages: a landing, sign in, consent, the device code, the apps
 * directory, and the dashboard where a person sees every app, every grant
 * and every subscription in one place. Server-rendered HTML, no framework,
 * one stylesheet.
 */
import type { AppRecord, Entitlement, Grant, Link, Offer, Principal } from "./spec.ts";
import { fillLink } from "./spec.ts";

export const esc = (value: unknown): string => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch] as string);

const CSS = `
:root{color-scheme:dark light;--bg:oklch(17% .012 250);--bg-2:oklch(20% .012 250);--card:oklch(22% .013 250);--fg:oklch(95% .006 90);--mute:oklch(70% .012 250);--line:oklch(30% .014 250);--accent:oklch(80% .15 190);--accent-ink:oklch(20% .04 190);--good:oklch(78% .15 150);--bad:oklch(72% .16 25);--warn:oklch(82% .14 85);--display:"Space Grotesk",system-ui,sans-serif;--body:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
@media(prefers-color-scheme:light){:root{--bg:oklch(98% .005 90);--bg-2:oklch(96% .006 90);--card:#fff;--fg:oklch(22% .012 250);--mute:oklch(48% .014 250);--line:oklch(88% .008 250);--accent:oklch(52% .14 190);--accent-ink:#fff;--good:oklch(52% .15 150);--bad:oklch(52% .17 25);--warn:oklch(60% .14 85)}}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 var(--body);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline;text-underline-offset:3px}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
header.top{border-bottom:1px solid var(--line);background:color-mix(in oklab,var(--bg) 85%,transparent);backdrop-filter:blur(8px);position:sticky;top:0;z-index:5}
header.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:1rem;height:60px}
.brand{display:flex;align-items:center;gap:.6rem;color:var(--fg);font:600 17px var(--display);letter-spacing:-.01em}.brand:hover{text-decoration:none}
.brand svg{width:24px;height:24px}.brand small{font:500 12px var(--body);color:var(--mute);letter-spacing:0;margin-left:.2rem}
nav.top{display:flex;align-items:center;gap:1.1rem;font-size:14px}nav.top a{color:var(--mute)}nav.top a:hover{color:var(--fg);text-decoration:none}nav.top a.btn{color:var(--accent-ink)}nav.top a.btn:hover{color:var(--accent-ink)}nav.top form{display:inline}
main{padding:2.5rem 0 5rem}
h1{font:600 clamp(1.7rem,3.6vw,2.6rem)/1.15 var(--display);letter-spacing:-.02em;margin:0 0 .6rem}
h2{font:600 1.15rem/1.3 var(--display);letter-spacing:-.01em;margin:2.4rem 0 .8rem;display:flex;align-items:baseline;gap:.6rem}h2 .count{font:500 12px var(--body);color:var(--mute)}
p{margin:.4rem 0}.mute{color:var(--mute)}.lead{font-size:1.1rem;color:var(--mute);max-width:56ch}
.eyebrow{font:500 12px var(--body);letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin:0 0 .8rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.25rem;margin:.7rem 0}
.row{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:center}
code{font:13px var(--mono);background:var(--bg-2);border:1px solid var(--line);padding:.1rem .4rem;border-radius:5px}
pre{font:13px/1.55 var(--mono);background:var(--bg-2);border:1px solid var(--line);border-radius:12px;padding:1rem 1.2rem;overflow:auto;margin:0}pre code{background:none;border:0;padding:0}
.pill{display:inline-block;font:500 12px var(--body);padding:.15rem .55rem;border:1px solid var(--line);border-radius:999px;margin:.15rem .25rem .15rem 0;color:var(--mute)}
.pill.good{color:var(--good);border-color:color-mix(in oklab,var(--good) 50%,var(--line))}.pill.bad{color:var(--bad);border-color:color-mix(in oklab,var(--bad) 50%,var(--line))}
form{display:inline}input,select,textarea{font:inherit;padding:.55rem .7rem;border:1px solid var(--line);border-radius:8px;background:var(--bg-2);color:var(--fg);max-width:100%}
input:focus,select:focus,textarea:focus{outline:2px solid color-mix(in oklab,var(--accent) 60%,transparent);outline-offset:1px;border-color:var(--accent)}
button,.btn{font:500 14px var(--body);padding:.6rem 1.05rem;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);cursor:pointer;text-decoration:none;display:inline-block;line-height:1.2}
button:hover,.btn:hover{text-decoration:none;filter:brightness(1.08)}
button.quiet,.btn.quiet{background:transparent;color:var(--fg);border-color:var(--line)}button.quiet:hover,.btn.quiet:hover{border-color:var(--mute)}
button.danger{background:transparent;color:var(--bad);border-color:color-mix(in oklab,var(--bad) 50%,var(--line))}
.links a{margin-right:.9rem;font-size:14px}label{display:block;margin:.5rem 0}
details summary{cursor:pointer;color:var(--mute);font-size:14px}details[open] summary{margin-bottom:.5rem}
.notice{border-color:color-mix(in oklab,var(--accent) 50%,var(--line));background:color-mix(in oklab,var(--accent) 8%,var(--card))}
.grid{display:grid;gap:1rem;grid-template-columns:repeat(3,minmax(0,1fr))}@media(max-width:760px){.grid{grid-template-columns:1fr}}
.feature{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.3rem 1.3rem 1.4rem}.feature svg{width:24px;height:24px;color:var(--accent);margin-bottom:.8rem}
.feature h3{font:600 1rem var(--display);margin:0 0 .35rem;letter-spacing:-.01em}.feature p{color:var(--mute);font-size:14px;margin:0}
.hero{padding:2.5rem 0 1.5rem;display:grid;gap:2.5rem;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);align-items:center}@media(max-width:860px){.hero{grid-template-columns:1fr}}
.cta{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:1.4rem;align-items:center}.cta a.plain{color:var(--mute);font-size:14px;margin-left:.3rem}
.stats{display:flex;gap:2rem;flex-wrap:wrap;margin-top:2rem;color:var(--mute);font-size:14px}.stats strong{display:block;font:600 1.5rem var(--display);color:var(--fg);letter-spacing:-.02em}
table.t{width:100%;border-collapse:collapse;font-size:14px}table.t th{text-align:left;color:var(--mute);font-weight:500;padding:.5rem .6rem;border-bottom:1px solid var(--line)}table.t td{padding:.6rem;border-bottom:1px solid var(--line);vertical-align:top}
footer.pfs-footer{padding:0}footer{border-top:1px solid var(--line);color:var(--mute);font-size:13px;padding:1.5rem 0}footer .wrap{display:flex;gap:1.2rem;flex-wrap:wrap;justify-content:space-between}footer a{color:var(--mute)}
ul.plain{list-style:none;padding:0;margin:.3rem 0}ul.plain li{margin:.2rem 0}
`;

const LOGO = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="12" r="5"/><path d="M13 12h8M17 12v3M20 12v2"/></svg>`;
const ICONS = {
  link: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.1 0l3-3a5 5 0 0 0-7.1-7.1l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7.1 0l-3 3a5 5 0 0 0 7.1 7.1l1.5-1.5"/></svg>`,
  branch: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="5" r="2.5"/><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="9" r="2.5"/><path d="M6 7.5v9M18 11.5a6 6 0 0 1-6 6H8.5"/></svg>`,
  carry: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="7" width="18" height="13" rx="2.5"/><path d="M8 7V5.5A2.5 2.5 0 0 1 10.5 3h3A2.5 2.5 0 0 1 16 5.5V7M3 12h18"/></svg>`,
};

export interface LayoutOptions {
  hubName: string;
  principal?: Principal | null;
  csrf?: string;
  /** Page-level description for the head. */
  description?: string;
  /** Extra HTML after the site footer: the Profullstack network footer when it is on. */
  footer?: string;
}

export function layout(title: string, body: string, options: LayoutOptions): string {
  const nav = options.principal
    ? `<nav class="top"><a href="/">Dashboard</a><a href="/apps">Apps</a><a href="https://logicsrc.com/openaccess">Spec</a><form method="post" action="/auth/signout"><input type="hidden" name="csrf" value="${esc(options.csrf ?? "")}"><button class="quiet" style="padding:.35rem .7rem;font-size:13px">Sign out</button></form></nav>`
    : `<nav class="top"><a href="/apps">Apps</a><a href="https://logicsrc.com/openaccess">Spec</a><a href="https://github.com/logicsrc/openaccess">GitHub</a><a class="btn" style="padding:.4rem .85rem;font-size:13px" href="/auth">Sign in</a></nav>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · ${esc(options.hubName)}</title><meta name="description" content="${esc(options.description ?? "OAuth 2.1 with a grant you can carry. One account, every app you use, and the subscriptions you paid for, honoured wherever they are honoured.")}"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono&display=swap"><style>${CSS}</style></head><body><header class="top"><div class="wrap"><a class="brand" href="/">${LOGO}${esc(options.hubName)}<small>by LogicSRC</small></a>${nav}</div></header><main><div class="wrap">${body}</div></main><footer><div class="wrap"><span>An open standard. Spec CC BY 4.0, reference hub MIT.</span><span><a href="https://logicsrc.com/openaccess">Specification</a> · <a href="https://github.com/logicsrc/openaccess">Source</a> · <a href="https://www.npmjs.com/package/@logicsrc/openaccess">npm</a> · <a href="https://openmcp.logicsrc.com/">OpenMCP catalog</a> · <a href="/.well-known/openaccess.json">Descriptor</a></span></div></footer>${options.footer ?? ""}</body></html>`;
}

export function landingPage(input: { apps: number; principals: number; hubUrl: string }): string {
  return `<section class="hero"><div><p class="eyebrow">An open standard for agents, apps and the people behind them</p><h1>OAuth 2.1 with a grant you can carry.</h1><p class="lead">One account here. Every app you use keeps its own users and links to it once. What you gave each app, and what you paid for, stays yours: hand a narrower grant to an agent, and take a subscription with you to every app that honours it.</p>
<div class="cta"><a class="btn" href="/auth">Sign in</a><a class="btn quiet" href="/apps">Browse the apps</a><a class="plain" href="https://logicsrc.com/openaccess">Read the spec</a></div>
<div class="stats"><div><strong>${input.apps}</strong>${input.apps === 1 ? "app" : "apps"} listed</div><div><strong>${input.principals}</strong>${input.principals === 1 ? "principal" : "principals"}</div><div><strong>Ed25519</strong>tokens, verified offline</div></div></div>
<pre><code>{
  "iss": "${esc(input.hubUrl)}",
  "sub": "oa_7f3c9e2a",
  "aud": "agenticjobs.work",
  "scope": "openid email jobs:read entitlements",
  "grant": "g_2b1e",  "parent": "g_0a9d",
  "limits": { "per_day": "50 USD" },
  "entitlements": ["profullstack.com/all-access"]
}</code></pre></section>
<section class="grid" style="margin-top:2rem"><div class="feature">${ICONS.link}<h3>Link, once</h3><p>Plain authorization code with PKCE, or a device code from a terminal. The app stores your <code>sub</code> beside its own user and nothing else changes.</p></div>
<div class="feature">${ICONS.branch}<h3>Delegate, narrower</h3><p>A grant hands down to an agent with fewer scopes, smaller limits and an earlier expiry. Revoke the parent and every child goes with it.</p></div>
<div class="feature">${ICONS.carry}<h3>Carry what you paid for</h3><p>A seller reports a sale as itself. Every app that honours the product hears, and your tokens carry it from then on. The hub keeps standing, not money.</p></div></section>
<section style="margin-top:3rem" class="card"><div class="row"><div><strong style="font-family:var(--display)">Run one, or adopt it in an app</strong><p class="mute" style="margin:.2rem 0 0">Node 24, one SQLite file, two dependencies. <code>npx @logicsrc/openaccess serve</code> runs a hub; <code>openaccess keygen</code> and <code>openaccess descriptor https://your.site</code> get an app started.</p></div><a class="btn quiet" href="https://github.com/logicsrc/openaccess">github.com/logicsrc/openaccess</a></div></section>`;
}

export function signInPage(options: { next: string | null; sent?: string; error?: string }): string {
  if (options.sent) return `<div style="max-width:460px"><p class="eyebrow">Check your mail</p><h1>A link is on its way</h1><p class="mute">Sent to <strong>${esc(options.sent)}</strong>. It works once, for fifteen minutes.</p></div>`;
  return `<div style="max-width:460px"><p class="eyebrow">Sign in</p><h1>Your email, and a link comes back.</h1><p class="mute">No password, ever. The same account works for every app that speaks OpenAccess.</p>${options.error ? `<p style="color:var(--bad)">${esc(options.error)}</p>` : ""}
<form method="post" action="/auth/start" style="display:block;margin-top:1.2rem"><input type="hidden" name="next" value="${esc(options.next ?? "")}"><label>Email <input type="email" name="email" required autofocus placeholder="you@example.com" style="width:100%"></label><button>Send the link</button></form></div>`;
}

export interface ConsentView {
  app: AppRecord;
  scopes: string[];
  honoured: string[];
  action: string;
  fields: Record<string, string>;
  csrf: string;
  device?: string;
}

export function consentPage(view: ConsentView): string {
  const { app } = view;
  const lines = view.scopes.map((scope) => `<li><code>${esc(scope)}</code> ${esc(app.descriptor.scopes?.[scope] ?? reservedLine(scope))}</li>`).join("");
  const hidden = Object.entries(view.fields).map(([name, value]) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`).join("");
  return `<div style="max-width:620px"><p class="eyebrow">Consent</p><h1>${esc(app.descriptor.name ?? app.id)} wants access</h1>
<p class="mute">${esc(app.descriptor.url ?? app.id)}${app.descriptor.operator ? ` · operated by <a href="${esc(app.descriptor.operator)}">${esc(app.descriptor.operator)}</a>` : " · no operator stated"}${app.verified ? "" : ' · <span class="pill bad">unverified</span>'}</p>
${view.device ? `<p>For the device showing code <strong>${esc(view.device)}</strong>.</p>` : ""}
<div class="card"><p><strong>It will be able to</strong></p><ul>${lines}</ul>
${view.scopes.includes("entitlements") ? `<p><strong>It will see</strong> ${view.honoured.length ? `that you hold ${view.honoured.map((product) => `<code>${esc(product)}</code>`).join(", ")}` : "which of the products it honours you hold (none right now)"}.</p>` : ""}
</div>
<form method="post" action="${esc(view.action)}" style="display:block"><input type="hidden" name="csrf" value="${esc(view.csrf)}">${hidden}<button name="decision" value="approve">Allow</button> <button class="quiet" name="decision" value="deny">Deny</button></form></div>`;
}

function reservedLine(scope: string): string {
  return { openid: "Know it is you", profile: "See your profile", email: "See your email address", entitlements: "See which of the products it honours you hold", "grants:delegate": "Hand narrower grants to agents on your behalf", "hub:manage": "Manage your grants and subscriptions at this hub" }[scope] ?? "";
}

export function devicePage(options: { userCode?: string; error?: string; done?: "approved" | "denied" }): string {
  if (options.done) return `<div style="max-width:460px"><p class="eyebrow">Device</p><h1>${options.done === "approved" ? "Approved" : "Denied"}</h1><p class="mute">You can go back to the device.</p></div>`;
  return `<div style="max-width:460px"><p class="eyebrow">Device</p><h1>Enter the code</h1><p class="mute">The eight letters your terminal or device is showing.</p>${options.error ? `<p style="color:var(--bad)">${esc(options.error)}</p>` : ""}
<form method="get" action="/device/verify" style="display:block;margin-top:1rem"><input name="user_code" value="${esc(options.userCode ?? "")}" placeholder="XXXX-XXXX" autofocus style="text-transform:uppercase;letter-spacing:.15em;font-family:var(--mono)"> <button>Continue</button></form></div>`;
}

export interface DashboardView {
  principal: Principal;
  links: Link[];
  apps: Map<string, AppRecord>;
  grants: Grant[];
  entitlements: Entitlement[];
  csrf: string;
  notice?: string;
  hubId: string;
}

export function dashboardPage(view: DashboardView): string {
  const { principal, csrf } = view;
  const appName = (appId: string): string => view.apps.get(appId)?.descriptor.name ?? appId;
  const roots = view.grants.filter((grant) => !grant.parent && grant.app !== view.hubId);
  const children = view.grants.filter((grant) => grant.parent);

  const linksHtml = view.links.length
    ? view.links
        .map((link) => {
          const grant = roots.find((root) => root.app === link.app);
          return `<div class="card"><div class="row"><div><strong style="font-family:var(--display)">${esc(appName(link.app))}</strong> <span class="mute">${esc(view.apps.get(link.app)?.descriptor.url ?? link.app)}</span><br>${grant ? grant.scope.map((scope) => `<span class="pill">${esc(scope)}</span>`).join("") : '<span class="mute">no grant</span>'}${grant?.expiresAt ? `<span class="pill">until ${esc(grant.expiresAt.slice(0, 10))}</span>` : ""}</div>
<div>${grant ? `<form method="post" action="/ui/grants/${esc(grant.id)}/revoke"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="danger">Revoke</button></form> ` : ""}<form method="post" action="/ui/links/${esc(link.app)}/remove"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="quiet">Unlink</button></form></div></div></div>`;
        })
        .join("")
    : `<p class="mute">No app is linked yet. When an app sends you here to sign in, it appears in this list.</p>`;

  const entitlementsHtml = view.entitlements.length
    ? view.entitlements
        .map((entitlement) => {
          const seller = view.apps.get(entitlement.seller);
          const offer = seller?.descriptor.offers?.find((candidate) => candidate.product === entitlement.product);
          const honouredBy = Array.from(view.apps.values()).filter((app) => (app.descriptor.honours ?? []).includes(entitlement.product) && app.id !== entitlement.seller);
          const good = ["active", "trialing"].includes(entitlement.status);
          return `<div class="card"><div class="row"><div><strong style="font-family:var(--display)">${esc(offer?.name ?? entitlement.product)}</strong> <span class="mute">${esc(entitlement.product)}</span> <span class="pill ${good ? "good" : "bad"}">${esc(entitlement.status)}</span>${entitlement.cancelRequestedAt ? '<span class="pill">cancel requested</span>' : ""}
<br><span class="mute">${offer?.price ? esc(offer.price) + " · " : ""}sold by ${esc(appName(entitlement.seller))}${entitlement.period.end ? ` · until ${esc(entitlement.period.end.slice(0, 10))}` : ""}${honouredBy.length ? ` · also honoured by ${honouredBy.map((app) => esc(app.descriptor.name ?? app.id)).join(", ")}` : ""}</span>
<div class="links">${offerLinks(offer, principal.id, ["pay", "manage", "upgrade", "promote", "support"])}${entitlement.receipt ? `<a href="${esc(entitlement.receipt)}">receipt</a>` : ""}</div></div>
<div>${good && !entitlement.cancelRequestedAt ? `<form method="post" action="/ui/entitlements/${esc(entitlement.id)}/cancel"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="danger">Cancel</button></form>` : offer?.links?.cancel ? `<a class="btn quiet" href="${esc(fillLink(offer.links.cancel, principal.id))}">Cancel at seller</a>` : ""}</div></div></div>`;
        })
        .join("")
    : `<p class="mute">Nothing yet. When an app you linked reports a subscription, it appears here and travels with you to every app that honours it.</p>`;

  const offers = Array.from(view.apps.values()).flatMap((app) => (app.descriptor.offers ?? []).map((offer) => ({ app, offer }))).filter(({ offer }) => !view.entitlements.some((entitlement) => entitlement.product === offer.product && ["active", "trialing"].includes(entitlement.status)));
  const offersHtml = offers.length
    ? `<h2>Available <span class="count">${offers.length}</span></h2>${offers.map(({ app, offer }) => `<div class="card"><div class="row"><div><strong style="font-family:var(--display)">${esc(offer.name ?? offer.product)}</strong> <span class="mute">${esc(offer.product)}${offer.price ? " · " + esc(offer.price) : ""} · from ${esc(app.descriptor.name ?? app.id)}</span><br><span class="mute">Honoured by ${Array.from(view.apps.values()).filter((candidate) => (candidate.descriptor.honours ?? []).includes(offer.product)).map((candidate) => esc(candidate.descriptor.name ?? candidate.id)).join(", ") || "the seller"}</span></div><div class="links">${offerLinks(offer, principal.id, ["pay"], "btn")}</div></div></div>`).join("")}`
    : "";

  const agentsHtml = children.length
    ? children
        .map((grant) => `<div class="card"><div class="row"><div><strong style="font-family:var(--display)">${esc(grant.holder ?? "bearer")}</strong> <span class="mute">on ${esc(appName(grant.app))} · from <code>${esc(grant.parent ?? "")}</code></span><br>${grant.scope.map((scope) => `<span class="pill">${esc(scope)}</span>`).join("")}${Object.entries(grant.limits).map(([key, value]) => `<span class="pill">${esc(key)} ${esc(value)}</span>`).join("")}${grant.expiresAt ? `<span class="pill">until ${esc(grant.expiresAt.slice(0, 10))}</span>` : ""}</div>
<form method="post" action="/ui/grants/${esc(grant.id)}/revoke"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="danger">Revoke</button></form></div></div>`)
        .join("")
    : `<p class="mute">No agent holds a grant from you.</p>`;

  const delegateForm = roots.length
    ? `<details><summary>Hand a narrower grant to an agent</summary><form method="post" action="/ui/grants/delegate" style="display:block" class="card"><input type="hidden" name="csrf" value="${esc(csrf)}">
<label>From <select name="grant">${roots.map((grant) => `<option value="${esc(grant.id)}">${esc(appName(grant.app))}: ${esc(grant.scope.join(" "))}</option>`).join("")}</select></label>
<label>For <input name="for" placeholder="https://bot.example/.well-known/openprofile.md (optional)" style="width:100%"></label>
<label>Scopes <input name="scope" placeholder="jobs:read jobs:apply" style="width:100%"></label>
<div class="row"><label>Per call <input name="per_call" placeholder="5 USD"></label><label>Per day <input name="per_day" placeholder="50 USD"></label><label>Lifetime <input name="lifetime" placeholder="500 USD"></label><label>Days <input name="days" type="number" min="1" placeholder="7"></label></div>
<button>Create</button> <span class="mute">The refresh token is shown once.</span></form></details>`
    : "";

  return `${view.notice ? `<div class="card notice">${view.notice}</div>` : ""}
<p class="eyebrow">Dashboard</p><h1>${esc(principal.email ?? principal.profile ?? principal.id)}</h1><p class="mute"><code>${esc(principal.id)}</code> · ${esc(principal.kind)}${principal.profile ? ` · <a href="${esc(principal.profile)}">${esc(principal.profile)}</a>` : ""}</p>
<details><summary>Profile</summary><form method="post" action="/ui/profile" style="display:block" class="card"><input type="hidden" name="csrf" value="${esc(csrf)}"><label>OpenProfile.md URL <input name="profile" value="${esc(principal.profile ?? "")}" placeholder="https://you.example/.well-known/openprofile.md" style="width:100%"></label><button class="quiet">Save</button></form></details>
<h2>Subscriptions <span class="count">${view.entitlements.length}</span></h2>${entitlementsHtml}${offersHtml}
<h2>Apps you linked <span class="count">${view.links.length}</span></h2>${linksHtml}
<h2>Agents <span class="count">${children.length}</span></h2>${agentsHtml}${delegateForm}`;
}

function offerLinks(offer: Offer | undefined, principal: string, keys: Array<keyof NonNullable<Offer["links"]>>, cls = ""): string {
  if (!offer?.links) return "";
  return keys
    .filter((key) => offer.links?.[key])
    .map((key) => `<a class="${cls}" href="${esc(fillLink(offer.links?.[key] as string, principal))}">${esc(key)}</a>`)
    .join(" ");
}

export function appsPage(apps: AppRecord[], options: { csrf?: string; error?: string; principal?: Principal | null }): string {
  const list = apps.length
    ? `<div class="grid">${apps
        .map((app) => `<div class="feature"><div class="row" style="align-items:flex-start"><strong style="font-family:var(--display)"><a href="/apps/${esc(app.id)}">${esc(app.descriptor.name ?? app.id)}</a></strong>${app.verified ? '<span class="pill good">verified</span>' : '<span class="pill bad">unverified</span>'}</div><p style="margin:.2rem 0 .6rem">${esc(app.descriptor.url ?? app.id)}</p><p>${Object.keys(app.descriptor.scopes ?? {}).length} scopes · ${(app.descriptor.offers ?? []).length} offers · ${app.descriptor.jwks ? "reports sales" : "public client"}<br>honours ${(app.descriptor.honours ?? []).map((product) => `<code>${esc(product)}</code>`).join(" ") || "nothing"}</p></div>`)
        .join("")}</div>`
    : `<p class="mute">No app yet.</p>`;
  return `<p class="eyebrow">Directory</p><h1>Apps <span class="count" style="font:500 14px var(--body);color:var(--mute)">${apps.length}</span></h1><p class="lead">Every app this hub knows. An app is registered by URL; the hub reads its descriptor from its own origin and lists what it found, never what was typed.</p>
<form method="post" action="/ui/apps" style="display:flex;gap:.6rem;flex-wrap:wrap;margin:1.2rem 0 .6rem"><input type="hidden" name="csrf" value="${esc(options.csrf ?? "")}"><input name="url" placeholder="https://app.example" style="flex:1;min-width:240px"> <button>Register</button></form>${options.error ? `<p style="color:var(--bad)">${esc(options.error)}</p>` : ""}
<details><summary>Register many at once (up to 1,000 domains)</summary><form method="post" action="/ui/apps/bulk" style="display:block" class="card"><input type="hidden" name="csrf" value="${esc(options.csrf ?? "")}"><textarea name="urls" rows="8" style="width:100%;font:13px var(--mono)" placeholder="one domain or URL per line, or comma-separated"></textarea><p class="mute">Each is probed for /.well-known/openaccess.json on its own origin. Those that answer are listed; the rest are reported and nothing else happens.</p><button>Probe and register</button></form></details>
<div style="margin-top:1.2rem">${list}</div>`;
}

export function bulkPage(job: { id: string; total: number; done: number; finishedAt: string | null; results: Array<{ url: string; ok: boolean; id?: string; verified?: boolean; name?: string; error?: string }> }): string {
  const listed = job.results.filter((r) => r.ok);
  const failed = job.results.filter((r) => !r.ok);
  const rows = [...listed, ...failed].map((r) => `<tr><td>${r.ok ? `<a href="/apps/${esc(r.id)}">${esc(r.name ?? r.id)}</a>` : esc(r.url)}</td><td>${r.ok ? '<span class="pill good">listed</span>' : '<span class="pill bad">no descriptor</span>'}</td><td class="mute">${esc(r.error ?? r.url)}</td></tr>`).join("");
  return `${job.finishedAt ? "" : '<meta http-equiv="refresh" content="3">'}<p class="eyebrow">Bulk registration</p><h1>${job.done} of ${job.total} probed</h1><p class="mute">Job <code>${esc(job.id)}</code>${job.finishedAt ? "" : ", refreshing"} · ${listed.length} listed, ${failed.length} without a descriptor</p>
<table class="t"><thead><tr><th>App</th><th>Result</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>
<p style="margin-top:1rem"><a href="/apps">Back to the apps</a> · <a href="/v1/apps/bulk/${esc(job.id)}">JSON</a></p>`;
}

export function appPage(app: AppRecord): string {
  const d = app.descriptor;
  return `<p class="eyebrow">App</p><h1>${esc(d.name ?? app.id)}</h1><p class="mute"><code>${esc(app.id)}</code> · ${esc(d.url ?? "")} · ${app.verified ? '<span class="pill good">verified</span>' : '<span class="pill bad">unverified</span>'}${d.operator ? ` · operated by <a href="${esc(d.operator)}">${esc(d.operator)}</a>` : ""}${app.lastError ? ` · <span class="pill bad">${esc(app.lastError)}</span>` : ""}</p>
<h2>Scopes</h2><ul>${Object.entries(d.scopes ?? {}).map(([scope, line]) => `<li><code>${esc(scope)}</code> ${esc(line)}</li>`).join("") || "<li class='mute'>none listed: the reserved openid, email and entitlements scopes still work</li>"}</ul>
<h2>Offers</h2><ul>${(d.offers ?? []).map((offer) => `<li><strong>${esc(offer.name ?? offer.product)}</strong> <code>${esc(offer.product)}</code> ${esc(offer.price ?? "")}</li>`).join("") || "<li class='mute'>none</li>"}</ul>
<h2>Honours</h2><ul>${(d.honours ?? []).map((product) => `<li><code>${esc(product)}</code></li>`).join("") || "<li class='mute'>nothing beyond its own offers</li>"}</ul>
<p class="mute">Descriptor: <a href="${esc(app.source)}">${esc(app.source)}</a></p>`;
}
