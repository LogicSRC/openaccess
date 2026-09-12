/**
 * The hub's pages: sign in, consent, the device code, and the dashboard where
 * a person sees every app, every grant and every subscription in one place.
 * Server-rendered HTML, no framework, one stylesheet.
 */
import type { AppRecord, Entitlement, Grant, Link, Offer, Principal } from "./spec.ts";
import { fillLink } from "./spec.ts";

export const esc = (value: unknown): string => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch] as string);

const CSS = `
:root{--bg:#f7f8f8;--fg:#1a2026;--mute:#5b6b7a;--line:#dfe4e8;--card:#fff;--accent:#0b6e4f;--danger:#a23b3b}
@media(prefers-color-scheme:dark){:root{--bg:#0f1417;--fg:#e6ebef;--mute:#9aa8b4;--line:#243039;--card:#161d22;--accent:#3fbf8f;--danger:#e07a7a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:2rem 1rem 4rem}header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
header a{color:var(--fg);text-decoration:none;font-weight:600}header nav a{color:var(--mute);font-weight:400;margin-left:1rem}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.1rem;margin:2rem 0 .5rem}p{margin:.4rem 0}.mute{color:var(--mute)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem;margin:.6rem 0}
.row{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:center}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:rgba(127,127,127,.12);padding:.1rem .35rem;border-radius:4px}
.pill{display:inline-block;font-size:12px;padding:.1rem .5rem;border:1px solid var(--line);border-radius:999px;margin:.1rem .2rem .1rem 0;color:var(--mute)}
.pill.good{color:var(--accent);border-color:var(--accent)}.pill.bad{color:var(--danger);border-color:var(--danger)}
form{display:inline}input,select{font:inherit;padding:.45rem .6rem;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);max-width:100%}
button,.btn{font:inherit;padding:.45rem .9rem;border-radius:6px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer;text-decoration:none;display:inline-block}
button.quiet,.btn.quiet{background:transparent;color:var(--fg);border-color:var(--line)}button.danger{background:transparent;color:var(--danger);border-color:var(--danger)}
.links a{margin-right:.8rem}.grid{display:grid;gap:.5rem;grid-template-columns:1fr}label{display:block;margin:.4rem 0}
details summary{cursor:pointer;color:var(--mute)}ul.plain{list-style:none;padding:0;margin:.3rem 0}ul.plain li{margin:.2rem 0}
`;

export function layout(title: string, body: string, options: { hubName: string; principal?: Principal | null; csrf?: string }): string {
  const nav = options.principal
    ? `<nav><a href="/">Dashboard</a><a href="/apps">Apps</a><form method="post" action="/auth/signout"><input type="hidden" name="csrf" value="${esc(options.csrf ?? "")}"><button class="quiet" style="padding:.2rem .6rem">Sign out</button></form></nav>`
    : `<nav><a href="/apps">Apps</a><a href="/auth">Sign in</a><a href="https://logicsrc.com/openaccess">Spec</a></nav>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · ${esc(options.hubName)}</title><style>${CSS}</style></head><body><main><header><a href="/">${esc(options.hubName)}</a>${nav}</header>${body}</main></body></html>`;
}

export function signInPage(options: { next: string | null; sent?: string; error?: string }): string {
  if (options.sent) return `<h1>Check your mail</h1><p>A sign-in link went to <strong>${esc(options.sent)}</strong>. It works once, for fifteen minutes.</p>`;
  return `<h1>Sign in</h1><p class="mute">Your email, and a link comes back. No password, ever.</p>${options.error ? `<p style="color:var(--danger)">${esc(options.error)}</p>` : ""}
<form method="post" action="/auth/start" style="display:block"><input type="hidden" name="next" value="${esc(options.next ?? "")}"><label>Email <input type="email" name="email" required autofocus placeholder="you@example.com"></label><button>Send the link</button></form>`;
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
  return `<h1>${esc(app.descriptor.name ?? app.id)} wants access</h1>
<p class="mute">${esc(app.descriptor.url ?? app.id)}${app.descriptor.operator ? ` · operated by <a href="${esc(app.descriptor.operator)}">${esc(app.descriptor.operator)}</a>` : " · no operator stated"}${app.verified ? "" : ' · <span class="pill bad">unverified</span>'}</p>
${view.device ? `<p>For the device showing code <strong>${esc(view.device)}</strong>.</p>` : ""}
<div class="card"><p><strong>It will be able to</strong></p><ul>${lines}</ul>
${view.scopes.includes("entitlements") ? `<p><strong>It will see</strong> ${view.honoured.length ? `that you hold ${view.honoured.map((product) => `<code>${esc(product)}</code>`).join(", ")}` : "which of the products it honours you hold (none right now)"}.</p>` : ""}
</div>
<form method="post" action="${esc(view.action)}" style="display:block"><input type="hidden" name="csrf" value="${esc(view.csrf)}">${hidden}<button name="decision" value="approve">Allow</button> <button class="quiet" name="decision" value="deny">Deny</button></form>`;
}

function reservedLine(scope: string): string {
  return { openid: "Know it is you", profile: "See your profile", email: "See your email address", entitlements: "See which of the products it honours you hold", "grants:delegate": "Hand narrower grants to agents on your behalf", "hub:manage": "Manage your grants and subscriptions at this hub" }[scope] ?? "";
}

export function devicePage(options: { userCode?: string; error?: string; done?: "approved" | "denied" }): string {
  if (options.done) return `<h1>${options.done === "approved" ? "Approved" : "Denied"}</h1><p>You can go back to the device.</p>`;
  return `<h1>Enter the code</h1><p class="mute">The eight letters your terminal or device is showing.</p>${options.error ? `<p style="color:var(--danger)">${esc(options.error)}</p>` : ""}
<form method="get" action="/device/verify" style="display:block"><input name="user_code" value="${esc(options.userCode ?? "")}" placeholder="XXXX-XXXX" autofocus style="text-transform:uppercase;letter-spacing:.15em;font-family:ui-monospace,monospace"> <button>Continue</button></form>`;
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
          return `<div class="card"><div class="row"><div><strong>${esc(appName(link.app))}</strong> <span class="mute">${esc(view.apps.get(link.app)?.descriptor.url ?? link.app)}</span><br>${grant ? grant.scope.map((scope) => `<span class="pill">${esc(scope)}</span>`).join("") : '<span class="mute">no grant</span>'}${grant?.expiresAt ? `<span class="pill">until ${esc(grant.expiresAt.slice(0, 10))}</span>` : ""}</div>
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
          return `<div class="card"><div class="row"><div><strong>${esc(offer?.name ?? entitlement.product)}</strong> <span class="mute">${esc(entitlement.product)}</span> <span class="pill ${good ? "good" : "bad"}">${esc(entitlement.status)}</span>${entitlement.cancelRequestedAt ? '<span class="pill">cancel requested</span>' : ""}
<br><span class="mute">${offer?.price ? esc(offer.price) + " · " : ""}sold by ${esc(appName(entitlement.seller))}${entitlement.period.end ? ` · until ${esc(entitlement.period.end.slice(0, 10))}` : ""}${honouredBy.length ? ` · also honoured by ${honouredBy.map((app) => esc(app.descriptor.name ?? app.id)).join(", ")}` : ""}</span>
<div class="links">${offerLinks(offer, principal.id, ["pay", "manage", "upgrade", "promote", "support"])}${entitlement.receipt ? `<a href="${esc(entitlement.receipt)}">receipt</a>` : ""}</div></div>
<div>${good && !entitlement.cancelRequestedAt ? `<form method="post" action="/ui/entitlements/${esc(entitlement.id)}/cancel"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="danger">Cancel</button></form>` : offer?.links?.cancel ? `<a class="btn quiet" href="${esc(fillLink(offer.links.cancel, principal.id))}">Cancel at seller</a>` : ""}</div></div></div>`;
        })
        .join("")
    : `<p class="mute">Nothing yet. When an app you linked reports a subscription, it appears here and travels with you to every app that honours it.</p>`;

  const offers = Array.from(view.apps.values()).flatMap((app) => (app.descriptor.offers ?? []).map((offer) => ({ app, offer }))).filter(({ offer }) => !view.entitlements.some((entitlement) => entitlement.product === offer.product && ["active", "trialing"].includes(entitlement.status)));
  const offersHtml = offers.length
    ? `<h2>Available</h2>${offers.map(({ app, offer }) => `<div class="card"><div class="row"><div><strong>${esc(offer.name ?? offer.product)}</strong> <span class="mute">${esc(offer.product)}${offer.price ? " · " + esc(offer.price) : ""} · from ${esc(app.descriptor.name ?? app.id)}</span><br><span class="mute">Honoured by ${Array.from(view.apps.values()).filter((candidate) => (candidate.descriptor.honours ?? []).includes(offer.product)).map((candidate) => esc(candidate.descriptor.name ?? candidate.id)).join(", ") || "the seller"}</span></div><div class="links">${offerLinks(offer, principal.id, ["pay"], "btn")}</div></div></div>`).join("")}`
    : "";

  const agentsHtml = children.length
    ? children
        .map((grant) => `<div class="card"><div class="row"><div><strong>${esc(grant.holder ?? "bearer")}</strong> <span class="mute">on ${esc(appName(grant.app))} · from <code>${esc(grant.parent ?? "")}</code></span><br>${grant.scope.map((scope) => `<span class="pill">${esc(scope)}</span>`).join("")}${Object.entries(grant.limits).map(([key, value]) => `<span class="pill">${esc(key)} ${esc(value)}</span>`).join("")}${grant.expiresAt ? `<span class="pill">until ${esc(grant.expiresAt.slice(0, 10))}</span>` : ""}</div>
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

  return `${view.notice ? `<div class="card" style="border-color:var(--accent)">${view.notice}</div>` : ""}
<h1>${esc(principal.email ?? principal.profile ?? principal.id)}</h1><p class="mute"><code>${esc(principal.id)}</code> · ${esc(principal.kind)}${principal.profile ? ` · <a href="${esc(principal.profile)}">${esc(principal.profile)}</a>` : ""}</p>
<details><summary>Profile</summary><form method="post" action="/ui/profile" style="display:block" class="card"><input type="hidden" name="csrf" value="${esc(csrf)}"><label>OpenProfile.md URL <input name="profile" value="${esc(principal.profile ?? "")}" placeholder="https://you.example/.well-known/openprofile.md" style="width:100%"></label><button class="quiet">Save</button></form></details>
<h2>Subscriptions</h2>${entitlementsHtml}${offersHtml}
<h2>Apps you linked</h2>${linksHtml}
<h2>Agents</h2>${agentsHtml}${delegateForm}`;
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
    ? apps
        .map((app) => `<div class="card"><div class="row"><div><strong><a href="/apps/${esc(app.id)}">${esc(app.descriptor.name ?? app.id)}</a></strong> <span class="mute">${esc(app.descriptor.url ?? app.id)}</span> ${app.verified ? '<span class="pill good">verified</span>' : '<span class="pill bad">unverified</span>'}${app.descriptor.jwks ? '<span class="pill">reports sales</span>' : '<span class="pill">public client</span>'}<br><span class="mute">${Object.keys(app.descriptor.scopes ?? {}).length} scopes · ${(app.descriptor.offers ?? []).length} offers · honours ${(app.descriptor.honours ?? []).map((product) => `<code>${esc(product)}</code>`).join(" ") || "nothing"}</span></div></div></div>`)
        .join("")
    : `<p class="mute">No app yet.</p>`;
  return `<h1>Apps</h1><p class="mute">Every app this hub knows. An app is registered by URL; the hub reads its descriptor from its own origin and lists what it found.</p>
<form method="post" action="/ui/apps" style="display:block"><input type="hidden" name="csrf" value="${esc(options.csrf ?? "")}"><input name="url" placeholder="https://app.example" style="width:60%"> <button>Register</button></form>${options.error ? `<p style="color:var(--danger)">${esc(options.error)}</p>` : ""}
<details><summary>Register many at once (up to 1,000 domains)</summary><form method="post" action="/ui/apps/bulk" style="display:block" class="card"><input type="hidden" name="csrf" value="${esc(options.csrf ?? "")}"><textarea name="urls" rows="8" style="width:100%;font:13px ui-monospace,monospace" placeholder="one domain or URL per line, or comma-separated"></textarea><p class="mute">Each is probed for /.well-known/openaccess.json on its own origin. Those that answer are listed; the rest are reported and nothing else happens.</p><button>Probe and register</button></form></details>${list}`;
}

export function bulkPage(job: { id: string; total: number; done: number; finishedAt: string | null; results: Array<{ url: string; ok: boolean; id?: string; verified?: boolean; name?: string; error?: string }> }): string {
  const listed = job.results.filter((r) => r.ok);
  const failed = job.results.filter((r) => !r.ok);
  const rows = [...listed, ...failed].map((r) => `<tr><td>${r.ok ? `<a href="/apps/${esc(r.id)}">${esc(r.name ?? r.id)}</a>` : esc(r.url)}</td><td>${r.ok ? '<span class="pill good">listed</span>' : '<span class="pill bad">no descriptor</span>'}</td><td class="mute">${esc(r.error ?? r.url)}</td></tr>`).join("");
  return `${job.finishedAt ? "" : '<meta http-equiv="refresh" content="3">'}<h1>Bulk registration</h1><p class="mute">Job <code>${esc(job.id)}</code> · ${job.done} of ${job.total} probed${job.finishedAt ? "" : ", refreshing"} · ${listed.length} listed, ${failed.length} without a descriptor</p>
<table style="width:100%;border-collapse:collapse"><thead><tr><th align="left">App</th><th align="left">Result</th><th align="left">Detail</th></tr></thead><tbody>${rows}</tbody></table>
<p><a href="/apps">Back to the apps</a> · <a href="/v1/apps/bulk/${esc(job.id)}">JSON</a></p>`;
}

export function appPage(app: AppRecord): string {
  const d = app.descriptor;
  return `<h1>${esc(d.name ?? app.id)}</h1><p class="mute"><code>${esc(app.id)}</code> · ${esc(d.url ?? "")} · ${app.verified ? '<span class="pill good">verified</span>' : '<span class="pill bad">unverified</span>'}${d.operator ? ` · operated by <a href="${esc(d.operator)}">${esc(d.operator)}</a>` : ""}${app.lastError ? ` · <span class="pill bad">${esc(app.lastError)}</span>` : ""}</p>
<h2>Scopes</h2><ul>${Object.entries(d.scopes ?? {}).map(([scope, line]) => `<li><code>${esc(scope)}</code> ${esc(line)}</li>`).join("") || "<li class='mute'>none listed</li>"}</ul>
<h2>Offers</h2><ul>${(d.offers ?? []).map((offer) => `<li><strong>${esc(offer.name ?? offer.product)}</strong> <code>${esc(offer.product)}</code> ${esc(offer.price ?? "")}</li>`).join("") || "<li class='mute'>none</li>"}</ul>
<h2>Honours</h2><ul>${(d.honours ?? []).map((product) => `<li><code>${esc(product)}</code></li>`).join("") || "<li class='mute'>nothing</li>"}</ul>
<p class="mute">Descriptor: <a href="${esc(app.source)}">${esc(app.source)}</a></p>`;
}
