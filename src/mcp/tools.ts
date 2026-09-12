/**
 * The hub's own tools, for an agent that speaks MCP and nothing else.
 *
 * An agent holding one of this hub's tokens can see what it holds, hand a
 * narrower grant on, revoke one, and check a person's standing with a
 * product. The public tools need no token.
 */
import type { Hub } from "../hub.ts";
import { HubError } from "../hub.ts";
import type { Grant, Principal } from "../spec.ts";
import { parseScope } from "../spec.ts";
import { text, toolError, type ToolDefinition, type ToolResult } from "./protocol.ts";

export interface ToolContext {
  hub: Hub;
  /** Who is calling, from the bearer token, if any. */
  actor: { principal: Principal; grant: Grant; scope: string[] } | null;
}

const object = (properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> => ({ type: "object", properties, required, additionalProperties: false });
const string = (description: string): Record<string, unknown> => ({ type: "string", description });

export const TOOLS: ToolDefinition[] = [
  { name: "whoami", title: "Who am I", description: "The principal behind the token, the grant it rides on, and its scopes and limits.", inputSchema: object({}) },
  { name: "my_grants", title: "My grants", description: "Every grant the principal gave, per app, with children delegated to agents.", inputSchema: object({ app: string("Only this app, by id.") }) },
  { name: "my_entitlements", title: "My entitlements", description: "Every product the principal holds, with pay, cancel, manage and promote links filled in, and which apps honour each.", inputSchema: object({}) },
  {
    name: "delegate_grant",
    title: "Delegate a grant",
    description: "Hand a narrower grant to an agent: a subset of this token's scopes, limits no larger, an expiry no later. Answers a refresh token for the agent, shown once.",
    inputSchema: object(
      {
        scope: string("Space-separated scopes, a subset of the parent's."),
        for: string("The agent's OpenProfile.md URL, so the app can see who holds it."),
        per_call: string('e.g. "5 USD"'),
        per_day: string('e.g. "50 USD", a rolling day'),
        lifetime: string('e.g. "500 USD"'),
        expires_in: { type: "integer", description: "Seconds until the child expires." },
        grant: string("Which of the principal's grants to delegate from. Defaults to the token's own grant."),
      },
      ["scope"],
    ),
  },
  { name: "revoke_grant", title: "Revoke a grant", description: "Revoke one of the principal's grants and every child delegated from it. The app hears at once.", inputSchema: object({ id: string("The grant id.") }, ["id"]) },
  { name: "cancel_entitlement", title: "Cancel a subscription", description: "Ask the seller to cancel. The standing stays until the seller reports the cancellation; the seller's cancel link comes back too.", inputSchema: object({ id: string("The entitlement id, from my_entitlements.") }, ["id"]) },
  { name: "check_entitlement", title: "Check an entitlement", description: "Does the principal hold this product in good standing.", inputSchema: object({ product: string("<host>/<slug>") }, ["product"]) },
  { name: "list_apps", title: "List apps", description: "The apps this hub knows: their scopes, what they sell, what they honour.", inputSchema: object({ q: string("A word to match.") }) },
  { name: "get_app", title: "Get an app", description: "One app in full: its descriptor as the hub last read it.", inputSchema: object({ id: string("The app id: its host.") }, ["id"]) },
  { name: "register_app", title: "Register an app", description: "Register an app by any URL on its origin. The hub reads /.well-known/openaccess.json there and lists what it found.", inputSchema: object({ url: string("The app's URL.") }, ["url"]) },
];

const needActor = (ctx: ToolContext): NonNullable<ToolContext["actor"]> => {
  if (!ctx.actor) throw new HubError("unauthorized", "This tool needs a bearer token from this hub: run `openaccess login`.", 401);
  return ctx.actor;
};

export async function callTool(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
  const { hub } = ctx;
  const str = (key: string): string | undefined => (typeof args[key] === "string" && (args[key] as string).trim() ? (args[key] as string).trim() : undefined);
  try {
    switch (name) {
      case "whoami": {
        const actor = needActor(ctx);
        return text(`${actor.principal.email ?? actor.principal.id} on ${actor.grant.app}: ${actor.scope.join(" ")}`, { principal: actor.principal, grant: actor.grant });
      }
      case "my_grants": {
        const actor = needActor(ctx);
        const grants = hub.store.grantsOf(actor.principal.id, { app: str("app") });
        return text(grants.map((grant) => `${grant.id}  ${grant.app}  ${grant.parent ? `child of ${grant.parent}` : "root"}  ${grant.scope.join(" ")}`).join("\n") || "No grants.", { grants });
      }
      case "my_entitlements": {
        const actor = needActor(ctx);
        const { entitlements } = hub.me(actor.principal);
        return text(entitlements.map((e) => `${e.id}  ${e.product}  ${e.status}  honoured by ${e.honouredBy.join(", ")}`).join("\n") || "No entitlements.", { entitlements });
      }
      case "delegate_grant": {
        const actor = needActor(ctx);
        let parent = actor.grant;
        if (str("grant")) {
          const chosen = hub.store.liveGrant(str("grant") as string);
          if (!chosen || chosen.principal !== actor.principal.id) return toolError("No such grant of yours.");
          parent = chosen;
        }
        if (parent.id === actor.grant.id && parent.app !== hub.selfId && !actor.scope.includes("grants:delegate")) return toolError("This token cannot delegate: it lacks grants:delegate.");
        const limits = { ...(str("per_call") ? { per_call: str("per_call") } : {}), ...(str("per_day") ? { per_day: str("per_day") } : {}), ...(str("lifetime") ? { lifetime: str("lifetime") } : {}) };
        const made = hub.delegate(parent, { for: str("for"), scope: parseScope(str("scope")), limits, expiresIn: typeof args.expires_in === "number" ? args.expires_in : null });
        return text(`Delegated ${made.grant.id} (${made.grant.scope.join(" ")}). Refresh token, shown once: ${made.refreshToken}`, { grant: made.grant, refresh_token: made.refreshToken, token_endpoint: `${hub.url}/token`, client_id: made.grant.app });
      }
      case "revoke_grant": {
        const actor = needActor(ctx);
        const revoked = hub.revoke(str("id") ?? "", actor.principal);
        return text(`Revoked ${revoked.map((grant) => grant.id).join(", ")}.`, { revoked });
      }
      case "cancel_entitlement": {
        const actor = needActor(ctx);
        const outcome = hub.requestCancel(str("id") ?? "", actor.principal);
        return text(`Asked ${outcome.entitlement.seller} to cancel ${outcome.entitlement.product}.${outcome.cancel ? ` Or cancel there: ${outcome.cancel}` : ""}`, outcome);
      }
      case "check_entitlement": {
        const actor = needActor(ctx);
        const outcome = hub.check(actor.principal.id, str("product") ?? "");
        return text(outcome.held ? `Held (${outcome.status}).` : `Not held${outcome.status ? ` (${outcome.status})` : ""}.`, outcome);
      }
      case "list_apps": {
        const apps = hub.store.listApps(str("q"));
        return text(apps.map((app) => `${app.id.padEnd(30)} ${app.verified ? "✓" : " "} ${app.descriptor.name ?? ""}`).join("\n") || "No apps.", { apps });
      }
      case "get_app": {
        const app = hub.app(str("id") ?? "");
        return text(JSON.stringify(app.descriptor, null, 2), { app });
      }
      case "register_app": {
        const url = str("url");
        if (!url) return toolError("Send {url}.");
        const app = await hub.probeApp(url, hub.store.getApp(new URL(url).hostname.replace(/^www\./, "")));
        return text(`${app.id}: ${app.verified ? "verified" : "unverified"}, ${Object.keys(app.descriptor.scopes ?? {}).length} scopes, ${(app.descriptor.offers ?? []).length} offers.`, { app });
      }
      default:
        return toolError(`No tool named ${name}.`);
    }
  } catch (error) {
    if (error instanceof HubError) return toolError(error.message);
    throw error;
  }
}
