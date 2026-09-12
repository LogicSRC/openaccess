/**
 * Telling an app what changed.
 *
 * One POST per event to the URL the app's own descriptor names, signed with
 * the hub's key so the receiver verifies against jwks_uri and no secret is
 * ever shared. Three attempts, then the failure is written down; fifty
 * failures in a row and deliveries to that app pause, still listed, so its
 * operator can see why.
 */
import { randomUUID } from "node:crypto";
import type { Store } from "./db.ts";
import { signBody, type SigningKey } from "./jwt.ts";
import type { AppRecord, Entitlement, Grant, HubEvent, Link, WebhookDelivery } from "./spec.ts";

export const SIGNATURE_HEADER = "x-openaccess-signature";
export const EVENT_HEADER = "x-openaccess-event";
export const DELIVERY_HEADER = "x-openaccess-delivery";
export const PAUSE_AFTER = 50;

export type Fetcher = typeof fetch;

export interface DeliverOptions {
  hub: string;
  key: SigningKey;
  fetch?: Fetcher;
  attempts?: number;
  timeoutMs?: number;
  log?: (line: string) => void;
}

export interface EventPayload {
  sub: string;
  grant?: Grant;
  entitlement?: Entitlement;
  link?: Link;
}

/** Send one event to one app. Never throws. Answers whether it was accepted. */
export async function deliverTo(store: Store, app: AppRecord, event: HubEvent, payload: EventPayload, options: DeliverOptions): Promise<boolean> {
  const target = app.descriptor.webhooks;
  if (!target) return false;
  if (app.webhookFailures >= PAUSE_AFTER) return false;
  const fetcher = options.fetch ?? fetch;
  const at = new Date().toISOString();
  const delivery: WebhookDelivery = { id: randomUUID(), event, at, hub: options.hub, ...payload };
  const body = JSON.stringify(delivery);
  let status: number | null = null;
  let error: string | null = null;
  let attempts = 0;
  for (; attempts < (options.attempts ?? 3); attempts++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
    try {
      const response = await fetcher(target, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "openaccess-hub", [SIGNATURE_HEADER]: signBody(body, options.key), [EVENT_HEADER]: event, [DELIVERY_HEADER]: delivery.id },
        body,
        signal: controller.signal,
      });
      status = response.status;
      error = null;
      if (response.ok) break;
      error = `answered ${response.status}`;
      if (response.status >= 400 && response.status < 500) {
        attempts++;
        break;
      }
    } catch (caught) {
      status = null;
      error = (caught as Error).name === "AbortError" ? "timed out" : (caught as Error).message;
    } finally {
      clearTimeout(timer);
    }
  }
  store.recordDelivery({ id: delivery.id, app: app.id, event, at, status, error, attempts });
  const ok = status !== null && status >= 200 && status < 300;
  if (!ok) options.log?.(`webhook ${app.id} ${target}: ${error ?? "failed"}`);
  return ok;
}

/** An entitlement event goes to every app that honours the product; a cancel request goes to the seller alone. */
export async function fanOut(store: Store, event: HubEvent, payload: EventPayload, options: DeliverOptions): Promise<number> {
  let targets: AppRecord[] = [];
  if (payload.entitlement) {
    targets = event === "entitlement.cancel_requested" ? [store.getApp(payload.entitlement.seller)].filter((app): app is AppRecord => Boolean(app)) : store.appsHonouring(payload.entitlement.product);
  } else if (payload.grant) {
    targets = [store.getApp(payload.grant.app)].filter((app): app is AppRecord => Boolean(app));
  } else if (payload.link) {
    targets = [store.getApp(payload.link.app)].filter((app): app is AppRecord => Boolean(app));
  }
  let sent = 0;
  for (const app of targets) if (await deliverTo(store, app, event, payload, options)) sent++;
  return sent;
}
