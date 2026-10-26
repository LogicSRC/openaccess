/**
 * The Profullstack network footer: off by default (someone else's hub is not
 * in that network), server-rendered with the ring and both badges when on.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Store } from "../src/db.ts";
import { createApp } from "../src/server.ts";
import { ringFooterEnabled } from "../src/ring-footer.ts";

process.env.PROFULLSTACK_FOOTER_OFFLINE = "1";
const mailer = { send: async () => {} } as never;
const html = { accept: "text/html,application/xhtml+xml" };
const make = () => createApp({ store: new Store(":memory:"), url: "https://hub.test", mailer, name: "Test hub" });

test("off unless PROFULLSTACK_FOOTER is set", async () => {
  delete process.env.PROFULLSTACK_FOOTER;
  assert.equal(ringFooterEnabled(), false);
  const page = await (await make().request("/", { headers: html })).text();
  assert.ok(!page.includes("data-pfs-footer"));
  assert.equal((await make().request("/.well-known/openwebring.json")).status, 404);
});

test("on: the landing page carries the ring and both badges", async () => {
  process.env.PROFULLSTACK_FOOTER = "1";
  try {
    const app = make();
    const page = await (await app.request("/", { headers: html })).text();
    assert.match(page, /rssamplifier\.com\/ring\/profullstack/);
    assert.match(page, /built\.indie\.pit\.world\/for\.svg/);
    assert.match(page, /pwamart\.com\/for\.svg/);
    const ring = await (await app.request("/.well-known/openwebring.json")).json();
    assert.ok(JSON.stringify(ring).includes("profullstack"));
  } finally {
    delete process.env.PROFULLSTACK_FOOTER;
  }
});
