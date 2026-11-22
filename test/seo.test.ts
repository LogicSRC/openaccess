/**
 * robots.txt and sitemap.xml: public pages only, every URL on the hub's own origin.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Store } from "../src/db.ts";
import { createApp } from "../src/server.ts";

process.env.PROFULLSTACK_FOOTER_OFFLINE = "1";
const mailer = { send: async () => {} } as never;

test("robots.txt points at this hub's sitemap and the sitemap stays on the hub's origin", async () => {
  const app = createApp({ store: new Store(":memory:"), url: "https://hub.test", mailer, name: "Test hub" });

  const robots = await app.request("/robots.txt");
  assert.equal(robots.status, 200);
  assert.match(robots.headers.get("content-type") ?? "", /text\/plain/);
  const text = await robots.text();
  assert.match(text, /^Sitemap: https:\/\/hub\.test\/sitemap\.xml$/m);
  assert.doesNotMatch(text, /Disallow: \/sitemap/);

  const sitemap = await app.request("/sitemap.xml");
  assert.equal(sitemap.status, 200);
  assert.match(sitemap.headers.get("content-type") ?? "", /application\/xml/);
  const xml = await sitemap.text();
  assert.match(xml, /<urlset /);
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  assert.ok(locs.includes("https://hub.test/apps"));
  for (const loc of locs) assert.ok(loc.startsWith("https://hub.test/"), loc);
});
