// Sharing Foxhole (share.ts): the settings link there and back, what an import makes of this device's settings, links
// that aren't one (or a page's zip bomb) refused, and the page with the APK served on the local network.
import assert from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { DEFAULTS } from "../dist/settings.js";
import { importPlan, parseShared, serveShare, shareData, shareLink, sharedWhat } from "../dist/share.js";

const relay = { deploymentId: "AKfycbx" + "a1B2-c3_D4".repeat(6) + "Zz", authKey: "k".repeat(32) };
const split = {
  default: "vpn",
  rules: [{ match: "bbc.co.uk", via: "vpn" }, { match: "app:Telegram", via: "direct" }, { match: "digikala.com", via: "direct" }],
  smart: true,
};
const mine = { ...DEFAULTS, relay, split };

// there and back: sites, not apps; the relay only when asked for
const data = shareData(mine, false);
assert.deepEqual(parseShared(shareLink(data)), { split: { ...split, rules: [split.rules[0], split.rules[2]] } }, "sites only, no relay");
const both = shareData(mine, true);
assert.deepEqual(parseShared(shareLink(both)).relay, relay);
assert.deepEqual(parseShared(`http://192.168.1.5:47534/#${both}`), parseShared(shareLink(both)), "the page's link");
assert.deepEqual(parseShared(` ${both.slice(0, 20)}\n${both.slice(20)} `), parseShared(both), "its data alone, broken into lines");
assert.equal(shareData(DEFAULTS, true), null, "nothing to share");
assert.deepEqual(parseShared(shareData({ ...DEFAULTS, relay }, true)), { relay }, "the relay alone");
const length = shareLink(shareData({ ...mine, split: { ...split, rules: Array.from({ length: 20 }, (_, i) => ({ match: `site${i}.example.com`, via: "direct" })) } }, true)).length;
assert.ok(length < 700, `20 sites and the relay in a short link (${length})`);

// not a link
for (const bad of ["", "hello", "foxhole://settings?d=", "foxhole://settings?d=%%%", shareLink(Buffer.from("not deflated").toString("base64url"))]) assert.equal(parseShared(bad), null, bad);
const z = (o) => shareLink(deflateRawSync(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"));
assert.equal(parseShared(z({ relay: { deploymentId: "x", authKey: 5 } })), null, "a relay that can't be one");
assert.equal(parseShared(z({ relay: { deploymentId: "short", authKey: "k".repeat(32) } })), null, "an ID the setup wouldn't take");
assert.equal(parseShared(z({ relay: { deploymentId: relay.deploymentId + "/../x", authKey: "k".repeat(32) } })), null, "nor one that leaves its path");
assert.equal(parseShared(z({ relay: { ...relay, authKey: "with spaces in it, quite long" } })), null, "a key the script can't hold");
assert.equal(parseShared(z("[1,2]")), null);
assert.equal(parseShared(z({})), null, "nothing in it");
assert.deepEqual(parseShared(z({ split: { default: "nope", rules: [{ match: "x.com", via: "maybe" }, { match: "y.com", via: "direct" }] } })).split, { default: "vpn", rules: [{ match: "y.com", via: "direct" }] }, "checked as the settings file is");
assert.equal(parseShared(z(`{"split":{"rules":[],"x":"${"a".repeat(2 << 20)}"}}`)), null, "a zip bomb's 2 MB isn't read");

// importing: its sites with mine (its own win), its switches on but mine not off, its relay instead of mine
const theirs = { split: { default: "vpn", rules: [{ match: "bbc.co.uk", via: "direct" }, { match: "x.com", via: "vpn" }], probe: true }, relay: { ...relay, authKey: "q".repeat(32) } };
const plan = importPlan(mine, theirs);
assert.deepEqual(plan.split, {
  default: "vpn",
  rules: [{ match: "app:Telegram", via: "direct" }, { match: "digikala.com", via: "direct" }, { match: "bbc.co.uk", via: "direct" }, { match: "x.com", via: "vpn" }],
  smart: true,
  probe: true,
});
assert.deepEqual(plan.relay, theirs.relay);
assert.deepEqual(plan.what, ["VPN relay AKfycbxa…D4Zz, in place of yours", "Split tunneling: Save data, 2 sites"]);
assert.deepEqual(importPlan(mine, { relay }).what, ["VPN relay AKfycbxa…D4Zz, yours already"]);
assert.equal(importPlan(mine, { relay }).split, undefined, "no split tunneling: mine as it is");
assert.deepEqual(importPlan(DEFAULTS, { split: { default: "direct", rules: [{ match: "x.com", via: "vpn" }] } }).what, ["Split tunneling: only the sites listed use the VPN, 1 site"]);
assert.deepEqual(sharedWhat({ split: { ...split, rules: [split.rules[0]] } }), ["Split tunneling: Iranian sites direct, 1 site"], "the sharer's own view");
assert.deepEqual(sharedWhat({ split: { default: "vpn", rules: [split.rules[0]] } }, mine), ["Split tunneling: 1 site (0 new)"]);

// the page, and the APK
const dir = mkdtempSync(join(tmpdir(), "foxhole-share-"));
const apk = join(dir, "base.apk");
writeFileSync(apk, Buffer.alloc(3_000_000, 7));
const server = await serveShare({ name: "Sara's <phone>", version: "9.8.7", apk, port: 47598 });
const home = await fetch("http://127.0.0.1:47598/");
const html = await home.text();
assert.equal(home.status, 200);
assert.match(html, /Foxhole from Sara&#39;s &#60;phone&#62;/, "its name, escaped");
assert.match(html, /href="\/Foxhole-9\.8\.7\.apk">Download Foxhole 9\.8\.7/);
assert.match(html, /3 MB/);
assert.match(html, /intent:\/\/settings\?d="\+d\+"#Intent;scheme=foxhole;package=io\.github\.diercohen\.foxhole;/, "Android opens Foxhole with the settings");
const got = await fetch("http://127.0.0.1:47598/Foxhole-9.8.7.apk");
assert.equal(got.headers.get("content-type"), "application/vnd.android.package-archive");
assert.match(got.headers.get("content-disposition"), /filename="Foxhole-9\.8\.7\.apk"/);
assert.equal((await got.arrayBuffer()).byteLength, 3_000_000);
assert.equal((await fetch("http://127.0.0.1:47598/base.apk")).status, 404, "only by its name");
assert.equal((await fetch("http://127.0.0.1:47598/", { method: "POST" })).status, 405);
server.close();

const desktop = await serveShare({ name: "", version: "9.8.7", apk: null, port: 47597 });
const page = await (await fetch("http://127.0.0.1:47597/")).text();
assert.doesNotMatch(page, /Download Foxhole/, "a computer has no APK to give");
assert.match(page, /releases\/latest/);
assert.equal((await fetch("http://127.0.0.1:47597/Foxhole-9.8.7.apk")).status, 404);
desktop.close();
console.log("ok - sharing: settings links, imports, the page and the APK");
