// node offline.test.mjs: no internet in the window (controller.js). Signing in offline: the sign-in screen says so
// (auth.net) and signs in by itself once it's back. Connect offline: it waits (state().offline), Try again looks at
// once (tries, cut off or offline), and once the internet's back it connects by itself, as it was asked (`again`);
// Cancel, Disconnect and Connect anyway end the wait. The network is Iran's own sites and the world's, sent to a door
// here that opens or to port 1 (refused); Mozilla's account server and the server list are stand-ins.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import https from "node:https";
import net from "node:net";
import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "foxhole-gui-offline-")); // userHome()
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (ok, ms = 5000) => {
  for (const end = Date.now() + ms; !ok() && Date.now() < end; ) await sleep(25);
  return ok();
};

// the network: nothing at first
const door = net.createServer((sock) => sock.destroy());
await new Promise((r) => door.listen(0, "127.0.0.1", r));
const realConnect = net.connect;
let iranUp = false, worldUp = false;
net.connect = (o, ...rest) => {
  const up = typeof o !== "object" ? null : /digikala|aparat/.test(o.host) ? iranUp : /cloudflare|microsoft/.test(o.host) ? worldUp : null;
  if (up === null) return realConnect(o, ...rest);
  const { lookup: _, ...to } = o;
  return realConnect({ ...to, host: "127.0.0.1", port: up ? door.address().port : 1 }, ...rest);
};
// Mozilla: its account server and the server list answer only while the world's up; the rest (the VPN's) never here
const list = { data: [{ code: "DE", name: "Germany", cities: [{ servers: [{ hostname: "de.example", port: 443 }] }] }] };
globalThis.fetch = async (url) => {
  const { hostname } = new URL(url);
  if (!worldUp) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ENETUNREACH" } });
  if (hostname === "api.accounts.firefox.com") return Response.json({ access_token: "at", expires_in: 86400 });
  if (hostname === "firefox.settings.services.mozilla.com") return Response.json(list);
  return new Response("not here", { status: 503 });
};

// Google (guardian.ts reachable: is Mozilla blocked, or is it the internet?), as the world: down at first
const realRequest = https.request;
https.request = (o, ...rest) => {
  if (o?.host !== "script.google.com") return realRequest(o, ...rest);
  const req = Object.assign(new EventEmitter(), { end() {}, destroy() {} });
  setImmediate(() => (worldUp ? rest[0]?.({ resume() {} }) : req.emit("error", new Error("ENETUNREACH"))));
  return req;
};
const { Controller } = await import("./controller.js");
const c = new Controller({ copy: () => {}, updates: { state: () => ({}), on() {} } });

// ── signing in offline: said so, and signed in once the internet's back ─────────────────────────────────────────────
c.signedIn({ uid: "u1", email: "me@example.com", sessionToken: "a".repeat(64) });
assert.ok(await until(() => c.state().auth.stage === "offline"), "the sign-in can't reach Mozilla");
assert.equal(c.state().auth.net, "offline", "and says it's the internet");
iranUp = true;
assert.ok(await until(() => c.state().auth.net === "cut"), "Iran's sites only: cut off, as the looks find it");
worldUp = true;
assert.ok(await until(() => c.state().auth.stage === "ready"), "signed in by itself once it's back, not 20 s later");
await c.reloadList();
assert.deepEqual(c.state().countries.map((x) => x.code), ["DE"]);

// ── Connect offline: it waits, and connects by itself once the internet's back ────────────────────────────────────
[iranUp, worldUp] = [false, false];
let asked = 0;
const again = () => void asked++; // the connect asked once more (pick's, the phone's)
await c.connect("DE", { again });
let s = c.state();
assert.deepEqual(s.offline && { code: s.offline.code, why: s.offline.why, tries: s.offline.tries }, { code: "DE", why: "offline", tries: 0 }, "waiting for the internet");
assert.equal(s.busy, false, "not busy meanwhile: the window's buttons work");
assert.equal(s.active, null);
assert.equal(s.message, null, "the dialog says it, not a toast");
await c.retryOffline();
assert.equal(c.state().offline.tries, 1, "Try again: still offline");
iranUp = true;
await c.retryOffline();
assert.deepEqual([c.state().offline.why, c.state().offline.tries], ["cut", 2], "Try again: cut off now");
assert.equal(asked, 0);
worldUp = true;
assert.ok(await until(() => asked === 1), "the internet back: it connects by itself, as asked");
assert.equal(c.state().offline, null, "and the dialog's gone");

// Cancel: it doesn't connect, the internet back or not
worldUp = false;
await c.connect("DE", { again });
assert.ok(c.state().offline);
c.cancelOffline();
assert.equal(c.state().offline, null, "cancelled");
worldUp = true;
await sleep(3000); // a look's while
assert.equal(asked, 1, "cancelled: no connect once the internet's back");

// Disconnect (the tray's, the tile's) ends the wait too
worldUp = false;
await c.connect("DE", { again });
await c.disconnect();
assert.equal(c.state().offline, null, "disconnect: no wait left");

// Connect anyway, for a network the look gets wrong: the connect goes on now
await c.connect("DE", { again });
c.connectAnyway();
assert.equal(asked, 2, "Connect anyway: connects at once");
assert.equal(c.state().offline, null);

// a connect without `again` (as before): no look, no wait
await c.connect("XX");
assert.equal(c.state().offline, null, "no again: no wait");

net.connect = realConnect;
https.request = realRequest;
door.close();
console.log("ok - offline: the sign-in waits for the internet and signs in once it's back; Connect waits, Try again looks, it connects by itself once it's back; Cancel, Disconnect and Connect anyway end the wait");
process.exit(0); // the controller's looks and checks go on in the background
