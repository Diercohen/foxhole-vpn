// node vpncheck.test.mjs: the window says connected only once the internet opens through Firefox VPN (controller.js, on
// proxy.ts checkVpn). A server that doesn't answer on this network: not connected, and why. Whole-system mode with no
// internet through it doesn't stay on: the VPN carrying, the proxy stays; carrying nothing either, it disconnects. A
// sign-in that's ended while connected disconnects and asks to sign in again; a token Guardian refuses at a connect is
// got anew, and the connect goes on by itself, once. Another VPN on (Windscribe's routes): whole-
// system mode says which before a password's asked. Android's VPN stands in for whole-system mode (no root here);
// Mozilla's account server, the server list and Guardian are stand-ins, the VPN's server a TLS one; `ip` and `ps` too.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the stand-in server's own certificate
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "foxhole-gui-vpncheck-")); // userHome()
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (ok, ms = 8000) => {
  for (const end = Date.now() + ms; !ok() && Date.now() < end; ) await sleep(25);
  return ok();
};
setTimeout(() => (console.error("FAIL - test timed out"), process.exit(1)), 60_000).unref();

// a free port for the proxy, not 1080
const free = net.createServer();
await new Promise((r) => free.listen(0, "127.0.0.1", r));
const proxyPort = free.address().port;
free.close();
mkdirSync(join(process.env.HOME, ".config", "foxhole-vpn"), { recursive: true });
writeFileSync(join(process.env.HOME, ".config", "foxhole-vpn", "settings.json"), JSON.stringify({ port: proxyPort }));

// Firefox VPN's server: answers each CONNECT's page while `vpn` is "ok", refuses it (403) while "refuse"
const dir = mkdtempSync(join(tmpdir(), "foxhole-gui-vpncheck-cert-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });
let vpn = "ok";
const server = tls.createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) }, (s) => {
  s.on("error", () => {});
  s.once("data", () => {
    if (vpn === "refuse") return void s.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    s.write("HTTP/1.1 200 OK\r\n\r\n");
    s.once("data", () => s.end("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n1.2.3.4"));
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const closed = net.createServer();
await new Promise((r) => closed.listen(0, "127.0.0.1", r));
const nowhere = closed.address().port; // a server the network blocks: nothing answers there
closed.close();

// the network: the world opens (proxy.ts reach: not offline, so a failure is the VPN's)
const door = net.createServer((sock) => sock.destroy());
await new Promise((r) => door.listen(0, "127.0.0.1", r));
const realConnect = net.connect;
net.connect = (o, ...rest) => {
  if (typeof o !== "object" || !/digikala|aparat|cloudflare\.com$|microsoft/.test(o.host ?? "") || o.port !== 443) return realConnect(o, ...rest);
  const { lookup: _, ...to } = o;
  return realConnect({ ...to, host: "127.0.0.1", port: door.address().port }, ...rest);
};
// Mozilla: its account server (a token, or the sign-in ended: errno 110) and the server list (two locations)
let signedIn = true;
const list = { data: [
  { code: "DE", name: "Germany", cities: [{ servers: [{ hostname: "127.0.0.1", port: server.address().port }] }] },
  { code: "JP", name: "Japan", cities: [{ servers: [{ hostname: "127.0.0.1", port: nowhere }] }] },
] };
globalThis.fetch = async (url) => {
  const { hostname } = new URL(url);
  if (hostname === "api.accounts.firefox.com")
    return signedIn ? Response.json({ access_token: "at", expires_in: 86400 }) : Response.json({ errno: 110, message: "Invalid authentication token" }, { status: 401 });
  if (hostname === "firefox.settings.services.mozilla.com") return Response.json(list);
  return new Response("not here", { status: 503 });
};
// Guardian: a pass (always due again: it's near its end), or the token refused once the sign-in's ended, or for the
// next `refusals` passes (a token it won't take, though the account server gives one)
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
let refusals = 0;
const realRequest = https.request;
https.request = (o, cb) => {
  if (o?.servername !== "vpn.mozilla.org") return realRequest(o, cb);
  const req = Object.assign(new EventEmitter(), { destroy() {} });
  req.end = () =>
    setImmediate(() => {
      const ok = signedIn && !(o.path === "/api/v1/fpn/token" && o.method === "GET" && refusals > 0 && refusals--);
      const res = Object.assign(new EventEmitter(), { statusCode: ok ? 200 : 401, rawHeaders: [] });
      cb(res);
      if (ok && o.method === "GET") res.emit("data", Buffer.from(JSON.stringify({ token: `${b64({})}.${b64({ nbf: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 })}.x` })));
      res.emit("end");
    });
  return req;
};
// Android's VPN for whole-system mode: the internet opens through it or not (`through`)
let through = true;
let sessions = 0, stopped = 0;
const android = {
  network: async () => "Wi-Fi",
  globalSession: () => ({
    async start() { sessions++; },
    async stop() { stopped++; },
    onExit() {},
    onNetworkChange() {},
    async addServer() {},
    verifyExitIp: async () => (through ? "1.2.3.4" : null),
  }),
};
const { Controller } = await import("./controller.js");
(await import("./dist/guardian.js")).useDirect((url, init) => fetch(url, init)); // Mozilla, directly: the fetch() stood in for above
const c = new Controller({ copy: () => {}, updates: { state: () => ({}), on() {} }, android });
c.signedIn({ uid: "u1", email: "me@example.com", sessionToken: "a".repeat(64) });
assert.ok(await until(() => c.state().auth.stage === "ready"), "signed in");
await c.reloadList();
const text = () => c.state().message?.text ?? "";

// ── a server that doesn't answer on this network: not connected, and why ───────────────────────────────────────
await c.connect("JP");
assert.equal(c.state().active, null, "not connected");
assert.equal(c.state().proxy, null, "no proxy left on");
assert.match(text(), /^connect failed: Firefox VPN's server doesn't answer on this network \(ECONNREFUSED\): it seems blocked here/);
await sleep(300); // the look at the network (netState) after it: online, so it stays said
assert.match(text(), /^connect failed: Firefox VPN's server/);

// it answers: connected
await c.connect("DE");
assert.equal(c.state().active, "DE");
assert.equal(text(), "connected");
// a move to the one that doesn't answer: refused before anything moves, the connection there was carries on
await c.connect("JP");
assert.equal(c.state().active, "DE", "still on Germany");
assert.match(text(), /^connect failed: Firefox VPN's server doesn't answer/);

// ── whole-system mode with no internet through it, the VPN carrying: it goes, the proxy stays ───────────────────
through = false;
await c.toggleGlobal();
assert.equal(sessions, 1);
assert.equal(stopped, 1, "whole-system mode taken down");
assert.equal(c.state().globalOn, false);
assert.equal(c.state().active, "DE", "the proxy works: it stays");
assert.equal(text(), "global failed: no internet through it, though the VPN works (a DNS problem?) — global off, SOCKS proxy still on");
// with it: on
through = true;
await c.toggleGlobal();
assert.equal(c.state().globalOn, true);
assert.equal(text(), "global ON · exit IP 1.2.3.4");
await c.toggleGlobal(); // off again
assert.equal(c.state().globalOn, false);

// ── carrying nothing either: it disconnects ───────────────────────────────────────────────────────────────────
through = false;
vpn = "refuse";
await c.toggleGlobal();
assert.equal(c.state().globalOn, false);
assert.equal(c.state().active, null, "disconnected, rather than say connected");
assert.equal(text(), "global failed: Firefox VPN's server refused it: HTTP/1.1 403 Forbidden — disconnected");
vpn = "ok";
through = true;

// ── Mozilla refuses the VPN's token at a connect, a new one too: another's got, and the connect goes by itself ──────
// (where it said to quit and open Foxhole again); refused on that one too, it's said, not tried again
refusals = 2; // the token in hand, and the new one Connection asks for at once
await c.connect("DE");
assert.equal(text(), "getting a new token from Mozilla…");
assert.ok(await until(() => c.state().active === "DE"), "connected by itself, on a new token");
await c.disconnect();
refusals = 4;
await c.connect("DE");
assert.ok(await until(() => /^Mozilla refused the VPN's token: Proxy pass: login rejected/.test(text())), `refused again: said (${text()})`);
await sleep(1500);
assert.equal(c.state().active, null, "not connected, nor tried again");
assert.equal(refusals, 0);
assert.equal(c.state().auth.stage, "ready");

// ── the sign-in ends while connected: disconnected, and the window asks to sign in again ──────────────────────────
await c.connect("DE");
assert.equal(c.state().active, "DE");
signedIn = false;
// a page through the proxy: its pass is due, Guardian refuses the token, the new one's refused too (errno 110)
await new Promise((resolve) => {
  const req = http.get({ host: "127.0.0.1", port: proxyPort, path: "http://api.ipify.org/", headers: { Host: "api.ipify.org" }, timeout: 5000 }, (res) => (res.resume(), resolve()));
  req.on("error", resolve).on("timeout", () => (req.destroy(), resolve()));
});
assert.ok(await until(() => c.state().auth.stage === "expired"), "Sign in again");
assert.equal(c.state().active, null, "disconnected");

// ── another VPN taking all the traffic (Windscribe's routes): whole-system mode says so before a password's asked ──────
if (process.platform === "linux") {
  const bin = mkdtempSync(join(tmpdir(), "foxhole-gui-vpncheck-bin-"));
  const routes = "0.0.0.0/1 via 10.146.52.1 dev tun0\ndefault via 192.168.0.1 dev wlo1 proto dhcp metric 20600\n128.0.0.0/1 via 10.146.52.1 dev tun0\n";
  writeFileSync(join(bin, "ip"), `#!/bin/sh\nprintf '${routes.replace(/\n/g, "\\n")}'\n`, { mode: 0o755 });
  writeFileSync(join(bin, "ps"), "#!/bin/sh\nprintf 'helper\\nWindscribe\\nwindscribeopenv\\nclash-verge-ser\\n'\n", { mode: 0o755 });
  const path = process.env.PATH;
  process.env.PATH = `${bin}:${path}`;
  const desktop = new Controller({ copy: () => {}, updates: { state: () => ({}), on() {} } });
  await desktop.toggleGlobal();
  assert.equal(desktop.state().message?.text, "global failed: Another VPN is on (Windscribe, on tun0) and takes all the traffic: turn it off for whole-system mode; the proxy works alongside it");
  assert.equal(desktop.state().pw, null, "no password asked for");
  assert.equal(desktop.state().globalOn, false);
  process.env.PATH = path;
}

net.connect = realConnect;
https.request = realRequest;
server.close();
door.close();
console.log("ok - vpn check: connected only once the internet opens through the server (a move to one that doesn't keeps the one there was); whole-system mode with none through it goes, the proxy staying if the VPN carries, else disconnected; an ended sign-in disconnects and asks to sign in again; a refused token at a connect, got anew and connected by itself, once; another VPN on, whole-system mode says which before a password");
process.exit(0);
