// node test/vpncheck.test.mjs: whether Firefox VPN carries anything before it's said to be on (proxy.ts checkVpn): a page
// asked of ipify and Cloudflare through the server, on a pass. A server that answers, one that isn't there (the network
// blocks it), one that refuses, one that takes the tunnel and lets nothing back, and one site down with the other up. Then
// the pass (connection.ts): a token Guardian refuses is asked for anew, once, as is a pass a VPN server refuses at a
// connect's look, and a sign-in that's ended is told, once.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the stand-in server's own certificate

import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
process.env.HOME = process.env.USERPROFILE = mkdtempSync(path.join(os.tmpdir(), "foxhole-home-")); // nothing in ~/.config
const { checkVpn, VpnCheckError } = await import("../dist/proxy.js");
const { Connection } = await import("../dist/connection.js");

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-vpncheck-"));
const key = path.join(dir, "k.pem"), cert = path.join(dir, "c.pem");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });

// Firefox VPN's server, as `how` has it for each CONNECT's site (and its head): "ok" answers the page, "refuse" a 403,
// "silent" lets nothing back, "expired" refuses the pass as Fastly does once it's expired by its clock
const asked = [];
function vpnServer(how) {
  const server = tls.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) => {
    s.on("error", () => {});
    let buf = "";
    const onData = (d) => {
      buf += d.toString("latin1");
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      s.removeListener("data", onData);
      const [, site] = /^CONNECT ([^:]+):80 /.exec(buf) ?? [];
      asked.push({ site, pass: /Proxy-Authorization: Bearer pass-1/.test(buf) });
      const way = how(site, buf);
      if (way === "refuse") return void s.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      if (way === "expired") return void s.end("HTTP/1.1 401 Bad Request (JWT)\r\nx-fastly-proxy-auth-failed: expired_token\r\n\r\ntoken expired\n");
      s.write("HTTP/1.1 200 OK\r\n\r\n");
      if (way === "silent") return;
      s.once("data", (req) => assert.match(req.toString(), new RegExp(`^GET \\S+ HTTP/1.1\\r\\nHost: ${site.replace(/\./g, "\\.")}\\r\\n`), "the page asked of the site"));
      s.once("data", () => s.end("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n1.2.3.4"));
    };
    s.on("data", onData);
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ server, at: { hostname: "localhost", ip: "127.0.0.1", port: server.address().port } })));
}
const conn = { currentPass: async () => ({ token: "pass-1", notBefore: 0, expires: 2 ** 31 }) };
const fails = (p) => p.then(() => assert.fail("it should fail"), (err) => err);

// it carries: both sites asked at once, on the pass, the first answer does
let { server, at } = await vpnServer(() => "ok");
await checkVpn(conn, at);
// the other's still asked, maybe a moment after (each connection's routes are raced first, proxy.ts connectTls)
for (const end = Date.now() + 2000; asked.length < 2 && Date.now() < end; ) await new Promise((r) => setTimeout(r, 10));
assert.deepEqual(asked.map((a) => a.site).sort(), ["api.ipify.org", "www.cloudflare.com"], "ipify and Cloudflare, both");
assert.ok(asked.every((a) => a.pass), "on the pass");
server.close();

// one site down: the other does
asked.length = 0;
({ server, at } = await vpnServer((site) => (site === "api.ipify.org" ? "refuse" : "ok")));
await checkVpn(conn, at);
server.close();

// refused: its status said
({ server, at } = await vpnServer(() => "refuse"));
let err = await fails(checkVpn(conn, at));
assert.ok(err instanceof VpnCheckError);
assert.equal(err.message, "Firefox VPN's server refused it: HTTP/1.1 403 Forbidden");
assert.equal(err.answered, true, "it answered on this network");
server.close();

// the tunnel's up, but nothing comes back through it
({ server, at } = await vpnServer(() => "silent"));
err = await fails(checkVpn(conn, at, 800));
assert.equal(err.message, "Firefox VPN's server took the connection, but nothing came back through it (timed out)");
assert.equal(err.answered, true);
server.close();

// nothing there: the network blocks it (here, a closed port's refusal; a silent drop says "timed out")
const closed = net.createServer();
await new Promise((r) => closed.listen(0, "127.0.0.1", r));
const nowhere = { hostname: "localhost", ip: "127.0.0.1", port: closed.address().port };
closed.close();
err = await fails(checkVpn(conn, nowhere));
assert.equal(err.message, "Firefox VPN's server doesn't answer on this network (ECONNREFUSED): it seems blocked here");
assert.equal(err.answered, false, "it didn't answer");
const silentDrop = net.createServer(() => {}); // takes the TCP connection, never the TLS handshake
await new Promise((r) => silentDrop.listen(0, "127.0.0.1", r));
err = await fails(checkVpn(conn, { hostname: "localhost", ip: "127.0.0.1", port: silentDrop.address().port }, 800));
assert.equal(err.message, "Firefox VPN's server doesn't answer on this network (timed out): it seems blocked here");
silentDrop.close();

// the pass's own errors come as they are (a sign-in that's ended, Guardian's)
const ended = Object.assign(new Error("This sign-in has ended (signed out, or expired): sign in again."), { errno: 110 });
err = await fails(checkVpn({ currentPass: async () => Promise.reject(ended) }, at));
assert.equal(err, ended);
console.log("ok - checkVpn: carries through the server (one site down, the other does); refused, nothing back, or no answer on this network, each said");

// ── the pass: Guardian (vpn.mozilla.org) stands in here, taking only the token "fresh"; each pass a new one, made now ────
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
let minted = 0;
const t0 = Math.floor(Date.now() / 1000);
const jwtN = (n) => `${b64({ alg: "none" })}.${b64({ nbf: t0, exp: t0 + 600, n })}.x`;
const realRequest = https.request;
let guardianAsked = [];
https.request = (o, cb) => {
  if (o?.servername !== "vpn.mozilla.org") return realRequest(o, cb);
  const req = Object.assign(new EventEmitter(), { destroy() {} });
  req.end = () =>
    setImmediate(() => {
      const token = o.headers.Authorization.slice(7);
      guardianAsked.push(token);
      const res = Object.assign(new EventEmitter(), { statusCode: token === "fresh" ? 200 : 401, rawHeaders: [] });
      cb(res);
      if (res.statusCode === 200) res.emit("data", Buffer.from(JSON.stringify({ token: jwtN(++minted) })));
      res.emit("end");
    });
  return req;
};

// a token kept from before that Guardian refuses: dropped, and a new one asked for, once
let made = 0;
const kept = {
  cached: null,
  async getAccessToken() {
    return (this.cached ??= ++made === 1 ? "stale" : "fresh");
  },
  forget() {
    this.cached = null;
  },
};
const c = new Connection(kept);
const pass = await c.currentPass();
assert.equal(pass.token, jwtN(1));
assert.deepEqual(guardianAsked, ["stale", "fresh"], "refused, then asked with a new token");

// a pass the VPN's servers no longer take (expired by their clock: this computer's slow), at a connect's look: it looks
// again on a new one, once, where the connect failed on it ("401 Bad Request (JWT)") till this clock said it was due
({ server, at } = await vpnServer((site, head) => (head.includes(pass.token) ? "expired" : "ok")));
await checkVpn(c, at);
assert.equal((await c.currentPass()).token, jwtN(2), "a new pass, kept");
server.close();
({ server, at } = await vpnServer(() => "expired"));
err = await fails(checkVpn(c, at));
assert.equal(err.message, "Firefox VPN's server refused it: HTTP/1.1 401 Bad Request (JWT)", "refused on the new one too: said");
assert.equal(minted, 3, "asked once more, not again and again");
server.close();
// one with no other token to give (FOXHOLE_ACCESS_TOKEN's): Guardian's refusal as it is, asked once
guardianAsked = [];
err = await fails(new Connection({ getAccessToken: async () => "stale" }).currentPass());
assert.equal(err.status, 401);
assert.deepEqual(guardianAsked, ["stale"]);

// a sign-in that's ended: told once (a page's many connections each ask), for this account only
let told = 0;
const gone = new Connection({ getAccessToken: async () => Promise.reject(ended) });
gone.onSignInEnded((e) => (assert.equal(e, ended), told++));
for (let i = 0; i < 3; i++) assert.equal(await fails(gone.currentPass()), ended, "the pass fails with it");
assert.equal(await fails(gone.refreshUsage()), ended, "the data left too");
assert.equal(told, 1, "told once");
gone.setAuth({ getAccessToken: async () => Promise.reject(Object.assign(new Error("offline"), { errno: undefined })) });
await fails(gone.currentPass());
assert.equal(told, 1, "another failure isn't an ended sign-in");
https.request = realRequest;
console.log("ok - the pass: a refused token asked for anew once; a pass the VPN's server refuses, anew at a connect's look, once; an ended sign-in told once");
process.exit(0);
