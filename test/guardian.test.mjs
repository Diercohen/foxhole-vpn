// Global mode pins Guardian's IP so renewing the pass never needs the tunnel. Requests
// must go to that IP yet keep the real hostname for TLS and Host, or Fastly can't serve
// them. A fake Guardian with a self-signed cert stands in; no network needed.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert

import http from "node:http";
import net from "node:net";
import https from "node:https";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { fetchPass, fetchUsage, pinGuardian, useRelay, useTunnel, GuardianBlocked, GuardianError } from "../dist/guardian.js";

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 15000).unref();

const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-vpn-"));
const key = path.join(dir, "k.pem");
const cert = path.join(dir, "c.pem");
execFileSync("openssl", [
  "req", "-x509", "-newkey", "rsa:2048", "-nodes",
  "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
], { stdio: "ignore" });

const jwt = `x.${Buffer.from(JSON.stringify({ nbf: 1, exp: 2 })).toString("base64url")}.y`;
const seen = [];
const guardian = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
  seen.push({ sni: req.socket.servername, host: req.headers.host, auth: req.headers.authorization });
  if (req.headers.authorization === "Bearer region") return res.writeHead(451).end(); // Mozilla refuses this network's country
  if (req.headers.authorization !== "Bearer good") return res.writeHead(401).end();
  res.writeHead(200, { "X-Quota-Limit": "100", "X-Quota-Remaining": "40", "X-Quota-Reset": "2026-11-01T00:00:00Z" });
  res.end(req.method === "HEAD" ? undefined : JSON.stringify({ token: jwt }));
});
await new Promise((r) => guardian.listen(0, "127.0.0.1", r));

// Every connection lands on the fake Guardian; record the address it was meant for.
let port = guardian.address().port;
const dialed = [];
https.globalAgent = new (class extends https.Agent {
  createConnection(opts, cb) {
    dialed.push(opts.host);
    return super.createConnection({ ...opts, host: "127.0.0.1", port }, cb);
  }
})({ keepAlive: false });

assert.strictEqual((await fetchUsage("good")).max, 100n, "HEAD carries the usage headers");
pinGuardian("203.0.113.7"); // TEST-NET-3, never a real host: proves the hostname isn't looked up
const { pass, usage } = await fetchPass("good");
assert.strictEqual(pass.token, jwt);
assert.strictEqual(pass.expires, 2);
assert.strictEqual(usage.remaining, 40n);
assert.deepStrictEqual(dialed, ["vpn.mozilla.org", "203.0.113.7"], "dials the hostname, then the pinned IP");
for (const s of seen) assert.deepStrictEqual(s, { sni: "vpn.mozilla.org", host: "vpn.mozilla.org", auth: "Bearer good" });

await assert.rejects(fetchPass("bad"), (err) => err instanceof GuardianError && err.status === 401);

// A 451 is Mozilla refusing this network's region by its address: with a relay set, the call goes again through it
// (Google's address); with none, it's what a relay gets around, as a blocked vpn.mozilla.org. Other refusals (401)
// aren't the address's, so they aren't relayed.
await assert.rejects(fetchPass("region"), (err) => err instanceof GuardianBlocked && err.region === true, "no relay: one is what's needed");
await assert.rejects(fetchUsage("region"), (err) => err instanceof GuardianBlocked && err.region, "the usage's check says so too");
const relayed = [];
const relayServer = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c)).on("end", () => {
    relayed.push(JSON.parse(body));
    const b = Buffer.from(JSON.stringify({ token: jwt })).toString("base64");
    res.end(JSON.stringify({ s: 200, h: { "X-Quota-Limit": "100", "X-Quota-Remaining": "7", "X-Quota-Reset": "2026-11-01T00:00:00Z" }, b }));
  });
});
await new Promise((r) => relayServer.listen(0, "127.0.0.1", r));
useRelay({ url: `http://127.0.0.1:${relayServer.address().port}/exec`, key: "k" });
const viaRelay = await fetchPass("region");
assert.strictEqual(viaRelay.pass.token, jwt, "the pass comes through the relay");
assert.strictEqual(viaRelay.usage.remaining, 7n, "with the relay's usage headers");
assert.deepStrictEqual(relayed, [{ k: "k", u: "https://vpn.mozilla.org/api/v1/fpn/token", m: "GET", h: { Authorization: "Bearer region", "Content-Type": "application/json" } }]);
await assert.rejects(fetchPass("bad"), (err) => err instanceof GuardianError && err.status === 401);
assert.strictEqual(relayed.length, 1, "a 401 isn't relayed");

// Connected, the calls go through the VPN's tunnel first (proxy.ts ownTunnel), TLS to vpn.mozilla.org on it: neither
// dialed directly nor relayed. A tunnel that can't open, or meets a 451 all the same, leaves the usual way.
const tunneled = [];
useTunnel(async (host, p) => (tunneled.push(`${host}:${p}`), net.connect(port, "127.0.0.1")));
const before = { dialed: dialed.length, seen: seen.length };
assert.strictEqual((await fetchUsage("good")).remaining, 40n, "the usage, through the tunnel");
assert.deepStrictEqual(tunneled, ["vpn.mozilla.org:443"]);
assert.strictEqual(dialed.length, before.dialed, "not dialed directly");
assert.deepStrictEqual(seen.at(-1), { sni: "vpn.mozilla.org", host: "vpn.mozilla.org", auth: "Bearer good" }, "the hostname's TLS, on the tunnel");
assert.strictEqual(seen.length, before.seen + 1);
await fetchPass("region");
assert.strictEqual(relayed.length, 2, "a 451 through the tunnel goes on the usual way, to the relay");
let n = dialed.length;
useTunnel(async () => null); // no pass in hand yet, or relay mode
await fetchUsage("good");
assert.strictEqual(dialed.length, ++n, "no tunnel: directly");
useTunnel(async () => Promise.reject(new Error("the VPN's server refused the pass")));
await fetchUsage("good");
assert.strictEqual(dialed.length, ++n, "a tunnel that fails: directly");
useTunnel(null);
useRelay(null);
relayServer.close();
guardian.close();
port = 1; // nothing listens there
await assert.rejects(
  fetchPass("good"),
  (err) => err.message === "can't reach vpn.mozilla.org" && err.cause?.code === "ECONNREFUSED",
);
console.log("ok - Guardian requests dial the pinned IP and keep the hostname for TLS and Host, and a 451 goes through the relay");
