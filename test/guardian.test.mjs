// Global mode pins Guardian's IP so renewing the pass never needs the tunnel. Requests
// must go to that IP yet keep the real hostname for TLS and Host, or Fastly can't serve
// them. A fake Guardian with a self-signed cert stands in; no network needed.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert

import https from "node:https";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { fetchPass, fetchUsage, pinGuardian, GuardianError } from "../dist/guardian.js";

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
guardian.close();
port = 1; // nothing listens there
await assert.rejects(
  fetchPass("good"),
  (err) => err.message === "can't reach vpn.mozilla.org" && err.cause?.code === "ECONNREFUSED",
);
console.log("ok - Guardian requests dial the pinned IP and keep the hostname for TLS and Host");
