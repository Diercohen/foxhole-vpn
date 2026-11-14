// The ways an update comes (ways.ts), offline: their order; a download that goes on by the next way where one can't
// connect, is too slow or breaks off, from where it stopped; through Firefox VPN opened for it (a fake Fastly server
// that wants the pass); through the relay (a fake Apps Script on a fake Google front) in pieces, its link to the file
// asked anew when it runs out; and the TUI's npm package, by those ways and checked against npm's checksum. A fake
// GitHub and a fake npm registry stand in.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the fakes' self-signed certificate
import assert from "node:assert";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-ways-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });
const cert = { key: readFileSync(path.join(dir, "k.pem")), cert: readFileSync(path.join(dir, "c.pem")) };

// GitHub: a release's file sent from elsewhere (its storage, by a link that runs out), Range and all; and npm's registry
const blob = randomBytes(9 * 1024 * 1024 + 12345); // three pieces through the relay (4 MB a piece)
const tgz = randomBytes(50_000); // the TUI's package
const hits = []; // what it was asked for the file: "path range"
const next = { cut: 0, slow: false, expired: 0 }; // the next answers for the file: broken off after `cut` bytes, trickling, refused as run out
const gh = https.createServer(cert, (req, res) => {
  const { pathname } = new URL(req.url, "https://x");
  if (pathname === "/foxhole-vpn/latest") {
    const integrity = `sha512-${createHash("sha512").update(tgz).digest("base64")}`;
    return res.end(JSON.stringify({ version: "9.9.9", dist: { tarball: `https://${req.headers.host}/foxhole-vpn/-/foxhole-vpn-9.9.9.tgz`, integrity } }));
  }
  if (pathname === "/foxhole-vpn/-/foxhole-vpn-9.9.9.tgz") return res.end(tgz);
  if (pathname === "/releases/download/v9.9.9/app.bin") return res.writeHead(302, { location: `https://${req.headers.host}/storage/app.bin?sig=1` }).end();
  if (pathname !== "/storage/app.bin") return res.writeHead(404).end();
  hits.push(`${pathname} ${req.headers.range ?? ""}`);
  if (next.expired) return next.expired--, res.writeHead(403).end("Signature not valid in the specified time frame");
  const m = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range ?? "");
  const from = m ? Number(m[1]) : 0;
  const to = m?.[2] ? Math.min(Number(m[2]), blob.length - 1) : blob.length - 1;
  if (from >= blob.length) return res.writeHead(416, { "content-range": `bytes */${blob.length}` }).end();
  const body = blob.subarray(from, to + 1);
  res.writeHead(m ? 206 : 200, { "content-length": body.length, ...(m && { "content-range": `bytes ${from}-${to}/${blob.length}` }) });
  if (next.slow) {
    next.slow = false;
    let i = 0;
    const t = setInterval(() => (res.destroyed || i * 1024 >= body.length ? clearInterval(t) : res.write(body.subarray(i * 1024, ++i * 1024))), 20);
    return void res.on("close", () => clearInterval(t));
  }
  if (next.cut) {
    const n = next.cut;
    next.cut = 0;
    return void res.write(body.subarray(0, n), () => res.destroy());
  }
  res.end(body);
});
const ghPort = await listen(gh);
process.env.FOXHOLE_REGISTRY = `https://127.0.0.1:${ghPort}`;

// Firefox VPN's server: TLS, then CONNECT with the pass, to GitHub whatever the name asked
const tunnels = [];
const fastly = tls.createServer(cert, (s) => {
  s.on("error", () => {});
  let buf = Buffer.alloc(0);
  s.on("data", function head(d) {
    buf = Buffer.concat([buf, d]);
    const i = buf.indexOf("\r\n\r\n");
    if (i < 0) return;
    s.removeListener("data", head);
    const text = buf.toString("latin1", 0, i);
    tunnels.push(text.split(" ")[1]);
    if (!/\r\nProxy-Authorization: Bearer faketoken\r\n/.test(`${text}\r\n`)) return s.end("HTTP/1.1 401 Unauthorized\r\n\r\n");
    const t = net.connect(ghPort, "127.0.0.1", () => (s.write("HTTP/1.1 200 OK\r\n\r\n"), s.pipe(t).pipe(s)));
    t.on("error", () => s.destroy());
  });
});
const fastlyPort = await listen(fastly);
let passFails = false; // Guardian won't give a pass (its answer has a status: not GitHub's)
const account = {
  anyServer: { hostname: "localhost", ip: "127.0.0.1", port: fastlyPort, quarantined: false },
  currentPass: async () => {
    if (passFails) throw Object.assign(new Error("Proxy pass: monthly data quota exceeded"), { status: 429 });
    return { token: "faketoken", notBefore: 0, expires: 9e9 };
  },
};

// Google's front, with the script on it: UrlFetchApp as Code.gs uses it (headers passed on, redirects not followed)
const KEY = "test-key-0123456789abcdef";
const calls = []; // the script's: { u, range }
const wrap = (obj) => `<html><script>goog.script.init("${JSON.stringify({ userHtml: JSON.stringify(obj) }).replace(/"/g, "\\x22")}", "", undefined, true);</script></html>`;
const front = tls.createServer(cert, (s) => {
  http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const p = JSON.parse(body);
      if (p.k !== KEY) return res.end(wrap({ e: "unauthorized" }));
      calls.push({ u: new URL(p.u).pathname, range: p.h.range });
      const u = new URL(p.u);
      const r = https.request({ host: "127.0.0.1", port: ghPort, path: u.pathname + u.search, headers: { ...p.h, host: u.host } }, (t) => {
        const chunks = [];
        t.on("data", (c) => chunks.push(c));
        t.on("end", () => res.end(wrap({ s: t.statusCode, h: t.headers, b: Buffer.concat(chunks).toString("base64") })));
      });
      r.on("error", (e) => res.end(wrap({ e: `Exception: ${e.message}` })));
      r.end();
    });
  }).emit("connection", s);
});
const frontPort = await listen(front);
const relay = { relay: { url: "https://script.google.com/macros/s/DEPLOY_ID_0123456789abcdefgh/exec", key: KEY }, server: { hostname: "www.google.com", ip: "127.0.0.1", port: frontPort, quarantined: false } };

const { updateWays, throughWays, download, get, triedText, wayName } = await import("../dist/ways.js");
const vias = (ways) => ways.map((w) => w.via);

// The order: Firefox VPN while it's on, then directly; else directly, then Firefox VPN opened for it; the relay last
const proxy = { host: "127.0.0.1", port: 1 };
assert.deepEqual(vias(updateWays({ vpn: proxy, conn: account, relay })), ["vpn", "direct", "relay"], "on: through Firefox VPN first");
assert.equal(updateWays({ vpn: proxy, conn: account }).find((w) => w.via === "vpn").proxy, proxy, "by the proxy that's running");
assert.deepEqual(vias(updateWays({ vpn: null, conn: account, relay })), ["direct", "vpn", "relay"], "off: directly first, then Firefox VPN");
assert.equal(typeof updateWays({ conn: account }).find((w) => w.via === "vpn").tunnel, "function", "opened for it");
assert.deepEqual(vias(updateWays({ conn: null, relay })), ["direct", "relay"], "not signed in: no Firefox VPN");
assert.deepEqual(vias(updateWays({ conn: account, relay: { relay: null, server: null } })), ["direct", "vpn"], "no relay set: none");
assert.equal(triedText(updateWays({ conn: account, relay })), "directly, through Firefox VPN or through your relay");
assert.equal(wayName({ via: "relay" }), "through your relay");

// throughWays: a way's failure goes on to the next; the server's answer (a status) is the last one tried
const seen = [];
assert.equal(await throughWays(updateWays({ conn: account, relay }), async (w) => (seen.push(w.via), w.via === "relay" ? "got" : Promise.reject(new Error("no")))), "got");
assert.deepEqual(seen, ["direct", "vpn", "relay"]);
seen.length = 0;
await assert.rejects(throughWays(updateWays({ conn: account, relay }), async (w) => (seen.push(w.via), Promise.reject(Object.assign(new Error("HTTP 404"), { status: 404 })))), { status: 404 });
assert.deepEqual(seen, ["direct"], "GitHub's 404 isn't asked again another way");
await assert.rejects(throughWays(updateWays({ relay }), async () => Promise.reject(new Error("cut"))), (err) => triedText(err.tried) === "directly or through your relay", "the ways tried are said");

const url = (host) => `https://${host}/releases/download/v9.9.9/app.bin`;
const here = url(`127.0.0.1:${ghPort}`);
const blocked = url("github.invalid"); // no such name: directly it can't connect; Firefox VPN's server and the relay reach it
const file = (n) => path.join(dir, n);

// Directly, by GitHub's redirect to its storage
let shown = 0;
await download(here, file("a"), { via: "direct" }, (p) => (shown = p));
assert.ok(readFileSync(file("a")).equals(blob) && shown === 100, "directly");

// Through Firefox VPN opened for it (directly blocked): its server is asked with the pass, for GitHub's name
const off = updateWays({ conn: account, relay });
hits.length = 0;
await throughWays(off, (w, last) => download(blocked, file("b"), w, () => {}, { last }));
assert.ok(readFileSync(file("b")).equals(blob), "through Firefox VPN while it's off");
assert.deepEqual(tunnels, ["github.invalid:443", "github.invalid:443"], "to GitHub, then its storage (no pass needed again from Guardian: the account has one)");
assert.deepEqual(hits, ["/storage/app.bin "], "Firefox VPN got it all at once");

// Through the relay when Firefox VPN won't give a pass either: in pieces, a few at once, written in order
passFails = true;
hits.length = 0;
calls.length = 0;
const way = [];
await throughWays(off, (w, last) => (way.push(w.via), download(blocked, file("c"), w, () => {}, { last })));
assert.deepEqual(way, ["direct", "vpn", "relay"]);
assert.ok(readFileSync(file("c")).equals(blob), "through the relay, the pieces make the file");
const M = 4 << 20;
const start = (c) => Number(/bytes=(\d+)/.exec(c.range)[1]);
const rest = calls.slice(2).sort((a, b) => start(a) - start(b)); // asked at once: in any order
assert.deepEqual([...calls.slice(0, 2), ...rest].map((c) => c.range), [`bytes=0-${M - 1}`, `bytes=0-${M - 1}`, `bytes=${M}-${2 * M - 1}`, `bytes=${2 * M}-${blob.length - 1}`], "a redirect, then a piece a call");
assert.equal(calls[0].u, "/releases/download/v9.9.9/app.bin", "the first to GitHub, the rest to where it sent");
assert.ok(calls.slice(1).every((c) => c.u === "/storage/app.bin"));
passFails = false;

// GitHub's link to its storage runs out between pieces: asked anew from GitHub, and the piece goes on
calls.length = 0;
writeFileSync(file("d"), blob.subarray(0, M)); // the first piece here already
next.expired = 1;
await download(blocked, file("d"), { via: "relay", conn: relay }, () => {});
assert.ok(readFileSync(file("d")).equals(blob), "a link that ran out is asked for again");
assert.deepEqual(calls.map((c) => c.u), ["/releases/download/v9.9.9/app.bin", "/storage/app.bin", "/releases/download/v9.9.9/app.bin", "/storage/app.bin", "/storage/app.bin"]);

// Directly, it breaks off: the next way carries on from there (by Range), not from the start
next.cut = 2 * M; // of the 9 MB
hits.length = 0;
rmSync(file("e"), { force: true });
await throughWays([{ via: "direct" }, { via: "relay", conn: relay }], (w, last) => download(here, file("e"), w, () => {}, { last }));
const kept = Number(/bytes=(\d+)-/.exec(hits[1])?.[1]);
assert.ok(kept > 0 && kept <= 2 * M && hits[0] === "/storage/app.bin ", "what came directly is kept");
assert.ok(readFileSync(file("e")).equals(blob), "and the relay brings the rest");

// Directly, it trickles: given up on (it isn't the last way), and Firefox VPN carries on
next.slow = true;
hits.length = 0;
rmSync(file("f"), { force: true });
const slow = { ms: 300, bytes: 64 * 1024 };
await throughWays([{ via: "direct" }, off[1]], (w, last) => download(here, file("f"), w, () => {}, { last, slow }));
assert.equal(hits.length, 2, "a second way took over");
assert.ok(readFileSync(file("f")).equals(blob), "from where the slow one stopped");
// the last way is let run, however slow (here: only a few KB short, so a moment)
next.slow = true;
writeFileSync(file("g"), blob.subarray(0, blob.length - 8 * 1024));
await download(here, file("g"), { via: "direct" }, () => {}, { last: true, slow });
assert.ok(readFileSync(file("g")).equals(blob), "the last way isn't given up on");

// Stopped (the TUI's esc): no other way is tried
const stop = new AbortController();
next.slow = true;
seen.length = 0;
rmSync(file("h"), { force: true });
setTimeout(() => stop.abort(new Error("stopped")), 100);
await assert.rejects(throughWays(off, (w, last) => (seen.push(w.via), download(here, file("h"), w, () => {}, { last, signal: stop.signal })), stop.signal), /stopped/);
assert.deepEqual(seen, ["direct"]);

// get(): a GitHub answer through each way, the relay's from memory
for (const w of [{ via: "direct" }, off[1], off[2]]) {
  const res = await get(here.replace("download/v9.9.9/app.bin", "nothing"), w);
  res.resume();
  assert.equal(res.statusCode, 404, `${w.via}: GitHub's own answer`);
}

// The TUI's package: npm's latest, then its file by the ways, checked against npm's checksum
const update = await import("../dist/update.js");
await update.checkUpdate([{ via: "direct" }]);
assert.equal(update.latestVersion(), "9.9.9");
assert.equal(update.canDownload(), true, "npm said where its package is");
const ways = [];
const tgzFile = await update.downloadUpdate([{ via: "vpn", proxy: { host: "127.0.0.1", port: 1 } }, { via: "direct" }], { onWay: (w) => ways.push(w.via) });
assert.deepEqual(ways, ["vpn", "direct"], "Firefox VPN's proxy first (on, but down here), then directly");
assert.ok(readFileSync(tgzFile).equals(tgz), "the package");
rmSync(path.dirname(tgzFile), { recursive: true });
tgz[0] ^= 1; // what comes isn't what npm published
await assert.rejects(update.downloadUpdate([{ via: "direct" }]), /doesn't match npm's checksum/);

gh.close();
fastly.close();
front.close();
console.log("ok - ways: their order; on by the next where one can't, breaks off or is too slow, from where it stopped; Firefox VPN opened for it; the relay in pieces, its link asked anew; npm's package checked");
process.exit(0);
