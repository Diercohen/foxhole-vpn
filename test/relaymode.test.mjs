// Relay mode end to end, offline: the proxy in relay mode, a mock of Google's front (fronted sites, and the Apps Script
// that fetches like Code.gs's UrlFetchApp) and a mock origin. Checks the certificates, opening HTTPS, batching,
// cookies, preflights, fronting, the made-up DNS answers and the error pages.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the mock front's self-signed certificate (Google's, in real life)
import os from "node:os";
import path from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
process.env.HOME = mkdtempSync(path.join(os.tmpdir(), "foxhole-relay-")); // the CA is made here, not in ~/.config
process.env.USERPROFILE = process.env.HOME;

import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import assert from "node:assert";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { X509Certificate } from "node:crypto";

const { startProxy } = await import("../dist/proxy.js");
const { caFiles, loadCa } = await import("../dist/mitm.js");
loadCa(); // made (and trusted) before relay mode starts, as the app does
const { relayCheck, relayVerdict, onRelayNotice, onRelaySplit, setDirectDial, fakeName, splitCookies, fronted, dnsAnswer, relayProblem } = await import("../dist/relaymode.js");
const { useSplit } = await import("../dist/split.js");
const { answerAddrs } = await import("../dist/dns.js");

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const KEY = "test-key-0123456789abcdef";

// The origin: what a site would answer
const origin = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    if (req.url === "/hello") return res.end(`hello from ${req.headers.host} ua=${req.headers["user-agent"] ?? ""} ae=${req.headers["accept-encoding"] ?? ""}`);
    if (req.url === "/echo") return res.end(`${req.method} ${req.headers["content-type"]} ${body}`);
    if (req.url === "/cookies") {
      res.setHeader("set-cookie", ["a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/", "b=2; Path=/"]);
      return res.end("ok");
    }
    if (req.url === "/big") return res.end("x".repeat(100_000));
    if (req.url === "/redirect") return res.writeHead(302, { location: "/hello" }).end();
    if (req.url === "/generate_204") return res.writeHead(204).end();
    if (req.url.startsWith("/challenge")) return res.writeHead(403, { "cf-mitigated": "challenge", "content-type": "text/html" }).end("Just a moment...");
    if (req.url === "/dns-query") return res.end(dnsAnswer(Buffer.from(body, "latin1"), body.length, ["127.0.0.1"], 60)); // every name is the mock front
    res.writeHead(404).end("nope");
  });
});
const originPort = await listen(origin);

// UrlFetchApp, as Code.gs uses it: every URL goes to the origin, its host in the Host header
function urlFetch(item) {
  return new Promise((resolve) => {
    const u = new URL(item.u);
    const headers = { ...item.h, host: u.host };
    const req = http.request({ host: "127.0.0.1", port: originPort, method: item.m, path: u.pathname + u.search, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        const gz = gzipSync(raw);
        const h = { ...res.headers };
        if (h["set-cookie"]) h["set-cookie"] = h["set-cookie"].join(", "); // joined, as Apps Script sometimes does
        resolve(gz.length < raw.length ? { s: res.statusCode, h, b: gz.toString("base64"), gz: 1 } : { s: res.statusCode, h, b: raw.toString("base64") });
      });
    });
    req.end(item.b ? Buffer.from(item.b, "base64") : undefined);
  });
}

// Google's front: the script (Host script.google.com) and fronted sites (any other Host)
const calls = [];
let script = "current"; // "old": Code.gs from before it escaped "<", so Apps Script's error page instead of its answer
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-front-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=www.google.com"], { stdio: "ignore" });
const wrap = (obj) => {
  // Apps Script's HtmlService page around the JSON (what parseEnvelope unwraps)
  const inner = JSON.stringify({ userHtml: JSON.stringify(obj) }).replace(/"/g, "\\x22");
  return `<html><script>goog.script.init("${inner}", "", undefined, true);</script></html>`;
};
const front = tls.createServer({ key: readFileSync(path.join(dir, "k.pem")), cert: readFileSync(path.join(dir, "c.pem")) }, (s) => {
  http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", async () => {
      if (req.headers.host !== "script.google.com") return res.end(`fronted ${req.headers.host}${req.url}`);
      assert.match(req.url, /^\/macros\/s\/DEPLOY_ID_0123456789abcdefgh\/exec$/);
      const p = JSON.parse(body);
      calls.push(p);
      if (p.k !== KEY) return res.end(wrap({ e: "unauthorized" }));
      // UrlFetchApp's error for an address it can't fetch, which names it ("<" and all)
      if (p.u?.includes("<"))
        return res.end(
          script === "old"
            ? '<div style="font-family:monospace">Exception: Malformed HTML content: {&quot;e&quot;:&quot;Exception: Invalid argument: https://&lt;foxhole&gt;/&quot;}</div>'
            : wrap({ e: script === "current" ? `Exception: Invalid argument: ${p.u}` : "Exception: something else" }),
        );
      const out = p.q ? { q: await Promise.all(p.q.map(urlFetch)) } : await urlFetch(p);
      res.setHeader("content-type", "text/html");
      res.end(wrap(out));
    });
  }).emit("connection", s);
});
const frontPort = await listen(front);

const conn = {
  relay: { url: "https://script.google.com/macros/s/DEPLOY_ID_0123456789abcdefgh/exec", key: KEY },
  server: { hostname: "www.google.com", ip: "127.0.0.1", port: frontPort, quarantined: false },
};
const notices = [];
onRelayNotice((m) => notices.push(m));
const proxy = await startProxy(conn, "127.0.0.1", 0);

/** A request through the proxy's HTTP side, in absolute form (plain HTTP). */
function viaHttpProxy(method, url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: proxy.port, method, path: url, headers: { host: new URL(url).host, ...headers } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, raw: res.rawHeaders, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** A TLS connection to host:443 through the proxy (CONNECT or SOCKS5), checked against Foxhole's CA. */
async function tunnel(host, how = "connect", port = 443) {
  const s = net.connect(proxy.port, "127.0.0.1");
  await new Promise((r) => s.once("connect", r));
  const read = () => new Promise((r) => s.once("data", r));
  if (how === "connect") {
    s.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    assert.match((await read()).toString(), /^HTTP\/1\.1 200/);
  } else {
    s.write(Buffer.from([5, 1, 0]));
    await read();
    const h = Buffer.from(host);
    s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 255])]));
    assert.equal((await read())[1], 0, "SOCKS5 CONNECT succeeded");
  }
  return s;
}
const ca = () => readFileSync(caFiles().cert, "utf8");
async function httpsGet(host, p, how, extra = "") {
  const raw = await tunnel(host, how);
  const t = tls.connect({ socket: raw, servername: host, ca: [ca()], rejectUnauthorized: true });
  await new Promise((r, j) => (t.once("secureConnect", r), t.once("error", j)));
  const cert = t.getPeerX509Certificate();
  t.write(`GET ${p} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n${extra}\r\n`);
  let out = "";
  for await (const d of t) out += d;
  return { out, cert };
}

// ── Plain HTTP through the HTTP proxy: relayed, batched, decoded
calls.length = 0;
const [a, b, c] = await Promise.all([1, 2, 3].map(() => viaHttpProxy("GET", "http://origin.example/hello")));
for (const r of [a, b, c]) assert.match(r.body, /^hello from origin\.example /, "relayed GET");
assert.match(a.body, /ae=$/, "no accept-encoding passed on: targets answer unencoded");
assert.equal(calls.length, 1, "three GETs at once go to the script in one call");
assert.equal(calls[0].q?.length, 3, "...as a batch of three");
assert.equal(calls[0].q[0].r, false, "redirects come back to the browser");

const big = await viaHttpProxy("GET", "http://origin.example/big");
assert.equal(big.body.length, 100_000, "Code.gs's gzip undone");
assert.equal(big.headers["content-length"], "100000");

const post = await viaHttpProxy("POST", "http://origin.example/echo", "a=b", { "content-type": "application/x-www-form-urlencoded" });
assert.equal(post.body, "POST application/x-www-form-urlencoded a=b", "a POST with its body and type");

const cookies = await viaHttpProxy("GET", "http://origin.example/cookies");
assert.deepEqual(cookies.headers["set-cookie"], ["a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/", "b=2; Path=/"], "joined Set-Cookie split back, the date's comma kept");

// ── A bot check (Cloudflare's), which never passes through the relay: a page saying so, whose button sends the site direct
const checked = await viaHttpProxy("GET", "http://www.checked.example/challenge?x=1", undefined, { "sec-fetch-mode": "navigate" });
assert.equal(checked.status, 403);
assert.match(checked.body, /checks for bots[\s\S]*name="u" value="\/challenge\?x=1"[\s\S]*Open it directly[\s\S]*Firefox VPN/, "a page saying why and what to do, not one that reloads forever");
assert.equal((await viaHttpProxy("GET", "http://www.checked.example/challenge")).body, "Just a moment...", "...but a script's request gets the site's answer");
{
  let split = { default: "vpn", rules: [] };
  useSplit(() => split);
  onRelaySplit((s) => (split = s));
  const press = (site = "same-origin") =>
    viaHttpProxy("POST", "http://www.checked.example/.foxhole/direct", "u=%2Fchallenge%3Fx%3D1", { "content-type": "application/x-www-form-urlencoded", "sec-fetch-site": site });
  setDirectDial(async () => null); // blocked where the user is
  const blocked = await press();
  assert.equal(blocked.status, 502);
  assert.match(blocked.body, /blocked where you are[\s\S]*Firefox VPN/, "blocked directly too: Firefox VPN, then");
  assert.equal(split.rules.length, 0, "...and no rule");
  setDirectDial(async () => net.connect(frontPort, "127.0.0.1")); // a TLS server (this test takes any certificate)
  assert.equal((await press("cross-site")).status, 403, "another site's page can't press it");
  const opened = await press();
  assert.equal(opened.status, 303, "it opens directly...");
  assert.equal(opened.headers.location, "http://www.checked.example/challenge?x=1", "...so back to the page");
  assert.deepEqual(split.rules, [{ match: "checked.example", via: "direct" }], "the site goes direct from now on, its other names too");
  assert.ok(notices.some((m) => /checked\.example goes direct/.test(m)), "and the app says so");
  useSplit(() => ({ default: "vpn", rules: [] }));
}

const redirect = await viaHttpProxy("GET", "http://origin.example/redirect");
assert.equal(redirect.status, 302, "the browser follows redirects itself");

const head = await viaHttpProxy("HEAD", "http://origin.example/hello");
assert.equal(head.status, 200);
assert.equal(head.body, "", "HEAD: no body");
assert.ok(Number(head.headers["content-length"]) > 0, "HEAD: the length GET would have");

const pre = await viaHttpProxy("OPTIONS", "http://api.origin.example/x", undefined, { origin: "https://app.origin.example", "access-control-request-method": "PUT" });
assert.equal(pre.status, 204, "a preflight is answered here");
assert.equal(pre.headers["access-control-allow-credentials"], "true", "same site: with cookies");
const preX = await viaHttpProxy("OPTIONS", "http://api.origin.example/x", undefined, { origin: "https://evil.example", "access-control-request-method": "PUT" });
assert.equal(preX.headers["access-control-allow-credentials"], undefined, "another site: without");

// ── HTTPS: opened with a certificate Foxhole's CA signed, over CONNECT and SOCKS5
const viaConnect = await httpsGet("secure.example", "/hello", "connect");
assert.match(viaConnect.out, /^HTTP\/1\.1 200[\s\S]*hello from secure\.example/, "HTTPS relayed (CONNECT)");
assert.ok(viaConnect.cert.checkHost("secure.example"), "the certificate names the site");
assert.ok(viaConnect.cert.checkIssued(new X509Certificate(ca())), "...and Foxhole's CA issued it");
const viaSocks = await httpsGet("socks.example", "/hello", "socks");
assert.match(viaSocks.out, /hello from socks\.example/, "HTTPS relayed (SOCKS5)");

// ── Fronted: YouTube goes to Google's front itself, Host www.youtube.com, its API too
calls.length = 0;
assert.match((await httpsGet("www.youtube.com", "/watch?v=1", "connect")).out, /fronted www\.youtube\.com\/watch\?v=1/, "YouTube fronted");
assert.match((await httpsGet("www.youtube.com", "/youtubei/v1/player", "connect")).out, /fronted www\.youtube\.com\/youtubei\/v1\/player/, "...its API too");
assert.equal(calls.length, 0, "...without the script");

// ── YouTube's videos: straight to the cache's address (looked up through the script), named www.google.com
const video = await httpsGet("rr1---sn-x.googlevideo.com", "/videoplayback?id=1", "connect");
assert.match(video.out, /fronted rr1---sn-x\.googlevideo\.com\/videoplayback\?id=1/, "a video from its cache");
assert.equal(calls.length, 1, "...the script only looked it up");
assert.match(calls[0].u, /dns-query$/);

// ── Google itself: its TLS untouched, to the front (the mock's own certificate, not Foxhole's)
{
  const raw = await tunnel("www.google.com", "connect");
  const t = tls.connect({ socket: raw, servername: "www.google.com", rejectUnauthorized: false });
  await new Promise((r) => t.once("secureConnect", r));
  assert.equal(t.getPeerX509Certificate().subject, "CN=www.google.com", "Google's own certificate, passed through");
  t.write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
  let out = "";
  for await (const d of t) out += d;
  assert.match(out, /fronted www\.google\.com\//);
}

// ── Not web traffic: direct (here a local echo server)
{
  const echo = net.createServer((s) => s.pipe(s));
  const echoPort = await listen(echo);
  const s = await tunnel("127.0.0.1", "socks", echoPort);
  s.write("ping");
  assert.equal((await new Promise((r) => s.once("data", r))).toString(), "ping", "a non-web port goes direct");
  s.destroy();
  echo.close();
}

// ── Global mode's lookups: made-up addresses at once, no IPv6, no HTTPS records
{
  const raw = await tunnel("cloudflare-dns.com", "socks");
  const t = tls.connect({ socket: raw, servername: "cloudflare-dns.com", ca: [ca()] });
  await new Promise((r, j) => (t.once("secureConnect", r), t.once("error", j)));
  const ask = (name, type) =>
    new Promise((resolve) => {
      const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
      const q = Buffer.concat([Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...labels, Buffer.from([0, 0, type, 0, 1])]);
      t.write(`POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\nContent-Type: application/dns-message\r\nContent-Length: ${q.length}\r\n\r\n`);
      t.write(q);
      let buf = Buffer.alloc(0);
      const on = (d) => {
        buf = Buffer.concat([buf, d]);
        const i = buf.indexOf("\r\n\r\n");
        const len = Number(buf.toString("latin1", 0, i).match(/content-length: (\d+)/i)?.[1]);
        if (i < 0 || buf.length < i + 4 + len) return;
        t.off("data", on);
        resolve(buf.subarray(i + 4, i + 4 + len));
      };
      t.on("data", on);
    });
  const a1 = await ask("blocked.example", 1);
  assert.equal(a1.readUInt16BE(0), 0x1234, "the query's id");
  const [ip] = answerAddrs(a1).map((x) => x.ip);
  assert.match(ip, /^198\.19\.\d+\.\d+$/, "a made-up address");
  assert.equal(fakeName(ip), "blocked.example", "...taken back to the name");
  assert.equal(answerAddrs(await ask("blocked.example", 1))[0].ip, ip, "the same one each time");
  const aaaa = await ask("blocked.example", 28);
  assert.equal(aaaa.readUInt16BE(6), 0, "no IPv6");
  t.destroy();
}

// ── Command-line tools, set up as `foxhole env` says: they trust Foxhole's CA and use the proxy (where installed)
{
  const { envLines } = await import("../dist/catrust.js");
  const env = { ...process.env };
  delete env.NODE_TLS_REJECT_UNAUTHORIZED;
  for (const l of envLines(`127.0.0.1:${proxy.port}`, false)) {
    const [, k, v] = l.match(/^export (\w+)='(.*)'$/);
    env[k] = v;
  }
  const run = (cmd, args) => promisify(execFile)(cmd, args, { env }).then((r) => r.stdout, (e) => (e.code === "ENOENT" ? null : Promise.reject(e)));
  const curl = await run("curl", ["-sS", "https://cli.example/hello"]);
  if (curl !== null) assert.match(curl, /hello from cli\.example/, "curl trusts it");
  const py = await run("python3", ["-c", 'import urllib.request; print(urllib.request.urlopen("https://py.example/hello").read().decode())']);
  if (py !== null) assert.match(py, /hello from py\.example/, "Python too");
}

// ── The relay check, and a wrong key: the error page and the notice
await relayCheck(conn); // it answers, and fetches
const works = await relayVerdict(conn); // Settings' check
assert.equal(works.tone, "ok", works.text);
assert.match(works.text, /deployment ID and auth key are right, and the script is up to date/);
script = "old";
assert.match((await relayVerdict(conn)).text, /right, but your Apps Script has older code/, "an older Code.gs: update it");
script = "other";
const unsure = await relayVerdict(conn);
assert.ok(unsure.tone === "ok" && !/up to date/.test(unsure.text), "an answer that doesn't show the code's age: no word on it");
script = "current";
const away = await relayVerdict({ relay: conn.relay, server: { hostname: "127.0.0.1", ip: "127.0.0.1", port: 1 } });
assert.match(away.text, /^Couldn't reach Google: /, "Google out of reach: not the keys' fault");
conn.relay = { ...conn.relay, key: "wrong-key-0123456789abcdef" };
assert.deepEqual(await relayVerdict(conn), { tone: "error", text: relayProblem("relay: unauthorized") }, "a wrong key: which one to fix");
const bad = await viaHttpProxy("POST", "http://origin.example/echo", "x");
assert.equal(bad.status, 502);
assert.match(bad.body, /AUTH_KEY/, "the page says what to fix");
assert.ok(notices.some((m) => /AUTH_KEY/.test(m)), "and so does the app");
await assert.rejects(relayCheck(conn), /AUTH_KEY/);

// ── Pure parts
const { firefoxPolicies } = await import("../dist/catrust.js");
const theirs = '{"policies":{"DisableTelemetry":true}}';
const withOurs = firefoxPolicies(theirs, "/x/ca.pem", true);
assert.deepEqual(JSON.parse(withOurs), { policies: { DisableTelemetry: true, Certificates: { Install: ["/x/ca.pem"] } } }, "Firefox's policies: ours added to theirs");
assert.deepEqual(JSON.parse(firefoxPolicies(withOurs, "/x/ca.pem", false)), JSON.parse(theirs), "...and taken out again");
assert.equal(firefoxPolicies(firefoxPolicies(null, "/x/ca.pem", true), "/x/ca.pem", false), null, "ours alone: no file left");
assert.deepEqual(splitCookies("a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT, b=2"), ["a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT", "b=2"]);
assert.ok(fronted("i.ytimg.com") && fronted("www.youtube.com"));
assert.ok(!fronted("music.youtube.com") && !fronted("rr1---sn-x.googlevideo.com") && !fronted("evilyoutube.com"));
assert.match(relayProblem("relay: Exception: Service invoked too many times for one day: urlfetch."), /quota/);
assert.match(relayProblem("relay: Exception: محتوای HTML معیوب: {"), /older code/, "the old Code.gs, in the owner's language");
const q = Buffer.from([0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0x61, 0, 0, 1, 0, 1]);
assert.deepEqual(answerAddrs(dnsAnswer(q, q.length, ["198.19.0.1"], 2)), [{ ip: "198.19.0.1", ttl: 2 }]);

await proxy.close();
front.close();
origin.close();
console.log("ok - relay mode");
process.exit(0);
