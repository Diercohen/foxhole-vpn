// Shield's YouTube switch (youtube.ts): its edits (pure), then through the proxy: a mock www.youtube.com with a
// certificate of its own behind a fake VPN server, a browser trusting Foxhole's certificate, and an app that doesn't.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // youtube.ts's own connections take the mock's self-signed certificate
import assert from "node:assert";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";
import os from "node:os";
import path from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";

process.env.HOME = process.env.USERPROFILE = mkdtempSync(path.join(os.tmpdir(), "foxhole-home-")); // youtube.json, the CA
const { editedText, fingerprint, readable, takesOver, useYoutube, youtubeHere, forgetRefusers, onYoutubeNotice, PAGE_SCRIPT } = await import("../dist/youtube.js");
const { startProxy } = await import("../dist/proxy.js");
const { loadCa, caFiles, CA_NAME } = await import("../dist/mitm.js");
loadCa();

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

// ── The edits
const player = '{"responseContext":{},"adPlacements":[{"adPlacementRenderer":{}}],"playerAds":[1],"adSlots":[],"videoDetails":{"videoId":"abc"},"adSlotRenderer":1}';
const json = editedText(player, "/youtubei/v1/player", false);
assert.deepEqual(Object.keys(JSON.parse(json)), ["responseContext", "no_ads", "videoDetails", "adSlotRenderer"], "the ad keys renamed, a longer key that starts the same kept");
assert.equal(editedText(json, "/youtubei/v1/player", false), json, "edited twice: the same");
assert.equal(editedText(String.raw`'{\x22adPlacements\x22:[1],\x22adSlots\x22:[]}' "{\"playerAds\":[]}"`, "/watch", false), String.raw`'{\x22no_ads\x22:[1],\x22no_ads\x22:[]}' "{\"no_ads\":[]}"`, "and in a page's JS strings");
const reel = JSON.stringify({ entries: [{ command: { reelWatchEndpoint: { videoId: "a" } } }, { command: { reelWatchEndpoint: { adClientParams: { isAd: true } } } }, { command: { reelWatchEndpoint: { videoId: "b" } } }] });
assert.deepEqual(JSON.parse(editedText(reel, "/youtubei/v1/reel/reel_watch_sequence", false)).entries.map((e) => e.command.reelWatchEndpoint.videoId), ["a", "b"], "Shorts: the ad dropped");
assert.equal(editedText("not json", "/youtubei/v1/reel/reel_watch_sequence", false), "not json");
const page = '<!DOCTYPE html><html lang="en"><head><script nonce="X">var ytInitialPlayerResponse = {"adPlacements":[]};</script></head><body></body></html>';
const strict = editedText(page, "/watch", { csp: "require-trusted-types-for 'script'; script-src 'nonce-ab+c/9=' 'unsafe-eval' 'strict-dynamic' https: http:" });
assert.ok(strict.startsWith('<!DOCTYPE html><html lang="en"><head><style>#masthead-ad{display:none!important}'), "the style first in <head>");
assert.ok(strict.includes(`<script nonce="ab+c/9=">${PAGE_SCRIPT}</script><script nonce="X">`), "the script with the page's nonce, before the page's own");
assert.ok(strict.includes('ytInitialPlayerResponse = {"no_ads":[]}'));
assert.ok(!editedText(page, "/watch", { csp: "script-src 'sha256-abc'" }).includes(PAGE_SCRIPT), "a policy with no nonce: no script, which it would stop");
assert.ok(editedText(page, "/watch", { csp: "" }).includes(`<style>`) && editedText(page, "/watch", { csp: "" }).includes(`<script>${PAGE_SCRIPT}`), "no policy: the script as it is");
assert.doesNotThrow(() => new Function(PAGE_SCRIPT), "the page script parses");

assert.equal(readable("gzip, deflate, br, zstd"), "gzip, deflate, br");
assert.equal(readable("zstd"), "identity");
assert.equal(readable(undefined), undefined);

// fingerprints: an app's TLS library, whatever its GREASE
const hello = (suites) => {
  const b = Buffer.alloc(46 + suites.length * 2);
  b[0] = 0x16;
  b[43] = 0; // no session id
  b.writeUInt16BE(suites.length * 2, 44);
  suites.forEach((s, i) => b.writeUInt16BE(s, 46 + i * 2));
  return b;
};
assert.equal(fingerprint(hello([0x0a0a, 0x1301, 0x1302])), fingerprint(hello([0xfafa, 0x1301, 0x1302])), "GREASE left out");
assert.notEqual(fingerprint(hello([0x1301, 0x1302])), fingerprint(hello([0x1302, 0x1301])), "another library");
assert.equal(fingerprint(Buffer.from([0x16])), "", "cut off");
assert.equal(takesOver(hello([0x1301]), "www.youtube.com"), true);
assert.equal(takesOver(hello([0x1301]), "i.ytimg.com"), false, "not YouTube's pages");
assert.equal(takesOver(Buffer.from("GET / HTTP/1.1\r\n"), "www.youtube.com"), false, "not TLS");
useYoutube(() => true, () => true);
assert.equal(youtubeHere({ remoteAddress: "127.0.0.1" }), true);
assert.equal(youtubeHere({ remoteAddress: "::ffff:127.0.0.1" }), true);
assert.equal(youtubeHere({ remoteAddress: "192.168.1.5" }), false, "another device sharing the proxy doesn't trust the certificate");
useYoutube(() => true, () => false);
assert.equal(youtubeHere({ remoteAddress: "127.0.0.1" }), false, "the certificate not trusted");
console.log("ok - YouTube's edits: the ad keys renamed (JSON and page strings), Shorts' ads dropped, the page's style and script by its policy, fingerprints");

// ── Through the proxy
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-yt-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=www.youtube.com"], { stdio: "ignore" });
const ytCert = readFileSync(path.join(dir, "c.pem"));
const asked = []; // what the mock was asked, with its Accept-Encoding
const filler = 'x"adPlacements"'.repeat(20_000); // keys across the chunks the page comes in
const yt = https.createServer({ key: readFileSync(path.join(dir, "k.pem")), cert: ytCert }, (req, res) => {
  asked.push(`${req.method} ${req.url} ae=${req.headers["accept-encoding"] ?? ""}`);
  req.resume();
  req.on("end", () => {
    if (req.url.startsWith("/youtubei/v1/player"))
      return res.writeHead(200, { "content-type": "application/json; charset=UTF-8", "content-encoding": "gzip", "alt-svc": 'h3=":443"' }).end(zlib.gzipSync(player));
    if (req.url.startsWith("/watch"))
      return res
        .writeHead(200, { "content-type": "text/html; charset=utf-8", "content-encoding": "br", "content-security-policy": "script-src 'nonce-N1' 'strict-dynamic'" })
        .end(zlib.brotliCompressSync(page.replace("<body>", `<body>${filler}`)));
    if (req.url === "/s/player/base.js") return res.writeHead(200, { "content-type": "text/javascript", "content-encoding": "gzip" }).end(zlib.gzipSync('a["adPlacements"]'));
    res.writeHead(404).end();
  });
});
const ytPort = await listen(yt);
// the VPN: each tunnel to the mock, whatever it names
let tunnels = 0;
const vpn = tls.createServer({ key: readFileSync(path.join(dir, "k.pem")), cert: ytCert }, (s) => {
  s.on("error", () => {});
  s.once("data", () => {
    tunnels++;
    const t = net.connect(ytPort, "127.0.0.1", () => (s.write("HTTP/1.1 200 OK\r\n\r\n"), s.pipe(t), t.pipe(s)));
  });
});
const conn = { server: { hostname: "127.0.0.1", port: await listen(vpn) }, currentPass: async () => ({ token: "t", notBefore: 0, expires: 2 ** 31 }) };
const proxy = await startProxy(conn, "127.0.0.1", 0);

/** An HTTP CONNECT to www.youtube.com through the proxy, then TLS as `opts` says: the TLS socket, or the error it ended with. */
function connect(opts = {}) {
  return new Promise((resolve) => {
    const raw = net.connect(proxy.port, "127.0.0.1", () => raw.write("CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n"));
    raw.once("data", (d) => {
      assert.match(d.toString(), /^HTTP\/1\.1 200/);
      const t = tls.connect({ socket: raw, servername: "www.youtube.com", ALPNProtocols: ["http/1.1"], ...opts });
      t.once("secureConnect", () => resolve(t));
      t.once("error", (err) => resolve(err));
    });
  });
}
/** Whole-system mode's way in: SOCKS from tun2socks to an address, YouTube named by the TLS hello alone. */
function socks() {
  return new Promise((resolve) => {
    const raw = net.connect(proxy.port, "127.0.0.1", () => raw.write(Buffer.from([5, 1, 0])));
    raw.once("data", () => {
      raw.write(Buffer.from([5, 1, 0, 1, 142, 250, 1, 1, 1, 187])); // 142.250.1.1:443
      raw.once("data", (d) => {
        assert.equal(d[1], 0, "SOCKS: connected");
        const t = tls.connect({ socket: raw, servername: "www.youtube.com", ALPNProtocols: ["http/1.1"] });
        t.once("secureConnect", () => resolve(t));
        t.once("error", resolve);
      });
    });
  });
}
/** A browser: keeps its connection for its next requests. */
class Browser extends http.Agent {
  constructor() {
    super({ keepAlive: true, maxSockets: 1 });
  }
  createConnection(_opts, cb) {
    connect().then((t) => cb(t instanceof Error ? t : null, t));
  }
}
const browser = new Browser();
const get = (p, method = "GET") =>
  new Promise((resolve, reject) => {
    const req = http.request({ host: "www.youtube.com", path: p, method, agent: browser, headers: { "accept-encoding": "gzip, deflate, br, zstd" } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ res, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end(method === "POST" ? "{}" : undefined);
  });

useYoutube(() => true, () => true);
const first = await connect();
assert.equal(first.getPeerCertificate().issuer.CN, CA_NAME, "taken over: Foxhole's certificate");
first.destroy();
const tun = await socks();
assert.equal(tun.getPeerCertificate().issuer.CN, CA_NAME, "whole-system mode: taken over by the hello's name");
tun.destroy();
const p = await get("/youtubei/v1/player?prettyPrint=false", "POST");
assert.equal(p.res.headers["content-encoding"], undefined, "edited: sent as it is");
assert.equal(p.res.headers["alt-svc"], undefined, "no HTTP/3, which wouldn't come this way");
assert.equal(p.body.toString(), json, "the player's answer without its ads");
const w = await get("/watch?v=abc");
const html = w.body.toString("latin1");
assert.ok(!html.includes('"adPlacements"') && html.split('"no_ads"').length - 1 === 20_001, "every key renamed, across the chunks");
assert.ok(html.includes(`<script nonce="N1">${PAGE_SCRIPT}</script>`), "the script, with the page's nonce");
const js = await get("/s/player/base.js");
assert.equal(js.res.headers["content-encoding"], "gzip", "a script passes as it came");
assert.equal(zlib.gunzipSync(js.body).toString(), 'a["adPlacements"]', "untouched");
assert.ok(asked.every((a) => !a.includes("zstd")), "never asked for zstd, which Node can't read");
assert.equal(tunnels, 1, "the browser's requests on one connection to YouTube");
browser.destroy();

// an app that trusts only its own certificates (curl with the mock's) refuses Foxhole's in the handshake, as apps do: from
// then on it gets YouTube as it is
const notices = [];
onYoutubeNotice((m) => notices.push(m));
const both = path.join(dir, "both.pem");
writeFileSync(both, `${ytCert}${readFileSync(caFiles().cert, "utf8")}`);
const curl = (ca) =>
  new Promise((r) =>
    execFile("curl", ["-s", "-o", os.devNull, "-w", "%{http_code}", "--max-time", "10", "-x", `http://127.0.0.1:${proxy.port}`, "--cacert", ca, "https://www.youtube.com/s/player/base.js"], (err, out) =>
      r(err ? `exit ${err.code}` : out),
    ),
  );
const own = path.join(dir, "c.pem");
assert.match(await curl(own), /^exit /, "refused Foxhole's certificate");
assert.equal(notices.length, 1, "told once");
assert.equal(await curl(own), "200", "next time: YouTube's own certificate, untouched");
assert.equal(JSON.parse(readFileSync(path.join(process.env.HOME, ".config", "foxhole-vpn", "youtube.json"), "utf8")).refuse.length, 1, "kept");
forgetRefusers();
assert.equal(await curl(both), "200", "forgotten (the switch turned on again): taken over, trusting both");
assert.match(await curl(own), /^exit /, "an app that once asked through Foxhole's certificate isn't learned as refusing");
assert.match(await curl(own), /^exit /, "so it isn't let through either");
assert.equal(notices.length, 1);
useYoutube(() => false, () => true);
const off = await connect();
assert.equal(off.getPeerCertificate().subject.CN, "www.youtube.com", "switched off: YouTube as it is");
off.destroy();

await proxy.close();
for (const s of [yt, vpn]) s.close();
console.log("ok - YouTube through the proxy: taken over with Foxhole's certificate (by name, or by the hello's over SOCKS to an address), the player's answer and page edited (gzip, br), scripts untouched, one upstream; a refusing app learned and let through, forgotten when asked");
process.exit(0);
