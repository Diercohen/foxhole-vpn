// The updater's network side: the latest version from where /releases/latest redirects, and a download that breaks
// off and carries on where it stopped, directly and through a proxy's CONNECT (the VPN's). A fake GitHub stands in.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert

import http from "node:http";
import https from "node:https";
import net from "node:net";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 15000).unref();

const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-update-"));
const key = path.join(dir, "k.pem");
const cert = path.join(dir, "c.pem");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });

const blob = randomBytes(300_000);
const ranges = []; // the Range header of each request for the file
let cut = true; // the first download breaks off halfway
const gh = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
  const base = `https://127.0.0.1:${gh.address().port}`;
  if (req.url === "/releases/latest") return res.writeHead(302, { location: `${base}/releases/tag/v9.9.9` }).end();
  if (req.url === "/releases/download/v9.9.9/app.dmg" || req.url === "/releases/download/v9.9.9/Foxhole-9.9.9.AppImage") return res.writeHead(302, { location: "/cdn/app.dmg" }).end(); // GitHub sends files from elsewhere
  if (req.url !== "/cdn/app.dmg") return res.writeHead(404).end();
  ranges.push(req.headers.range ?? null);
  const from = Number(/^bytes=(\d+)-$/.exec(req.headers.range ?? "")?.[1] ?? 0);
  if (from >= blob.length) return res.writeHead(416, { "content-range": `bytes */${blob.length}` }).end();
  if (!from) res.writeHead(200, { "content-length": blob.length });
  else res.writeHead(206, { "content-length": blob.length - from, "content-range": `bytes ${from}-${blob.length - 1}/${blob.length}` });
  if (!cut) return res.end(blob.subarray(from));
  cut = false;
  res.write(blob.subarray(0, blob.length / 2), () => res.destroy());
});
await new Promise((r) => gh.listen(0, "127.0.0.1", r));
// what foxhole's own proxy does for HTTPS: CONNECT, then bytes both ways
const tunnels = [];
const proxy = http.createServer().on("connect", (req, client) => {
  tunnels.push(req.url);
  const [host, port] = req.url.split(":");
  const up = net.connect(Number(port), host, () => (client.write("HTTP/1.1 200 Connection established\r\n\r\n"), up.pipe(client).pipe(up)));
  up.on("error", () => client.destroy());
});
await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
const via = { host: "127.0.0.1", port: proxy.address().port };

process.env.FOXHOLE_RELEASES = `https://127.0.0.1:${gh.address().port}/releases`;
const { latest, download } = await import("./updater.js");

assert.equal(await latest(), "9.9.9", "the version from /releases/latest's redirect");
assert.equal(await latest(via), "9.9.9", "through the proxy too");
assert.deepEqual(tunnels, [`127.0.0.1:${gh.address().port}`], "the tunnel goes to the URL's own port");

const file = path.join(dir, "app.dmg");
const url = `${process.env.FOXHOLE_RELEASES}/download/v9.9.9/app.dmg`;
let shown = 0;
await assert.rejects(download(url, file, undefined, () => {}), "a download broken off fails");
const kept = statSync(file).size; // what arrived before the break (what was still in flight is lost)
assert.ok(kept > 0 && kept <= blob.length / 2, "and keeps what came");
await download(url, file, via, (p) => (shown = p));
assert.deepEqual(ranges, [null, `bytes=${kept}-`], "the next try asks for the rest only");
assert.ok(readFileSync(file).equals(blob), "the pieces make the file");
assert.equal(shown, 100, "progress reaches 100%");
await download(url, file, undefined, () => {});
assert.ok(readFileSync(file).equals(blob) && ranges.length === 3, "a file already complete stays as it is");
await assert.rejects(download(`${process.env.FOXHOLE_RELEASES}/download/v9.9.9/other.dmg`, path.join(dir, "x"), undefined, () => {}), { status: 404 });

// The Update button, on an AppImage (the kind that needs no system tools): found, downloaded to Downloads, ready, put in on
// the quit; the file stays there to install by hand until the new version runs
const { Updater } = await import("./updater.js");
const appImage = path.join(dir, "Foxhole.AppImage");
const downloads = path.join(dir, "Downloads");
const upd = path.join(dir, "upd");
writeFileSync(appImage, "the old version");
const phases = [];
const target = { kind: "appimage", file: appImage };
const u = new Updater({ dir: upd, downloads, target, via: () => via, changed: () => phases.push(u.state()?.phase) });
u.start();
await u.check();
assert.deepEqual(u.state(), { version: "9.9.9", auto: true, kind: "appimage", phase: null, progress: null, ready: false, error: null, file: null }, "a newer release is offered");
assert.equal(await u.update(), true, "the button's download ends ready");
assert.ok(phases.includes("downloading") && phases.includes("installing"), "the window sees it download, then install");
const saved = path.join(downloads, "Foxhole-9.9.9.AppImage");
assert.equal(u.state().file, saved, "the file is in Downloads");
assert.equal(readFileSync(appImage, "utf8"), "the old version", "nothing changes before the quit");
assert.equal(u.install({ relaunch: true }), false, "the app relaunches itself (from the AppImage's file)");
assert.ok(readFileSync(appImage).equals(blob), "the new AppImage is in its place");
if (process.platform !== "win32") assert.ok(statSync(appImage).mode & 0o100, "and can run");
assert.ok(readFileSync(saved).equals(blob), "and the download stays, to install by hand");

// The next start, still the old version (VERSION is below 9.9.9): it didn't take, so the file is offered by hand
const again = new Updater({ dir: upd, downloads, target, via: () => null, changed: () => {} });
again.start();
assert.equal(again.state().version, "9.9.9");
assert.equal(again.state().error, "the last try didn't take");
assert.equal(again.state().file, saved);
// an install that fails at the quit says why at the next start (here: the app's folder is gone)
const lost = new Updater({ dir: upd, downloads, target: { kind: "appimage", file: path.join(dir, "gone", "Foxhole.AppImage") }, via: () => null, changed: () => {} });
lost.start();
assert.equal(lost.install({ relaunch: true }), false);
const after = new Updater({ dir: upd, downloads, target, via: () => null, changed: () => {} });
after.start();
assert.match(after.state().error, /^the last try failed: ENOENT/, "the reason survives the restart");
// a download of a version no newer than this one (already in) is cleared at the start
writeFileSync(path.join(downloads, "Foxhole-0.0.1.AppImage"), "old");
new Updater({ dir: upd, downloads, target, via: () => null, changed: () => {} }).start();
assert.ok(!existsSync(path.join(downloads, "Foxhole-0.0.1.AppImage")) && existsSync(saved), "an installed version's file goes, a newer one stays");

// a release without this system's file: said so, and nothing to install by hand
const w = new Updater({ dir: path.join(dir, "upd-win"), downloads, target: { kind: "win", exe: "Foxhole.exe" }, via: () => null, changed: () => {} });
w.start();
await w.check();
assert.equal(await w.update(), false);
assert.equal(w.state().error, "this release has no download for your system yet");
assert.equal(w.state().file, null);
assert.equal(w.install({ relaunch: true }), false, "nothing to install");
assert.equal(w.installByHand(), false);

gh.close();
proxy.close();
console.log("ok - updates: the latest version, a download resumed after a break, through the proxy too; the Update button's download, kept in Downloads, put in on the quit, offered by hand when it didn't take");
