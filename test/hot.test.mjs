// The hot config (hot.ts): only a file its key signed, with its fields as they should be, never one older than what's
// kept; from a mirror (a stand-in here) to ~/.config in a throwaway HOME; and dns.ts's fallback by its rules.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the stand-in mirror's self-signed localhost cert
import assert from "node:assert";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MIRRORS, hot, later, newNotice, newestHot, onHot, parseHot, refreshHot } from "../dist/hot.js";
import { alternatives } from "../dist/dns.js";

const home = mkdtempSync(join(tmpdir(), "foxhole-hot-"));
process.env.HOME = home; // userHome(): the kept file goes here, not in ~/.config

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const signed = (data, key = privateKey) => JSON.stringify({ data, sig: sign(null, Buffer.from(JSON.stringify(data)), key).toString("base64") });

// only what the key signed
const data = { issued: "2026-11-07T10:00:00.000Z", notice: " Use the relay on MCI. ", fallback: { "146.75.": ["151.101.1."] }, fronted: ["gemini.google.com"] };
assert.deepEqual(parseHot(signed(data), publicKey), { ...data, notice: "Use the relay on MCI." });
const forged = JSON.parse(signed(data));
forged.data.notice = "Install this other app";
assert.equal(parseHot(JSON.stringify(forged), publicKey), null, "a notice changed after signing");
assert.equal(parseHot(signed(data, generateKeyPairSync("ed25519").privateKey), publicKey), null, "another key");
assert.equal(parseHot(signed(data)), null, "not the key Foxhole trusts");
for (const bad of [null, "", "{}", "[1]", JSON.stringify({ data }), JSON.stringify({ data, sig: "AAAA" })]) assert.equal(parseHot(bad, publicKey), null, String(bad));
assert.equal(parseHot(signed({ notice: "no time" }), publicKey), null, "no issued");
assert.equal(parseHot(signed({ issued: "soon" }), publicKey), null);
assert.equal(parseHot(signed({ ...data, expires: "never" }), publicKey), null);
assert.deepEqual(parseHot(signed({ issued: data.issued, notice: 5, fallback: { "146.75.": [1] }, fronted: "x.com" }), publicKey), { issued: data.issued }, "fields that aren't what they should be are dropped");
const repoFile = readFileSync(new URL("../hot.json", import.meta.url), "utf8");
assert.ok(parseHot(repoFile), "the repo's hot.json is signed with the key src/hot.ts trusts");

// the newest of the mirrors', and never older than what's kept
const newer = signed({ ...data, issued: "2026-11-08T10:00:00.000Z" });
assert.equal(newestHot([null, signed(data), newer, JSON.stringify(forged)], publicKey).text, newer);
assert.equal(newestHot([null, "<html>a captive portal</html>"], publicKey), null);
const a = parseHot(signed(data), publicKey), b = parseHot(newer, publicKey);
assert.ok(later(b, a) && !later(a, b) && !later(a, a) && later(a, null));

// dns.ts's fallback addresses by the rules
assert.deepEqual(alternatives("146.75.117.91", { "146.75.": ["151.101.1.", "151.101.65."] }), ["151.101.1.91", "151.101.65.91"]);
assert.deepEqual(alternatives("146.75.117.91", { "146.75.117.": ["199.232.1.9", "not an address", "1.2.3."] }), ["199.232.1.9", "1.2.3.91"]);
assert.deepEqual(alternatives("8.8.8.8", { "146.75.": ["151.101.1."] }), []);

// from a mirror to ~/.config, as it came
const dir = mkdtempSync(join(tmpdir(), "foxhole-hot-tls-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });
let asked = 0;
const mirror = https.createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) }, (req, res) => {
  asked++;
  if (req.url === "/hot.json") res.end(repoFile);
  else res.writeHead(404).end();
});
await new Promise((r) => mirror.listen(0, "127.0.0.1", r));
const at = `https://127.0.0.1:${mirror.address().port}`;
MIRRORS.splice(0, MIRRORS.length, `${at}/hot.json`, `${at}/gone.json`);
assert.equal(hot(), null, "none yet: the built-in values");
let told = 0;
onHot(() => told++);
await refreshHot();
assert.equal(told, 1, "a new one is told of");
assert.deepEqual(hot(), parseHot(repoFile));
assert.equal(readFileSync(join(home, ".config", "foxhole-vpn", "hot.json"), "utf8"), repoFile, "kept as it came, signature and all");
assert.equal(newNotice(), parseHot(repoFile).notice ?? null);
await refreshHot();
assert.equal(asked, 2, "not asked again within the hour");
mirror.close();
console.log("ok - hot config: signed, never older, kept; Mozilla's fallback by its rules");
