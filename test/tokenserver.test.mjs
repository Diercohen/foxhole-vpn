// The loopback token receiver: shape/expiry/scope validation, secret-path
// gating, and a real round-trip over 127.0.0.1. No Firefox, no network.
import assert from "node:assert";
import { mkdtempSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validToken, startTokenReceiver, saveToken, loadSavedToken, forgetToken, tokenFile } from "../dist/tokenserver.js";

const VPN_SCOPE = "https://identity.mozilla.com/apps/vpn profile";
const jwt = (body) => "x." + Buffer.from(JSON.stringify(body)).toString("base64url") + ".y";
const future = Math.floor(Date.now() / 1000) + 3600;
const past = Math.floor(Date.now() / 1000) - 10;

assert.ok(validToken(jwt({ exp: future, scope: VPN_SCOPE })), "valid token accepted");
assert.ok(!validToken(jwt({ exp: past, scope: VPN_SCOPE })), "expired rejected");
assert.ok(!validToken(jwt({ exp: future, scope: "profile" })), "missing VPN scope rejected");
assert.ok(validToken(jwt({ scope: VPN_SCOPE })), "exp is optional"); // only rejected if present and past
assert.ok(!validToken("not.a.jwt"), "garbage rejected");
assert.ok(!validToken("only.two"), "wrong segment count rejected");
assert.ok(!validToken(42), "non-string rejected");

const good = jwt({ exp: future, scope: VPN_SCOPE });
const rec = await startTokenReceiver(5000, 47390);
assert.ok(rec.url.startsWith("http://127.0.0.1:47390/"), "uses the fixed port");
// A second receiver on the same port falls back to a random one.
const rec2 = await startTokenReceiver(5000, 47390);
assert.ok(!rec2.url.startsWith("http://127.0.0.1:47390/"), "busy port falls back");
rec2.close();

// Wrong path (even same host/port) is a 404 — the secret gates access.
const base = rec.url.replace(/\/[0-9a-f]+$/, "");
const miss = await fetch(base + "/deadbeef", { method: "POST", body: JSON.stringify({ token: good }) });
assert.equal(miss.status, 404, "unknown path refused");

// Invalid token on the right path is a 400 and does not resolve.
const bad = await fetch(rec.url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "nope" }) });
assert.equal(bad.status, 400, "invalid token refused");

// A valid token posts ok and resolves the promise.
const ok = await fetch(rec.url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: good }) });
assert.equal(ok.status, 200, "valid token accepted over the wire");
assert.equal(await rec.token, good, "token promise resolves with the posted token");
rec.close();

// The snippet posts to the secret URL.
assert.ok(rec.snippet.includes(rec.url), "snippet targets the secret URL");
assert.ok(rec.snippet.includes("getOAuthToken"), "snippet mints the VPN token");

// Saved token: written 0600 under $HOME/.config/foxhole-vpn, read back, forgotten.
// A temp HOME (and no SUDO_USER) so a real saved token is never touched.
delete process.env.SUDO_USER;
const home = mkdtempSync(join(tmpdir(), "foxhole-home-"));
process.env.HOME = home;
assert.equal(tokenFile(), join(home, ".config", "foxhole-vpn", "token"), "token file under HOME");
assert.equal(loadSavedToken(), null, "nothing saved yet");
saveToken(good);
assert.equal(loadSavedToken(), good, "saved token reads back");
assert.equal(statSync(tokenFile()).mode & 0o777, 0o600, "token file is 0600");
assert.equal(statSync(join(home, ".config", "foxhole-vpn")).mode & 0o777, 0o700, "folder is 0700");
forgetToken();
assert.equal(loadSavedToken(), null, "forgotten token is gone");
rmSync(home, { recursive: true, force: true });

console.log("ok - token receiver validates, round-trips over loopback, and saves privately");
