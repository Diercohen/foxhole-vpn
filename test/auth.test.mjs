// FirefoxAuth: the onepw key derivation (the spec's test vector), the signed
// fxa-credentials request, token reuse, the clock-skew retry, and the relay where
// FxA is blocked; then whether a session's sign-in is confirmed (sessionVerified),
// a signed GET. fetch is stubbed; no Firefox, no network.
import assert from "node:assert";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FirefoxAuth, RefreshAuth, destroyToken, fetchAvatar, sessionCredentials, sessionVerified, VPN_SCOPES } from "../dist/auth.js";
import { useDirect, useRelay } from "../dist/guardian.js";

useDirect((url, init) => fetch(url, init)); // Mozilla, directly: the fetch() stood in for below

process.env.HOME = mkdtempSync(join(tmpdir(), "foxhole-auth-")); // userHome(): the tokens kept (tokens.json)

// https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol#test-vectors
const sessionToken = Buffer.from(Array.from({ length: 32 }, (_, i) => 0xa0 + i)).toString("hex");
const creds = sessionCredentials(sessionToken);
assert.equal(creds.id, "c0a29dcf46174973da1378696e4c82ae10f723cf4f4d9f75e39f4ae3851595ab", "tokenID");
assert.equal(creds.key.toString("hex"), "9d8f22998ee7f5798b887042466b72d53e56ab0c094388bf65831f702d2febc0", "reqHMACkey");

const dir = mkdtempSync(join(tmpdir(), "foxhole-vpn-"));
writeFileSync(join(dir, "signedInUser.json"), JSON.stringify({ accountData: { sessionToken } }));

// A fake FxA that checks the HAWK header the way the server does, and wants ts=1000.
const calls = [];
const fxa = async (url, init) => {
  const h = Object.fromEntries([...init.headers.authorization.matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
  calls.push({ url: String(url), body: JSON.parse(init.body), ts: Number(h.ts) });
  const hash = createHash("sha256").update(`hawk.1.payload\napplication/json\n${init.body}\n`).digest("base64");
  const u = new URL(url);
  const normalized = `hawk.1.header\n${h.ts}\n${h.nonce}\nPOST\n${u.pathname}\n${u.hostname}\n443\n${hash}\n\n`;
  assert.equal(h.id, creds.id, "signed by the session token's id");
  assert.equal(h.hash, hash, "payload hash");
  assert.equal(h.mac, createHmac("sha256", creds.key).update(normalized).digest("base64"), "mac");
  if (h.ts !== "1000") return Response.json({ errno: 111, message: "Invalid timestamp", serverTime: 1000 }, { status: 401 });
  return Response.json({ access_token: `tok${calls.length}`, expires_in: 86400 });
};
globalThis.fetch = fxa;

const auth = new FirefoxAuth({ profileDir: dir });
assert.equal(await auth.getAccessToken(), "tok2", "a skewed clock is retried on the server's time");
assert.equal(calls.length, 2);
assert.equal(calls[1].url, "https://api.accounts.firefox.com/v1/oauth/token");
assert.deepEqual(calls[1].body, {
  client_id: "5882386c6d801776",
  grant_type: "fxa-credentials",
  scope: VPN_SCOPES.join(" "),
  ttl: 86400,
});
assert.equal(await auth.getAccessToken(), "tok2", "reused while fresh");
assert.equal(calls.length, 2, "no second request");
// kept for the next start (tokens.json), which so connects where the account server can't be reached
assert.equal(await new FirefoxAuth({ profileDir: dir }).getAccessToken(), "tok2", "kept: the next start has it");
assert.equal(calls.length, 2, "Mozilla not asked");
auth.forget(); // Guardian refused it: the kept one goes too

// A signed-out or revoked session says so instead of failing vaguely.
globalThis.fetch = async () => Response.json({ errno: 110, message: "Invalid authentication token" }, { status: 401 });
await assert.rejects(new FirefoxAuth({ profileDir: dir }).getAccessToken(), /sign in to Firefox again/);

// api.accounts.firefox.com won't connect (blocked, as on Iranian networks): with a relay set, the request goes through
// it (guardian.ts mozillaFetch) as signed, the HAWK header and body unchanged and the body's type as the script's ct,
// so FxA checks it out from Google too
useRelay({ url: "https://script.google.com/macros/s/x/exec", key: "k" });
const relayed = [];
globalThis.fetch = async (url, init) => {
  if (new URL(url).hostname === "api.accounts.firefox.com") throw new TypeError("fetch failed");
  const p = JSON.parse(init.body); // the script's request (httprelay.ts)
  relayed.push(p);
  assert.equal(p.ct, "application/json", "the type the payload hash has");
  const res = await fxa(p.u, { headers: p.h, body: Buffer.from(p.b, "base64").toString() });
  return Response.json({ s: res.status, h: {}, b: Buffer.from(await res.text()).toString("base64") });
};
assert.equal(await new FirefoxAuth({ profileDir: dir }).getAccessToken(), "tok4", "the token, through the relay (the clock's retry too)");
assert.deepEqual(relayed.map((p) => [p.k, p.m, p.u, Object.keys(p.h)]), Array(2).fill(["k", "POST", "https://api.accounts.firefox.com/v1/oauth/token", ["authorization"]]));
useRelay(null);

// Past half its life (an hour of a day's), it's used at once and a new one made meanwhile, once each 10 minutes at most
let short = 0;
globalThis.fetch = async () => Response.json({ access_token: `short${++short}`, expires_in: 3600 });
const aging = new FirefoxAuth({ profileDir: dir });
aging.forget(); // tok4, kept
assert.equal(await aging.getAccessToken(), "short1");
assert.equal(await aging.getAccessToken(), "short1", "used at once");
await new Promise((r) => setTimeout(r, 50));
assert.equal(await aging.getAccessToken(), "short2", "the new one, made meanwhile");
assert.equal(short, 2, "once in 10 minutes");
assert.equal(await new FirefoxAuth({ profileDir: dir }).getAccessToken(), "short2", "and kept for the next start");

// Whether a session's sign-in is confirmed: GET /session/status signed with it, as the page asks it. A fake FxA that
// checks the HAWK header of a GET (no payload, so no hash), wants ts=1000, and answers as `status` says.
let status = {};
const statusCalls = [];
const fxaStatus = async (url, init) => {
  const h = Object.fromEntries([...init.headers.authorization.matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
  const u = new URL(url);
  statusCalls.push(`${init.method} ${u.href} ${h.ts}`);
  assert.equal(init.body, undefined, "a GET: no body");
  assert.deepEqual(Object.keys(init.headers), ["authorization"], "nor its type");
  assert.equal(h.hash, undefined, "nor a payload hash");
  assert.equal(h.id, creds.id, "signed by the session token's id");
  const normalized = `hawk.1.header\n${h.ts}\n${h.nonce}\nGET\n${u.pathname}\n${u.hostname}\n443\n\n\n`;
  assert.equal(h.mac, createHmac("sha256", creds.key).update(normalized).digest("base64"), "mac");
  if (h.ts !== "1000") return Response.json({ errno: 111, message: "Invalid timestamp", serverTime: 1000 }, { status: 401 });
  return typeof status === "number" ? Response.json({ errno: status, message: "Invalid authentication token" }, { status: 401 }) : Response.json(status);
};
globalThis.fetch = fxaStatus;
const details = (o = {}) => ({ accountEmailVerified: true, sessionVerificationMethod: "email-otp", sessionVerified: true, sessionVerificationMeetsMinimumAAL: true, verified: true, ...o });
status = { state: "verified", uid: "u1", details: details() };
assert.equal(await sessionVerified(sessionToken), true, "confirmed");
const [first, again, ...more] = statusCalls.splice(0);
assert.match(first, /^GET https:\/\/api\.accounts\.firefox\.com\/v1\/session\/status \d+$/);
assert.equal(again, "GET https://api.accounts.firefox.com/v1/session/status 1000", "a skewed clock is retried on the server's time");
assert.deepEqual(more, []);
status = { state: "unverified", uid: "u1", details: details({ sessionVerificationMethod: null, sessionVerified: false, verified: false }) };
assert.equal(await sessionVerified(sessionToken), false, "a code from the email still to type");
status = { state: "verified", uid: "u1", details: details({ accountEmailVerified: false, verified: false }) };
assert.equal(await sessionVerified(sessionToken), false, "a new account, its email not confirmed yet");
status = { state: "verified", uid: "u1", details: details({ sessionVerificationMeetsMinimumAAL: false }) };
assert.equal(await sessionVerified(sessionToken), false, "the account's second step (2FA) still to go");
status = { state: "verified", uid: "u1" };
assert.equal(await sessionVerified(sessionToken), true, "an answer without the details, as before them: its state");
status = 110;
await assert.rejects(sessionVerified(sessionToken), (err) => err.errno === 110, "a session that's gone says so");

// ...through the relay where FxA is blocked: a GET, without a body
useRelay({ url: "https://script.google.com/macros/s/x/exec", key: "k" });
relayed.length = 0;
globalThis.fetch = async (url, init) => {
  if (new URL(url).hostname === "api.accounts.firefox.com") throw new TypeError("fetch failed");
  const p = JSON.parse(init.body);
  relayed.push(p);
  const res = await fxaStatus(p.u, { method: p.m, headers: p.h, body: p.b });
  return Response.json({ s: res.status, h: {}, b: Buffer.from(await res.text()).toString("base64") });
};
status = { state: "verified", uid: "u1", details: details() };
assert.equal(await sessionVerified(sessionToken), true, "confirmed, through the relay");
assert.deepEqual(relayed.map((p) => [p.m, p.u, Object.keys(p.h), "b" in p, "ct" in p]), Array(2).fill(["GET", "https://api.accounts.firefox.com/v1/session/status", ["authorization"], false, false]));
useRelay(null);

// A sign-in for another device (tvpair.ts): the refresh token, and the first VPN token Mozilla answers with it
const asked = [];
globalThis.fetch = async (url, init) => {
  asked.push(JSON.parse(init.body));
  return Response.json({ access_token: "first", refresh_token: "ab".repeat(32), expires_in: 3600 });
};
const handed = await new FirefoxAuth({ profileDir: dir }).deviceSignIn();
assert.equal(handed.refreshToken, "ab".repeat(32));
assert.equal(handed.access.token, "first");
assert.ok(Math.abs(handed.access.expires - (Date.now() + 3600_000)) < 5000, "when it expires, from expires_in");
assert.deepEqual(asked.pop(), { client_id: "5882386c6d801776", grant_type: "fxa-credentials", scope: VPN_SCOPES.join(" "), access_type: "offline" }, "asked as before");

// A sent sign-in (RefreshAuth) with that first token: used, Mozilla not asked (where its account server can't be
// reached, it's what connects), and kept for the next start, readable only by the user; dropped once Guardian refuses
// it (forget), and the next asked for
let made = 0;
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  if (url.endsWith("/oauth/destroy")) return Response.json({});
  assert.equal(body.grant_type, "refresh_token", "a token made with the refresh token");
  return Response.json({ access_token: `made${++made}`, expires_in: 86400 });
};
const sentTok = "cd".repeat(32);
assert.equal(await new RefreshAuth(sentTok, handed.access).getAccessToken(), "first", "the first, as sent");
assert.equal(made, 0, "Mozilla not asked");
assert.equal(await new RefreshAuth(sentTok).getAccessToken(), "first", "kept: the next start has it");
const tokensFile = join(process.env.HOME, ".config", "foxhole-vpn", "tokens.json");
assert.equal(statSync(tokensFile).mode & 0o777, 0o600, "readable only by the user");
assert.ok(!readFileSync(tokensFile, "utf8").includes(sentTok), "under a hash of its sign-in, not the sign-in itself");
new RefreshAuth(sentTok).forget();
assert.equal(await new RefreshAuth(sentTok).getAccessToken(), "made1", "forgotten: the next is made");
assert.equal(await new RefreshAuth(sentTok).getAccessToken(), "made1", "and kept");
assert.equal(await new RefreshAuth("ef".repeat(32)).getAccessToken(), "made2", "another sign-in never gets it");
assert.equal(await new RefreshAuth(sentTok, { token: "stale", expires: Date.now() + 60_000 }).getAccessToken(), "made1", "a first one about to expire isn't taken");
await destroyToken(sentTok);
assert.equal(await new RefreshAuth(sentTok).getAccessToken(), "made3", "signed out of: its token goes too");

// The account's picture: Mozilla's profile read with the VPN's token, the picture as a data: URL; none (Mozilla's
// default) is null, the window's first letter; no answer throws, to be asked again
let profile = { avatar: "https://firefoxusercontent.com/abc", avatarDefault: false };
const pics = [];
globalThis.fetch = async (url, init) => {
  pics.push([String(url), init.headers?.authorization]);
  if (String(url).endsWith("/v1/profile")) return Response.json(profile);
  return new Response(Buffer.from("png!"), { headers: { "content-type": "image/png" } });
};
assert.equal(await fetchAvatar("vpntok"), `data:image/png;base64,${Buffer.from("png!").toString("base64")}`, "the picture");
assert.deepEqual(pics, [["https://profile.accounts.firefox.com/v1/profile", "Bearer vpntok"], ["https://firefoxusercontent.com/abc", undefined]], "the profile with the token, the picture without it");
profile = { avatar: "https://profile.accounts.firefox.com/v1/avatar/d", avatarDefault: true };
assert.equal(await fetchAvatar("vpntok"), null, "Mozilla's default: none");
globalThis.fetch = async () => new Response("", { status: 503 });
await assert.rejects(fetchAvatar("vpntok"), "no answer: asked again later");

console.log("ok - Firefox login: onepw keys, the signed token request, reuse, clock-skew retry, and through the relay; a session's sign-in confirmed or not, a signed GET; a sign-in for another device with its first token, and a sent one's tokens kept; the account's picture, or none");
