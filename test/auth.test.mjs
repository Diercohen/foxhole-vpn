// FirefoxAuth: the onepw key derivation (the spec's test vector), the signed
// fxa-credentials request, token reuse, and the clock-skew retry. fetch is
// stubbed; no Firefox, no network.
import assert from "node:assert";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FirefoxAuth, sessionCredentials, VPN_SCOPES } from "../dist/auth.js";

// https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol#test-vectors
const sessionToken = Buffer.from(Array.from({ length: 32 }, (_, i) => 0xa0 + i)).toString("hex");
const creds = sessionCredentials(sessionToken);
assert.equal(creds.id, "c0a29dcf46174973da1378696e4c82ae10f723cf4f4d9f75e39f4ae3851595ab", "tokenID");
assert.equal(creds.key.toString("hex"), "9d8f22998ee7f5798b887042466b72d53e56ab0c094388bf65831f702d2febc0", "reqHMACkey");

const dir = mkdtempSync(join(tmpdir(), "foxhole-vpn-"));
writeFileSync(join(dir, "signedInUser.json"), JSON.stringify({ accountData: { sessionToken } }));

// A fake FxA that checks the HAWK header the way the server does, and wants ts=1000.
const calls = [];
globalThis.fetch = async (url, init) => {
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

// A signed-out or revoked session says so instead of failing vaguely.
globalThis.fetch = async () => Response.json({ errno: 110, message: "Invalid authentication token" }, { status: 401 });
await assert.rejects(new FirefoxAuth({ profileDir: dir }).getAccessToken(), /sign in to Firefox again/);

console.log("ok - Firefox login: onepw keys, the signed token request, reuse, clock-skew retry");
