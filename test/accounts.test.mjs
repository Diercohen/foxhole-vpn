// Accounts: the file (and an earlier version's user carried over), adding, using and removing one.
import assert from "node:assert";
import { mkdirSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "foxhole-accounts-"));
process.env.HOME = home; // userHome()
const { loadAccounts, saveAccounts, parseAccounts, withOwn, without, withFirefox, takeSent, withSent, AlreadySignedIn, FIREFOX } = await import("../dist/accounts.js");
const { sessionCredentials } = await import("../dist/auth.js");
const config = join(home, ".config", "foxhole-vpn");
const tok = (c) => c.repeat(64);

// A first start: none, and nothing written until there's one
assert.deepEqual(loadAccounts(), { current: null, firefox: false, own: [], lowSeen: {} });
// An earlier version's user (it saved the last country): Firefox's sign-in, in use, as before
mkdirSync(config, { recursive: true });
writeFileSync(join(config, "country"), "DE");
assert.deepEqual(loadAccounts(), { current: FIREFOX, firefox: true, own: [], lowSeen: {} });
assert.equal(statSync(join(config, "accounts.json")).mode & 0o777, 0o600, "kept private: it holds sessions");

let a = withOwn(loadAccounts(), { uid: "u1", email: "one@example.com", sessionToken: tok("a") });
a = withOwn(a, { uid: "u2", email: "two@example.com", sessionToken: tok("b") });
assert.equal(a.current, "u2", "a new account is the one in use");
saveAccounts(a);
assert.deepEqual(loadAccounts(), a, "and stays so for the next start");
assert.equal(without(a, "u2").current, FIREFOX, "the one in use gone: the next on the list");
assert.equal(without(without(without(a, "u2"), FIREFOX), "u1").current, null, "none left: the first start's question again");
assert.equal(without(a, FIREFOX).firefox, false, "Firefox's off the list (Firefox itself stays signed in)");
assert.equal(withFirefox(without(a, FIREFOX)).current, FIREFOX);
assert.equal(parseAccounts(JSON.stringify({ current: "gone", own: [{ uid: "u1", email: "e", sessionToken: "short" }, { uid: "u3", email: "e", sessionToken: tok("c") }] })).current, "u3",
  "a malformed session is dropped, an unknown current falls back");
assert.equal(parseAccounts("{oops"), null);

// A sign-in another device sent (takeSent): checked with Mozilla, then on the list and in use. A stand-in for Mozilla's
// account server: a refresh token is in the request, a session signs it (its HAWK id says which); `alive` are taken.
const alive = new Set();
const sessions = [tok("a"), tok("b"), tok("f")];
globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://api.accounts.firefox.com/v1/oauth/token");
  const token = JSON.parse(init.body).refresh_token ?? sessions.find((t) => init.headers.authorization.includes(sessionCredentials(t).id));
  return alive.has(token) ? Response.json({ access_token: "at", expires_in: 86400 }) : Response.json({ errno: 110, message: "Invalid token" }, { status: 401 });
};
const list = without(a, FIREFOX); // u1 and u2, each with a full sign-in (a session); u2 in use
const sent = (uid, email, c) => ({ uid, email, refreshToken: tok(c), extra: "not kept" });

alive.add(tok("c"));
let took = await takeSent(list, sent("u3", "three@example.com", "c"));
let next = withSent(list, took);
assert.equal(next.current, "u3", "a sign-in sent is the one in use");
assert.deepEqual(next.own.at(-1), { uid: "u3", email: "three@example.com", refreshToken: tok("c") }, "kept as the file keeps one");
assert.equal(next.own.length, 3);
assert.equal(took.replaced, null, "none replaced");
assert.deepEqual(withSent({ ...list, lowSeen: { u1: "Dec" } }, took).lowSeen, { u1: "Dec" }, "on the list as it is when it's saved: what changed while Mozilla was asked stays");
await assert.rejects(takeSent(list, sent("u4", "four@example.com", "d")), /has ended/, "what Mozilla turns down isn't taken: the sender's told why");
await assert.rejects(takeSent(list, { uid: "u4", email: "four@example.com", refreshToken: "short" }), /isn't a sign-in Foxhole can keep/);
alive.add(tok("d"));
await assert.rejects(takeSent(list, sent("u4", "four\x1b[2J@example.com", "d")), /isn't a sign-in Foxhole can keep/, "nothing a terminal would act on");

// the account's on the list already: a sign-in that still works stays (a full one isn't given up for a VPN-only one)
alive.add(tok("a"));
const twin = await takeSent(list, sent("u1", "one@example.com", "c")).catch((err) => err);
assert.ok(twin instanceof AlreadySignedIn && twin.id === "u1" && twin.email === "one@example.com");
assert.match(twin.message, /the other device is already signed in with one@example.com/, "as its sender reads it");
assert.equal((await takeSent(list, sent("other-uid", "ONE@example.com", "c")).catch((err) => err)).id, "u1", "by its email too (Mozilla's ignore case)");
// one that has ended: the new one takes its place, and the one it replaces comes back, to sign out
took = await takeSent(list, sent("u2", "two@example.com", "c"));
next = withSent(list, took);
assert.deepEqual(next.own.map((x) => [x.uid, !!x.sessionToken, x.refreshToken]), [["u1", true, undefined], ["u2", false, tok("c")]], "an ended sign-in renewed");
assert.equal(next.current, "u2");
assert.deepEqual(took.replaced, { uid: "u2", email: "two@example.com", sessionToken: tok("b") }, "the ended one, to sign out");
took = await takeSent(list, sent("u2-again", "two@example.com", "c"));
next = withSent(list, took);
assert.deepEqual(next.own.map((x) => x.uid), ["u1", "u2-again"], "the same email under a new id: not listed twice");
assert.equal(next.current, "u2-again");
assert.equal(took.replaced?.uid, "u2");

// Firefox's sign-in on the list, to the same account: said so, not added beside it
const profile = join(home, ".mozilla", "firefox", "p.default-release");
mkdirSync(profile, { recursive: true });
writeFileSync(join(home, ".mozilla", "firefox", "profiles.ini"), "[Profile0]\nName=default\nIsRelative=1\nPath=p.default-release\nDefault=1\n");
writeFileSync(join(profile, "signedInUser.json"), JSON.stringify({ accountData: { email: "fox@example.com", uid: "uf", verified: true, sessionToken: tok("f") } }));
const inFirefox = await takeSent(a, sent("uf", "fox@example.com", "c")).catch((err) => err);
assert.ok(inFirefox instanceof AlreadySignedIn && inFirefox.id === FIREFOX && inFirefox.email === "fox@example.com");
assert.equal(withSent(list, await takeSent(list, sent("uf", "fox@example.com", "c"))).current, "uf", "Firefox's isn't on the list: added");
writeFileSync(join(profile, "signedInUser.json"), "null"); // Firefox signed out
assert.equal(withSent(a, await takeSent(a, sent("uf", "fox@example.com", "c"))).current, "uf", "Firefox signed out: added");

console.log("ok - accounts: the file, an earlier version's user carried over, adding, using and removing; a sign-in another device sent");
