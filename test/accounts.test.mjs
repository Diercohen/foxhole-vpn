// Accounts: the file (and an earlier version's user carried over), adding, using and removing one.
import assert from "node:assert";
import { mkdirSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "foxhole-accounts-"));
process.env.HOME = home; // userHome()
const { loadAccounts, saveAccounts, parseAccounts, withOwn, without, withFirefox, FIREFOX } = await import("../dist/accounts.js");
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

console.log("ok - accounts: the file, an earlier version's user carried over, adding, using and removing");
