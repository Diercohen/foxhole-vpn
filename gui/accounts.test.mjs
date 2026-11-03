// The window's accounts (controller.js): one signed in to again isn't added twice (an alert says so, the first
// session is kept); another one is added. Sessions are made up: Mozilla turns them down, which changes nothing here.
import assert from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "foxhole-gui-accounts-")); // userHome()
const { Controller } = await import("./controller.js");
const { loadAccounts } = await import("./dist/accounts.js");
const c = new Controller({ copy: () => {}, updates: { state: () => ({}), on() {} } });
const tok = (ch) => ch.repeat(64);

c.signedIn({ uid: "u1", email: "Me@Example.com", sessionToken: tok("a") });
assert.equal(c.state().notice.title, "Signed in");
const id = c.state().notice.id;
c.signedIn({ uid: "u1", email: "Me@Example.com", sessionToken: tok("a") }); // the same sign-in handed over again (the phone's page)
assert.equal(c.state().notice.id, id, "no alert for it");
assert.equal(loadAccounts().own[0]?.sessionToken, tok("a"), "its session kept");
c.signedIn({ uid: "u1", email: "me@example.com", sessionToken: tok("b") }); // the same account (Mozilla's emails ignore case)
assert.equal(c.state().accounts.length, 1, "not added twice");
assert.equal(c.state().notice.title, "Already signed in");
assert.match(c.state().notice.text, /already signed in with me@example.com/);
assert.equal(loadAccounts().own[0].sessionToken, tok("a"), "the first session kept");
c.signedIn({ uid: "u2", email: "two@example.com", sessionToken: tok("c") });
assert.deepEqual(c.state().accounts.map((a) => a.email).sort(), ["Me@Example.com", "two@example.com"], "another account is added");

console.log("ok - accounts: one signed in to again isn't added twice; another is");
process.exit(0); // the controller's sign-in tries go on in the background
