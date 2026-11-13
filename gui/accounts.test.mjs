// The window's accounts (controller.js): one signed in to again isn't added twice (an alert says so, the first
// session is kept); another one is added. Sessions are made up: Mozilla turns them down, which changes nothing here.
// Then a sign-in another device sends (tvAccept): one here already, its sign-in good, stays as it is (its sender's
// told; an alert says so, with the relay that came with it); one whose sign-in has ended is replaced, and signed out;
// a new one is added, and in use.
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

// ── A sign-in from another device, over loopback; a stand-in for Mozilla's account server (a refresh token is in
// the request, a session signs it: its HAWK id says which), `alive` those it takes ─────────────────────────────────
const { askTv, sendToTv, TV_PORT } = await import("./dist/tvpair.js");
const { sessionCredentials } = await import("./dist/auth.js");
const { loadSettings } = await import("./dist/settings.js");
const sessions = [tok("a"), tok("b"), tok("c")]; // u1's is a, u2's c
const alive = new Set([tok("a")]);
const destroyed = []; // signed out at Mozilla
const real = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  const u = new URL(url);
  if (u.hostname === "127.0.0.1") return real(url, init); // the sender's
  if (u.hostname !== "api.accounts.firefox.com") return new Response("not here", { status: 503 }); // the VPN's own, in the background
  const body = JSON.parse(init.body || "{}");
  const signed = sessions.find((t) => init.headers?.authorization?.includes(sessionCredentials(t).id));
  if (u.pathname.endsWith("/destroy")) return destroyed.push(body.token ?? signed), Response.json({});
  return alive.has(body.refresh_token ?? signed) ? Response.json({ access_token: "at", expires_in: 86400 }) : Response.json({ errno: 110, message: "Invalid token" }, { status: 401 });
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** This computer waiting again, as Add account → Sign in from another device has it: its code, and where to send. */
async function waiting() {
  for (let i = 0; c.state().tvWait && i < 100; i++) await sleep(20); // the last wait's put away first
  await c.tvWait(true);
  for (let i = 0; !c.state().tvWait?.code && !c.state().tvWait?.error && i < 200; i++) await sleep(20);
  const w = c.state().tvWait;
  if (!w?.code) return null; // the sign-in port is in use here (a Foxhole window waiting): not tried
  return { code: w.code, tv: { host: "127.0.0.1", port: TV_PORT, name: "", pub: (await askTv({ host: "127.0.0.1", port: TV_PORT })).pub } };
}

let w = await waiting();
if (!w) console.log(`skip - a sign-in from another device: port ${TV_PORT} is in use here`);
else {
  // u1's here, its full sign-in good: kept, and the sender's told
  const relay = { deploymentId: "AKfycb" + "x".repeat(40), authKey: "my key" };
  alive.add(tok("d"));
  await assert.rejects(sendToTv(w.tv, { code: w.code }, { account: { uid: "u1", email: "me@example.com", refreshToken: tok("d") }, relay }, "Phone"), /the other device is already signed in with Me@Example\.com/);
  assert.equal(c.state().notice.title, "Already signed in");
  assert.match(c.state().notice.text, /^Your VPN relay came from Phone: .+\nYou're already signed in with Me@Example\.com, so it isn't added again\.$/, "the relay that came with it, and the account that's here");
  assert.equal(loadAccounts().own.find((x) => x.uid === "u1").sessionToken, tok("a"), "its full sign-in kept, not given up for a VPN-only one");
  assert.deepEqual(loadSettings().relay, relay, "the relay saved");
  assert.ok(!destroyed.length, "nothing signed out here");

  // u2's sign-in has ended: the sent one takes its place, and the old one's signed out
  w = await waiting();
  alive.add(tok("e"));
  assert.deepEqual(await sendToTv(w.tv, { code: w.code }, { account: { uid: "u2", email: "two@example.com", refreshToken: tok("e") } }, "Phone"), { account: true, relay: false });
  assert.equal(c.state().notice.title, "Signed in");
  assert.deepEqual(loadAccounts().own.find((x) => x.uid === "u2"), { uid: "u2", email: "two@example.com", refreshToken: tok("e") }, "in its place");
  assert.equal(loadAccounts().current, "u2");
  for (let i = 0; !destroyed.length && i < 50; i++) await sleep(20);
  assert.deepEqual(destroyed, [tok("c")], "the ended one, signed out");

  // a new one: added, and in use
  w = await waiting();
  assert.deepEqual(await sendToTv(w.tv, { code: w.code }, { account: { uid: "u3", email: "three@example.com", refreshToken: tok("d") } }, "Phone"), { account: true, relay: false });
  assert.match(c.state().notice.text, /You're signed in with three@example\.com, sent from Phone, and it's the account in use now\./);
  assert.deepEqual(c.state().accounts.map((a) => a.email), ["Me@Example.com", "two@example.com", "three@example.com"]);
  assert.equal(loadAccounts().current, "u3");
}

console.log("ok - accounts: one signed in to again isn't added twice; another is; a sign-in another device sends, as the terminal takes one");
process.exit(0); // the controller's sign-in tries go on in the background
