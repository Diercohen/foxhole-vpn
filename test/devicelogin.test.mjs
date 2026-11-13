// The terminal's "Sign in from another device" (devicelogin.ts): what it shows in a wide, a tall and a short terminal,
// and the wait itself, over loopback: a sign-in sent with a relay is the account in use (Firefox's leaves the list),
// one that's here already is used as it is (once its sign-in has ended, the new one takes its place, the old one
// signed out), one Mozilla turns down isn't taken, and a new code is shown again.
// fetch stands in for Mozilla's account server; no Firefox, no network.
import assert from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = process.env.USERPROFILE = mkdtempSync(join(tmpdir(), "foxhole-device-")); // accounts.json and settings.json go here
delete process.env.FOXHOLE_RELAY_ID;
delete process.env.FOXHOLE_RELAY_KEY;
const { deviceLines, deviceLogin } = await import("../dist/devicelogin.js");
const { askTv, sendToTv } = await import("../dist/tvpair.js");
const { vw } = await import("../dist/ui.js");
const { loadAccounts, saveAccounts, withFirefox } = await import("../dist/accounts.js");
const { loadSettings } = await import("../dist/settings.js");

const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
const text = (lines) => plain(lines.join("\n"));
const QR = /[█▀▄]/; // a line of the QR code
const CODE = "K 7 M   2 Q X";

// ── What's on the terminal ──────────────────────────────────────────────────────────────────────────────────────
const waiting = { code: "K7M2QX", host: "192.168.1.23", link: `http://192.168.1.23:47533/#${"A".repeat(22)}.${"B".repeat(43)}` };
const net = "Wi-Fi · Home";

// a wide terminal: the QR code, the words beside it
let lines = deviceLines(waiting, { width: 98, height: 30, net });
assert.equal(lines.length, 23, "as tall as its QR code");
assert.ok(lines.every((l) => QR.test(plain(l).slice(0, 45)) || !plain(l).slice(0, 45).trim()), "the QR code on the left of every line");
assert.ok(lines.every((l) => vw(l) <= 98), "no wider than the room");
const beside = lines.map((l) => plain(l).slice(48).trimEnd()).join("\n");
assert.match(beside.replace(/\n/g, " "), /open Settings → Sign in a TV or phone, and scan this QR code or type this code:/);
assert.ok(beside.includes(CODE), "the code, a letter at a time");
assert.match(beside.replace(/\n/g, " "), /This computer is on Wi-Fi · Home · 192\.168\.1\.23: the other device must be on it too\./);
assert.match(beside.replace(/\n/g, " "), /the other device's VPN relay comes along/);

// a narrow but tall one: the QR code under the code
lines = deviceLines(waiting, { width: 62, height: 45, net, fw: ["sudo ufw allow 47533/tcp"] });
assert.equal(lines.filter((l) => QR.test(l)).length >= 21 && lines.length <= 45, true);
assert.ok(lines.every((l) => vw(l) <= 62));
assert.ok(lines.findIndex((l) => plain(l).includes(CODE)) < lines.findIndex((l) => QR.test(l)), "how, the code, then the QR code");
assert.match(text(lines), /open the port in the firewall:\nsudo ufw allow 47533\/tcp/, "a firewall that's on: what opens the port");
assert.equal(deviceLines(waiting, { width: 80, height: 45, net }).filter((l) => QR.test(l)).length, lines.filter((l) => QR.test(l)).length, "80 columns: not beside (no room for the words), under");
assert.ok(deviceLines(waiting, { width: 80, height: 45, net }).every((l) => vw(l) <= 62), "and no wider than the other popups");

// a short one: the code is all it takes; the lines after it only while they fit
lines = deviceLines(waiting, { width: 62, height: 14, net });
assert.ok(!lines.some((l) => QR.test(l)) && lines.length <= 14);
assert.match(text(lines).replace(/\n/g, " "), /Sign in a TV or phone, and type this code:/, "nothing to scan: not said");
assert.ok(text(lines).includes(CODE) && text(lines).includes("192.168.1.23"));
assert.match(text(lines), /A larger terminal shows a QR code to scan, too\./);
lines = deviceLines(waiting, { width: 62, height: 8, net, fw: ["sudo ufw allow 47533/tcp"] });
assert.ok(lines.length <= 8 && text(lines).includes(CODE) && text(lines).includes("192.168.1.23") && !text(lines).includes("ufw"), "the network before the firewall");
assert.ok(text(deviceLines(waiting, { width: 62, height: 2, net })).includes(CODE), "the code whatever the room");

// not on a network: no QR code, and it says so
lines = deviceLines({ code: "K7M2QX", host: null, link: null }, { width: 98, height: 40, net: null });
assert.ok(!lines.some((l) => QR.test(l)));
assert.match(text(lines).replace(/\n/g, " "), /This computer isn't on a network: connect it to the Wi-Fi or a cable first\./);
assert.ok(!text(lines).includes("larger terminal"), "no QR code to promise");
assert.match(text(deviceLines(waiting, { width: 62, height: 14 })).replace(/\n/g, " "), /This computer is on a network · 192\.168\.1\.23/, "a network whose name isn't known");

// ── The wait ────────────────────────────────────────────────────────────────────────────────────────────────────
const tok = (c) => c.repeat(64);
const alive = new Set(); // the sign-ins Mozilla still takes
const destroyed = []; // those signed out at Mozilla
const real = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (new URL(url).hostname !== "api.accounts.firefox.com") return real(url, init); // the other device's, over loopback
  const body = JSON.parse(init.body);
  if (new URL(url).pathname === "/v1/oauth/destroy") return destroyed.push(body.token), Response.json({});
  return alive.has(body.refresh_token) ? Response.json({ access_token: "at", expires_in: 86400 }) : Response.json({ errno: 110, message: "Invalid token" }, { status: 401 });
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** This "computer" waiting on `port`, and the other device's side of it: the code on the terminal now, and where to send. */
function wait(port) {
  const said = [];
  const stop = new AbortController();
  const done = deviceLogin({ signal: stop.signal, say: (t) => said.push(plain(t)), host: () => "127.0.0.1", port, size: () => ({ cols: 110, rows: 40 }) });
  const code = async (not) => {
    for (;;) {
      const shown = said.join("\n").match(/\b[2-9A-HJKMNP-Z]( [2-9A-HJKMNP-Z]){2} {3}[2-9A-HJKMNP-Z]( [2-9A-HJKMNP-Z]){2}\b/g)?.at(-1).replace(/ /g, "");
      if (shown && shown !== not) return shown;
      await sleep(20);
    }
  };
  const tv = async () => ({ host: "127.0.0.1", port, name: "", pub: (await askTv({ host: "127.0.0.1", port })).pub });
  return { said, stop, done, code, tv, out: () => said.join("\n") };
}

// Firefox's sign-in in use, signed out: `foxhole login`'s d. A phone sends its sign-in, its relay with it
saveAccounts(withFirefox(loadAccounts()));
const account = { uid: "u1", email: "me@example.com", refreshToken: tok("c") };
const relay = { deploymentId: "AKfycb" + "x".repeat(40), authKey: "my key" };
alive.add(tok("c"));
let w = wait(47591);
let code = await w.code();
assert.match(w.out(), /Sign in from another device/);
assert.match(w.out(), /Waiting for the sign-in · press q or Ctrl\+C to cancel/);
assert.ok(w.said[0].split("\n").some((l) => QR.test(l)), "110 columns by 40: its QR code too");
assert.deepEqual(await sendToTv(await w.tv(), { code }, { account, relay }, "Phone"), { account: true, relay: true });
assert.equal(await w.done, "me@example.com", "signed in");
assert.deepEqual(loadAccounts(), { current: "u1", firefox: false, own: [account], lowSeen: {} }, "the account in use; Firefox's, which didn't work, off the list");
assert.deepEqual(loadSettings().relay, relay, "its relay saved");
assert.match(w.out(), /✓ Your VPN relay came from Phone\.\n✓ Signed in with me@example\.com, sent from Phone\./);

// the account's here already, its sign-in good: used as it is, the new one not kept (its sender is told, and ends it)
alive.add(tok("d"));
w = wait(47592);
code = await w.code();
await assert.rejects(sendToTv(await w.tv(), { code }, { account: { ...account, refreshToken: tok("d") } }, "Phone"), /the other device is already signed in with me@example\.com/);
assert.equal(await w.done, "me@example.com");
assert.equal(loadAccounts().own[0].refreshToken, tok("c"), "the sign-in it had");
assert.match(w.out(), /✓ me@example\.com is signed in here already: it's the account in use\./);

// its sign-in has ended since: the new one takes its place, and the one it replaces is signed out at Mozilla
alive.delete(tok("c"));
w = wait(47594);
code = await w.code();
assert.deepEqual(await sendToTv(await w.tv(), { code }, { account: { ...account, refreshToken: tok("d") } }, "Phone"), { account: true, relay: false });
assert.equal(await w.done, "me@example.com");
assert.deepEqual(loadAccounts().own, [{ ...account, refreshToken: tok("d") }], "the new sign-in in its place");
for (let i = 0; !destroyed.length && i < 50; i++) await sleep(20);
assert.deepEqual(destroyed, [tok("c")], "the ended one, signed out");

// one Mozilla turns down isn't taken, and it goes on waiting; a relay alone is, and it goes on waiting too
w = wait(47593);
code = await w.code();
await assert.rejects(sendToTv(await w.tv(), { code }, { account: { uid: "u9", email: "nine@example.com", refreshToken: tok("e") } }, "Laptop"), /This sign-in has ended/);
assert.match(w.out(), /The sign-in from Laptop wasn't taken: This sign-in has ended/);
assert.equal(loadAccounts().current, "u1", "nothing changed");
const other = { deploymentId: "AKfycb" + "y".repeat(40), authKey: "another key" };
assert.deepEqual(await sendToTv(await w.tv(), { code }, { relay: other }, "Laptop"), { account: false, relay: true });
assert.deepEqual(loadSettings().relay, other, "in place of the one here");
assert.match(w.out(), /✓ Your VPN relay came from Laptop\.\nStill waiting for the sign-in…/);
// wrong codes: after five a new one, on the terminal again
for (let i = 0; i < 5; i++) await sendToTv(await w.tv(), { code: code === "222222" ? "333333" : "222222" }, { account }, "x").catch(() => {});
const renewed = await w.code(code);
assert.equal(w.said.filter((t) => t.includes("Sign in from another device")).length, 2, "shown again, once");
assert.deepEqual(await sendToTv(await w.tv(), { code: renewed }, { relay }, "Laptop"), { account: false, relay: true }, "the new code is the one that works");

// another Foxhole here waits already (its window's dialog): said, not waited for
await assert.rejects(wait(47593).done, /Another app on this computer is using Foxhole's sign-in port \(47593\)/);
w.stop.abort(); // q
assert.equal(await w.done, null, "cancelled");

console.log("ok - sign in from another device, in the terminal: the QR code beside or under the code where it fits; a sign-in and its relay taken, one that's here used, one Mozilla refuses not");
