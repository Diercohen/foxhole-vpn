// A TV's sign-in from another device (tvpair.ts), over loopback: by its code and by its QR code's link; a wrong code
// is refused, and after a few the TV shows a new one; what the TV refuses to sign in with, the sender is told. A VPN
// relay comes along with a sign-in, or alone; and a TV or phone waiting for a relay alone takes only that.
import assert from "node:assert";
import { askTv, normalizeCode, parseTvLink, sendToTv, waitForSignIn } from "../dist/tvpair.js";

const account = { uid: "u1", email: "me@example.com", refreshToken: "ab".repeat(32) };
const relay = { deploymentId: "AKfycb" + "x".repeat(40), authKey: "my key" };
const got = [];
let refuse = null, changes = 0;
const tv = await waitForSignIn({
  name: "Living room TV",
  host: () => "127.0.0.1",
  port: 47599,
  accept: async (a, from) => {
    if (refuse) throw new Error(refuse);
    got.push({ ...a, from });
  },
  changed: () => changes++,
});

assert.equal(normalizeCode(" ab3-x9k "), "AB3X9K");
assert.equal(normalizeCode("AB0X9K"), null, "0 isn't one of its characters");
assert.equal(normalizeCode("AB3X9"), null);

const { code, link } = tv.waiting();
assert.match(code, /^[2-9A-HJKMNP-Z]{6}$/);
const fromLink = parseTvLink(link);
assert.ok(fromLink && fromLink.host === "127.0.0.1" && fromLink.port === 47599 && fromLink.secret);
assert.equal(parseTvLink("http://127.0.0.1:47599/#nope"), null);
assert.equal(parseTvLink("https://example.com/"), null);
assert.equal((await askTv(fromLink)).want, "signin", "it says what it waits for");

const byCode = { host: "127.0.0.1", port: 47599, name: "", pub: fromLink.pub };
assert.deepEqual(await sendToTv(byCode, { code: code.toLowerCase() }, { account }, "Laptop"), { account: true, relay: false });
assert.deepEqual(got.pop(), { account, relay: null, from: "Laptop" }, "by the code");
await sendToTv(fromLink, {}, { account }, "Phone");
assert.equal(got.pop().from, "Phone", "by the QR code's link");

// the relay: with the sign-in, alone, and not one (then the sign-in alone)
assert.deepEqual(await sendToTv(fromLink, {}, { account, relay }, "Laptop"), { account: true, relay: true });
assert.deepEqual(got.pop(), { account, relay, from: "Laptop" }, "a sign-in with its relay");
assert.deepEqual(await sendToTv(fromLink, {}, { relay }, "Laptop"), { account: false, relay: true });
assert.deepEqual(got.pop(), { account: null, relay, from: "Laptop" }, "a relay alone, to the sign-in screen");
await sendToTv(fromLink, {}, { account, relay: { deploymentId: "short", authKey: "k" } }, "x");
assert.equal(got.pop().relay, null, "a Deployment ID the setup wouldn't take isn't one");
await assert.rejects(sendToTv(fromLink, {}, {}, "x"), /no account in it/);

await assert.rejects(sendToTv(byCode, { code: "222222" }, { account }, "x"), /isn't the code on the TV/);
await assert.rejects(sendToTv(byCode, { code: "0" }, { account }, "x"), /6 letters and digits/);
refuse = "Mozilla refused it";
await assert.rejects(sendToTv(fromLink, {}, { account }, "x"), /Mozilla refused it/, "the TV's reason, to the sender");
refuse = null;
for (let i = 0; i < 4; i++) await sendToTv(byCode, { code: "222222" }, { account }, "x").catch(() => {});
assert.equal(changes, 1, "a new code after five wrong ones");
assert.notEqual(tv.waiting().code, code);
await assert.rejects(sendToTv(fromLink, {}, { account }, "x"), /isn't this TV's anymore/, "the old QR code with it");
tv.stop();

// a phone (or a TV, later) waiting for a relay alone: a sign-in sent along isn't taken, and one without a relay is refused
const phone = await waitForSignIn({ name: "Phone", want: "relay", host: () => "127.0.0.1", port: 47598, accept: async (a, from) => void got.push({ ...a, from }), changed: () => {} });
const phoneLink = parseTvLink(phone.waiting().link);
const there = await askTv(phoneLink);
assert.equal(there.want, "relay", "it says it waits for a relay");
assert.deepEqual(await sendToTv({ ...phoneLink, want: there.want }, {}, { account, relay }, "Laptop"), { account: false, relay: true });
assert.deepEqual(got.pop(), { account: null, relay, from: "Laptop" }, "the relay alone");
await assert.rejects(sendToTv(phoneLink, {}, { account }, "Old laptop"), /waiting for a VPN relay, and none came/, "an older Foxhole's sign-in");
assert.equal(got.length, 0);
phone.stop();
console.log("ok - TV sign-in: by code and by QR code, with a relay or a relay alone, wrong codes refused and the code renewed, the TV's refusal passed on");
