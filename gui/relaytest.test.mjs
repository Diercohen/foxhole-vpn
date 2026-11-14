// node relaytest.test.mjs: a relay turned on is tested first (controller.js #testRelay), whichever way it came: its
// fields saved (only when they changed), its setup finished, Check again from its dialog; the dialog's closed, and a
// relay turned off takes its test away. Google's front is out of reach here (refused), so each test fails at once.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync } from "node:fs";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "foxhole-gui-relaytest-")); // userHome()
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (ok, ms = 5000) => {
  for (const end = Date.now() + ms; !ok() && Date.now() < end; ) await sleep(20);
  return ok();
};
const realRequest = https.request;
let fronted = 0;
https.request = (o, ...rest) => {
  if (o?.host !== "www.gstatic.com") return realRequest(o, ...rest);
  fronted++;
  const req = Object.assign(new EventEmitter(), { end() {}, write() {}, destroy() {}, setTimeout() {} });
  setImmediate(() => req.emit("error", Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" })));
  return req;
};
globalThis.fetch = async () => new Response("not here", { status: 503 }); // Mozilla: nothing needed of it here

const { Controller } = await import("./controller.js");
const c = new Controller({ copy: () => {}, updates: { state: () => ({}), on() {} } });
const ID = "DEPLOY_ID_0123456789abcdefgh", KEY = "test-key-0123456789abcdef";

// the Settings fields saved: tested, its answer for Settings (no dialog: via settings)
assert.equal(await c.setRelay(ID, KEY), true);
let t = c.state().relayTest;
assert.equal(t?.via, "settings", "turned on: tested at once");
assert.ok(await until(() => c.state().relayTest.tone === "error"));
t = c.state().relayTest;
assert.match(t.steps[0].text, /^Couldn't reach Google: /);
assert.equal(t.title, "Couldn't check your relay", "Google out of reach: not the relay's fault");
const first = t.id;

// saved again unchanged (the field left): not tested again
await c.setRelay(ID, "");
assert.equal(c.state().relayTest.id, first, "the same relay: no new test");

// its setup finished: tested again, for its dialog
await c.setRelay(ID, KEY, "wizard");
assert.equal(c.state().relayTest.via, "wizard", "the setup's: always tested, its dialog shows it");
assert.ok(await until(() => c.state().relayTest.tone));
c.closeRelayTest();
assert.equal(c.state().relayTest.closed, true, "the dialog closed: Settings still has it");

// Check again in that dialog: the dialog's own test again
const again = await c.checkRelay(ID, "", "wizard");
assert.equal(again.via, "wizard");
assert.ok(!again.closed && again.id > first);
// Settings' Check of typed fields not saved: said so
const typed = await c.checkRelay("OTHER_ID_0123456789abcdefgh", "another-key-0123456789");
assert.deepEqual([typed.via, typed.unsaved], ["check", true]);
assert.deepEqual(await c.checkRelay("", ""), { tone: "error", text: "Type the Deployment ID first." }, "nothing to test");

// turned off: no test left, and none of an old script
await c.setRelay("", "");
assert.equal(c.state().relayTest, null);
assert.equal(c.state().relayOld, false);
assert.ok(fronted >= 4, "each test asked Google's front");

https.request = realRequest;
console.log("ok - relay test: a relay turned on is tested first (its fields saved when changed, its setup, Check again), its dialog closed, gone with the relay");
process.exit(0);
