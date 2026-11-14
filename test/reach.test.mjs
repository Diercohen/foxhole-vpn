// node test/reach.test.mjs: proxy.ts reach(), the look at the network the window's offline dialog and a connection
// that lost the internet go by (Iran's own sites and the world's, sent here: a door that opens, or port 1, refused),
// and watchReach(), its looks every few seconds; netState() on it, as the VPN's failed dials have it.
import assert from "node:assert/strict";
import net from "node:net";

const { reach, watchReach, netState, NET_CUT, NET_OFF } = await import("../dist/proxy.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const door = net.createServer((sock) => sock.destroy());
await new Promise((r) => door.listen(0, "127.0.0.1", r));
const realConnect = net.connect;
let iranUp = false, worldUp = false, names = 0;
net.connect = (o, ...rest) => {
  if (typeof o !== "object") return realConnect(o, ...rest);
  const up = /digikala|aparat/.test(o.host) ? iranUp : /cloudflare|microsoft/.test(o.host) ? worldUp : null;
  if (up === null) return realConnect(o, ...rest);
  names++; // by name: the lookup's Node's (lookupOnce), not done before
  const { lookup: _, ...rest0 } = o;
  return realConnect({ ...rest0, host: "127.0.0.1", port: up ? door.address().port : 1 }, ...rest);
};

assert.equal(await reach(), "offline", "nothing opens: offline");
assert.ok(names >= 2, "the sites dialed by name");
iranUp = true;
assert.equal(await reach(), "cut", "Iran's own sites only: cut off");
assert.equal(await netState(), NET_CUT, "netState says so in words");
worldUp = true;
assert.equal(await reach(), "online", "the world opens: online");
assert.equal(await netState(), null);
[iranUp, worldUp] = [false, false];
assert.equal(await netState(), NET_OFF);

// a site that takes no answer at all (a dropped packet): the look ends at its time, not the system's
net.connect = (o, ...rest) => (typeof o === "object" && /digikala|aparat|cloudflare|microsoft/.test(o.host) ? new net.Socket() : realConnect(o, ...rest));
const t0 = Date.now();
assert.equal(await reach(200), "offline", "silence: offline");
assert.ok(Date.now() - t0 < 1000, "within its time");
net.connect = (o, ...rest) => {
  if (typeof o !== "object" || !/digikala|aparat|cloudflare|microsoft/.test(o.host)) return realConnect(o, ...rest);
  const { lookup: _, ...rest0 } = o;
  return realConnect({ ...rest0, host: "127.0.0.1", port: (/cloudflare|microsoft/.test(o.host) ? worldUp : iranUp) ? door.address().port : 1 }, ...rest);
};

// watchReach: a look every `ms`, one at a time; now() at once; nothing after stop()
const looks = [];
const watch = watchReach((r) => looks.push(r), 30);
await sleep(200);
assert.ok(looks.length >= 2 && looks.every((r) => r === "offline"), "looks again and again while offline");
worldUp = true;
watch.now();
for (let i = 0; looks.at(-1) !== "online" && i < 50; i++) await sleep(20);
assert.equal(looks.at(-1), "online", "the internet back, seen");
watch.stop();
const n = looks.length;
await sleep(150);
assert.equal(looks.length, n, "no look after stop()");

net.connect = realConnect;
door.close();
console.log("ok - reach: online, cut off (Iran's sites only) or offline, by name and within its time; watchReach looks till it's stopped");
