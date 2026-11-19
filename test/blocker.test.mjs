// Shield (blocker.ts): reading lists, which names are blocked, the user's rules, the lists' files, the settings, and the
// proxy refusing a blocked site. Local only: test/blocker-live.mjs gets the real lists.
import net from "node:net";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { nameIn, hashList, useBlocker, blocked, blockerOn, blockerOf, parseBlocker, listState, reloadBlockLists, DEFAULT_BLOCKER } from "../dist/blocker.js";
import { nxdomain, question } from "../dist/dns.js";
import { parseSettings } from "../dist/settings.js";
import { startProxy } from "../dist/proxy.js";
process.env.HOME = process.env.USERPROFILE = mkdtempSync(path.join(os.tmpdir(), "foxhole-home-")); // the data counts go here

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 20000).unref();

// A list's lines: plain names and hosts files, comments, and what's no site
assert.equal(nameIn("ads.example.com"), "ads.example.com");
assert.equal(nameIn("0.0.0.0 Tracker.Example.COM # a tracker"), "tracker.example.com");
assert.equal(nameIn("127.0.0.1\tminer.example.net."), "miner.example.net");
assert.equal(nameIn(":: ads.example.org"), "ads.example.org");
for (const line of ["# a comment", "", "   ", "0.0.0.0 localhost", "127.0.0.1 my.localdomain", "1.2.3.4", "0.0.0.0 0.0.0.0", "com", "||ads.example.com^", "a b c"])
  assert.equal(nameIn(line), null, JSON.stringify(line));

// The lists' files, as refreshBlocker writes them
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-lists-"));
const write = async (id, text) => {
  const h = await hashList(text);
  writeFileSync(path.join(dir, `block-${id}.bin`), Buffer.from(h.buffer, h.byteOffset, h.byteLength));
  return h;
};
const ads = await write("ads", "doubleclick.net\n0.0.0.0 ads.example.com\n# x\nads.example.com\ncloudflare-dns.com\nfastly-masque.net\n");
assert.equal(ads.length, 4, "the same name twice is kept once");
assert.ok(ads.every((h, i) => i === 0 || ads[i - 1] < h), "sorted, for the binary search");
await write("malware", "evil.test\r\n"); // Windows line ends

let b = { lists: ["ads"] };
useBlocker(() => b, dir);
assert.equal(blocked("doubleclick.net"), "ads");
assert.equal(blocked("stats.g.DoubleClick.net."), "ads", "a subdomain, whatever its case, with the root's dot");
assert.equal(blocked("notdoubleclick.net"), null, "not a name that only ends the same");
assert.equal(blocked("net"), null);
assert.equal(blocked("evil.test"), null, "a list that's off");
assert.equal(blocked("cloudflare-dns.com"), null, "Foxhole's own hosts, whatever a list has");
assert.equal(blocked("mask.fastly-masque.net"), null, "and the VPN's servers");
assert.equal(blocked(undefined, "1.2.3.4"), null, "an address alone: only the rules say");
b = { lists: ["ads", "malware"] };
assert.equal(blocked("www.evil.test"), "malware", "a list turned on");

// The user's rules: block what no list has, allow what one does; the most specific wins, addresses too
b = {
  lists: ["ads"],
  rules: [
    { match: "ads.example.com", via: "allow" },
    { match: "example.org", via: "block" },
    { match: "ok.example.org", via: "allow" },
    { match: "10.0.0.0/8", via: "block" },
    { match: "10.9.9.9", via: "allow" },
  ],
};
assert.equal(blocked("x.ads.example.com"), null, "allowed, though a list has it");
assert.equal(blocked("www.example.org"), "rule");
assert.equal(blocked("a.ok.example.org"), null, "the most specific rule wins");
assert.equal(blocked(undefined, "10.1.2.3"), "rule");
assert.equal(blocked("10.1.2.3"), "rule", "an address as the name");
assert.equal(blocked("site.example", "10.1.2.3"), "rule", "a name no rule has: its address's");
assert.equal(blocked(undefined, "10.9.9.9"), null);
assert.equal(blocked(undefined, "11.1.2.3"), null);
assert.equal(blocked("doubleclick.net"), "ads", "the rest still by the lists");

assert.equal(blockerOn({ lists: [] }), false);
assert.equal(blockerOn({ lists: [], rules: [{ match: "x.com", via: "allow" }] }), false, "only allowing: nothing to block");
assert.equal(blockerOn({ lists: [], rules: [{ match: "x.com", via: "block" }] }), true);
assert.equal(blockerOn({ lists: ["ads"] }), true);

// The window's states: blocking (with the names' count) or being got
b = { lists: ["ads", "social"] };
reloadBlockLists();
assert.deepEqual(listState("ads"), { state: "ready", count: 4 });
assert.deepEqual(listState("social"), { state: "getting", count: 0 }, "no file yet");
const small = await write("crypto", "coin.example\n"); // under 4 KB: a pooled Buffer, maybe at an unaligned offset
assert.equal(small.length, 1);
b = { lists: ["crypto"] };
reloadBlockLists();
assert.equal(blocked("www.coin.example"), "crypto", "a small file read back");

// Settings: cleaned as read, Malware and Ads when there's nothing, all off kept
assert.deepEqual(blockerOf(undefined), DEFAULT_BLOCKER);
assert.deepEqual(DEFAULT_BLOCKER, { lists: ["malware", "ads"] });
assert.equal(parseBlocker(undefined), undefined);
assert.equal(parseBlocker("ads"), undefined);
assert.deepEqual(
  parseBlocker({
    lists: ["crypto", "nope", "malware", "malware"],
    youtube: true,
    rules: [
      { match: " Ads.Example.com ", via: "block" },
      { match: "not a site", via: "block" },
      { match: "x.com", via: "maybe" },
      { match: "ads.example.com", via: "allow" },
      "x.com",
    ],
  }),
  { lists: ["malware", "crypto"], youtube: true, rules: [{ match: "ads.example.com", via: "block" }] },
);
assert.deepEqual(parseBlocker({ lists: [] }), { lists: [] }, "all off is kept, not the defaults");
assert.deepEqual(parseSettings(JSON.stringify({ blocker: { lists: ["porn"], youtube: "yes" } })).blocker, { lists: ["porn"] });
assert.equal(parseSettings("{}").blocker, undefined, "none: the defaults, for current users too");

// DNS's answer to a blocked name: its question, no answers, NXDOMAIN
const name = Buffer.concat(["ads", "example", "com"].map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])));
const q = Buffer.concat([Buffer.from([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]), name, Buffer.from([0, 0, 1, 0, 1]), Buffer.alloc(11)]); // an EDNS record after it
const qi = question(q);
const r = nxdomain(q, qi.end);
assert.equal(r.readUInt16BE(0), 0x1234, "its id");
assert.equal(r.readUInt16BE(2), 0x8183, "a response, recursion asked and available, NXDOMAIN");
assert.deepEqual([r.readUInt16BE(4), r.readUInt16BE(6), r.readUInt16BE(8), r.readUInt16BE(10)], [1, 0, 0, 0], "the question alone");
assert.equal(question(r).name, "ads.example.com");
assert.equal(r.length, qi.end);

// The proxy: a blocked site is refused at once, never dialed
let dialed = 0;
const upstream = net.createServer((s) => (dialed++, s.destroy()));
await new Promise((res) => upstream.listen(0, "127.0.0.1", res));
const conn = { server: { hostname: "127.0.0.1", port: upstream.address().port }, currentPass: async () => ({ token: "t", notBefore: 0, expires: 2 ** 31 }) };
const proxy = await startProxy(conn, "127.0.0.1", 0);
const read = (sock) => new Promise((res) => sock.once("data", res));
b = { lists: ["ads"] };
const c = net.connect(proxy.port, "127.0.0.1");
c.write(Buffer.from([5, 1, 0]));
await read(c);
c.write(Buffer.concat([Buffer.from([5, 1, 0, 3, 15]), Buffer.from("doubleclick.net"), Buffer.from([1, 187])]));
const rep = await Promise.race([read(c).then((d) => d[1]), new Promise((res) => c.once("close", () => res("closed")))]);
assert.notEqual(rep, 0, "SOCKS: no success");
c.destroy();
const h = net.connect(proxy.port, "127.0.0.1");
h.write("CONNECT ads.doubleclick.net:443 HTTP/1.1\r\nHost: ads.doubleclick.net:443\r\n\r\n");
assert.match((await read(h)).toString(), /^HTTP\/1\.1 403/, "HTTP: forbidden");
h.destroy();
const g = net.connect(proxy.port, "127.0.0.1");
g.write("GET http://doubleclick.net/ad.js HTTP/1.1\r\nHost: doubleclick.net\r\n\r\n");
assert.match((await read(g)).toString(), /^HTTP\/1\.1 403/, "plain HTTP too");
g.destroy();
await new Promise((res) => setTimeout(res, 200));
assert.equal(dialed, 0, "the VPN was never asked");
await proxy.close();
upstream.close();

console.log("ok - Shield: lists read, names matched with their subdomains, Foxhole's own hosts kept, rules both ways, files read back, settings cleaned, NXDOMAIN, the proxy refusing");
process.exit(0);
