// UDP through the VPN: the wire formats, then SOCKS5 UDP ASSOCIATE end to end against a fake connect-udp server.
// No Firefox, no credentials: a self-signed cert stands in for Fastly's.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

import assert from "node:assert";
import dgram from "node:dgram";
import http2 from "node:http2";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { varint, readVarint, capsule, takeCapsules, parseUdpRequest, udpReply } from "../dist/udp.js";
import { startProxy } from "../dist/proxy.js";
import { useSplit } from "../dist/split.js";
process.env.HOME = process.env.USERPROFILE = mkdtempSync(path.join(os.tmpdir(), "foxhole-home-")); // the data counts (traffic.json) go here, not in ~/.config

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

// ── wire formats
for (const n of [0, 1, 63, 64, 300, 16383, 16384, 70000, 2 ** 30 - 1]) {
  const b = varint(n);
  assert.equal(b.length, n < 64 ? 1 : n < 16384 ? 2 : 4, `varint ${n}: its length`);
  assert.deepEqual(readVarint(Buffer.concat([Buffer.from([9]), b]), 1), [n, 1 + b.length], `varint ${n} round-trips`);
}
assert.equal(readVarint(Buffer.from([0x40]), 0), null, "a cut-off varint: none yet");
assert.deepEqual([...capsule(Buffer.from("hi"))], [0, 3, 0, 0x68, 0x69], "DATAGRAM capsule: type 0, length, context 0, payload");
const two = Buffer.concat([capsule(Buffer.from("one")), Buffer.from([0x21, 2, 7, 7]), capsule(Buffer.alloc(100, 1))]); // with an unknown capsule between
let got = [];
let rest = Buffer.alloc(0);
for (let i = 0; i < two.length; i += 7) {
  // the stream cuts capsules anywhere
  const r = takeCapsules(Buffer.concat([rest, two.subarray(i, i + 7)]));
  got.push(...r.payloads.map((p) => Buffer.from(p)));
  rest = r.rest;
}
assert.deepEqual(got.map((p) => p.length), [3, 100], "payloads come out whole, however the stream's cut; other capsules skipped");
assert.equal(rest.length, 0, "nothing left over");
for (const [host, data] of [["1.2.3.4", "v4"], ["2001:db8:0:0:0:0:0:42", "v6"], ["example.com", "name"]]) {
  const r = parseUdpRequest(udpReply(host, 3478, Buffer.from(data)));
  assert.equal(r.port, 3478, `${host}: port`);
  assert.equal(r.data.toString(), data, `${host}: payload`);
  assert.equal(net.isIPv6(host) ? r.host.replace(/(^|:)0(?=:|$)/g, "$1").replace(/:{3,}/, "::") : r.host, net.isIPv6(host) ? "2001:db8::42" : host, `${host}: address`);
}
assert.deepEqual([...udpReply("::1", 1, Buffer.alloc(0)).subarray(4, 20)], [...Array(15).fill(0), 1], "a short IPv6 address is written out whole");
assert.equal(parseUdpRequest(Buffer.from([0, 0, 1, 1, 1, 2, 3, 4, 0, 53, 9])), null, "a fragment is refused");
console.log("ok - UDP wire formats: varints, DATAGRAM capsules, SOCKS5 UDP headers");

// ── end to end
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-udp-"));
const key = path.join(dir, "k.pem");
const cert = path.join(dir, "c.pem");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });

// Fake Fastly: connect-udp to port 53 is refused as Fastly does; any other port echoes each datagram back.
const opened = [];
const server = http2.createSecureServer({ key: readFileSync(key), cert: readFileSync(cert), settings: { enableConnectProtocol: true } });
server.on("stream", (stream, h) => {
  stream.on("error", () => {});
  const m = /^\/\.well-known\/masque\/udp\/([^/]+)\/(\d+)\/$/.exec(h[":path"] ?? "");
  if (h[":method"] !== "CONNECT" || h[":protocol"] !== "connect-udp" || !m) return stream.respond({ ":status": 400 }, { endStream: true });
  opened.push({ host: decodeURIComponent(m[1]), port: Number(m[2]), auth: h["proxy-authorization"] });
  if (m[2] === "53") {
    stream.respond({ ":status": 502, "proxy-status": "Fastly; error=destination_ip_prohibited" });
    return stream.end("Destination IP Prohibited");
  }
  stream.respond({ ":status": 200, "capsule-protocol": "?1" });
  let buf = Buffer.alloc(0);
  stream.on("data", (d) => {
    const r = takeCapsules(Buffer.concat([buf, d]));
    buf = Buffer.from(r.rest);
    for (const p of r.payloads) stream.write(capsule(Buffer.concat([Buffer.from("echo:"), p])));
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const conn = {
  server: { hostname: "localhost", ip: "127.0.0.1", port: server.address().port },
  async currentPass() {
    return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
  },
};
const proxy = await startProxy(conn, "127.0.0.1", 0);

// A plain UDP echo server for the direct rule
const echo = dgram.createSocket("udp4");
echo.on("message", (m, r) => echo.send(Buffer.concat([Buffer.from("direct:"), m]), r.port, r.address));
await new Promise((r) => echo.bind(0, "127.0.0.1", r));

const read = (s) => new Promise((r) => s.once("data", r));
const ctl = net.connect(proxy.port, "127.0.0.1");
ctl.on("error", () => {});
await new Promise((r) => ctl.once("connect", r));
ctl.write(Buffer.from([5, 1, 0]));
assert.deepEqual([...(await read(ctl))], [5, 0], "no login asked");
ctl.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0])); // UDP ASSOCIATE, from anywhere
const rep = await read(ctl);
assert.equal(rep[1], 0, "UDP ASSOCIATE accepted");
const relayAt = { address: [...rep.subarray(4, 8)].join("."), port: rep.readUInt16BE(8) };
assert.equal(relayAt.address, "127.0.0.1", "the relay is on the address the client reached");

const app = dgram.createSocket("udp4");
await new Promise((r) => app.bind(0, "127.0.0.1", r));
const replies = [];
app.on("message", (m) => replies.push(parseUdpRequest(m)));
const send = (host, port, text) => app.send(udpReply(host, port, Buffer.from(text)), relayAt.port, relayAt.address);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 3000) => {
  for (const end = Date.now() + ms; !f() && Date.now() < end; ) await wait(20);
  return f();
};

send("1.2.3.4", 3478, "stun");
send("1.2.3.4", 3478, "again"); // while the stream opens: queued, not lost
assert.ok(await until(() => replies.length >= 2), "answers come back through the VPN");
assert.deepEqual(replies.map((r) => [r.host, r.port, r.data.toString()]), [["1.2.3.4", 3478, "echo:stun"], ["1.2.3.4", 3478, "echo:again"]], "from the address and port asked, in order");
assert.equal(opened.filter((o) => o.port === 3478).length, 1, "one stream per destination");
assert.equal(opened[0].auth, "Bearer faketoken", "the proxy pass goes with it");

send("1.2.3.4", 443, "quic");
send("1.2.3.4", 53, "dns");
await wait(300);
send("1.2.3.4", 53, "dns again");
await wait(300);
assert.ok(!opened.some((o) => o.port === 443), "QUIC isn't sent to the VPN");
assert.equal(opened.filter((o) => o.port === 53).length, 1, "a port the VPN refused isn't asked about again");
assert.equal(replies.length, 2, "and nothing comes back for either");

useSplit(() => ({ default: "vpn", rules: [{ match: "127.0.0.1", via: "direct" }] }));
send("127.0.0.1", echo.address().port, "local");
assert.ok(await until(() => replies.length === 3), "a direct site's datagram goes straight there");
assert.deepEqual([replies[2].host, replies[2].port, replies[2].data.toString()], ["127.0.0.1", echo.address().port, "direct:local"], "and its answer comes back from it");

ctl.destroy(); // the association ends with its connection
await wait(100);
send("1.2.3.4", 3478, "after");
await wait(300);
assert.equal(replies.length, 3, "nothing is relayed once the association's connection closed");

// The relay carries only the web: there, UDP ASSOCIATE is refused (the app falls back, as before UDP was carried)
const relayProxy = await startProxy({ ...conn, relay: { deploymentId: "x", authKey: "y" } }, "127.0.0.1", 0);
const c2 = net.connect(relayProxy.port, "127.0.0.1");
c2.on("error", () => {});
await new Promise((r) => c2.once("connect", r));
c2.write(Buffer.from([5, 1, 0]));
await read(c2);
c2.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
assert.equal((await read(c2))[1], 7, "relay mode: UDP ASSOCIATE not supported");
c2.destroy();

app.close();
echo.close();
await proxy.close();
await relayProxy.close();
server.close();
console.log("ok - UDP through the VPN: SOCKS5 UDP ASSOCIATE to connect-udp, QUIC and refused ports dropped, direct rules, relay mode refused");
process.exit(0);
