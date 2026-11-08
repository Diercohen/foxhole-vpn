// Smart DNS: the queries and answers (pure), then the server: a fake network DNS (which answers a blocked name with the
// filter's address) and a fake VPN server, both local, in a throwaway HOME with a fresh sanctioned list.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert for the fake VPN server

import assert from "node:assert";
import dgram from "node:dgram";
import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";

const home = mkdtempSync(path.join(os.tmpdir(), "foxhole-home-"));
process.env.HOME = process.env.USERPROFILE = home;
const lists = path.join(home, ".config", "foxhole-vpn", "lists");
mkdirSync(lists, { recursive: true });
for (const [f, text] of [["iran-domains.txt", "digikala.com\n"], ["iran-ips.txt", "5.22.0.0/17\n"], ["sanctioned.txt", "sanctioned.example\n"]]) writeFileSync(path.join(lists, f), text); // fresh: nothing downloaded

const { questionOf, answerWith, filterAnswer, homeAddress, startSmartDns } = await import("../dist/smartdns.js");
const { useSplit } = await import("../dist/split.js");
const { filteredByName } = await import("../dist/proxy.js");
const { knownBlocked } = await import("../dist/smart.js");

/** A query for `name` of `type` (1 A, 28 AAAA), asking for recursion, with an EDNS record as browsers send. */
function query(name, type = 1, id = 0x1234) {
  const q = Buffer.concat([...name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0, type >> 8, type & 255, 0, 1])]);
  const head = Buffer.from([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
  return Buffer.concat([head, q, Buffer.from([0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0])]);
}
/** The network DNS's answer to `q`: a CNAME (compressed), then `ip` (A, or AAAA when it has colons). */
function answer(q, ip) {
  const { end } = questionOf(q);
  const head = Buffer.from(q.subarray(0, end));
  head.writeUInt16BE(0x8180, 2);
  head.writeUInt16BE(2, 6);
  head.writeUInt32BE(0, 8);
  const cname = Buffer.from([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, 0x63, 0xc0, 12]); // c.<name>
  const v6 = ip.includes(":");
  const data = v6 ? Buffer.from(ip.split(":").flatMap((g) => [parseInt(g, 16) >> 8, parseInt(g, 16) & 255])) : Buffer.from(ip.split(".").map(Number));
  const rr = Buffer.concat([Buffer.from([0xc0, 12, 0, v6 ? 28 : 1, 0, 1, 0, 0, 0, 60, 0, data.length]), data]);
  return Buffer.concat([head, cname, rr]);
}
const ipOf = (r) => (r.readUInt16BE(6) ? [...r.subarray(-4)].join(".") : null);

// ── the packets
const q = query("WWW.Example.com");
assert.deepEqual(questionOf(q), { name: "www.example.com", type: 1, end: 12 + 17 + 4 });
assert.equal(questionOf(Buffer.from(q).fill(0x80, 2, 3)), null, "a response isn't a question");
assert.equal(questionOf(q.subarray(0, 20)), null, "nor is a cut-off one");
const a = answerWith(q, questionOf(q).end, 1, "192.168.1.5");
assert.equal(a.readUInt16BE(0), 0x1234, "its id");
assert.equal(a.readUInt16BE(2), 0x8180, "a response, recursion asked and available");
assert.deepEqual([a.readUInt16BE(6), a.readUInt16BE(10)], [1, 0], "one answer, the query's EDNS dropped");
assert.equal(ipOf(a), "192.168.1.5");
const six = query("www.example.com", 28);
assert.equal(answerWith(six, questionOf(six).end, 28, "192.168.1.5").readUInt16BE(6), 0, "AAAA: none, so the device uses this one");
assert.ok(filterAnswer(answer(q, "10.10.34.36")), "the filter's address, past a CNAME");
assert.ok(filterAnswer(answer(six, "2001:4188:2:600:10:10:34:36")), "and its IPv6 one");
assert.ok(!filterAnswer(answer(q, "93.184.216.34")) && !filterAnswer(q.subarray(0, 14)), "a real answer, a cut-off one");
assert.ok(homeAddress("192.168.0.5") && homeAddress("::ffff:10.1.2.3") && homeAddress("fe80::1") && homeAddress("100.64.0.9") && homeAddress("127.0.0.1"));
assert.ok(!homeAddress("8.8.8.8") && !homeAddress("100.128.0.1") && !homeAddress("2001:db8::1") && !homeAddress(undefined), "the internet's aren't served");
console.log("ok - smart DNS packets: the question, this computer's answer, the filter's answers found");

// ── the server
const net53 = dgram.createSocket("udp4"); // the network's own DNS
const asked = [];
net53.on("message", (m, from) => {
  const { name } = questionOf(m);
  asked.push(name);
  net53.send(answer(m, name === "filtered.example" ? "10.10.34.36" : "93.184.216.34"), from.port, from.address);
});
await new Promise((res) => net53.bind(0, "127.0.0.1", res));
dns.setServers([`127.0.0.1:${net53.address().port}`]);

const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-dns-cert-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });
const tunnels = []; // the VPN server's CONNECT requests
const vpn = tls.createServer({ key: readFileSync(path.join(dir, "k.pem")), cert: readFileSync(path.join(dir, "c.pem")) }, (sock) => {
  sock.on("error", () => {});
  sock.once("data", (d) => {
    tunnels.push(d.toString().split(" ")[1]);
    sock.write("HTTP/1.1 200 OK\r\n\r\n");
    sock.once("data", (hello) => sock.end(`vpn:${hello.toString("latin1").split("\r\n")[0]}`));
  });
});
await new Promise((res) => vpn.listen(0, "127.0.0.1", res));
const conn = { server: { hostname: "127.0.0.1", port: vpn.address().port }, relay: null, currentPass: async () => ({ token: "t", notBefore: 0, expires: 2 ** 31 }) };
let connected = true;
let rules = { default: "vpn", rules: [{ match: "ruled.example", via: "vpn" }, { match: "mine.sanctioned.example", via: "direct" }] };
useSplit(() => rules);
// the sites' port 443, as the filter leaves it: the handshake of a name it stops gets silence
const certs = { key: readFileSync(path.join(dir, "k.pem")), cert: readFileSync(path.join(dir, "c.pem")) };
const sites = tls.createServer({ ...certs, SNICallback: (name, cb) => name !== "cdn.stopped.example" && cb(null, tls.createSecureContext(certs)) }, (s) => s.on("error", () => {}).end());
sites.on("tlsClientError", () => {});
await new Promise((res) => sites.listen(0, "127.0.0.1", res));
const sitesAt = { host: "127.0.0.1", port: sites.address().port };
const srv = await startSmartDns(conn, { host: "127.0.0.1", self: () => "192.168.9.9", vpn: () => connected, ports: { dns: 0, https: 0, http: 0, chat: 0 }, sites: sitesAt });

/** Asks the smart DNS: its answer's address, null for none. */
async function ask(name, type = 1) {
  const c = dgram.createSocket("udp4");
  const got = new Promise((res) => c.once("message", res));
  c.send(query(name, type, Math.floor(Math.random() * 65535)), srv.ports.dns, "127.0.0.1");
  const r = await got;
  c.close();
  return type === 1 ? ipOf(r) : r.readUInt16BE(6);
}
assert.equal(await ask("plain.example"), "93.184.216.34", "a site that needs no VPN: the network's own answer");
assert.equal(await ask("www.sanctioned.example"), "192.168.9.9", "a sanctioned one: this computer");
assert.ok(!asked.includes("www.sanctioned.example"), "without asking the network");
assert.equal(await ask("www.sanctioned.example", 28), 0, "and no IPv6 address, so the device comes here");
assert.equal(await ask("filtered.example"), "192.168.9.9", "a name the network answers with the filter's address: this computer");
assert.ok(knownBlocked("filtered.example"), "learned as blocked");
assert.equal(await ask("ruled.example"), "192.168.9.9", "a site the rules send through the VPN");
assert.equal(await ask("cdn.stopped.example"), "192.168.9.9", "a name with a real DNS answer whose handshake the filter stops: this computer");
assert.ok(knownBlocked("other.stopped.example"), "its whole site learned as blocked");
assert.equal(await ask("cdn.stopped.example", 28), 0, "and no IPv6 address");
assert.equal(await filteredByName("x.example", { host: "127.0.0.1", port: 1 }), false, "nothing listening (a game's server): says nothing");
const resets = net.createServer((s) => s.once("data", () => s.resetAndDestroy()));
await new Promise((res) => resets.listen(0, "127.0.0.1", res));
assert.equal(await filteredByName("x.example", { host: "127.0.0.1", port: resets.address().port }), true, "a hello that's reset: the filter's");
resets.close();
assert.equal(await ask("mine.sanctioned.example"), "93.184.216.34", "one they send direct, sanctioned or not");
connected = false;
assert.equal(await ask("www.sanctioned.example"), "93.184.216.34", "not connected: the network's answers, so the rest still works");
connected = true;

// the web, by the name in its first bytes, through the VPN
const http = net.connect(srv.ports.http, "127.0.0.1");
http.write("GET /watch HTTP/1.1\r\nHost: www.sanctioned.example\r\n\r\n");
let got = "";
http.on("data", (d) => (got += d));
await new Promise((res) => http.once("close", res));
assert.equal(got, "vpn:GET /watch HTTP/1.1", "plain HTTP: the request, through the VPN");
const t = tls.connect({ port: srv.ports.https, host: "127.0.0.1", servername: "video.sanctioned.example" });
t.on("error", () => {});
await new Promise((res) => t.once("close", res));
assert.deepEqual(tunnels, ["www.sanctioned.example:80", "video.sanctioned.example:443"], "HTTPS by its SNI, to the site's own port");


// WhatsApp's chat names no site: by its header, on 5222 or 443, through the VPN to its server's 443
tunnels.length = 0;
for (const [at, hello] of [[srv.ports.chat, "WA\x06\x03rest"], [srv.ports.https, "ED\x00\x01rest"]]) {
  const c = net.connect(at, "127.0.0.1");
  c.write(Buffer.from(hello, "latin1"));
  let back = "";
  const began = Date.now();
  c.on("data", (d) => (back += d.toString("latin1")));
  await new Promise((res) => c.once("close", res));
  assert.equal(back, `vpn:${hello}`, "its first bytes, through the VPN");
  assert.ok(Date.now() - began < 1500, "without waiting for an HTTP head");
}
assert.deepEqual(tunnels, ["g.whatsapp.net:443", "g.whatsapp.net:443"]);
const other = net.connect(srv.ports.chat, "127.0.0.1");
other.write("<stream:stream>");
other.on("error", () => {});
await new Promise((res) => other.once("close", res));
assert.deepEqual(tunnels, ["g.whatsapp.net:443", "g.whatsapp.net:443"], "anything else on 5222 goes nowhere");

srv.close();
sites.close();
net53.close();
vpn.close();
console.log("ok - smart DNS: blocked and sanctioned sites answered with this computer and carried through the VPN; the rest, and all when off, the network's");
process.exit(0);
