// Checks the DoH-over-SOCKS forwarder: a DNS query in (UDP and TCP) comes back
// as the DoH server's answer, carried through a fake SOCKS proxy. No real tunnel.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert

import net from "node:net";
import tls from "node:tls";
import dgram from "node:dgram";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { startDnsForwarder } from "../dist/dns.js";

setTimeout(() => {
  console.error("FAIL - timed out");
  process.exit(1);
}, 15000).unref();

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const ANSWER = Buffer.from([0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]); // arbitrary DNS-ish bytes

const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-vpn-dns-"));
const key = path.join(dir, "k.pem");
const cert = path.join(dir, "c.pem");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=cloudflare-dns.com"], { stdio: "ignore" });

// Fake DoH server: for each POST (keep-alive), reply 200 with ANSWER.
let dohRequests = 0;
const doh = tls.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) => {
  let buf = Buffer.alloc(0);
  s.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      const i = buf.indexOf("\r\n\r\n");
      if (i < 0) return;
      const len = Number(buf.toString("latin1", 0, i).match(/content-length:\s*(\d+)/i)[1]);
      if (buf.length < i + 4 + len) return;
      buf = buf.subarray(i + 4 + len);
      dohRequests++;
      s.write(
        `HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: ${ANSWER.length}\r\nConnection: keep-alive\r\n\r\n`,
      );
      s.write(ANSWER);
    }
  });
});
const dohPort = await listen(doh);

// Fake SOCKS5 proxy: no-auth, CONNECT (any addr) -> the fake DoH server.
const socks = net.createServer((c) => {
  let stage = 0;
  const onData = (d) => {
    if (stage === 0) {
      c.write(Buffer.from([0x05, 0x00]));
      stage = 1;
    } else {
      assert.equal(d[3], 0x03, "forwarder used a DOMAIN address (server-side resolve)");
      c.removeListener("data", onData); // hand the socket to the pipe
      c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      const up = net.connect(dohPort, "127.0.0.1", () => {
        c.pipe(up);
        up.pipe(c);
      });
      up.on("error", () => c.destroy());
    }
  };
  c.on("data", onData);
  c.on("error", () => c.destroy());
});
const socksPort = await listen(socks);

const fwd = await startDnsForwarder({
  socksHost: "127.0.0.1",
  socksPort,
  dohHost: "cloudflare-dns.com",
  host: "127.0.0.1",
  port: 0,
});
// port:0 picked an ephemeral port; read it back from the underlying sockets is
// awkward, so bind explicitly on a high port instead.
await fwd.close();

const PORT = 15353;
const f = await startDnsForwarder({ socksHost: "127.0.0.1", socksPort, dohHost: "cloudflare-dns.com", host: "127.0.0.1", port: PORT });

// UDP query -> answer.
const QUERY = Buffer.from([0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
const udpAns = await new Promise((resolve, reject) => {
  const c = dgram.createSocket("udp4");
  c.on("message", (m) => {
    c.close();
    resolve(m);
  });
  c.on("error", reject);
  c.send(QUERY, PORT, "127.0.0.1");
});
assert.deepEqual(udpAns, ANSWER, "UDP query returns the DoH answer");

// TCP query (2-byte length prefix) -> length-prefixed answer.
const tcpAns = await new Promise((resolve, reject) => {
  const c = net.connect(PORT, "127.0.0.1", () => {
    const framed = Buffer.alloc(2 + QUERY.length);
    framed.writeUInt16BE(QUERY.length, 0);
    QUERY.copy(framed, 2);
    c.write(framed);
  });
  let buf = Buffer.alloc(0);
  c.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    if (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
      c.destroy();
      resolve(buf.subarray(2, 2 + buf.readUInt16BE(0)));
    }
  });
  c.on("error", reject);
});
assert.deepEqual(tcpAns, ANSWER, "TCP query returns the DoH answer");
assert.ok(dohRequests >= 2, "DoH server was reached for both queries");

await f.close();
socks.close();
doh.close();
console.log("ok - DoH-over-SOCKS forwarder resolves UDP and TCP queries through the tunnel");
process.exit(0);
