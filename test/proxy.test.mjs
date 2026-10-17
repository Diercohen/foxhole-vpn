// End-to-end check of the SOCKS5 -> upstream-CONNECT bridge, with fake servers.
// No Firefox, no credentials: a self-signed cert stands in for the Fastly proxy.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert

import net from "node:net";
import tls from "node:tls";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { startProxy } from "../dist/proxy.js";

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 15000).unref();

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const read = (sock) => new Promise((r) => sock.once("data", r));
const write = (sock, buf) => new Promise((r) => sock.write(buf, r));

// Self-signed cert for the fake upstream.
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-vpn-"));
const key = path.join(dir, "k.pem");
const cert = path.join(dir, "c.pem");
execFileSync("openssl", [
  "req", "-x509", "-newkey", "rsa:2048", "-nodes",
  "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
], { stdio: "ignore" });

// Fake target: echoes whatever it receives.
const target = net.createServer((s) => s.pipe(s));
const targetPort = await listen(target);

// Fake upstream: drops the first `dropFirst` connections (a flaky network), then
// accepts CONNECT with a Bearer pass and tunnels to the target.
function makeUpstream(dropFirst) {
  const state = { connections: 0, sawAuth: false };
  const server = tls.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) => {
    if (++state.connections <= dropFirst) return s.destroy();
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      const i = buf.indexOf("\r\n\r\n");
      if (i < 0) return;
      s.removeListener("data", onData);
      const head = buf.toString("latin1", 0, i);
      assert.match(head, /^CONNECT 127\.0\.0\.1:\d+ HTTP\/1\.1/, "CONNECT line");
      state.sawAuth = /Proxy-Authorization: Bearer faketoken/.test(head);
      const tport = Number(head.match(/^CONNECT 127\.0\.0\.1:(\d+)/)[1]);
      const t = net.connect(tport, "127.0.0.1", () => {
        s.write("HTTP/1.1 200 OK\r\n\r\n");
        const rest = buf.subarray(i + 4);
        if (rest.length) t.write(rest);
        s.pipe(t);
        t.pipe(s);
      });
    };
    s.on("data", onData);
  });
  return { server, state };
}

// One SOCKS5 CONNECT through the proxy, then an echo round-trip.
async function roundTrip(proxyPort) {
  const c = net.connect(proxyPort, "127.0.0.1");
  c.on("error", () => {});
  await write(c, Buffer.from([0x05, 0x01, 0x00]));
  const greet = await read(c);
  assert.deepEqual([greet[0], greet[1]], [0x05, 0x00], "SOCKS5 no-auth reply");
  await write(c, Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, targetPort >> 8, targetPort & 0xff]));
  const rep = await read(c);
  assert.equal(rep[0], 0x05, "SOCKS5 reply version");
  assert.equal(rep[1], 0x00, "SOCKS5 CONNECT succeeded");
  await write(c, Buffer.from("ping foxhole-vpn"));
  const echo = await read(c);
  assert.equal(echo.toString(), "ping foxhole-vpn", "data round-trips through the tunnel");
  c.destroy();
}

async function scenario(name, dropFirst, expectedAttempts) {
  const { server, state } = makeUpstream(dropFirst);
  const upstreamPort = await listen(server);
  // Minimal Connection stand-in (duck-typed to what proxy.ts uses).
  const conn = {
    server: { hostname: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0);
  await roundTrip(handle.port);
  assert.ok(state.sawAuth, "upstream received the Bearer proxy pass");
  assert.equal(state.connections, expectedAttempts, `${name}: upstream attempts`);
  await handle.close();
  server.close();
  console.log(`ok - ${name}`);
}

await scenario("SOCKS5 bridge tunnels TCP through an authenticated upstream CONNECT", 0, 1);
await scenario("a dropped upstream connection is retried automatically", 1, 2);
target.close();
process.exit(0);
