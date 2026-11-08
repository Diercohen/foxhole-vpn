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
import { lookup } from "node:dns/promises";
import { startProxy } from "../dist/proxy.js";
process.env.HOME = process.env.USERPROFILE = mkdtempSync(path.join(os.tmpdir(), "foxhole-home-")); // the data counts (traffic.json) go here, not in ~/.config

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

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
// `silentBefore`: connections made before then never answer (dropped by the network without a word).
function makeUpstream(dropFirst) {
  const state = { connections: 0, sawAuth: false, connectOn: [], silentBefore: 0 };
  const server = tls.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) => {
    s.on("error", () => {}); // a ready connection the proxy closes resets this end
    if (++state.connections <= dropFirst) return s.destroy();
    const madeAt = Date.now();
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      if (madeAt < state.silentBefore) return;
      buf = Buffer.concat([buf, d]);
      const i = buf.indexOf("\r\n\r\n");
      if (i < 0) return;
      s.removeListener("data", onData);
      const head = buf.toString("latin1", 0, i);
      assert.match(head, /^CONNECT 127\.0\.0\.1:\d+ HTTP\/1\.1/, "CONNECT line");
      state.sawAuth = /Proxy-Authorization: Bearer faketoken/.test(head);
      state.connectOn.push(madeAt);
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

async function scenario(name, dropFirst) {
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
  assert.ok(state.connections > dropFirst, `${name}: dialed again past the dropped connections`);
  await handle.close();
  server.close();
  console.log(`ok - ${name}`);
}

// Tunnels after the first open on connections made ahead of time (no TCP and TLS handshakes to wait for); one the
// network dropped without a word is raced by a new connection after a moment.
async function ready() {
  const { server, state } = makeUpstream(0);
  const upstreamPort = await listen(server);
  const conn = {
    server: { hostname: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0);
  await roundTrip(handle.port); // a new connection, and ready ones made meanwhile
  await new Promise((r) => setTimeout(r, 300));
  const made = state.connections;
  assert.ok(made > 1, "ready connections made after the first tunnel");
  let t = Date.now();
  await roundTrip(handle.port);
  assert.ok(state.connectOn.at(-1) < t, "the next tunnel's CONNECT came on a connection made before it was asked for");

  await new Promise((r) => setTimeout(r, 300));
  state.silentBefore = Date.now(); // every ready connection goes quiet
  t = Date.now();
  await roundTrip(handle.port);
  const took = Date.now() - t;
  assert.ok(took >= 1500 && took < 8000, `a silent ready connection gives way to a new one after a moment (${took} ms)`);
  assert.ok(state.connectOn.at(-1) >= state.silentBefore, "that tunnel is on the new connection");
  await handle.close();
  server.close();
  console.log("ok - tunnels open on ready connections; a silent one is raced by a new connection");
}

// HTTP proxy on the same port: CONNECT (https:// sites) and a plain http:// GET.
async function httpScenarios() {
  const { server } = makeUpstream(0);
  const upstreamPort = await listen(server);
  const conn = {
    server: { hostname: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0);

  // CONNECT: 200 Connection Established, then raw bytes round-trip.
  const c = net.connect(handle.port, "127.0.0.1");
  c.on("error", () => {});
  await write(c, `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`);
  const est = (await read(c)).toString();
  assert.match(est, /^HTTP\/1\.1 200 /, "CONNECT answered 200");
  await write(c, "ping over http CONNECT");
  assert.equal((await read(c)).toString(), "ping over http CONNECT", "CONNECT tunnel round-trips");
  c.destroy();

  // Plain GET in absolute form: forwarded as origin-form, proxy headers dropped.
  // The echo target sends back exactly what reached it.
  const g = net.connect(handle.port, "127.0.0.1");
  g.on("error", () => {});
  await write(g, `GET http://127.0.0.1:${targetPort}/path?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n` +
    `Proxy-Authorization: Basic secret\r\nProxy-Connection: keep-alive\r\n\r\n`);
  const got = (await read(g)).toString();
  assert.match(got, /^GET \/path\?x=1 HTTP\/1\.1\r\n/, "origin-form request line");
  assert.match(got, /\r\nHost: 127\.0\.0\.1\r\n/, "other headers kept");
  assert.match(got, /\r\nConnection: close\r\n/, "one request per connection");
  assert.doesNotMatch(got, /Proxy-/i, "proxy headers not forwarded");
  g.destroy();

  // Garbage that is neither SOCKS5 nor a valid HTTP proxy request: 400.
  const b = net.connect(handle.port, "127.0.0.1");
  b.on("error", () => {});
  await write(b, "GET /relative HTTP/1.1\r\n\r\n");
  assert.match((await read(b)).toString(), /^HTTP\/1\.1 400 /, "non-proxy request refused");
  b.destroy();

  // close() must not wait for clients that keep a connection open (browsers do).
  const idle = net.connect(handle.port, "127.0.0.1");
  idle.on("error", () => {});
  await write(idle, `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\n\r\n`);
  await read(idle);
  const t0 = Date.now();
  await handle.close();
  assert.ok(Date.now() - t0 < 1000, "close() returns despite an open client connection");
  server.close();
  console.log("ok - HTTP proxy (CONNECT and plain GET) works on the same port");
}

// Global mode with its bypass route gone sends our own dial to the VPN server back
// through the tun into the proxy. That must be refused, not dialed again (a loop).
async function loopGuard() {
  const { server, state } = makeUpstream(0);
  const upstreamPort = await listen(server);
  const conn = {
    server: { hostname: "localhost", ip: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0);
  const c = net.connect(handle.port, "127.0.0.1");
  c.on("error", () => {});
  await write(c, `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\n\r\n`);
  assert.match((await read(c)).toString(), /^HTTP\/1\.1 502 /, "dial to the VPN server's own IP refused");
  assert.equal(state.connections, 0, "upstream never dialed");
  c.destroy();
  await handle.close();
  server.close();
  console.log("ok - a dial that loops back to the VPN server is refused");
}

// The VPN refuses port 22, so SSH to GitHub must go to ssh.github.com:443 instead.
async function githubSsh() {
  const seen = []; // the CONNECT line of each upstream dial
  const server = tls.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) => {
    s.on("error", () => {});
    s.once("data", (d) => {
      seen.push(d.toString("latin1").split("\r\n")[0]);
      s.end("HTTP/1.1 200 OK\r\n\r\n");
    });
  });
  const upstreamPort = await listen(server);
  const conn = {
    server: { hostname: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0);
  const dialed = async (hostPort) => {
    const c = net.connect(handle.port, "127.0.0.1");
    c.on("error", () => {});
    await write(c, `CONNECT ${hostPort} HTTP/1.1\r\n\r\n`);
    await read(c);
    c.destroy();
    return seen.at(-1);
  };
  assert.equal(await dialed("github.com:22"), "CONNECT ssh.github.com:443 HTTP/1.1", "GitHub SSH moved to 443");
  assert.equal(await dialed("github.com:443"), "CONNECT github.com:443 HTTP/1.1", "GitHub HTTPS untouched");
  assert.equal(await dialed("example.com:22"), "CONNECT example.com:22 HTTP/1.1", "other SSH servers untouched");

  // Global mode: tun2socks sends only the IP that ssh resolved github.com to.
  // real DNS: slow or none here, that case is skipped rather than timing the whole file out
  const ip = await Promise.race([lookup("github.com", { family: 4 }).then((a) => a.address, () => null), new Promise((r) => setTimeout(r, 3000, null))]);
  if (ip) {
    const c = net.connect(handle.port, "127.0.0.1");
    c.on("error", () => {});
    await write(c, Buffer.from([0x05, 0x01, 0x00]));
    await read(c);
    await write(c, Buffer.from([0x05, 0x01, 0x00, 0x01, ...ip.split(".").map(Number), 0, 22]));
    await read(c);
    c.destroy();
    assert.equal(seen.at(-1), "CONNECT ssh.github.com:443 HTTP/1.1", "GitHub SSH by IP moved to 443");
  }
  await handle.close();
  server.close();
  console.log(`ok - SSH to GitHub goes to ssh.github.com:443${ip ? "" : " (IP case skipped: no DNS)"}`);
}

// Quitting closes the proxy while a tunnel may still be opening: that tunnel must close
// too, or it keeps foxhole from exiting until the far end gives up on it.
async function closeMidDial() {
  let upClosed;
  const closed = new Promise((r) => (upClosed = r));
  const server = tls.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) => {
    s.once("data", () => {
      s.once("close", upClosed); // the tunnel's own connection (ready ones close with the proxy too)
      setTimeout(() => s.write("HTTP/1.1 200 OK\r\n\r\n"), 200); // answers after the client left
    });
    s.on("error", () => {});
  });
  const upstreamPort = await listen(server);
  const conn = {
    server: { hostname: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0);
  const c = net.connect(handle.port, "127.0.0.1");
  c.on("error", () => {});
  await write(c, Buffer.from([0x05, 0x01, 0x00]));
  await read(c);
  await write(c, Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, targetPort >> 8, targetPort & 0xff]));
  await new Promise((r) => setTimeout(r, 50)); // the dial is in flight
  await handle.close();
  const ok = await Promise.race([closed.then(() => true), new Promise((r) => setTimeout(r, 3000, false))]);
  assert.ok(ok, "the tunnel closes with the proxy");
  c.destroy();
  server.close();
  console.log("ok - closing the proxy mid-dial closes that tunnel too");
}

// With a login set, a client must sign in: SOCKS5 username/password (RFC 1929) or HTTP Basic.
async function login() {
  const { server } = makeUpstream(0);
  const upstreamPort = await listen(server);
  const conn = {
    server: { hostname: "127.0.0.1", port: upstreamPort },
    async currentPass() {
      return { token: "faketoken", notBefore: 0, expires: 2 ** 31 };
    },
  };
  const handle = await startProxy(conn, "127.0.0.1", 0, () => ({ username: "fox", password: "s3cret" }));
  const socks = async (methods, user, pass) => {
    const c = net.connect(handle.port, "127.0.0.1");
    c.on("error", () => {});
    await write(c, Buffer.from([0x05, methods.length, ...methods]));
    const choice = (await read(c))[1];
    if (choice !== 0x02) return { c, choice };
    const [u, p] = [Buffer.from(user), Buffer.from(pass)];
    await write(c, Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
    return { c, choice, status: (await read(c))[1] };
  };
  let r = await socks([0x00]);
  assert.equal(r.choice, 0xff, "SOCKS5 without a login method: refused");
  r.c.destroy();
  r = await socks([0x00, 0x02], "fox", "wrong");
  assert.equal(r.status, 0x01, "SOCKS5 wrong password: refused");
  r.c.destroy();
  r = await socks([0x00, 0x02], "fox", "s3cret");
  assert.equal(r.status, 0x00, "SOCKS5 right login: accepted");
  await write(r.c, Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, targetPort >> 8, targetPort & 0xff]));
  assert.equal((await read(r.c))[1], 0x00, "then CONNECT works");
  await write(r.c, "ping with a login");
  assert.equal((await read(r.c)).toString(), "ping with a login", "and data round-trips");
  r.c.destroy();

  const http = async (auth) => {
    const c = net.connect(handle.port, "127.0.0.1");
    c.on("error", () => {});
    await write(c, `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\n${auth ? `Proxy-Authorization: Basic ${Buffer.from(auth).toString("base64")}\r\n` : ""}\r\n`);
    const head = (await read(c)).toString();
    c.destroy();
    return head;
  };
  assert.match(await http(), /^HTTP\/1\.1 407 [\s\S]*Proxy-Authenticate: Basic/, "HTTP without a login: 407");
  assert.match(await http("fox:nope"), /^HTTP\/1\.1 407 /, "HTTP wrong password: 407");
  assert.match(await http("fox:s3cret"), /^HTTP\/1\.1 200 /, "HTTP right login: tunnel up");
  await handle.close();
  server.close();
  console.log("ok - a proxy login is asked over SOCKS5 and HTTP");
}

await scenario("SOCKS5 bridge tunnels TCP through an authenticated upstream CONNECT", 0);
await ready();
await login();
await closeMidDial();
await httpScenarios();
await scenario("a dropped upstream connection is retried automatically", 5);
await loopGuard();
await githubSsh();
target.close();
process.exit(0);
