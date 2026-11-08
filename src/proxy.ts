import net from "node:net";
import tls from "node:tls";
import { createHash, timingSafeEqual } from "node:crypto";
import { lookup } from "node:dns/promises";
import type { Connection } from "./connection.js";
import { red, verbose } from "./ui.js";
import { log } from "./log.js";
import { route, splitOn, appsOn, probeOn, type Via } from "./split.js";
import { track, save as saveTraffic } from "./traffic.js";
import { filterAddress, learnBlocked, listsVia, refreshLists, type Try } from "./smart.js";
import { appFor } from "./apps.js";
import { answers } from "./restore.js";
import { nameOf, DOH_HOST } from "./dns.js";
import { IP_HOST, TRACE_HOST } from "./netinfo.js";
import { relayServe, fakeName, realIp, setDirectTo, setDirectDial } from "./relaymode.js";
import { udpAssociate, closeUdp } from "./udp.js";

// Throttled stderr: a browser opens many connections, so don't repeat the same
// failure more than once every few seconds.
let lastWarn = "";
let lastWarnAt = 0;
let sink = (msg: string) => console.error(red(`proxy: ${msg}`));

/** Sends proxy warnings elsewhere; the TUI shows them in its status row, since writing to the terminal would scroll its screen. */
export function onProxyWarning(fn: (msg: string) => void): void {
  sink = fn;
}
function warn(msg: string): void {
  log(`proxy: ${msg}`); // always: the TUI's Logs popup shows these
  if (!verbose) return; // e.g. "Destination IP Prohibited" for a blocked port: noise in normal use
  const now = Date.now();
  if (msg === lastWarn && now - lastWarnAt < 5000) return;
  lastWarn = msg;
  lastWarnAt = now;
  sink(msg);
}

const UPSTREAM_ATTEMPTS = 3;
const UPSTREAM_TIMEOUT_MS = 15_000;

/** The upstream answered CONNECT with a non-200 status. */
class UpstreamStatusError extends Error {
  constructor(
    readonly status: number,
    statusLine: string,
    // Fastly's Proxy-Status says the VPN refuses this port (SSH, mail): asking again won't change it
    readonly prohibited = false,
  ) {
    super(prohibited ? `${statusLine} (the VPN refuses this port)` : statusLine);
  }
}

/** Readable reason, including the per-address causes inside an AggregateError. */
function describe(err: unknown): string {
  if (err instanceof AggregateError) {
    const causes = err.errors.map((e: { code?: string; message?: string }) => e.code ?? e.message);
    return causes.join("/") || "connection failed";
  }
  const e = err as { message?: string; code?: string } | undefined;
  return e?.message || e?.code || String(err);
}

// Local proxy on one port that speaks both SOCKS5 and HTTP, told apart by the
// first byte (SOCKS5 always opens with 0x05; HTTP opens with a method name).
// TCP is tunnelled by HTTP CONNECT, each client connection to the chosen Fastly server over TLS with the current
// proxy pass; SOCKS5's UDP ASSOCIATE by connect-udp (udp.ts).

const SOCKS_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const CMD_UDP = 0x03;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;

interface Target {
  host: string;
  port: number;
  udp?: boolean; // a SOCKS5 UDP ASSOCIATE: host and port are where the client sends from (or zeros)
}

/** The next chunk a client sends. */
function nextChunk(socket: net.Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    socket.once("data", resolve);
    socket.once("error", reject);
  });
}

function readRequest(socket: net.Socket): Promise<Target> {
  return new Promise((resolve, reject) => {
    socket.once("data", (buf) => {
      if (buf[0] !== SOCKS_VERSION || (buf[1] !== CMD_CONNECT && buf[1] !== CMD_UDP)) {
        // 0x07 = command not supported.
        socket.write(Buffer.from([SOCKS_VERSION, 0x07, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]));
        return reject(new Error("Only CONNECT and UDP ASSOCIATE are supported"));
      }
      const atyp = buf[3];
      let host: string;
      let offset: number;
      if (atyp === ATYP_IPV4) {
        host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
        offset = 8;
      } else if (atyp === ATYP_DOMAIN) {
        const len = buf[4];
        host = buf.toString("utf8", 5, 5 + len);
        offset = 5 + len;
      } else if (atyp === ATYP_IPV6) {
        const parts: string[] = [];
        for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(4 + i).toString(16));
        host = parts.join(":");
        offset = 20;
      } else {
        socket.write(Buffer.from([SOCKS_VERSION, 0x08, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]));
        return reject(new Error("Unknown address type"));
      }
      const port = buf.readUInt16BE(offset);
      resolve({ host, port, ...(buf[1] === CMD_UDP && { udp: true }) });
    });
    socket.once("error", reject);
  });
}

function replySuccess(socket: net.Socket): void {
  // BND.ADDR/PORT are ignored by clients for CONNECT; send zeros.
  socket.write(Buffer.from([SOCKS_VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]));
}

function replyFailure(socket: net.Socket): void {
  socket.write(Buffer.from([SOCKS_VERSION, 0x01, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]));
}

interface Upstream {
  hostname: string;
  port: number;
  ip?: string;
}

/** A new TLS connection to the VPN server: its pinned IP in global mode, else looked up; SNI and certificate by name. */
function connectTls(server: Upstream): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const fail = (err: Error) => {
      clearTimeout(timer);
      up.destroy();
      reject(err);
    };
    const timer = setTimeout(() => fail(new Error("timed out")), UPSTREAM_TIMEOUT_MS);
    const up = tls.connect({ host: server.ip ?? server.hostname, port: server.port, servername: server.hostname, ALPNProtocols: ["http/1.1"] }, () => {
      clearTimeout(timer);
      up.removeListener("error", fail);
      resolve(up);
    });
    up.once("error", fail);
  });
}

/** Issues HTTP CONNECT for `target` with the proxy pass on the TLS connection `up`, which is the tunnel once it's up. */
function connectThrough(up: tls.TLSSocket, passToken: string, target: Target): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      up.destroy();
      reject(err);
    };
    const timer = setTimeout(() => fail(new Error("timed out")), UPSTREAM_TIMEOUT_MS);
    let header = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      header = Buffer.concat([header, chunk]);
      const end = header.indexOf("\r\n\r\n");
      if (end === -1) {
        if (header.length > 64 * 1024) fail(new Error("oversized CONNECT response"));
        return;
      }
      up.removeListener("data", onData);
      const head = header.toString("latin1", 0, end);
      const statusLine = head.split("\r\n", 1)[0].trim();
      const code = Number(statusLine.split(" ")[1]);
      if (code !== 200) {
        fail(new UpstreamStatusError(code, statusLine, /^proxy-status:.*destination_ip_prohibited/im.test(head)));
        return;
      }
      settled = true;
      clearTimeout(timer);
      // Hand over any bytes that arrived after the header.
      const leftover = header.subarray(end + 4);
      resolve(up);
      if (leftover.length) up.emit("data", leftover);
    };
    up.on("data", onData);
    up.once("error", fail);
    up.once("close", () => fail(new Error("upstream closed the connection")));
    const hostHeader = target.host.includes(":") ? `[${target.host}]` : target.host;
    up.write(`CONNECT ${hostHeader}:${target.port} HTTP/1.1\r\nHost: ${hostHeader}:${target.port}\r\nProxy-Authorization: Bearer ${passToken}\r\n\r\n`);
  });
}

// ── Ready connections. A tunnel's CONNECT needs a TCP and a TLS handshake with the VPN server first: three round trips
// in all, ~800 ms from Iran (measured 2026-11). A few connections are made ahead of time, so a tunnel costs only its
// CONNECT's round trip (~230 ms). Fastly keeps an idle one open for minutes (150 s seen); each is closed after
// WARM_IDLE_MS unused, and only opening tunnels makes more, so an idle proxy keeps none. HTTP/2 would reuse one
// connection as well, but Fastly's 64 KB flow-control window holds an upload there to ~1 Mbit/s.
const WARM = 4;
const WARM_IDLE_MS = 100_000;
// A ready connection the network dropped without a word (a switch of Wi-Fi) never answers: after this, a new one races it
const WARM_GRACE_MS = 2000;

const warm = new Set<tls.TLSSocket>();
let warmFor = ""; // the server they're to: one at a time, the one in use
let warming = 0;
const serverKey = (s: Upstream) => `${s.hostname} ${s.ip ?? ""} ${s.port}`;

/** Makes ready connections to `server` up to WARM, closing those to another. */
function topUp(server: Upstream): void {
  const key = serverKey(server);
  if (key !== warmFor) closeWarm(key);
  for (let n = warm.size + warming; n < WARM; n++) {
    warming++;
    connectTls(server)
      .then((up) => {
        if (key !== warmFor) return void up.destroy();
        warm.add(up);
        up.on("error", () => {}); // a reset while it waits: its "close" takes it off the list
        up.once("close", () => warm.delete(up));
        up.setTimeout(WARM_IDLE_MS, () => up.destroy());
      }, () => {}) // unreachable: the tunnel that needs one says so
      .finally(() => warming--);
  }
}

/** Closes the ready connections; `next`: the server the next ones are to, if any. */
function closeWarm(next = ""): void {
  for (const up of warm) up.destroy();
  warm.clear();
  warmFor = next;
}

/** A ready connection to `server`, if one's waiting; either way, another one is made. */
function takeWarm(server: Upstream): tls.TLSSocket | null {
  let up: tls.TLSSocket | null = null;
  if (serverKey(server) === warmFor) {
    for (const s of warm) {
      warm.delete(s);
      if (!s.destroyed) {
        up = s;
        break;
      }
    }
  }
  topUp(server);
  up?.setTimeout(0);
  return up;
}

/** Opens a tunnel to `target` through the upstream: on a ready connection, if one's waiting, else on a new one. */
function openUpstream(server: Upstream, passToken: string, target: Target): Promise<tls.TLSSocket> {
  const fresh = () => connectTls(server).then((up) => connectThrough(up, passToken, target));
  const ready = takeWarm(server);
  if (!ready) return fresh();
  return new Promise((resolve, reject) => {
    let done = false;
    let racing = false;
    const win = (up: tls.TLSSocket) => {
      if (done) return void up.destroy(); // the race's loser
      done = true;
      clearTimeout(timer);
      resolve(up);
    };
    const lose = (err: unknown) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(err);
    };
    const race = () => {
      if (racing) return;
      racing = true;
      clearTimeout(timer);
      fresh().then(win, lose);
    };
    const timer = setTimeout(race, WARM_GRACE_MS);
    // The server's own answer stands; a ready connection that turns out dead gives way to a new one at once.
    connectThrough(ready, passToken, target).then(win, (err) => (err instanceof UpstreamStatusError ? lose(err) : race()));
  });
}

/** Opens the upstream, retrying transient failures (not proxy rejections). */
async function openUpstreamWithRetry(
  server: Upstream,
  passToken: string,
  target: Target,
): Promise<tls.TLSSocket> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= UPSTREAM_ATTEMPTS; attempt++) {
    try {
      return await openUpstream(server, passToken, target);
    } catch (err) {
      lastErr = err;
      // A 4xx (bad pass, refused target) or a refused port won't change on retry.
      if (err instanceof UpstreamStatusError && (err.status < 500 || err.prohibited)) break;
      if (attempt < UPSTREAM_ATTEMPTS) await new Promise((r) => setTimeout(r, 250 * attempt));
    }
  }
  throw lastErr;
}

// The VPN refuses port 22, but GitHub serves the same SSH, with the same host key
// (so ssh doesn't notice the switch), on ssh.github.com:443.
const GITHUB_SSH: Target = { host: "ssh.github.com", port: 443 };

/** True for SSH to github.com. tun2socks (global mode) gives only the IP, so match it against github.com's addresses: the lookup ssh itself just made. */
async function isGithubSsh(target: Target): Promise<boolean> {
  if (target.port !== 22) return false;
  if (!net.isIP(target.host)) return target.host.toLowerCase() === "github.com";
  try {
    return (await lookup("github.com", { all: true })).some((a) => a.address === target.host);
  } catch {
    return false; // can't tell: dial it as asked
  }
}

/** Opens the VPN tunnel to `target`, or null (with a warning) if it can't. */
async function dial(conn: Connection, target: Target): Promise<tls.TLSSocket | null> {
  const server = conn.server;
  if (!server) return null;
  // Global mode with its bypass route gone (network change): our own upstream dial came
  // back through the tun. Dialing again would loop, a new connection each turn.
  if (target.host === server.ip) return null;
  if (await isGithubSsh(target)) target = GITHUB_SSH;
  let pass;
  try {
    pass = await conn.currentPass();
  } catch (err) {
    warn(`cannot get a VPN pass: ${(err as Error).message}`);
    return null;
  }
  try {
    const up = await openUpstreamWithRetry(server, pass.token, target);
    dialed(true);
    return up;
  } catch (err) {
    warn(`upstream connect failed for ${target.host}:${target.port}: ${describe(err)}`);
    if (!(err instanceof UpstreamStatusError)) dialed(false); // its server answered: the network's fine
    return null;
  }
}

// ── Split tunneling: each connection goes through the VPN or direct, as the rules say (split.ts).

// foxhole's own lookups and exit-IP check always use the VPN: global mode's DNS rides on the one,
// the TUI's "ip" row on the other.
export const OWN_HOSTS = new Set([DOH_HOST, IP_HOST, TRACE_HOST]);

// Global mode: direct connections leave from the uplink's address, or the tun would take them.
// directOk: they really do (a probe says so); until then, and if not, they use the VPN.
let directFrom: string | null = null;
let directOk = true;

// TEST-NET-1 (RFC 5737) is never routed: a connection to it reaches this proxy only if
// connections from directFrom loop back through the tun.
const PROBE: Target = { host: "192.0.2.1", port: 9 };
let probing = 0;
let probeSeen = false;

/**
 * Global mode's routes are going up, down or moving: until setDirectFrom, direct sites use the VPN.
 * Dialed then, a direct connection would go into the tun, come back here, and be dialed again.
 */
export function holdDirect(): void {
  directOk = false;
}

/** Global mode on (`address`: the uplink's) or off (null). With an address, direct sites wait for the probe. */
export function setDirectFrom(address: string | null): void {
  directFrom = address;
  directOk = !address;
  if (!address) return;
  void (async () => {
    probing++;
    probeSeen = false;
    let refused = false;
    const s = net.connect({ ...PROBE, localAddress: address });
    // macOS refuses outright a connection whose route would loop ("no route to host"). On Linux it
    // would loop instead (seen below), so an error there is the far end's answer, not a refusal.
    s.on("error", (e: NodeJS.ErrnoException) => {
      if (process.platform !== "linux" && ["EHOSTUNREACH", "ENETUNREACH", "EADDRNOTAVAIL"].includes(e.code ?? "")) refused = true;
    });
    await new Promise((r) => setTimeout(r, 1000));
    s.destroy();
    probing--;
    if (directFrom !== address) return; // superseded by a network change
    directOk = !probeSeen && !refused;
    if (!directOk) {
      const msg = "direct sites can't get past the tun on this system: they use the VPN";
      log(`proxy: ${msg}`);
      sink(msg);
    }
  })();
}

/** True when direct sites can go direct now (always, outside global mode). */
export const directReady = (): boolean => directOk;

/** The site a client's first bytes name: a TLS ClientHello's SNI or an HTTP request's Host; null if neither. Pure. */
export function sniffHost(b: Buffer): string | null {
  try {
    if (b[0] === 0x16 && b[5] === 0x01) {
      // record header 5, handshake header 4, version 2, random 32; then session id, cipher suites, compressions
      let p = 43;
      p += 1 + b[p];
      p += 2 + b.readUInt16BE(p);
      p += 1 + b[p];
      const end = p + 2 + b.readUInt16BE(p);
      for (p += 2; p + 4 <= end; p += 4 + b.readUInt16BE(p + 2)) {
        if (b.readUInt16BE(p) !== 0) continue;
        // server_name: list length 2, then type 0 (a host name), length 2, the name
        const len = b.readUInt16BE(p + 7);
        return b[p + 6] === 0 && p + 9 + len <= b.length ? b.toString("latin1", p + 9, p + 9 + len).toLowerCase() : null;
      }
      return null;
    }
    const head = b.toString("latin1", 0, Math.min(b.length, 8192));
    if (!/^[A-Z]+ \S+ HTTP\/1\.[01]\r\n/.test(head)) return null;
    return head.match(/\r\nhost:[ \t]*([^\s:]+)/i)?.[1].toLowerCase() ?? null;
  } catch {
    return null; // cut off
  }
}

/** A client's first bytes: enough to name the site (a whole ClientHello or HTTP head, maybe over several reads), or what came in `ms`. Leaves the socket paused. */
function firstBytes(socket: net.Socket, ms = 2000): Promise<Buffer> {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    const done = () => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("close", done);
      socket.pause();
      resolve(buf);
    };
    // TLS: the record's length says; HTTP (a method in capitals): the blank line; else nothing to wait for
    const whole = () =>
      buf[0] === 0x16 ? buf.length >= 5 && buf.length >= 5 + buf.readUInt16BE(3) : buf[0] >= 0x41 && buf[0] <= 0x5a ? buf.includes("\r\n\r\n") : true;
    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (whole() || buf.length >= 16384) done();
    };
    const timer = setTimeout(done, ms);
    socket.on("data", onData);
    socket.once("close", done);
  });
}

/** Connects to `target` outside the VPN, within `ms`; in global mode from the uplink's address, past the tun. */
function dialDirect(target: Target, ms = UPSTREAM_TIMEOUT_MS): Promise<net.Socket | null> {
  return new Promise((resolve) => {
    const s = net.connect({ host: target.host, port: target.port, ...(directFrom ? { localAddress: directFrom, family: 4 } : {}) });
    const fail = (err: Error) => {
      warn(`direct connect failed for ${target.host}:${target.port}: ${describe(err)}`);
      s.destroy();
      resolve(null);
    };
    s.setTimeout(ms, () => fail(new Error("timed out")));
    s.once("error", fail);
    s.once("connect", () => {
      s.setTimeout(0);
      s.removeListener("error", fail);
      resolve(s);
    });
  });
}

/**
 * Opens the way the rules give `target` (from `app`, when known), the VPN tunnel or a direct connection, and sends it
 * `hello` (the client's first bytes, when they were read first); null (warned) if it can't. foxhole's own hosts always
 * use the VPN.
 */
async function open(conn: Connection, target: Target, name?: string, app?: string, hello?: Buffer | null): Promise<net.Socket | null> {
  const fake = fakeName(target.host); // relay mode's made-up address, still cached after a switch to the VPN: by name
  if (fake) target = { host: fake, port: target.port };
  const ip = net.isIP(target.host) ? target.host : undefined;
  const site = name ?? (ip ? nameOf(ip) : target.host);
  const via = site && OWN_HOSTS.has(site.toLowerCase()) ? "vpn" : route(site, ip, app);
  if (via === "probe") return probe(conn, target, site, hello);
  // Direct where it can be. macOS global mode: a direct site goes around the tun by its DNS answer (relay.ts), but some
  // connections come through it (an app's own with apps in the rules, the relay's held back for apps listed for the
  // VPN, an Iranian address smart found by its range), so the address is routed out the uplink first.
  // ponytail: macOS routes by address, not app: from then on every app's connections to that address go around the
  // tun too, till global mode ends. Per-app routing without that needs a Network Extension.
  const direct = via === "direct" && (directOk || (!!ip && !!pinDirect && !!(await pastTun(ip))));
  return sent(direct ? await dialDirect(target) : await dial(conn, target), site ?? target.host, direct ? "direct" : "vpn", hello);
}

/** Where each upstream connection goes, for its data's count by site (traffic.ts), which splice starts. */
const routeOf = new WeakMap<net.Socket, { name?: string; via: Via }>();

/** `up`, sent `hello` first, and its site and way noted for the count. */
function sent(up: net.Socket | null, name: string | undefined, via: Via, hello?: Buffer | null): net.Socket | null {
  if (!up) return null;
  routeOf.set(up, { name, via });
  if (hello?.length) up.write(hello);
  return up;
}

// ── Save data (smart's probe): a site no list names is tried direct with the client's first bytes. Iran's filter shows
// as its DNS answering with the filter's own address, as a reset, or as silence; then the site goes through the VPN,
// and is remembered as blocked for a few days (smart.ts), so it isn't tried again meanwhile.
const PROBE_MS = 2500;

/** The first bytes `s` gets within `ms`, or null if it ends, fails or stays silent. Leaves it paused. */
function firstAnswer(s: net.Socket, ms: number): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const done = (b: Buffer | null) => {
      clearTimeout(timer);
      s.removeListener("data", done).removeListener("close", none);
      s.pause();
      resolve(b);
    };
    const none = () => done(null);
    const timer = setTimeout(none, ms);
    s.on("error", () => {}); // a reset is the filter's answer: its "close" says so
    s.on("data", done).once("close", none);
  });
}

/** Save data: `target` direct if it opens that way with `hello`, else through the VPN. Sends `hello` either way. */
async function probe(conn: Connection, target: Target, site: string | undefined, hello?: Buffer | null): Promise<net.Socket | null> {
  const viaVpn = async () => sent(await dial(conn, target), site ?? target.host, "vpn", hello);
  if (!hello?.length) return viaVpn(); // nothing to try it with: not the web
  // macOS global mode takes a direct address around the tun for every app till it ends: with it would go whatever
  // shares it (a CDN's), blocked sites too, past the proxy. So nothing is tried there.
  if (pinDirect) return viaVpn();
  let ip = net.isIP(target.host) ? target.host : null;
  if (!ip) {
    // the lookup a direct connection makes: Iran's DNS answers a blocked name with its filter's address
    ip = await lookup(target.host).then((a) => a.address, () => null);
    if (!ip || filterAddress(ip)) return learnBlocked(site), viaVpn();
  }
  if (!(await pastTun(ip))) return viaVpn(); // global mode, where direct can't get past the tun: nothing learned
  // a filtered address can drop the handshake instead: it isn't waited for like a slow site
  const direct = await dialDirect({ host: ip, port: target.port }, PROBE_MS);
  if (!direct) return learnBlocked(site), viaVpn();
  direct.write(hello);
  const answer = await firstAnswer(direct, PROBE_MS);
  // plain HTTP: the filter answers with its own page, which links to it
  if (!answer || answer.includes("10.10.34.3")) {
    direct.destroy();
    learnBlocked(site);
    return viaVpn();
  }
  direct.unshift(answer); // the client gets it first, through splice
  return sent(direct, site ?? target.host, "direct");
}

// ── Smart DNS (smartdns.ts): another device of the home's, told this computer's address for a site that needs the
// VPN, connects here on its port 443 or 80. Its first bytes name the site, which goes through the VPN.

/** A connection that came by smart DNS's answer for a site's `port`: through the VPN to the site its first bytes name. */
export async function serveByName(socket: net.Socket, conn: Connection, port: number): Promise<void> {
  socket.on("error", () => socket.destroy());
  const hello = await firstBytes(socket);
  const name = sniffHost(hello);
  // the relay can't: it reads the web with foxhole's own certificate, which a TV doesn't trust
  const up = name && !socket.destroyed && !conn.relay ? sent(await dial(conn, { host: name, port }), name, "vpn", hello) : null;
  if (!up) return void socket.destroy();
  splice(socket, up);
}

// ── Blocked or sanctioned? The Split sheet's check of a typed site: its page tried directly and through the VPN, at
// once. The filter shows as on save data's tries; a refusal of Iran (403, 451) only inside TLS, so the page is asked for.
const CHECK_MS = 6000;

/** The status `s` (a connection to `name`'s port 443) gets for `name`'s page, or why it gets none. Closes `s`. */
function pageOver(s: net.Socket, name: string): Promise<Try> {
  return new Promise((resolve) => {
    const t = tls.connect({ socket: s, servername: name, ALPNProtocols: ["http/1.1"] });
    const done = (r: Try) => {
      clearTimeout(timer);
      t.destroy();
      s.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => done({ fail: "silent" }), CHECK_MS);
    t.once("secureConnect", () => t.write(`GET / HTTP/1.1\r\nHost: ${name}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n`));
    t.once("data", (b: Buffer) => done({ status: Number(/^HTTP\/1\.[01] (\d{3})/.exec(b.toString("latin1"))?.[1]) || 200 }));
    // a reset is the filter's; anything else (a certificate not the site's, not TLS at all) someone else's answer
    t.once("error", (e: NodeJS.ErrnoException) => done({ fail: e.code === "ECONNRESET" || e.code === "EPIPE" ? "cut" : "tls" }));
    t.once("close", () => done({ fail: "cut" }));
  });
}

/** `name` tried directly: null if it can't be here (global mode: macOS would route it around the tun for every app). */
async function tryDirect(name: string): Promise<Try | null> {
  if (pinDirect || !directOk) return null;
  const ip = await lookup(name).then((a) => a.address, () => null);
  if (!ip) return { fail: "dns" };
  if (filterAddress(ip)) return { fail: "filter" };
  const s = await dialDirect({ host: ip, port: 443 }, CHECK_MS);
  return s ? pageOver(s, name) : { fail: "silent" };
}

/** `name` tried through the VPN, a few KB of its data. */
async function tryVpn(conn: Connection, name: string): Promise<Try> {
  const up = dial(conn, { host: name, port: 443 });
  // a site that doesn't answer keeps the VPN's server trying it (and dial retrying) a long while
  const s = await Promise.race([up, new Promise<null>((r) => setTimeout(r, CHECK_MS, null))]);
  if (s) return pageOver(s, name);
  void up.then((late) => late?.destroy());
  return { fail: "silent" };
}

/** `name` tried directly and (`conn`: connected) through the VPN; null for a way it can't be tried. */
export async function checkSite(conn: Connection | null, name: string): Promise<{ direct: Try | null; vpn: Try | null }> {
  // the sanctioned list meanwhile, for the sites that turn Iran away at sign-in, past a page that opens
  const lists = Promise.race([refreshLists(), new Promise((r) => setTimeout(r, CHECK_MS))]);
  const [direct, vpn] = await Promise.all([tryDirect(name), conn ? tryVpn(conn, name) : null, lists]);
  return { direct, vpn };
}

// ── The network itself, when the VPN's server doesn't answer: Iran can cut its international internet off and keep
// its own up. Then nothing abroad opens, and it isn't the Wi-Fi, nor Foxhole.
const HOME = ["www.digikala.com", "www.aparat.com"]; // Iran's own, up through a cut
const WORLD = ["www.cloudflare.com", "www.microsoft.com"]; // abroad, and not filtered in Iran
export const NET_CUT = "International internet looks cut off: Iran's own sites open, the rest of the world doesn't. It isn't your Wi-Fi, nor Foxhole.";
export const NET_OFF = "No internet: not even Iran's own sites open. Check the Wi-Fi or mobile data.";

/** NET_CUT or NET_OFF when the network is so, else null (the world opens, or it can't be told: global mode). */
export async function netState(): Promise<string | null> {
  if (pinDirect || !directOk) return null;
  const opens = (hosts: string[]) =>
    Promise.any(hosts.map((host) => dialDirect({ host, port: 443 }, 5000).then((s) => s?.destroy() ?? Promise.reject()))).then(() => true, () => false);
  const [home, world] = await Promise.all([opens(HOME), opens(WORLD)]);
  return world ? null : home ? NET_CUT : NET_OFF;
}

let netSink: ((said: string | null) => void) | null = null;
let netSaid: string | null = null;
let netAt = 0;

/** Tells `fn` when the VPN's connections fail for the network's state (netState's words), and null once they work again. */
export function onNetState(fn: (said: string | null) => void): void {
  netSink = fn;
}

/** A dial's outcome: failures look at the network, once a minute at most (a page fails many at once). */
function dialed(ok: boolean): void {
  if (ok) {
    if (netSaid) netSink?.((netSaid = null));
    return;
  }
  if (!netSink || Date.now() - netAt < 60_000) return;
  netAt = Date.now();
  void netState().then((said) => said !== netSaid && netSink?.((netSaid = said)));
}

/**
 * The app behind a client of this computer's, when a rule names apps (finding it costs a look at the system's
 * connections). Not on a phone: Android's VPN does apps itself, iOS can't tell them apart.
 */
const PHONE = (process.platform as string) === "android" || (process.platform as string) === "ios";
const appOf = (socket: net.Socket, target: Target) => (!PHONE && appsOn() ? appFor(socket, target) : Promise.resolve(undefined));

// ── Relay mode (relaymode.ts): the web through the user's Apps Script; what isn't HTTP goes direct.

// macOS global mode: an address must be routed out the uplink before a direct connection to it (global.ts sets this)
let pinDirect: ((ip: string) => Promise<void>) | null = null;
export const setPinDirect = (fn: typeof pinDirect): void => void (pinDirect = fn);

// The ports where a client's first bytes tell HTTP and TLS apart; elsewhere some protocols wait for the server first
const WEB_PORTS = new Set([80, 443, 8080, 8443]);
// This computer and its network: no use sending them to Google
const LOCAL = /^(localhost|.+\.(localhost|local|lan|home\.arpa)|127\.[\d.]+|10\.[\d.]+|192\.168\.[\d.]+|172\.(1[6-9]|2\d|3[01])\.[\d.]+|169\.254\.[\d.]+|::1|f[cd][0-9a-f]{2}:.*|fe80:.*)$/i;

/** A direct connection in relay mode. In global mode a site's real address comes through the relay (lookups here give made-up ones). */
async function relayDirect(conn: Pick<Connection, "relay" | "server">, target: Target, name: string): Promise<net.Socket | null> {
  let host = target.host;
  if (fakeName(host) || ((directFrom || pinDirect) && !net.isIP(host))) {
    const real = await realIp(conn, name);
    if (!real) return (warn(`no address found for ${name}`), null);
    host = real;
  }
  if (!(await pastTun(host))) return (warn(`${name}:${target.port} isn't web traffic, which the relay can't carry, and can't go direct past the tun`), null);
  return dialDirect({ host, port: target.port });
}

/** What a direct connection to `ip` needs in relay mode to get past global mode's tun (macOS: its route pinned), or null if it can't. */
async function pastTun(ip: string): Promise<{ localAddress?: string; family?: number } | null> {
  if (pinDirect) return pinDirect(ip).then(() => ({}), () => ({}));
  if (!directOk) return null;
  return directFrom ? { localAddress: directFrom, family: 4 } : {};
}
setDirectTo(pastTun); // relay mode's own direct connections (YouTube's videos) go the same way
setDirectDial((conn, host, port) => relayDirect(conn, { host, port }, host)); // its check that a site opens directly

/** Relay mode: a connection the client opened (after its reply), web traffic to the relay, the rest direct. `early`: bytes it already sent. */
async function relayOpen(conn: Connection, socket: net.Socket, target: Target, early: Buffer): Promise<void> {
  const app = await appOf(socket, target);
  let first = early;
  if (!first.length && WEB_PORTS.has(target.port)) {
    const got = firstBytes(socket); // listening before it flows: nothing the client sends gets missed
    socket.resume();
    first = await got;
  } else socket.pause(); // until it's spliced: what it sends meanwhile waits

  if (socket.destroyed) return;
  const ip = net.isIP(target.host) ? target.host : undefined;
  const name = sniffHost(first) ?? (ip ? (fakeName(ip) ?? nameOf(ip)) : undefined) ?? target.host;
  const tlsHello = first[0] === 0x16;
  const web = tlsHello || /^[A-Z]{3,7} \S+ HTTP\/1\.[01]\r\n/.test(first.toString("latin1", 0, 2100));
  if (web && !LOCAL.test(name) && (OWN_HOSTS.has(name) || route(name, ip, app) !== "direct")) {
    return relayServe(conn, socket, first, { host: name, port: target.port, tls: tlsHello });
  }
  const up = await relayDirect(conn, target, name);
  if (!up) return void socket.destroy();
  if (first.length) up.write(first);
  splice(socket, up);
}

/** Pipes two sockets into each other until either side closes. */
function splice(a: net.Socket, b: net.Socket): void {
  // The client hung up while the tunnel was opening (tun2socks quitting, a cancelled
  // connection): its "close" already fired, so nothing below would ever close the tunnel.
  if (a.destroyed) return void b.destroy();
  const r = routeOf.get(b);
  if (r) track(a, r.name, r.via);
  a.pipe(b);
  b.pipe(a);
  const close = () => {
    a.destroy();
    b.destroy();
  };
  a.once("close", close);
  b.once("close", close);
  b.once("error", close);
}

/** A proxy username and password (SOCKS5 RFC 1929, HTTP Basic). */
export interface ProxyLogin {
  username: string;
  password: string;
}

const digest = (l: ProxyLogin) => createHash("sha256").update(`${l.username}\0${l.password}`).digest();
/** True if the login given matches, compared in constant time. */
const sameLogin = (given: ProxyLogin | null, want: ProxyLogin) => !!given && timingSafeEqual(digest(given), digest(want));

/** The RFC 1929 username/password a SOCKS5 client sent, or null if malformed. */
function socksLogin(b: Buffer): ProxyLogin | null {
  const ulen = b[1] ?? 0;
  const plen = b[2 + ulen];
  if (b[0] !== 0x01 || plen === undefined || b.length < 3 + ulen + plen) return null;
  return { username: b.toString("utf8", 2, 2 + ulen), password: b.toString("utf8", 3 + ulen, 3 + ulen + plen) };
}

/** The login in a request's Proxy-Authorization: Basic header, or null. */
function basicLogin(lines: string[]): ProxyLogin | null {
  const b64 = lines.find((l) => /^proxy-authorization:/i.test(l))?.match(/^[^:]+:\s*basic\s+(\S+)/i)?.[1];
  if (!b64) return null;
  const s = Buffer.from(b64, "base64").toString("utf8");
  const i = s.indexOf(":");
  return i < 0 ? null : { username: s.slice(0, i), password: s.slice(i + 1) };
}

async function handleClient(socket: net.Socket, conn: Connection, login: ProxyLogin | null): Promise<void> {
  socket.on("error", () => socket.destroy());
  const first = await nextChunk(socket);
  return first[0] === SOCKS_VERSION ? handleSocks(socket, conn, first, login) : handleHttp(socket, conn, first, login);
}

async function handleSocks(socket: net.Socket, conn: Connection, greeting: Buffer, login: ProxyLogin | null): Promise<void> {
  const methods = [...greeting.subarray(2, 2 + greeting[1])];
  if (login || !methods.includes(0x00)) {
    // Username/password: required with a login, else used only when it's all the client offers
    if (!methods.includes(0x02)) return void socket.end(Buffer.from([SOCKS_VERSION, 0xff])); // no acceptable method
    socket.write(Buffer.from([SOCKS_VERSION, 0x02]));
    const given = socksLogin(await nextChunk(socket));
    if (!given || (login && !sameLogin(given, login))) return void socket.end(Buffer.from([0x01, 0x01]));
    socket.write(Buffer.from([0x01, 0x00]));
  } else socket.write(Buffer.from([SOCKS_VERSION, 0x00])); // no authentication required
  const target = await readRequest(socket);
  if (target.udp) {
    // the relay carries only the web: as before UDP was carried at all, an app's UDP finds no way and it falls back
    if (conn.relay) return void socket.end(Buffer.from([SOCKS_VERSION, 0x07, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]));
    return udpAssociate(socket, conn, pastTun);
  }
  if (probing && target.host === PROBE.host && target.port === PROBE.port) return void ((probeSeen = true), socket.destroy());
  if (conn.relay) {
    replySuccess(socket); // the first bytes, which say where it goes, come only after
    return relayOpen(conn, socket, target, Buffer.alloc(0));
  }
  // tun2socks (global mode) gives only an address. When rules need the site's name, the client's first
  // bytes have it, exactly even on a CDN address many sites share: a TLS SNI, an HTTP Host. They come
  // only after the reply, so it goes first.
  const app = await appOf(socket, target); // before the reply: once it has one, tun2socks' app may be done already
  let hello: Buffer | null = null;
  let name: string | undefined;
  // Saving data, every site's first bytes are read so too: they try the direct way (probe).
  if ((net.isIP(target.host) || probeOn()) && splitOn() && (target.port === 443 || target.port === 80)) {
    replySuccess(socket);
    hello = await firstBytes(socket);
    if (socket.destroyed) return;
    name = sniffHost(hello) ?? undefined;
  }
  const up = await open(conn, target, name, app, hello);
  if (!up) {
    if (!hello) replyFailure(socket);
    socket.destroy();
    return;
  }
  if (!hello) replySuccess(socket);
  splice(socket, up);
}

const HTTP_MAX_HEAD = 64 * 1024;

/** Ends an HTTP client connection with a status line (and any extra header lines). */
function httpError(socket: net.Socket, status: string, headers = ""): void {
  socket.end(`HTTP/1.1 ${status}\r\n${headers}Content-Length: 0\r\nConnection: close\r\n\r\n`);
}

/**
 * HTTP proxy: CONNECT host:port (https:// sites — end-to-end TLS, we only see
 * the host) and plain http:// requests in absolute form, which are sent on as
 * origin-form with the proxy headers removed. One request per connection:
 * "Connection: close" keeps a reused client socket from reaching the wrong host.
 */
async function handleHttp(socket: net.Socket, conn: Connection, first: Buffer, login: ProxyLogin | null): Promise<void> {
  let head = first;
  while (head.indexOf("\r\n\r\n") < 0) {
    if (head.length > HTTP_MAX_HEAD) return httpError(socket, "431 Request Header Fields Too Large");
    head = Buffer.concat([head, await nextChunk(socket)]);
  }
  socket.pause(); // hold any body bytes until the tunnel is up (pipe resumes)
  const end = head.indexOf("\r\n\r\n");
  const lines = head.toString("latin1", 0, end).split("\r\n");
  if (login && !sameLogin(basicLogin(lines), login)) {
    return httpError(socket, "407 Proxy Authentication Required", 'Proxy-Authenticate: Basic realm="foxhole-vpn"\r\n');
  }
  const [method, url, version = "HTTP/1.1"] = lines[0].split(" ");
  const rest = head.subarray(end + 4);

  let target: Target;
  let request: Buffer | null = null; // what to send upstream; null = tunnel (CONNECT)
  if (method === "CONNECT") {
    const m = url?.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
    if (!m) return httpError(socket, "400 Bad Request");
    target = { host: m[1] ?? m[2], port: Number(m[3]) };
    if (conn.relay) {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      return relayOpen(conn, socket, target, rest);
    }
  } else {
    let u: URL;
    try {
      u = new URL(url ?? "");
    } catch {
      return httpError(socket, "400 Bad Request");
    }
    if (u.protocol !== "http:") return httpError(socket, "400 Bad Request");
    target = { host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port || 80) };
    // relay mode: the request as it came, absolute URL and all (it says where each one on this connection goes)
    if (conn.relay && !LOCAL.test(target.host) && (OWN_HOSTS.has(target.host) || route(target.host, undefined, await appOf(socket, target)) !== "direct")) {
      return relayServe(conn, socket, head, { ...target, tls: false });
    }
    const headers = lines.slice(1).filter((l) => !/^(proxy-[^:]*|connection|keep-alive):/i.test(l));
    request = Buffer.concat([
      Buffer.from(`${method} ${u.pathname}${u.search} ${version}\r\n${[...headers, "Connection: close"].join("\r\n")}\r\n\r\n`, "latin1"),
      rest,
    ]);
  }

  if (!request && !conn.relay && probeOn() && (target.port === 443 || target.port === 80)) {
    // saving data: the client's first bytes try the direct way (probe), and they come only after the 200
    const app = await appOf(socket, target);
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    let hello = rest;
    if (!hello.length) {
      const got = firstBytes(socket);
      socket.resume();
      hello = await got;
    }
    if (socket.destroyed) return;
    const up = await open(conn, target, sniffHost(hello) ?? undefined, app, hello);
    if (!up) return void socket.destroy();
    return splice(socket, up);
  }
  const up = conn.relay ? await relayDirect(conn, target, target.host) : await open(conn, target, undefined, await appOf(socket, target), request);
  if (!up) return httpError(socket, "502 Bad Gateway");
  if (request) {
    if (conn.relay) up.write(request); // open sent it already
  } else {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (rest.length) up.write(rest);
  }
  splice(socket, up);
}

export interface ProxyHandle {
  port: number;
  close(): Promise<void>;
  /** Drops every client connection, so each reconnects the new way (a switch between Firefox VPN and the relay). */
  reset(): void;
}

/**
 * Starts the local SOCKS5 + HTTP proxy. Resolves once it is listening. `login` gives the
 * username/password a client (by its address) must sign in with, or null for none.
 */
export async function startProxy(
  conn: Connection,
  host = "127.0.0.1",
  port = 1080,
  login: (address: string | undefined) => ProxyLogin | null = () => null,
): Promise<ProxyHandle> {
  // macOS and Windows let 127.0.0.1:port be taken while another program listens on *:port, which then silently
  // loses this computer's connections to us: refuse a port something already answers on
  if (port && (await answers(port))) {
    throw Object.assign(new Error(`port ${port} is already in use by another program (or another Foxhole)`), { code: "EADDRINUSE" });
  }
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    handleClient(socket, conn, login(socket.remoteAddress)).catch(() => socket.destroy());
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address() as net.AddressInfo;
      listsVia({ host: host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host, port: addr.port }); // smart's new lists come through the VPN
      resolve({
        port: addr.port,
        // server.close() alone waits for every client to hang up, and browsers keep
        // connections open, so drop them (each one's tunnel closes with it).
        close: () =>
          new Promise<void>((res) => {
            server.close(() => res());
            for (const s of sockets) s.destroy();
            closeWarm();
            closeUdp();
            saveTraffic(); // the closed connections' data is in now
          }),
        reset: () => {
          for (const s of sockets) s.destroy();
        },
      });
    });
  });
}
