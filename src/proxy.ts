import net from "node:net";
import tls from "node:tls";
import { createHash, timingSafeEqual } from "node:crypto";
import { lookup } from "node:dns/promises";
import type { Connection } from "./connection.js";
import { red, verbose } from "./ui.js";
import { log } from "./log.js";
import { route, splitOn, type Via } from "./split.js";
import { nameOf, DOH_HOST } from "./dns.js";
import { IP_HOST } from "./netinfo.js";

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
  ) {
    super(statusLine);
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
// TCP only — the upstream is HTTP CONNECT. Each client connection is tunnelled
// to the chosen Fastly server over TLS using the current proxy pass.

const SOCKS_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;

interface Target {
  host: string;
  port: number;
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
      if (buf[0] !== SOCKS_VERSION || buf[1] !== CMD_CONNECT) {
        // 0x07 = command not supported.
        socket.write(Buffer.from([SOCKS_VERSION, 0x07, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]));
        return reject(new Error("Only CONNECT is supported"));
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
      resolve({ host, port });
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

/** Opens a TLS tunnel to the upstream and issues HTTP CONNECT for `target`. */
function openUpstream(server: Upstream, passToken: string, target: Target): Promise<tls.TLSSocket> {
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
    const up = tls.connect(
      {
        host: server.ip ?? server.hostname, // pinned IP in global mode, else resolve
        port: server.port,
        servername: server.hostname, // TLS SNI/cert always uses the hostname
        ALPNProtocols: ["http/1.1"],
      },
      () => {
        const hostHeader = target.host.includes(":") ? `[${target.host}]` : target.host;
        up.write(
          `CONNECT ${hostHeader}:${target.port} HTTP/1.1\r\n` +
            `Host: ${hostHeader}:${target.port}\r\n` +
            `Proxy-Authorization: Bearer ${passToken}\r\n` +
            `\r\n`,
        );
      },
    );
    let header = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      header = Buffer.concat([header, chunk]);
      const end = header.indexOf("\r\n\r\n");
      if (end === -1) {
        if (header.length > 64 * 1024) fail(new Error("oversized CONNECT response"));
        return;
      }
      up.removeListener("data", onData);
      const statusLine = header.toString("latin1", 0, header.indexOf("\r\n")).trim();
      const code = Number(statusLine.split(" ")[1]);
      if (code !== 200) {
        fail(new UpstreamStatusError(code, statusLine));
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
      // A 4xx (bad pass, refused target) won't change on retry.
      if (err instanceof UpstreamStatusError && err.status < 500) break;
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
    return await openUpstreamWithRetry(server, pass.token, target);
  } catch (err) {
    warn(`upstream connect failed for ${target.host}:${target.port}: ${describe(err)}`);
    return null;
  }
}

// ── Split tunneling: each connection goes through the VPN or direct, as the rules say (split.ts).

// foxhole's own lookups and exit-IP check always use the VPN: global mode's DNS rides on the one,
// the TUI's "ip" row on the other.
export const OWN_HOSTS = new Set([DOH_HOST, IP_HOST]);

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

/** Connects to `target` outside the VPN; in global mode from the uplink's address, past the tun. */
function dialDirect(target: Target): Promise<net.Socket | null> {
  return new Promise((resolve) => {
    const s = net.connect({ host: target.host, port: target.port, ...(directFrom ? { localAddress: directFrom, family: 4 } : {}) });
    const fail = (err: Error) => {
      warn(`direct connect failed for ${target.host}:${target.port}: ${describe(err)}`);
      s.destroy();
      resolve(null);
    };
    s.setTimeout(UPSTREAM_TIMEOUT_MS, () => fail(new Error("timed out")));
    s.once("error", fail);
    s.once("connect", () => {
      s.setTimeout(0);
      s.removeListener("error", fail);
      resolve(s);
    });
  });
}

/** VPN or direct for a connection to the site `name` (when known) at `ip` (when known). */
function via(name: string | undefined, ip: string | undefined): Via {
  if (name && OWN_HOSTS.has(name.toLowerCase())) return "vpn";
  return route(name, ip) === "direct" && directOk ? "direct" : "vpn";
}

/** Opens the way the rules give `target`, the VPN tunnel or a direct connection; null (warned) if it can't. */
async function open(conn: Connection, target: Target, name?: string): Promise<net.Socket | null> {
  const ip = net.isIP(target.host) ? target.host : undefined;
  return via(name ?? (ip ? nameOf(ip) : target.host), ip) === "direct" ? dialDirect(target) : dial(conn, target);
}

/** Pipes two sockets into each other until either side closes. */
function splice(a: net.Socket, b: net.Socket): void {
  // The client hung up while the tunnel was opening (tun2socks quitting, a cancelled
  // connection): its "close" already fired, so nothing below would ever close the tunnel.
  if (a.destroyed) return void b.destroy();
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
  if (probing && target.host === PROBE.host && target.port === PROBE.port) return void ((probeSeen = true), socket.destroy());
  // tun2socks (global mode) gives only an address. When rules need the site's name, the client's first
  // bytes have it, exactly even on a CDN address many sites share: a TLS SNI, an HTTP Host. They come
  // only after the reply, so it goes first.
  let hello: Buffer | null = null;
  let name: string | undefined;
  if (net.isIP(target.host) && splitOn() && (target.port === 443 || target.port === 80)) {
    replySuccess(socket);
    hello = await firstBytes(socket);
    if (socket.destroyed) return;
    name = sniffHost(hello) ?? undefined;
  }
  const up = await open(conn, target, name);
  if (!up) {
    if (!hello) replyFailure(socket);
    socket.destroy();
    return;
  }
  if (hello) up.write(hello);
  else replySuccess(socket);
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
  } else {
    let u: URL;
    try {
      u = new URL(url ?? "");
    } catch {
      return httpError(socket, "400 Bad Request");
    }
    if (u.protocol !== "http:") return httpError(socket, "400 Bad Request");
    target = { host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port || 80) };
    const headers = lines.slice(1).filter((l) => !/^(proxy-[^:]*|connection|keep-alive):/i.test(l));
    request = Buffer.concat([
      Buffer.from(`${method} ${u.pathname}${u.search} ${version}\r\n${[...headers, "Connection: close"].join("\r\n")}\r\n\r\n`, "latin1"),
      rest,
    ]);
  }

  const up = await open(conn, target);
  if (!up) return httpError(socket, "502 Bad Gateway");
  if (request) up.write(request);
  else {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (rest.length) up.write(rest);
  }
  splice(socket, up);
}

export interface ProxyHandle {
  port: number;
  close(): Promise<void>;
}

/**
 * Starts the local SOCKS5 + HTTP proxy. Resolves once it is listening. `login` gives the
 * username/password a client (by its address) must sign in with, or null for none.
 */
export function startProxy(
  conn: Connection,
  host = "127.0.0.1",
  port = 1080,
  login: (address: string | undefined) => ProxyLogin | null = () => null,
): Promise<ProxyHandle> {
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
      resolve({
        port: addr.port,
        // server.close() alone waits for every client to hang up, and browsers keep
        // connections open, so drop them (each one's tunnel closes with it).
        close: () =>
          new Promise<void>((res) => {
            server.close(() => res());
            for (const s of sockets) s.destroy();
          }),
      });
    });
  });
}
