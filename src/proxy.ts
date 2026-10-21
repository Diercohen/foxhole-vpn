import net from "node:net";
import tls from "node:tls";
import { lookup } from "node:dns/promises";
import type { Connection } from "./connection.js";
import { red, verbose } from "./ui.js";
import { log } from "./log.js";

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

async function handleClient(socket: net.Socket, conn: Connection): Promise<void> {
  socket.on("error", () => socket.destroy());
  const first = await nextChunk(socket);
  return first[0] === SOCKS_VERSION ? handleSocks(socket, conn) : handleHttp(socket, conn, first);
}

async function handleSocks(socket: net.Socket, conn: Connection): Promise<void> {
  socket.write(Buffer.from([SOCKS_VERSION, 0x00])); // no authentication required
  const target = await readRequest(socket);
  const up = await dial(conn, target);
  if (!up) {
    replyFailure(socket);
    socket.destroy();
    return;
  }
  replySuccess(socket);
  splice(socket, up);
}

const HTTP_MAX_HEAD = 64 * 1024;

/** Ends an HTTP client connection with a status line. */
function httpError(socket: net.Socket, status: string): void {
  socket.end(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
}

/**
 * HTTP proxy: CONNECT host:port (https:// sites — end-to-end TLS, we only see
 * the host) and plain http:// requests in absolute form, which are sent on as
 * origin-form with the proxy headers removed. One request per connection:
 * "Connection: close" keeps a reused client socket from reaching the wrong host.
 */
async function handleHttp(socket: net.Socket, conn: Connection, first: Buffer): Promise<void> {
  let head = first;
  while (head.indexOf("\r\n\r\n") < 0) {
    if (head.length > HTTP_MAX_HEAD) return httpError(socket, "431 Request Header Fields Too Large");
    head = Buffer.concat([head, await nextChunk(socket)]);
  }
  socket.pause(); // hold any body bytes until the tunnel is up (pipe resumes)
  const end = head.indexOf("\r\n\r\n");
  const lines = head.toString("latin1", 0, end).split("\r\n");
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

  const up = await dial(conn, target);
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

/** Starts the local SOCKS5 + HTTP proxy. Resolves once it is listening. */
export function startProxy(conn: Connection, host = "127.0.0.1", port = 1080): Promise<ProxyHandle> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    handleClient(socket, conn).catch(() => socket.destroy());
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
