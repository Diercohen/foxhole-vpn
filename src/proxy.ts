import net from "node:net";
import tls from "node:tls";
import type { Connection } from "./connection.js";
import { red } from "./ui.js";

// Throttled stderr: a browser opens many connections, so don't repeat the same
// failure more than once every few seconds.
let lastWarn = "";
let lastWarnAt = 0;
function warn(msg: string): void {
  const now = Date.now();
  if (msg === lastWarn && now - lastWarnAt < 5000) return;
  lastWarn = msg;
  lastWarnAt = now;
  console.error(red(`proxy: ${msg}`));
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

// Local SOCKS5 proxy (TCP CONNECT only — the upstream is HTTP CONNECT, which is
// TCP-only). Each client connection is tunnelled to the chosen Fastly server
// over TLS using the current proxy pass. No external dependencies.

const SOCKS_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;

interface Target {
  host: string;
  port: number;
}

function readHandshake(socket: net.Socket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once("data", (buf) => {
      if (buf[0] !== SOCKS_VERSION) return reject(new Error("Not SOCKS5"));
      // Reply: version 5, no authentication required.
      socket.write(Buffer.from([SOCKS_VERSION, 0x00]));
      resolve();
    });
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

async function handleClient(socket: net.Socket, conn: Connection): Promise<void> {
  socket.on("error", () => socket.destroy());
  await readHandshake(socket);
  const target = await readRequest(socket);
  const server = conn.server;
  if (!server) {
    replyFailure(socket);
    socket.destroy();
    return;
  }
  let pass;
  try {
    pass = await conn.currentPass();
  } catch (err) {
    warn(`cannot get a VPN pass: ${(err as Error).message}`);
    replyFailure(socket);
    socket.destroy();
    return;
  }
  let up: tls.TLSSocket;
  try {
    up = await openUpstreamWithRetry(server, pass.token, target);
  } catch (err) {
    warn(`upstream connect failed: ${describe(err)}`);
    replyFailure(socket);
    socket.destroy();
    return;
  }
  replySuccess(socket);
  socket.pipe(up);
  up.pipe(socket);
  const close = () => {
    socket.destroy();
    up.destroy();
  };
  socket.once("close", close);
  up.once("close", close);
  up.once("error", close);
}

export interface ProxyHandle {
  port: number;
  close(): Promise<void>;
}

/** Starts the local SOCKS5 proxy. Resolves once it is listening. */
export function startProxy(conn: Connection, host = "127.0.0.1", port = 1080): Promise<ProxyHandle> {
  const server = net.createServer((socket) => {
    handleClient(socket, conn).catch(() => socket.destroy());
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address() as net.AddressInfo;
      resolve({
        port: addr.port,
        close: () =>
          new Promise<void>((res) => {
            server.close(() => res());
          }),
      });
    });
  });
}
