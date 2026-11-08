// UDP through Firefox's VPN. Its servers carry UDP as MASQUE's connect-udp (RFC 9298) over HTTP/2 only (HTTP/1.1 gets a
// 405), each datagram a DATAGRAM capsule (RFC 9297) on the request's stream, and only to some ports: 80, 443, 3478, 8080,
// 8443 and 49152 and up (seen 2026-11). Those are STUN's and TURN's, and WebRTC's media, so calls get through; DNS, NTP
// and most games' ports don't. Apps hand UDP over by SOCKS5's UDP ASSOCIATE, as whole-system mode's tun2socks and
// hev-socks5-tunnel do. QUIC (UDP to 80 and 443) is dropped, so browsers use TCP, which is faster here: over HTTP/2
// Fastly's 64 KB flow-control window holds an upload to ~1 Mbit/s.
import dgram from "node:dgram";
import http2 from "node:http2";
import net from "node:net";
import tls from "node:tls";
import type { Connection } from "./connection.js";
import type { Server } from "./serverlist.js";
import { nameOf } from "./dns.js";
import { route } from "./split.js";
import { count } from "./traffic.js";
import { log } from "./log.js";

// ── Wire formats ────────────────────────────────────────────────────────────────────────────────────────────────

/** A QUIC variable-length integer (RFC 9000 §16), up to 2^30 - 1. Pure. */
export function varint(n: number): Buffer {
  if (n < 0x40) return Buffer.from([n]);
  if (n < 0x4000) return Buffer.from([0x40 | (n >> 8), n & 0xff]);
  const b = Buffer.alloc(4);
  b.writeUInt32BE((0x80000000 | n) >>> 0);
  return b;
}

/** The varint at `p` in `b` and where the next field starts, or null if `b` ends first. Pure. */
export function readVarint(b: Buffer, p: number): [value: number, next: number] | null {
  if (p >= b.length) return null;
  const len = 1 << (b[p] >> 6);
  if (p + len > b.length) return null;
  let v = b[p] & 0x3f;
  for (let i = 1; i < len; i++) v = v * 256 + b[p + i];
  return [v, p + len];
}

/** A DATAGRAM capsule (type 0) carrying the UDP payload `data` (context ID 0). Pure. */
export const capsule = (data: Buffer): Buffer => Buffer.concat([varint(0), varint(data.length + 1), varint(0), data]);

/** The UDP payloads in `buf`'s whole capsules (other capsules skipped), and the cut-off rest to wait on. Pure. */
export function takeCapsules(buf: Buffer): { payloads: Buffer[]; rest: Buffer } {
  const payloads: Buffer[] = [];
  let p = 0;
  for (;;) {
    const type = readVarint(buf, p);
    const len = type && readVarint(buf, type[1]);
    if (!type || !len || len[1] + len[0] > buf.length) break;
    const end = len[1] + len[0];
    const ctx = type[0] === 0 ? readVarint(buf.subarray(0, end), len[1]) : null;
    if (ctx && ctx[0] === 0) payloads.push(buf.subarray(ctx[1], end));
    p = end;
  }
  return { payloads, rest: buf.subarray(p) };
}

/** An IPv6 address's 16 bytes. Pure. */
function v6Bytes(ip: string): Buffer {
  const [head, tail = ""] = ip.split("::");
  const groups = (s: string) => (s ? s.split(":") : []);
  const h = groups(head);
  const t = groups(tail);
  const all = ip.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  const b = Buffer.alloc(16);
  all.forEach((g, i) => b.writeUInt16BE(parseInt(g, 16) || 0, i * 2));
  return b;
}

/** A datagram a SOCKS5 client sent to the relay (RFC 1928 §7): where it goes and what it carries; null if malformed or a fragment. Pure. */
export function parseUdpRequest(b: Buffer): { host: string; port: number; data: Buffer } | null {
  if (b.length < 10 || b[2] !== 0) return null; // FRAG: none of the clients splits datagrams
  let host: string;
  let p: number;
  if (b[3] === 0x01) (host = [...b.subarray(4, 8)].join(".")), (p = 8);
  else if (b[3] === 0x03) (host = b.toString("utf8", 5, 5 + b[4])), (p = 5 + b[4]);
  else if (b[3] === 0x04 && b.length >= 22) {
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) parts.push(b.readUInt16BE(4 + i).toString(16));
    (host = parts.join(":")), (p = 20);
  } else return null;
  if (!host || b.length < p + 2) return null;
  return { host, port: b.readUInt16BE(p), data: b.subarray(p + 2) };
}

/** A datagram for a SOCKS5 client, from `host`:`port`. Pure. */
export function udpReply(host: string, port: number, data: Buffer): Buffer {
  const portBytes = Buffer.from([port >> 8, port & 0xff]);
  if (net.isIPv4(host)) return Buffer.concat([Buffer.from([0, 0, 0, 0x01, ...host.split(".").map(Number)]), portBytes, data]);
  if (net.isIPv6(host)) return Buffer.concat([Buffer.from([0, 0, 0, 0x04]), v6Bytes(host), portBytes, data]);
  const name = Buffer.from(host);
  return Buffer.concat([Buffer.from([0, 0, 0, 0x03, name.length]), name, portBytes, data]);
}

// ── The HTTP/2 session the flows share ──────────────────────────────────────────────────────────────────────────

type Conn = Pick<Connection, "server" | "currentPass">;

let h2: { key: string; session: http2.ClientHttp2Session; ready: Promise<void> } | null = null;

/** The HTTP/2 session to `server`, a new one if there's none (or only one to another server). */
function sessionTo(server: Server): { session: http2.ClientHttp2Session; ready: Promise<void> } {
  const key = `${server.hostname} ${server.ip ?? ""} ${server.port}`;
  if (h2 && h2.key === key && !h2.session.closed && !h2.session.destroyed) return h2;
  h2?.session.close();
  const session = http2.connect(`https://${server.hostname}:${server.port}`, {
    createConnection: () => tls.connect({ host: server.ip ?? server.hostname, port: server.port, servername: server.hostname, ALPNProtocols: ["h2"] }),
    settings: { initialWindowSize: 1 << 20 },
  });
  const gone = () => void (h2?.session === session && (h2 = null));
  session.on("error", (e) => log(`udp: the VPN's HTTP/2 session failed: ${e.message}`)).on("close", gone).on("goaway", gone);
  session.unref(); // an idle session never keeps foxhole running
  // extended CONNECT (:protocol) is only asked for once the server's SETTINGS allow it
  const ready = new Promise<void>((resolve, reject) => {
    session.once("remoteSettings", (s) => (s.enableConnectProtocol ? resolve() : reject(new Error("the VPN server doesn't take connect-udp"))));
    session.once("close", () => reject(new Error("closed")));
  });
  ready.catch(() => {});
  h2 = { key, session, ready };
  return h2;
}

/** Closes the session (the proxy's closing). */
export function closeUdp(): void {
  h2?.session.close();
  h2 = null;
}

// Ports the VPN refused (Fastly's Proxy-Status: destination_ip_prohibited), not asked for again for a while
const refused = new Map<number, number>();
const REFUSED_MS = 10 * 60_000;
const QUIC = new Set([80, 443]);
const IDLE_MS = 60_000; // a flow nothing went through for this long is closed (tun2socks' own UDP timeout is 60 s)
const MAX_FLOWS = 256; // per association
const QUEUE = 64; // datagrams held while a flow's stream opens

/** Whether UDP to `port` is worth sending to the VPN: not QUIC, not a port it refused lately. */
export function udpPortOk(port: number, now = Date.now()): boolean {
  return !QUIC.has(port) && (refused.get(port) ?? 0) <= now;
}

interface Flow {
  at: number; // last datagram either way
  retryAt?: number; // a flow that failed to open: datagrams to its destination are dropped till then
  close(): void;
  send(data: Buffer): void;
}
const RETRY_MS = 5000;

/** A flow through the VPN to `host`:`port`: a connect-udp stream, opened as its first datagram comes. Its data's counted to `site`. */
function vpnFlow(conn: Conn, host: string, port: number, back: (data: Buffer) => void, done: (failed: boolean) => void, site = host): Flow {
  let queue: Buffer[] | null = [];
  let stream: http2.ClientHttp2Stream | null = null;
  let closed = false;
  const flow: Flow = {
    at: Date.now(),
    close: () => {
      if (closed) return;
      closed = true;
      stream?.close();
      done(!!queue); // still queueing: it never opened
    },
    send: (data) => {
      flow.at = Date.now();
      count(site, "vpn", data.length);
      if (queue) return void (queue.length < QUEUE && queue.push(data));
      stream?.write(capsule(data));
    },
  };
  void (async () => {
    await Promise.resolve(); // the caller has its flow before this can close it
    const server = conn.server;
    if (!server) return flow.close();
    const { session, ready } = sessionTo(server);
    const pass = await conn.currentPass();
    await ready;
    if (closed) return;
    const s = (stream = session.request(
      {
        ":method": "CONNECT",
        ":protocol": "connect-udp",
        ":scheme": "https",
        ":authority": `${server.hostname}:${server.port}`,
        ":path": `/.well-known/masque/udp/${encodeURIComponent(host)}/${port}/`,
        "capsule-protocol": "?1",
        "proxy-authorization": `Bearer ${pass.token}`,
      },
      { endStream: false },
    ));
    s.on("error", () => flow.close()).on("close", () => flow.close());
    s.once("response", (headers) => {
      if (headers[":status"] !== 200) {
        if (/destination_ip_prohibited/.test(String(headers["proxy-status"] ?? ""))) {
          if ((refused.get(port) ?? 0) <= Date.now()) log(`udp: the VPN refuses port ${port} (${host})`);
          refused.set(port, Date.now() + REFUSED_MS);
        } else log(`udp: ${host}:${port} answered ${headers[":status"]}`);
        return flow.close();
      }
      for (const d of queue ?? []) s.write(capsule(d));
      queue = null;
    });
    let buf = Buffer.alloc(0);
    s.on("data", (chunk: Buffer) => {
      flow.at = Date.now();
      const { payloads, rest } = takeCapsules(buf.length ? Buffer.concat([buf, chunk]) : chunk);
      buf = Buffer.from(rest);
      for (const p of payloads) count(site, "vpn", p.length), back(p);
    });
  })().catch((err) => {
    log(`udp: can't open ${host}:${port} through the VPN: ${(err as Error).message}`);
    flow.close();
  });
  return flow;
}

/** How a direct datagram to `ip` gets past whole-system mode's tun ({} where nothing's needed), or null if it can't. */
export type PastTun = (ip: string) => Promise<{ localAddress?: string } | null>;

/**
 * Serves one SOCKS5 UDP ASSOCIATE: a relay socket on the address `client` reached us on, its datagrams each to the VPN
 * (a flow per destination) or direct, as the split rules say; answers come back the same way. It ends with `client`'s
 * connection, as RFC 1928 has it.
 */
export async function udpAssociate(client: net.Socket, conn: Conn, pastTun: PastTun): Promise<void> {
  const local = client.localAddress?.replace(/^::ffff:/, "") ?? "127.0.0.1";
  const peerIp = client.remoteAddress?.replace(/^::ffff:/, "");
  const relay = dgram.createSocket(net.isIPv6(local) ? "udp6" : "udp4");
  await new Promise<void>((resolve, reject) => relay.once("error", reject).bind(0, local, () => (relay.removeListener("error", reject), resolve())));
  const { port } = relay.address();
  const reply = Buffer.from([0x05, 0x00, 0x00, ...(net.isIPv6(local) ? [0x04, ...v6Bytes(local)] : [0x01, ...local.split(".").map(Number)]), port >> 8, port & 0xff]);
  client.write(reply);

  let peer: { address: string; port: number } | null = null; // where the client sends from, and gets its answers
  const flows = new Map<string, Flow>();
  const direct: Partial<Record<"udp4" | "udp6", dgram.Socket>> = {};
  const toClient = (host: string, p: number, data: Buffer) => peer && relay.send(udpReply(host, p, data), peer.port, peer.address);

  const directSocket = (family: "udp4" | "udp6", localAddress?: string) => {
    let s = direct[family];
    if (s) return s;
    s = direct[family] = dgram.createSocket(family);
    s.on("error", () => {}).on("message", (m, r) => toClient(r.address, r.port, m));
    if (localAddress && family === "udp4") s.bind(0, localAddress);
    return s;
  };

  const sweep = setInterval(() => {
    const old = Date.now() - IDLE_MS;
    for (const f of flows.values()) if (f.at < old) f.close();
  }, IDLE_MS / 2);
  sweep.unref();

  relay.on("error", () => client.destroy());
  relay.on("message", (msg, rinfo) => {
    if (rinfo.address.replace(/^::ffff:/, "") !== peerIp) return; // only the client that asked
    peer ??= { address: rinfo.address, port: rinfo.port };
    const d = parseUdpRequest(msg);
    if (!d || !d.port) return;
    const key = `${d.host} ${d.port}`;
    const flow = flows.get(key);
    if (flow && !(flow.retryAt && flow.retryAt <= Date.now())) return flow.send(d.data);
    if (flows.size >= MAX_FLOWS && !flow) return;
    const ip = net.isIP(d.host) ? d.host : undefined;
    const name = ip ? nameOf(ip) : d.host;
    const via = route(name, ip);
    if (via === "direct") {
      let how: ReturnType<PastTun> | null = null; // asked once: on macOS it routes the address around the tun
      const f: Flow = {
        at: Date.now(),
        close: () => flows.delete(key),
        send: (data) => {
          f.at = Date.now();
          void (how ??= pastTun(ip ?? d.host)).then((past) => {
            if (!past) return;
            directSocket(net.isIPv6(ip ?? "") ? "udp6" : "udp4", past.localAddress).send(data, d.port, d.host);
          });
        },
      };
      flows.set(key, f);
      return f.send(d.data);
    }
    if (!udpPortOk(d.port)) {
      // QUIC (browsers then use TCP) or a port the VPN refused lately: dropped, and looked at again after a while
      const at = Date.now();
      return void flows.set(key, { at, retryAt: at + RETRY_MS, close: () => flows.delete(key), send: () => {} });
    }
    const f = vpnFlow(conn, d.host, d.port, (data) => toClient(d.host, d.port, data), (failed) => {
      if (flows.get(key) !== f) return;
      if (!failed) return void flows.delete(key);
      const at = Date.now();
      flows.set(key, { at, retryAt: at + RETRY_MS, close: () => flows.delete(key), send: () => {} });
    }, name ?? d.host);
    flows.set(key, f);
    f.send(d.data);
  });

  const end = () => {
    clearInterval(sweep);
    for (const f of [...flows.values()]) f.close();
    relay.close();
    for (const s of Object.values(direct)) s?.close();
  };
  client.on("data", () => {}); // nothing more comes on it; it's only held open
  client.once("close", end);
  client.once("error", () => client.destroy());
}
