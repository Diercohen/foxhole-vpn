import dgram from "node:dgram";
import net from "node:net";
import tls from "node:tls";
import { viaOf } from "./split.js";

// A local DNS resolver that forwards every query as DNS-over-HTTPS (RFC 8484)
// *through the SOCKS proxy*. This keeps name resolution inside the tunnel on
// port 443 (the VPN forbids port 53 and can't carry UDP), so lookups aren't
// visible to — or blockable by — the local network. The DoH wire format is the
// same bytes as a UDP DNS message, so queries pass through opaquely.

const SOCKS_V = 0x05;

export const DOH_HOST = "cloudflare-dns.com";

/** Reads a (maybe compressed) name at `off`: [lowercase name, offset after it]. Throws if malformed. */
function readName(m: Buffer, off: number): [string, number] {
  const labels: string[] = [];
  let end = -1; // after the first pointer: where the name ends in the message
  for (let jumps = 0; ; ) {
    const len = m[off];
    if (len === undefined) throw new RangeError("truncated");
    if ((len & 0xc0) === 0xc0) {
      if (end < 0) end = off + 2;
      if (++jumps > 16) throw new RangeError("pointer loop");
      off = m.readUInt16BE(off) & 0x3fff;
    } else if (len === 0) {
      return [labels.join(".").toLowerCase(), end < 0 ? off + 1 : end];
    } else {
      labels.push(m.toString("latin1", off + 1, off + 1 + len));
      off += 1 + len;
    }
  }
}

/** The (first) name a DNS message asks about, or null if malformed. Pure. */
export function questionName(msg: Buffer): string | null {
  try {
    return msg.readUInt16BE(4) ? readName(msg, 12)[0] : null;
  } catch {
    return null;
  }
}

/** The IPv4 addresses in a DNS answer, with their TTLs (what parses of a cut-off one). Pure. */
export function answerAddrs(msg: Buffer): { ip: string; ttl: number }[] {
  const out: { ip: string; ttl: number }[] = [];
  try {
    let off = 12;
    for (let q = msg.readUInt16BE(4); q > 0; q--) off = readName(msg, off)[1] + 4;
    for (let a = msg.readUInt16BE(6); a > 0; a--) {
      off = readName(msg, off)[1];
      const type = msg.readUInt16BE(off), ttl = msg.readUInt32BE(off + 4), len = msg.readUInt16BE(off + 8);
      if (type === 1 && len === 4 && off + 14 <= msg.length) out.push({ ip: [...msg.subarray(off + 10, off + 14)].join("."), ttl });
      off += 10 + len;
    }
  } catch {
    /* cut off: what was read */
  }
  return out;
}

// Which site each address was looked up for: global mode's tun2socks gives the proxy only
// addresses, and split tunneling decides by name. The newest lookup of an address wins.
const names = new Map<string, { name: string; until: number }>();

/** The site a recent lookup through this forwarder gave `ip` for. */
export function nameOf(ip: string): string | undefined {
  const e = names.get(ip);
  return e && e.until > Date.now() ? e.name : undefined;
}

function remember(answer: Buffer): void {
  const name = questionName(answer);
  if (!name) return;
  for (const { ip, ttl } of answerAddrs(answer)) {
    names.delete(ip); // re-added last: the oldest go first
    names.set(ip, { name, until: Date.now() + Math.max(ttl, 300) * 1000 }); // apps keep an address past its TTL
  }
  for (const ip of names.keys()) {
    if (names.size <= 10_000) break;
    names.delete(ip);
  }
}

/** Asks the local network's resolver over UDP, from `from` (global mode routes that out the uplink). Rejects on a timeout or a cut-off answer. */
function askLocal(q: Buffer, server: string, from: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket("udp4");
    let open = true;
    const done = (err: Error | null, m?: Buffer) => {
      if (!open) return;
      open = false;
      clearTimeout(timer);
      s.close();
      if (err) reject(err);
      else resolve(m!);
    };
    const timer = setTimeout(() => done(new Error("timed out")), 2000);
    s.on("error", (e) => done(e));
    s.on("message", (m) => m.readUInt16BE(0) === q.readUInt16BE(0) && done(m[2] & 0x02 ? new Error("truncated") : null, m));
    s.bind(0, from, () => s.send(q, 53, server));
  });
}

/** Opens a TCP tunnel to host:port through a SOCKS5 proxy, using a DOMAIN name
 * (so the proxy resolves it server-side — no bootstrap IP needed). */
function socksConnect(socksHost: string, socksPort: number, host: string, port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const s = net.connect(socksPort, socksHost);
    let stage = 0;
    const onData = (d: Buffer) => {
      if (stage === 0) {
        if (d[0] !== SOCKS_V || d[1] !== 0x00) return reject(new Error("SOCKS5 no-auth refused"));
        const h = Buffer.from(host, "ascii");
        s.write(Buffer.concat([Buffer.from([SOCKS_V, 0x01, 0x00, 0x03, h.length]), h, Buffer.from([port >> 8, port & 0xff])]));
        stage = 1;
      } else {
        s.removeListener("data", onData);
        if (d[1] !== 0x00) return reject(new Error(`SOCKS5 connect failed (reply ${d[1]})`));
        resolve(s);
      }
    };
    s.on("data", onData);
    s.once("error", reject);
    s.once("connect", () => s.write(Buffer.from([SOCKS_V, 0x01, 0x00])));
  });
}

/** Keeps one reusable TLS connection to a DoH endpoint over the SOCKS proxy and
 * serialises queries over it (reconnecting on failure). */
export class DohClient {
  readonly #socksHost: string;
  readonly #socksPort: number;
  readonly #dohHost: string;
  #sock: tls.TLSSocket | null = null;
  #chain: Promise<unknown> = Promise.resolve();

  constructor(socksHost: string, socksPort: number, dohHost: string) {
    this.#socksHost = socksHost;
    this.#socksPort = socksPort;
    this.#dohHost = dohHost;
  }

  /** Resolves a raw DNS query to a raw DNS answer. Serialised. */
  query(q: Buffer): Promise<Buffer> {
    const run = () => this.#doQuery(q);
    const p = this.#chain.then(run, run);
    this.#chain = p.catch(() => {});
    return p;
  }

  async #doQuery(q: Buffer): Promise<Buffer> {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        return await this.#request(await this.#ensure(), q);
      } catch (err) {
        this.#sock?.destroy();
        this.#sock = null;
        if (attempt === 1) throw err;
      }
    }
    throw new Error("unreachable");
  }

  async #ensure(): Promise<tls.TLSSocket> {
    if (this.#sock && !this.#sock.destroyed) return this.#sock;
    const raw = await socksConnect(this.#socksHost, this.#socksPort, this.#dohHost, 443);
    const sock = tls.connect({ socket: raw, servername: this.#dohHost, ALPNProtocols: ["http/1.1"] });
    await new Promise<void>((res, rej) => {
      sock.once("secureConnect", res);
      sock.once("error", rej);
    });
    this.#sock = sock;
    return sock;
  }

  #request(sock: tls.TLSSocket, q: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let buf = Buffer.alloc(0);
      let bodyStart = -1;
      let bodyLen = -1;
      const timer = setTimeout(() => done(new Error("DoH timeout")), 10000);
      const done = (err?: Error, out?: Buffer) => {
        clearTimeout(timer);
        sock.removeListener("data", onData);
        sock.removeListener("error", onErr);
        if (err) reject(err);
        else resolve(out!);
      };
      const onErr = (e: Error) => done(e);
      const onData = (d: Buffer) => {
        buf = Buffer.concat([buf, d]);
        if (bodyStart < 0) {
          const i = buf.indexOf("\r\n\r\n");
          if (i < 0) return;
          const head = buf.toString("latin1", 0, i);
          const status = Number(head.split(" ")[1]);
          if (status !== 200) return done(new Error(`DoH HTTP ${status}`));
          const m = head.match(/content-length:\s*(\d+)/i);
          if (!m) return done(new Error("DoH response had no content-length"));
          bodyLen = Number(m[1]);
          bodyStart = i + 4;
        }
        if (buf.length >= bodyStart + bodyLen) done(undefined, buf.subarray(bodyStart, bodyStart + bodyLen));
      };
      sock.on("data", onData);
      sock.once("error", onErr);
      sock.write(
        `POST /dns-query HTTP/1.1\r\nHost: ${this.#dohHost}\r\n` +
          `Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n` +
          `Content-Length: ${q.length}\r\nConnection: keep-alive\r\n\r\n`,
      );
      sock.write(q);
    });
  }

  close(): void {
    this.#sock?.destroy();
    this.#sock = null;
  }
}

export interface DnsForwarder {
  port: number; // the port it listens on, UDP and TCP (the one picked, when asked for 0)
  close(): Promise<void>;
}

export interface DnsForwarderOptions {
  socksHost: string;
  socksPort: number;
  dohHost: string;
  host: string;
  port: number; // 0: any port free for both UDP and TCP
  /** Parallel DoH connections; each serialises its queries. Default 1. */
  connections?: number;
  /** Split tunneling: the local network's resolver for sites that go direct, and the address to ask it from. */
  local?: () => { server: string; from: string } | null;
  /** Each answer's name and IPv4 addresses, awaited before it's returned (macOS routes direct sites then). */
  onAnswer?: (name: string, ips: string[]) => Promise<void>;
}

/** Starts a UDP+TCP DNS listener that forwards every query via DoH-over-SOCKS. */
export async function startDnsForwarder(o: DnsForwarderOptions): Promise<DnsForwarder> {
  const pool = Array.from({ length: o.connections ?? 1 }, () => ({
    doh: new DohClient(o.socksHost, o.socksPort, o.dohHost),
    busy: 0,
  }));
  // Send each query down the least-busy connection.
  const doh = async (q: Buffer): Promise<Buffer> => {
    const c = pool.reduce((a, b) => (b.busy < a.busy ? b : a));
    c.busy++;
    try {
      return await c.doh.query(q);
    } finally {
      c.busy--;
    }
  };
  // A site that goes direct is looked up where it'll be reached, on the local network (local
  // answers, no VPN data), else through the tunnel. Every answer is remembered for the proxy.
  const query = async (q: Buffer): Promise<Buffer> => {
    const name = questionName(q);
    const local = name && viaOf(name) === "direct" ? o.local?.() : null;
    const ans = (local && (await askLocal(q, local.server, local.from).catch(() => null))) || (await doh(q));
    remember(ans);
    if (name && o.onAnswer) await o.onAnswer(name, answerAddrs(ans).map((a) => a.ip)).catch(() => {});
    return ans;
  };

  // Only this computer may ask: Linux takes any of its addresses on any interface, so a neighbour could
  // reach a non-loopback listener (global mode's, on the tun) and look things up through the user's VPN.
  const local = (addr = "") => addr === o.host || addr.startsWith("127.");

  const onTcp = (sock: net.Socket) => {
    if (!local(sock.remoteAddress)) return void sock.destroy();
    let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      // DNS-over-TCP frames each message with a 2-byte length prefix.
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0);
        const q = buf.subarray(2, 2 + len);
        buf = buf.subarray(2 + len);
        query(q)
          .then((ans) => {
            const out = Buffer.alloc(2 + ans.length);
            out.writeUInt16BE(ans.length, 0);
            ans.copy(out, 2);
            sock.write(out);
          })
          .catch(() => sock.destroy());
      }
    });
    sock.on("error", () => sock.destroy());
  };

  for (let attempt = 1; ; attempt++) {
    const tcp = net.createServer(onTcp);
    const udp = dgram.createSocket("udp4");
    udp.on("message", (msg, rinfo) => {
      if (!local(rinfo.address)) return;
      query(msg)
        .then((ans) => udp.send(ans, rinfo.port, rinfo.address))
        .catch(() => {});
    });
    try {
      await new Promise<void>((res, rej) => {
        tcp.once("error", rej);
        tcp.listen(o.port, o.host, res);
      });
      const port = (tcp.address() as net.AddressInfo).port;
      await new Promise<void>((res, rej) => {
        udp.once("error", rej);
        udp.bind(port, o.host, res);
      });
      return {
        port,
        close: async () => {
          for (const c of pool) c.doh.close();
          udp.close();
          await new Promise<void>((r) => tcp.close(() => r()));
        },
      };
    } catch (err) {
      tcp.close();
      try {
        udp.close();
      } catch {
        /* never bound */
      }
      // A free TCP port's UDP twin can still be taken (e.g. by mDNS on 5353): pick another.
      if (o.port !== 0 || attempt >= 5) throw err;
    }
  }
}
