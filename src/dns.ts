import dgram from "node:dgram";
import net from "node:net";
import tls from "node:tls";

// A local DNS resolver that forwards every query as DNS-over-HTTPS (RFC 8484)
// *through the SOCKS proxy*. This keeps name resolution inside the tunnel on
// port 443 (the VPN forbids port 53 and can't carry UDP), so lookups aren't
// visible to — or blockable by — the local network. The DoH wire format is the
// same bytes as a UDP DNS message, so queries pass through opaquely.

const SOCKS_V = 0x05;

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
  close(): Promise<void>;
}

export interface DnsForwarderOptions {
  socksHost: string;
  socksPort: number;
  dohHost: string;
  host: string;
  port: number;
}

/** Starts a UDP+TCP DNS listener that forwards every query via DoH-over-SOCKS. */
export async function startDnsForwarder(o: DnsForwarderOptions): Promise<DnsForwarder> {
  const doh = new DohClient(o.socksHost, o.socksPort, o.dohHost);

  const udp = dgram.createSocket("udp4");
  udp.on("message", (msg, rinfo) => {
    doh
      .query(msg)
      .then((ans) => udp.send(ans, rinfo.port, rinfo.address))
      .catch(() => {});
  });

  const tcp = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      // DNS-over-TCP frames each message with a 2-byte length prefix.
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0);
        const q = buf.subarray(2, 2 + len);
        buf = buf.subarray(2 + len);
        doh
          .query(q)
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
  });

  await new Promise<void>((res, rej) => {
    udp.once("error", rej);
    udp.bind(o.port, o.host, res);
  });
  await new Promise<void>((res, rej) => {
    tcp.once("error", rej);
    tcp.listen(o.port, o.host, res);
  });

  return {
    close: async () => {
      doh.close();
      udp.close();
      await new Promise<void>((r) => tcp.close(() => r()));
    },
  };
}
