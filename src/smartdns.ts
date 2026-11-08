// Smart DNS: this computer as the DNS server of the home's other devices (a TV, a game console, an iPhone), which then
// need no app. A site that needs the VPN is answered with this computer's address: Iran's filter blocks it (the
// network's DNS answers with the filter's address, this computer found it blocked, or a handshake with it just now was
// stopped, as a blocked site's CDN's is, whose DNS answers are real), it refuses Iran (the sanctioned list), or a rule
// sends it through the VPN. The device then connects here, on 443 or 80, and the site its first bytes
// name goes through the VPN (proxy.ts serveByName). Every other name gets the network's own answer and goes direct, on
// Iran's cheaper data. Only the web and WhatsApp's chat (on 5222 too) come here: a game's or a call's traffic doesn't.
import dgram from "node:dgram";
import dns from "node:dns";
import net from "node:net";
import type { Connection } from "./connection.js";
import { filteredByName, serveByName, type Target } from "./proxy.js";
import { currentSplit, ruleFor } from "./split.js";
import { filterAddress, iranian, knownBlocked, learnBlocked, refreshLists, sanctioned } from "./smart.js";
import { log } from "./log.js";

const TTL = 60; // seconds: a device asks again soon after connecting or disconnecting
const TRIED_MS = 3600_000; // a name's handshake isn't tried again for this long
const A = 1;
const AAAA = 28;

/** A query's question: its name (lowercased), type, and where it ends. Null if it isn't one plain question. Pure. */
export function questionOf(m: Buffer): { name: string; type: number; end: number } | null {
  if (m.length < 17 || m.readUInt16BE(4) !== 1 || m[2] & 0x80) return null; // a query, of one question
  const labels: string[] = [];
  let p = 12;
  for (let len = m[p]; len !== 0; len = m[p]) {
    if (len === undefined || len > 63) return null; // a question's name is never compressed
    labels.push(m.toString("latin1", p + 1, p + 1 + len));
    p += 1 + len;
  }
  if (p + 5 > m.length) return null;
  return { name: labels.join(".").toLowerCase(), type: m.readUInt16BE(p + 1), end: p + 5 };
}

/** The answer to query `q` (its question ending at `end`): `ip` for an A question, no records for the rest (AAAA, HTTPS: else a device could go around). Pure. */
export function answerWith(q: Buffer, end: number, type: number, ip: string): Buffer {
  const head = Buffer.from(q.subarray(0, end));
  head.writeUInt16BE(0x8080 | (q.readUInt16BE(2) & 0x7900), 2); // a response, recursion as asked, and available
  const rr = type === A ? Buffer.from([0xc0, 12, 0, A, 0, 1, 0, 0, 0, TTL, 0, 4, ...ip.split(".").map(Number)]) : Buffer.alloc(0);
  head.writeUInt16BE(rr.length ? 1 : 0, 6);
  head.writeUInt32BE(0, 8); // no authority, no additional records (the query's EDNS dropped)
  return Buffer.concat([head, rr]);
}

/** Past the (maybe compressed) name at `p`. */
function pastName(m: Buffer, p: number): number {
  for (;;) {
    const len = m[p];
    if (len === undefined) throw new RangeError("cut off");
    if (len >= 0xc0) return p + 2;
    if (len === 0) return p + 1;
    p += 1 + len;
  }
}

/** The addresses in `r`, a DNS answer, as far as it isn't cut off. Pure. */
function addressesIn(r: Buffer): string[] {
  const out: string[] = [];
  try {
    let p = pastName(r, 12) + 4;
    for (let i = r.readUInt16BE(6); i > 0; i--) {
      p = pastName(r, p);
      const type = r.readUInt16BE(p);
      const len = r.readUInt16BE(p + 8);
      const data = r.subarray(p + 10, p + 10 + len);
      if (type === A && len === 4) out.push(data.join("."));
      if (type === AAAA && len === 16) out.push(Array.from({ length: 8 }, (_, j) => data.readUInt16BE(j * 2).toString(16)).join(":"));
      p += 10 + len;
    }
  } catch {
    /* cut off: what came before */
  }
  return out;
}

/** True when `r`, the network's DNS's answer, gives Iran's filter's address: the name is blocked. Pure. */
export const filterAnswer = (r: Buffer): boolean => addressesIn(r).some(filterAddress);

/** Query `m` (its question ending at `end`) as an A question, without its EDNS. Pure. */
function askingA(m: Buffer, end: number): Buffer {
  const a = Buffer.from(m.subarray(0, end));
  a.writeUInt16BE(A, end - 4);
  a.writeUInt16BE(0, 10);
  return a;
}

/** A device of this network's (private, link-local, CGNAT, loopback addresses): the only ones served, so this isn't an open resolver. Pure. */
export const homeAddress = (a = ""): boolean =>
  /^(::ffff:)?(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(a) || a === "::1" || /^f[c-e][0-9a-f]{2}:/i.test(a);

/** A name that isn't on the internet. Pure. */
const onlyHere = (name: string): boolean => !name.includes(".") || /\.(local|lan|home\.arpa|arpa)$/.test(name);

/** Whether a device looking up `name` is answered with this computer, without asking the network: a rule, or a list, says it needs the VPN. */
function needsVpn(name: string): boolean {
  if (onlyHere(name)) return false;
  const rule = ruleFor(currentSplit(), name);
  return rule ? rule.via === "vpn" : sanctioned(name) || knownBlocked(name);
}

/** The network's own DNS server, where this computer asks ("ip" or "ip:port"): the first that isn't this server (`ours`). */
function upstream(ours: (host: string, port: number) => boolean): { host: string; port: number } | null {
  for (const s of dns.getServers()) {
    const m = /^\[(.+)\]:(\d+)$/.exec(s) ?? (net.isIP(s) ? [s, s, "53"] : /^(.+):(\d+)$/.exec(s));
    const host = m?.[1];
    if (host && net.isIP(host) && !ours(host, Number(m[2]))) return { host, port: Number(m[2]) };
  }
  return null;
}

/** `m` asked of the network's DNS server: its answer, or null after 4 s. */
function forward(m: Buffer, to: { host: string; port: number }): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const s = dgram.createSocket(net.isIPv6(to.host) ? "udp6" : "udp4");
    let over = false;
    const done = (r: Buffer | null) => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      s.close();
      resolve(r);
    };
    const timer = setTimeout(() => done(null), 4000);
    s.on("error", () => done(null));
    s.on("message", (r) => r.readUInt16BE(0) === m.readUInt16BE(0) && done(r));
    s.send(m, to.port, to.host);
  });
}

/**
 * Where Smart DNS listens: macOS lets an app have ports below 1024 on every address only (so it steps aside for
 * whole-system mode, whose DNS relay has 53 there too); elsewhere this computer's address on the network, not
 * loopback's, where Linux's systemd-resolved and Windows' whole-system DNS forwarder have 53.
 */
export const smartDnsHost = (lan: string | null): string | null => (process.platform === "darwin" ? "0.0.0.0" : lan);

/** Why Smart DNS couldn't start, for people. Pure. */
export function smartDnsProblem(err: NodeJS.ErrnoException & { port?: number }): string {
  if (err.code === "EACCES") return "Linux keeps ports 53, 80 and 443 for root. To let Foxhole have them: sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53";
  if (err.code === "EADDRINUSE") return `Port ${err.port ?? 53} is taken by another app here (a DNS server, Internet Sharing, a web server): quit it, then turn this on again.`;
  return err.message;
}

export interface SmartDns {
  ports: { dns: number; https: number; http: number; chat: number }; // where it listens (tests ask for any)
  close(): void;
}

/**
 * Serves DNS (UDP) and the web on `host`: `self` is this computer's address on the network, `vpn` says it's connected
 * through Firefox VPN (till then every lookup gets the network's own answer, so the devices still have the rest).
 * Throws if a port can't be had (EACCES: Linux keeps those below 1024 for root; EADDRINUSE: another DNS server).
 */
export async function startSmartDns(
  conn: Connection,
  o: { host: string; self: () => string | null; vpn: () => boolean; ports?: { dns: number; https: number; http: number; chat: number }; sites?: Target },
): Promise<SmartDns> {
  const want = o.ports ?? { dns: 53, https: 443, http: 80, chat: 5222 };
  const tried = new Map<string, { until: number; stopped: Promise<boolean> }>();
  /** Whether the filter stops `name` at its handshake. Once for a device's A, AAAA and HTTPS questions, which come together. */
  const stopped = (name: string, m: Buffer, end: number, to: { host: string; port: number }): Promise<boolean> => {
    if (onlyHere(name) || ruleFor(currentSplit(), name) || iranian(name)) return Promise.resolve(false);
    const had = tried.get(name);
    if (had && had.until > Date.now()) return had.stopped;
    if (tried.size >= 5000) tried.clear();
    const verdict = forward(askingA(m, end), to).then((r) => {
      const ip = r && addressesIn(r)[0];
      if (!ip || iranian(name, ip)) return false;
      return filterAddress(ip) || (!homeAddress(ip) && filteredByName(name, o.sites ?? { host: ip, port: 443 }));
    });
    tried.set(name, { until: Date.now() + TRIED_MS, stopped: verdict });
    return verdict;
  };
  const reply = async (m: Buffer): Promise<Buffer | null> => {
    const q = questionOf(m);
    if (!q) return null;
    const self = o.vpn() ? o.self() : null;
    if (self) void refreshLists(); // the sanctioned list if it isn't here yet: connected, it comes through the VPN
    if (self && needsVpn(q.name)) return answerWith(m, q.end, q.type, self);
    const to = upstream(ours);
    const r = to && (await forward(m, to));
    if (r && to && self && (filterAnswer(r) || (await stopped(q.name, m, q.end, to)))) {
      learnBlocked(q.name); // this computer's own connections skip trying it too (save data)
      return answerWith(m, q.end, q.type, self);
    }
    return r;
  };
  const udp = dgram.createSocket(net.isIPv6(o.host) ? "udp6" : "udp4");
  // a resolver this server itself answers on (this computer's DNS set to itself): asking it would go round and round
  const ours = (host: string, port: number) =>
    port === udp.address().port && (host === o.host || (o.host === "0.0.0.0" && (host.startsWith("127.") || host === o.self())));
  udp.on("message", (m, from) => {
    if (homeAddress(from.address)) void reply(m).then((r) => r && udp.send(r, from.port, from.address), () => {});
  });
  const sockets = new Set<net.Socket>();
  const web = ([[want.https, 443], [want.http, 80], [want.chat, 5222]] as const).map(([at, port]) => ({
    at,
    srv: net.createServer((s) => {
      if (!homeAddress(s.remoteAddress)) return void s.destroy();
      sockets.add(s);
      s.once("close", () => sockets.delete(s));
      void serveByName(s, conn, port);
    }),
  }));
  const close = () => {
    try {
      udp.close();
    } catch {
      /* never bound */
    }
    for (const w of web) w.srv.close();
    for (const s of sockets) s.destroy();
  };
  try {
    await new Promise<void>((res, rej) => udp.once("error", rej).bind(want.dns, o.host, () => (udp.removeListener("error", rej), res())));
    for (const w of web) await new Promise<void>((res, rej) => w.srv.once("error", rej).listen(w.at, o.host, () => (w.srv.removeListener("error", rej), res())));
  } catch (err) {
    close();
    throw err;
  }
  udp.on("error", (err) => log(`smart dns: ${err.message}`));
  const ports = { dns: udp.address().port, https: (web[0].srv.address() as net.AddressInfo).port, http: (web[1].srv.address() as net.AddressInfo).port, chat: (web[2].srv.address() as net.AddressInfo).port };
  log(`smart dns: on ${o.host}, DNS on ${ports.dns}, the web on ${ports.https} and ${ports.http}, WhatsApp's chat on ${ports.chat}`);
  return { ports, close };
}
