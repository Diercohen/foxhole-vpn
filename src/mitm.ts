// Relay mode reads HTTPS to carry it (an Apps Script relay can only fetch URLs, not pass bytes): the browser's TLS
// ends here, with a certificate for the site made on the fly and signed by a CA made on this computer the first
// time, which the user trusts once (catrust.ts). Node can't make certificates, so they're written out in DER here
// and signed with node:crypto. EC P-256 throughout: one key for every site's certificate, made once a run.
import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate, createPrivateKey, type KeyObject } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, join } from "node:path";
import tls from "node:tls";
import { userHome } from "./profile.js";

// ── DER, as much as a certificate needs ─────────────────────────────────────────────────────

function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...len]), body]);
}
const seq = (...p: Buffer[]) => der(0x30, ...p);
const set = (...p: Buffer[]) => der(0x31, ...p);
const int = (b: Buffer) => der(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
const utf8 = (s: string) => der(0x0c, Buffer.from(s, "utf8"));
const bits = (b: Buffer, unused = 0) => der(0x03, Buffer.from([unused]), b);
const octets = (b: Buffer) => der(0x04, b);
const TRUE = der(0x01, Buffer.from([0xff]));
function oid(s: string): Buffer {
  const [a, b, ...rest] = s.split(".").map(Number);
  const out = [40 * a + b];
  for (let v of rest) {
    const enc = [v & 0x7f];
    while ((v >>= 7)) enc.unshift(0x80 | (v & 0x7f));
    out.push(...enc);
  }
  return der(0x06, Buffer.from(out));
}
/** UTCTime until 2049, then GeneralizedTime, as RFC 5280 says. */
function time(d: Date): Buffer {
  const s = d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
  return d.getUTCFullYear() < 2050 ? der(0x17, Buffer.from(s.slice(2))) : der(0x18, Buffer.from(s));
}
const ext = (id: string, critical: boolean, value: Buffer) => seq(oid(id), ...(critical ? [TRUE] : []), octets(value));
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), utf8(cn))), set(seq(oid("2.5.4.10"), utf8("Foxhole"))));
const ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"));
const DAY = 86_400_000;

/** A certificate for `subject`'s public key, signed by `issuerKey`. PEM. */
function certificate(o: { subject: string; issuer: string; pub: KeyObject; issuerKey: KeyObject; days: number; exts: Buffer[] }): string {
  const now = Date.now();
  const serial = randomBytes(16);
  serial[0] = (serial[0] & 0x7f) | 0x01; // positive, and never 0
  const tbs = seq(
    der(0xa0, int(Buffer.from([2]))), // v3
    int(serial),
    ECDSA_SHA256,
    name(o.issuer),
    seq(time(new Date(now - DAY)), time(new Date(now + o.days * DAY))), // a day back: a clock a little behind still takes it
    name(o.subject),
    o.pub.export({ type: "spki", format: "der" }),
    der(0xa3, seq(...o.exts)),
  );
  const cert = seq(tbs, ECDSA_SHA256, bits(sign("sha256", tbs, o.issuerKey)));
  return new X509Certificate(cert).toString(); // also checks it parses
}

/** The key identifier for a public key: SHA-1 of its SubjectPublicKeyInfo (RFC 5280's other method). */
const keyId = (pub: KeyObject) => createHash("sha1").update(pub.export({ type: "spki", format: "der" })).digest();

// ── The CA ──────────────────────────────────────────────────────────────────────────────────

export const CA_NAME = "Foxhole Relay CA";

const dir = () => join(userHome(), ".config", "foxhole-vpn");
/** The CA's certificate (public: what's trusted), its key (private to the user), and Node's roots plus it, for tools that take one file. */
export const caFiles = () => ({ cert: join(dir(), "relay-ca.pem"), key: join(dir(), "relay-ca-key.pem"), bundle: join(dir(), "relay-ca-bundle.pem") });

let ca: { pem: string; key: KeyObject; id: Buffer } | null = null;

/** The CA, made and saved the first time. */
export function loadCa(): { pem: string; key: KeyObject; id: Buffer } {
  if (ca) return ca;
  const f = caFiles();
  if (existsSync(f.cert) && existsSync(f.key)) {
    const pem = readFileSync(f.cert, "utf8");
    const key = createPrivateKey(readFileSync(f.key, "utf8"));
    if (!existsSync(f.bundle)) writeFileSync(f.bundle, [...tls.rootCertificates, pem].join("\n"));
    return (ca = { pem, key, id: keyId(new X509Certificate(pem).publicKey) });
  }
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const id = keyId(publicKey);
  const pem = certificate({
    subject: CA_NAME,
    issuer: CA_NAME,
    pub: publicKey,
    issuerKey: privateKey,
    days: 3650,
    exts: [
      ext("2.5.29.19", true, seq(TRUE, int(Buffer.from([0])))), // a CA, signing only certificates for sites (pathlen 0)
      ext("2.5.29.15", true, bits(Buffer.from([0x86]), 1)), // digitalSignature, keyCertSign, cRLSign
      ext("2.5.29.14", false, octets(id)),
    ],
  });
  mkdirSync(dirname(f.cert), { recursive: true, mode: 0o700 });
  writeFileSync(f.key, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  chmodSync(f.key, 0o600);
  writeFileSync(f.cert, pem);
  writeFileSync(f.bundle, [...tls.rootCertificates, pem].join("\n"));
  return (ca = { pem, key: privateKey, id });
}

/** The CA's certificate as PEM, if it was made; null before relay mode was first used. */
export function caPem(file = caFiles().cert): string | null {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/** The CA's SHA-1 and SHA-256 fingerprints (hex, no colons): how the trust stores name it. */
export function caFingerprints(pem: string): { sha1: string; sha256: string } {
  const c = new X509Certificate(pem);
  return { sha1: c.fingerprint.replace(/:/g, ""), sha256: c.fingerprint256.replace(/:/g, "") };
}

// ── Sites' certificates ─────────────────────────────────────────────────────────────────────

let leafKey: { pub: KeyObject; pem: string; key: KeyObject } | null = null;
const contexts = new Map<string, tls.SecureContext>();

/** A TLS context for serving `host` (a name or an IP), its certificate made the first time and kept. */
export function siteContext(host: string): tls.SecureContext {
  host = host.toLowerCase().replace(/\.$/, "");
  let c = contexts.get(host);
  if (c) return c;
  const authority = loadCa();
  if (!leafKey) {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    leafKey = { pub: publicKey, key: privateKey, pem: privateKey.export({ type: "pkcs8", format: "pem" }) as string };
  }
  const ip = isIP(host);
  const san = ip
    ? der(0x87, ip === 4 ? Buffer.from(host.split(".").map(Number)) : ipv6Bytes(host))
    : der(0x82, Buffer.from(host, "ascii"));
  const cert = certificate({
    subject: host.slice(0, 64),
    issuer: CA_NAME,
    pub: leafKey.pub,
    issuerKey: authority.key,
    days: 396, // with the day back, 397 in all: under the 398 that browsers and Apple take for a site's certificate
    exts: [
      ext("2.5.29.15", true, bits(Buffer.from([0x80]), 7)), // digitalSignature
      ext("2.5.29.37", false, seq(oid("1.3.6.1.5.5.7.3.1"))), // for TLS servers
      ext("2.5.29.17", false, seq(san)),
      ext("2.5.29.35", false, seq(der(0x80, authority.id))),
    ],
  });
  c = tls.createSecureContext({ key: leafKey.pem, cert });
  if (contexts.size >= 2000) contexts.delete(contexts.keys().next().value!); // the oldest
  contexts.set(host, c);
  return c;
}

/** An IPv6 address's 16 bytes. */
function ipv6Bytes(s: string): Buffer {
  const [head, tail = ""] = s.split("::");
  const h = head ? head.split(":") : [];
  const t = s.includes("::") ? (tail ? tail.split(":") : []) : [];
  const groups = [...h, ...Array<string>(8 - h.length - t.length).fill("0"), ...t];
  return Buffer.from(groups.flatMap((g) => [parseInt(g, 16) >> 8, parseInt(g, 16) & 0xff]));
}
