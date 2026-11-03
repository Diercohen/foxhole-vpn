// Signing a TV in from a computer or phone that has Foxhole (Android TV, mobile/). The TV waits on the local network,
// its screen showing a QR code (its address, its key and a secret) and a 6-character code. The other device, signed
// in, finds it (from the QR code, or by looking for it on its own network with the code) and sends it a sign-in of
// its own: a VPN-only refresh token (auth.ts), encrypted to the TV's key (X25519, AES-GCM) with the secret, or with
// the code stretched by scrypt, so what's sent can't be read on the network, nor the code guessed from it offline.
import { createCipheriv, createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, randomInt, scrypt, type KeyObject } from "node:crypto";
import http from "node:http";
import { networkInterfaces } from "node:os";

/** The port a TV waits on. */
export const TV_PORT = 47533;
const PATH = "/foxhole-tv";
const INFO = "foxhole tv sign-in v1";
/** The code's letters and digits: none that look alike (0 O, 1 I L). */
const ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
/** Wrong codes a TV takes before it shows a new one. */
const TRIES = 5;

export interface TvAccount {
  uid: string;
  email: string;
  refreshToken: string;
}

const b64 = (b: Buffer) => b.toString("base64url");
const unb64 = (s: string) => Buffer.from(s, "base64url");
const rawPub = (k: KeyObject) => unb64(k.export({ format: "jwk" }).x as string);
const importPub = (raw: Buffer) => createPublicKey({ key: { kty: "OKP", crv: "X25519", x: b64(raw) }, format: "jwk" });

/** The code as typed: capitals, without spaces or dashes; null if it can't be one. Pure. */
export function normalizeCode(text: string): string | null {
  const c = text.toUpperCase().replace(/[\s-]/g, "");
  return c.length === 6 && [...c].every((ch) => ALPHABET.includes(ch)) ? c : null;
}

/** The code, stretched (scrypt, salted with the TV's key): each guess costs about 100 ms and 32 MB. */
const stretch = (code: string, tvPub: Buffer) =>
  new Promise<Buffer>((resolve, reject) =>
    scrypt(code, Buffer.concat([Buffer.from(INFO), tvPub]), 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, key) => (err ? reject(err) : resolve(key))),
  );

/** The message's key: both keys' shared secret, and the QR code's secret or the stretched code. */
const messageKey = (shared: Buffer, proof: Buffer, tvPub: Buffer, pub: Buffer) =>
  Buffer.from(hkdfSync("sha256", Buffer.concat([shared, proof]), Buffer.concat([tvPub, pub]), INFO, 32));

// ── The TV ──────────────────────────────────────────────────────────────────────────────────────────────────────

/** What the TV's screen shows while it waits. */
export interface TvWaiting {
  code: string;
  link: string | null; // the QR code's (null: no local network)
  host: string | null;
}

export interface TvSignIn {
  waiting(): TvWaiting;
  stop(): void;
}

/**
 * Waits for a sign-in from another device, on `port` of every interface. `accept` takes the account sent (and the
 * sender's name), and resolves once it's signed in with it (rejects: the sender is told why). `changed`: a new code.
 */
export async function waitForSignIn(opts: {
  name: string;
  host: () => string | null;
  accept: (account: TvAccount, from: string) => Promise<void>;
  changed: () => void;
  port?: number;
}): Promise<TvSignIn> {
  const port = opts.port ?? TV_PORT;
  const fresh = async () => {
    const { privateKey, publicKey } = generateKeyPairSync("x25519");
    const pub = rawPub(publicKey);
    const code = Array.from({ length: 6 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
    return { privateKey, pub, code, secret: randomBytes(16), codeKey: await stretch(code, pub), failures: 0 };
  };
  let keys = await fresh();
  let busy = false; // one sign-in at a time

  const answer = (res: http.ServerResponse, status: number, body: object) =>
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));

  const server = http.createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0];
    if (req.method === "GET" && path === PATH) return answer(res, 200, { foxhole: 1, name: opts.name, pub: b64(keys.pub) });
    if (req.method === "GET") return void res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(page(opts.name));
    if (req.method !== "POST" || path !== PATH) return answer(res, 404, { error: "not here" });
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => ((body += c), body.length > 16_384 && req.destroy()));
    req.on("end", async () => {
      if (busy) return answer(res, 409, { error: "the TV is signing in already" });
      busy = true;
      try {
        const m = JSON.parse(body) as { pub?: string; via?: string; iv?: string; ct?: string };
        const pub = unb64(String(m.pub ?? ""));
        const proof = m.via === "qr" ? keys.secret : keys.codeKey;
        let account: TvAccount & { from?: string };
        try {
          const key = messageKey(diffieHellman({ privateKey: keys.privateKey, publicKey: importPub(pub) }), proof, keys.pub, pub);
          const all = unb64(String(m.ct ?? ""));
          const d = createDecipheriv("aes-256-gcm", key, unb64(String(m.iv ?? "")));
          d.setAAD(Buffer.from(INFO));
          d.setAuthTag(all.subarray(all.length - 16));
          account = JSON.parse(Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]).toString("utf8"));
        } catch {
          // a wrong code (or a damaged message): after a few, a new code, so they can't be tried one by one
          if (++keys.failures >= TRIES) (keys = await fresh()), opts.changed();
          return answer(res, 403, { error: m.via === "qr" ? "that QR code isn't this TV's anymore" : "that isn't the code on the TV" });
        }
        const { uid, email, refreshToken, from } = account;
        if (![uid, email, refreshToken].every((v) => typeof v === "string" && v)) return answer(res, 400, { error: "no account in it" });
        await opts.accept({ uid, email, refreshToken }, typeof from === "string" ? from.slice(0, 80) : "");
        answer(res, 200, { ok: true, name: opts.name });
      } catch (err) {
        answer(res, 400, { error: (err as Error).message });
      } finally {
        busy = false;
      }
    });
  });
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(port, "0.0.0.0", () => resolve()));
  return {
    waiting: () => {
      const host = opts.host();
      return { code: keys.code, host, link: host ? `http://${host}:${port}/#${b64(keys.secret)}.${b64(keys.pub)}` : null };
    },
    stop: () => void server.close(),
  };
}

/** The page a phone's camera app opens from the QR code: open it in Foxhole (Android), or how to. */
function page(name: string): string {
  const tv = name.replace(/[<>&"']/g, "");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in ${tv}</title><style>body{font:17px/1.5 system-ui,sans-serif;background:#07060c;color:#f6f3fb;margin:0;padding:32px 24px;text-align:center}
a{display:inline-block;margin:18px 0;padding:14px 26px;border-radius:14px;background:#ff7a1a;color:#fff;font-weight:700;text-decoration:none}p{color:#cfc8dc}</style></head>
<body><h2>Sign in ${tv}</h2><p>Open this in <b>Foxhole</b>, signed in, to send the TV a sign-in.</p>
<a id="open" href="#">Open in Foxhole</a>
<p>No button? Open Foxhole on this phone or a computer on the same Wi-Fi: <b>Settings → Sign in a TV</b>, and scan the TV's code there or type the code shown on the TV.</p>
<script>document.getElementById("open").href="intent://tv?l="+encodeURIComponent(location.href)+"#Intent;scheme=foxhole;package=io.github.diercohen.foxhole;end";</script>
</body></html>`;
}

// ── The computer or phone ───────────────────────────────────────────────────────────────────────────────────────

/** A TV found waiting. */
export interface Tv {
  host: string;
  port: number;
  name: string;
  pub: string;
  secret?: string; // from its QR code
}

/** The TV in a QR code's link (or one the app was opened with); null if it isn't one. Pure. */
export function parseTvLink(text: string): Tv | null {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    return null;
  }
  const [secret, pub] = url.hash.slice(1).split(".");
  if (url.protocol !== "http:" || !secret || !pub || unb64(pub).length !== 32 || unb64(secret).length !== 16) return null;
  return { host: url.hostname, port: Number(url.port) || 80, name: "", pub, secret };
}

/** This device's local networks: its address on each, and the /24 around it. */
function lanAddresses(): string[] {
  const out: string[] = [];
  for (const [name, addrs] of Object.entries(networkInterfaces())) {
    if (/^(lo|docker|br-|veth|virbr|tun|tap|wg|utun|ppp|tailscale|zt|foxhole|vEthernet|Loopback)/i.test(name)) continue;
    for (const a of addrs ?? []) if (a.family === "IPv4" && !a.internal && !a.address.startsWith("169.254.")) out.push(a.address);
  }
  return out;
}

/** Asks one address whether a TV waits there; its details, or null. */
async function ask(host: string, port: number, ms: number): Promise<Tv | null> {
  try {
    const res = await fetch(`http://${host}:${port}${PATH}`, { signal: AbortSignal.timeout(ms) });
    const d = (await res.json()) as { foxhole?: number; name?: string; pub?: string };
    return d.foxhole === 1 && typeof d.pub === "string" ? { host, port, name: String(d.name ?? "TV"), pub: d.pub } : null;
  } catch {
    return null;
  }
}

/**
 * The TVs waiting on this device's networks: every address of the /24 around each of its own is asked at once.
 * ponytail: a /24 only; a bigger network's TV elsewhere in it is found from its QR code.
 */
export async function findTvs(ms = 2500): Promise<Tv[]> {
  const hosts = new Set<string>();
  for (const a of lanAddresses()) {
    const base = a.split(".").slice(0, 3).join(".");
    for (let i = 1; i < 255; i++) if (`${base}.${i}` !== a) hosts.add(`${base}.${i}`);
  }
  const found = await Promise.all([...hosts].map((h) => ask(h, TV_PORT, ms)));
  return found.filter((t): t is Tv => !!t);
}

/** The TV's details again, from its QR code's address (its name, and that it's still waiting). */
export const askTv = (tv: Tv, ms = 4000) => ask(tv.host, tv.port, ms);

/**
 * Sends `account` to `tv`, with its QR code's secret or the code typed. Resolves once the TV is signed in with it;
 * rejects with the TV's answer (a wrong code: "that isn't the code on the TV").
 */
export async function sendToTv(tv: Tv, proofOf: { code?: string }, account: TvAccount, from: string): Promise<void> {
  const tvPub = unb64(tv.pub);
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const pub = rawPub(publicKey);
  const code = proofOf.code ? normalizeCode(proofOf.code) : null;
  if (!tv.secret && !code) throw new Error("the code is 6 letters and digits, as on the TV");
  const proof = tv.secret ? unb64(tv.secret) : await stretch(code as string, tvPub);
  const key = messageKey(diffieHellman({ privateKey, publicKey: importPub(tvPub) }), proof, tvPub, pub);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(INFO));
  const ct = Buffer.concat([c.update(JSON.stringify({ ...account, from }), "utf8"), c.final(), c.getAuthTag()]);
  const res = await fetch(`http://${tv.host}:${tv.port}${PATH}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pub: b64(pub), via: tv.secret ? "qr" : "code", iv: b64(iv), ct: b64(ct) }),
    signal: AbortSignal.timeout(30_000), // the TV checks the sign-in with Mozilla first
  });
  const d = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
  if (!res.ok || !d.ok) throw new Error(d.error ?? `the TV answered ${res.status}`);
}
