// Signing a TV in from a computer or phone that has Foxhole (Android TV, mobile/); a phone or a computer too, where
// that's picked over Mozilla's own sign-in ("the TV" below is whichever waits). The TV waits on the local network,
// its screen showing a QR code (its address, its key and a secret) and a 6-character code. The other device, signed
// in, finds it (from the QR code, or by looking for it on its own network with the code) and sends it a sign-in of
// its own: a VPN-only refresh token (auth.ts), encrypted to the TV's key (X25519, AES-GCM) with the secret, or with
// the code stretched by scrypt, so what's sent can't be read on the network, nor the code guessed from it offline.
// Its VPN relay (httprelay.ts) can come with it, which a TV needs where Mozilla is blocked or refuses the country; and a
// TV or phone can wait the same way for a relay alone, later (made on a computer: a phone or TV can't make one).
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
// what a waiting device answers a sender it turns away; the sender says them itself, by the status (an older one's "the TV" may be a phone)
const BUSY = "the other device is taking a sign-in already";
const OLD_QR = "that QR code isn't the one on the other screen anymore";
const WRONG_CODE = "that isn't the code on the other screen";

export interface TvAccount {
  uid: string;
  email: string;
  refreshToken: string;
}

/** A VPN relay sent along, as Settings keeps it. */
export interface TvRelay {
  deploymentId: string;
  authKey: string;
}

/** What a device waits for: a sign-in (a TV's sign-in screen, a relay may come with it), or a relay alone. */
export type TvWant = "signin" | "relay";

/** The relay in a message, if it's one: a Deployment ID as the setup takes them, and a key. Pure. */
function relayIn(v: unknown): TvRelay | null {
  const r = v as Partial<TvRelay> | null;
  const id = typeof r?.deploymentId === "string" ? r.deploymentId : "";
  const key = typeof r?.authKey === "string" ? r.authKey : "";
  return /^[\w-]{20,200}$/.test(id) && key.length > 0 && key.length <= 200 && key === key.trim() ? { deploymentId: id, authKey: key } : null;
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
 * Waits for a sign-in from another device (`want`: or a relay alone), on `port` of every interface. `accept` takes what
 * was sent (a sign-in, a relay, or both; and the sender's name), and resolves once it's in use (rejects: the sender is
 * told why). `changed`: a new code.
 */
export async function waitForSignIn(opts: {
  name: string;
  want?: TvWant;
  host: () => string | null;
  accept: (got: { account: TvAccount | null; relay: TvRelay | null }, from: string) => Promise<void>;
  changed: () => void;
  port?: number;
}): Promise<TvSignIn> {
  const port = opts.port ?? TV_PORT;
  const want = opts.want ?? "signin";
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
    if (req.method === "GET" && path === PATH) return answer(res, 200, { foxhole: 1, name: opts.name, pub: b64(keys.pub), want });
    if (req.method === "GET") return void res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(page(opts.name, want));
    if (req.method !== "POST" || path !== PATH) return answer(res, 404, { error: "not here" });
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => ((body += c), body.length > 16_384 && req.destroy()));
    req.on("end", async () => {
      if (busy) return answer(res, 409, { error: BUSY });
      busy = true;
      try {
        const m = JSON.parse(body) as { pub?: string; via?: string; iv?: string; ct?: string };
        const pub = unb64(String(m.pub ?? ""));
        const proof = m.via === "qr" ? keys.secret : keys.codeKey;
        let message: Partial<TvAccount> & { relay?: unknown; from?: unknown };
        try {
          const key = messageKey(diffieHellman({ privateKey: keys.privateKey, publicKey: importPub(pub) }), proof, keys.pub, pub);
          const all = unb64(String(m.ct ?? ""));
          const d = createDecipheriv("aes-256-gcm", key, unb64(String(m.iv ?? "")));
          d.setAAD(Buffer.from(INFO));
          d.setAuthTag(all.subarray(all.length - 16));
          message = JSON.parse(Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]).toString("utf8"));
        } catch {
          // a wrong code (or a damaged message): after a few, a new code, so they can't be tried one by one
          if (++keys.failures >= TRIES) (keys = await fresh()), opts.changed();
          return answer(res, 403, { error: m.via === "qr" ? OLD_QR : WRONG_CODE });
        }
        const { uid, email, refreshToken, from } = message;
        // a relay alone is waited for: a sign-in sent along isn't taken
        const account = want === "signin" && [uid, email, refreshToken].every((v) => typeof v === "string" && v) ? ({ uid, email, refreshToken } as TvAccount) : null;
        const relay = relayIn(message.relay);
        // an older Foxhole sends a sign-in only
        if (want === "relay" && !relay) return answer(res, 400, { error: "it's waiting for a VPN relay, and none came: update Foxhole on this device, or set its relay up first" });
        if (!account && !relay) return answer(res, 400, { error: "no account in it" });
        await opts.accept({ account, relay }, typeof from === "string" ? from.slice(0, 80) : "");
        answer(res, 200, { ok: true, name: opts.name, account: !!account, relay: !!relay });
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
function page(name: string, want: TvWant): string {
  const tv = name.replace(/[<>&"']/g, "");
  const relay = want === "relay";
  const title = relay ? `Send your relay to ${tv}` : `Sign in ${tv}`;
  const it = /\btv\b/i.test(tv) ? "the TV" : "it";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>body{font:17px/1.5 system-ui,sans-serif;background:#07060c;color:#f6f3fb;margin:0;padding:32px 24px;text-align:center}
a{display:inline-block;margin:18px 0;padding:14px 26px;border-radius:14px;background:${relay ? "#9b4dff" : "#ff7a1a"};color:#fff;font-weight:700;text-decoration:none}p{color:#cfc8dc}</style></head>
<body><h2>${title}</h2><p>${relay ? "Open this in <b>Foxhole</b>, with your VPN relay set up, to send it." : `Open this in <b>Foxhole</b>, signed in, to send ${it} a sign-in.`}</p>
<a id="open" href="#">Open in Foxhole</a>
<p>No button? Open Foxhole on this phone or a computer on the same Wi-Fi: <b>${relay ? "Settings → VPN relay → Send to a TV or phone" : "Settings → Sign in a TV or phone"}</b>, and scan the code there or type the code shown on the other screen.</p>
<script>document.getElementById("open").href="intent://tv?l="+encodeURIComponent(location.href)+"#Intent;scheme=foxhole;package=io.github.diercohen.foxhole;end";</script>
</body></html>`;
}

// ── The computer or phone ───────────────────────────────────────────────────────────────────────────────────────

/** A TV found waiting (or a phone, for a relay). */
export interface Tv {
  host: string;
  port: number;
  name: string;
  pub: string;
  want: TvWant; // what it waits for (from its QR code alone: not known yet, "signin")
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
  return { host: url.hostname, port: Number(url.port) || 80, name: "", pub, want: "signin", secret };
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
    const d = (await res.json()) as { foxhole?: number; name?: string; pub?: string; want?: string };
    // an older TV says nothing of what it wants: a sign-in
    return d.foxhole === 1 && typeof d.pub === "string" ? { host, port, name: String(d.name ?? "TV"), pub: d.pub, want: d.want === "relay" ? "relay" : "signin" } : null;
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
 * Sends `account` and/or `relay` to `tv`, with its QR code's secret or the code typed. Resolves, once the TV is signed in
 * or has the relay, with what it took (one waiting for a relay alone leaves a sign-in); rejects with the TV's answer (a
 * wrong code: "that isn't the code on the TV").
 */
export async function sendToTv(tv: Tv, proofOf: { code?: string }, what: { account?: TvAccount; relay?: TvRelay }, from: string): Promise<{ account: boolean; relay: boolean }> {
  const tvPub = unb64(tv.pub);
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const pub = rawPub(publicKey);
  const code = proofOf.code ? normalizeCode(proofOf.code) : null;
  if (!tv.secret && !code) throw new Error("the code is 6 letters and digits, as on the other screen");
  const proof = tv.secret ? unb64(tv.secret) : await stretch(code as string, tvPub);
  const key = messageKey(diffieHellman({ privateKey, publicKey: importPub(tvPub) }), proof, tvPub, pub);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(INFO));
  // the account's fields at the top, as a TV of Foxhole 1.1 reads them (it leaves the relay)
  const ct = Buffer.concat([c.update(JSON.stringify({ ...what.account, ...(what.relay && { relay: what.relay }), from }), "utf8"), c.final(), c.getAuthTag()]);
  const res = await fetch(`http://${tv.host}:${tv.port}${PATH}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pub: b64(pub), via: tv.secret ? "qr" : "code", iv: b64(iv), ct: b64(ct) }),
    signal: AbortSignal.timeout(30_000), // the TV checks the sign-in with Mozilla first
  });
  const d = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string; account?: boolean; relay?: boolean };
  if (res.status === 403) throw new Error(tv.secret ? OLD_QR : WRONG_CODE);
  if (res.status === 409) throw new Error(BUSY);
  if (!res.ok || !d.ok) throw new Error(d.error ?? `the other device answered ${res.status}`);
  // a TV of Foxhole 1.1 says nothing of it: it takes the sign-in, and leaves the relay
  return { account: d.account ?? !!what.account, relay: d.relay ?? false };
}
