// Relay mode: the web through the user's own Google Apps Script relay (assets/relay/Code.gs, the one httprelay.ts uses
// for Guardian) instead of Firefox's VPN, when that's out of reach or the user picks it. The script can only fetch
// URLs, so HTTPS is opened here (mitm.ts) and each request goes to it as JSON; it fetches the page from Google's
// servers and sends it back. Google's own sites that a censor blocks by name (YouTube, its pictures, Google's fonts
// and scripts) go faster, straight to Google: to its address with www.google.com as the TLS name and the site in the
// Host header ("fronting"), which Google's front ends route by. The script is reached the same way, and YouTube's
// videos come from its caches the same way too (viaCache). proxy.ts sends what isn't HTTP direct: a script can't carry it. Ported from MasterHttpRelayVPN's client
// (https://github.com/masterking32/MasterHttpRelayVPN), whose Code.gs this talks to.
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import type { Connection } from "./connection.js";
import { parseEnvelope } from "./httprelay.js";
import { siteContext } from "./mitm.js";
import { DOH_HOST, question, answerAddrs } from "./dns.js";
import { viaOf, currentSplit, type Split } from "./split.js";
import { log } from "./log.js";

/** The TLS name every connection to Google uses: what a censor sees. */
export const FRONT = "www.google.com";
/**
 * Where Google's front is looked up: every one of its addresses serves every Google site, but Iran's DNS answers
 * www.google.com with forcesafesearch's, which puts YouTube in Restricted Mode and Search in SafeSearch.
 */
export const FRONT_AT = "www.gstatic.com";
const SCRIPT = "script.google.com";

// Google's sites that its front ends serve and a censor blocks by name: fronted (MasterHttpRelayVPN's list, and gstatic.com).
// Then those that turn the script away (its forced User-Agent; its shared servers taken for bots), and busy ones that
// answer the same either way, to spare the script's quota. Never all of google.com: much of Google answers an Iranian
// address with 403 (Gemini, Cloud, Firebase, its developer sites, www.googleapis.com) and works only through the script.
const FRONTED = ["youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com", "ggpht.com", "gvt1.com", "gvt2.com", "gstatic.com", "fonts.googleapis.com",
  "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com", "googletagmanager.com", "googletagservices.com", "script.google.com",
  "meet.google.com", "calendar.google.com", "docs.google.com", "drive.google.com", "accounts.google.com", "myaccount.google.com", "scholar.google.com", "news.google.com", "support.google.com", "translate.google.com", "translate.googleapis.com",
  "youtubekids.com", "recaptcha.net",
  "ajax.googleapis.com", "yt3.googleusercontent.com", "play-lh.googleusercontent.com", "lh3.googleusercontent.com"];
const under = (host: string, d: string) => host === d || host.endsWith(`.${d}`);
/**
 * Fronted, but not YouTube Music (it's not offered everywhere). YouTube's API is too: the video links it hands out
 * are tied to the address that asked, the user's own, which is where viaCache fetches the videos from. Pure.
 */
export const fronted = (host: string): boolean => FRONTED.some((d) => under(host, d)) && !under(host, "music.youtube.com");
/** Google itself, which the censor leaves alone: passed on as it is, to the same front, without our certificate. */
export const GOOGLE_DIRECT = new Set(["www.google.com", "google.com", "safebrowsing.google.com"]);

/** What relay mode needs of a Connection: the relay, and where Google's front is (none yet: looked up). */
type Conn = Pick<Connection, "relay" | "server">;

/** Where Google's front is dialed: its address pinned in global mode, else looked up. */
const frontAt = (conn: Conn) => conn.server?.ip ?? conn.server?.hostname ?? FRONT_AT;
const frontPort = (conn: Conn) => conn.server?.port ?? 443;

// kept open between requests, closed after 30 s idle (before Google would, so one is never reused as it closes)
const relayAgent = new https.Agent({ keepAlive: true, maxSockets: 16, timeout: 30_000 });
const frontAgent = new https.Agent({ keepAlive: true, maxSockets: 48, timeout: 30_000 });
const cacheAgent = new https.Agent({ keepAlive: true, maxSockets: 16, timeout: 30_000 });

/** Relay calls this session (each counts against the script's daily quota) and requests sent to Google directly. */
export const relayStats = { relayed: 0, fronted: 0 };

// ── Problems the user should hear about ─────────────────────────────────────────────────────

let notice = (msg: string) => console.error(msg);
let said = "", saidAt = 0;
/** Where relay problems the user can fix go (the TUI's status line, the app's toast). */
export const onRelayNotice = (fn: (msg: string) => void): void => void (notice = fn);

/** The user-facing reason for a relay failure, or null when it's just this request. Pure. */
export function relayProblem(msg: string): string | null {
  if (/unauthorized/i.test(msg)) return "Relay: your Apps Script's AUTH_KEY doesn't match the auth key in Settings.";
  if (/invoked too many times|quota/i.test(msg)) return "Relay: today's Google quota is used up (about 20,000 requests a day). It comes back within 24 hours; Firefox VPN still works.";
  if (/HTTP 404/.test(msg)) return "Relay: Google doesn't know this deployment. Check the Deployment ID in Settings.";
  if (/HTTP (302|401|403)/.test(msg)) return "Relay: the deployment isn't open to everyone. In Apps Script deploy it with Who has access: Anyone.";
  if (/function not found|doPost/i.test(msg)) return "Relay: the script isn't foxhole's. Paste the relay code into Apps Script again (Settings → set up).";
  // older Code.gs sent what sites' headers hold (Link: <…>) as HTML, which Apps Script refuses as malformed (in any language)
  if (/Exception:.*HTML/.test(msg)) return "Relay: your Apps Script has older code that fails on many sites. Update it: Settings → VPN relay → Set up step by step.";
  return null;
}

/** Tells the user `m`, but not the same again within 30 s. */
function tell(m: string): void {
  if (m === said && Date.now() - saidAt < 30_000) return;
  said = m;
  saidAt = Date.now();
  notice(m);
}

function problem(err: Error, what: string): void {
  const m = relayProblem(err.message);
  log(`relay: ${what}: ${err.message}`);
  if (m) tell(m);
}

// ── Calling the script ──────────────────────────────────────────────────────────────────────

/** One request for the script to make (Code.gs's fields). */
interface Item {
  m: string;
  u: string;
  h: Record<string, string>;
  r: false; // redirects come back to the browser, with their cookies
  b?: string;
  ct?: string;
}
/** What the script answers for one: the target's status, headers and body, or why it couldn't. */
interface Reply {
  s?: number;
  h?: Record<string, string | string[]>;
  b?: string;
  gz?: number;
  e?: string;
}

/** One POST to the script through Google's front; its envelope, or why not. */
function callScript(conn: Conn, payload: object): Promise<Reply & { q?: Reply[] }> {
  const relay = conn.relay;
  if (!relay) return Promise.reject(new Error("relay mode is off"));
  const body = JSON.stringify({ k: relay.key, ...payload });
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: frontAt(conn),
        port: frontPort(conn),
        servername: FRONT,
        method: "POST",
        path: new URL(relay.url).pathname,
        agent: relayAgent,
        timeout: 90_000,
        headers: { host: SCRIPT, "content-type": "application/json", "content-length": Buffer.byteLength(body), "accept-encoding": "gzip" },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("error", reject);
        res.on("end", () => {
          let buf = Buffer.concat(chunks);
          try {
            if (res.headers["content-encoding"] === "gzip") buf = gunzipSync(buf);
            if (res.statusCode !== 200) throw new Error(`relay: Apps Script returned HTTP ${res.statusCode}`);
            resolve(parseEnvelope(buf.toString("utf8")) as Reply);
          } catch (err) {
            reject(err);
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("relay: no answer in 90 s")));
    req.on("error", reject);
    req.end(body);
  });
}

// At most this many calls at once: Apps Script runs about 30 at a time for an account, and Guardian's calls share them.
let calls = 0;
const waiting: (() => void)[] = [];
async function slot<T>(fn: () => Promise<T>): Promise<T> {
  if (calls >= 12) await new Promise<void>((r) => waiting.push(r));
  calls++;
  try {
    return await fn();
  } finally {
    calls--;
    waiting.shift()?.();
  }
}

/** Calls the script, once more after a dropped connection when `again` (the request is safe to repeat). */
async function call(conn: Conn, payload: object, again: boolean): Promise<Reply & { q?: Reply[] }> {
  try {
    return await slot(() => callScript(conn, payload));
  } catch (err) {
    if (!again || /^relay:/.test((err as Error).message)) throw err; // the script's answer: the same next time
    await new Promise((r) => setTimeout(r, 300));
    return slot(() => callScript(conn, payload));
  }
}

// A page asks for dozens of files at once: GETs that come within 15 ms go to the script together (Code.gs's fetchAll).
let queue: { item: Item; done: (r: Reply | Error) => void }[] = [];
let timer: NodeJS.Timeout | null = null;

function flush(conn: Conn): void {
  if (timer) clearTimeout(timer);
  timer = null;
  const batch = queue;
  queue = [];
  if (!batch.length) return;
  const one = batch.length === 1;
  call(conn, one ? batch[0].item : { q: batch.map((b) => b.item) }, true).then(
    (env) => {
      // Code.gs before 2026-10-31 gives each request after one that failed the answer before it ("fetch failed" shows it): those go again, alone
      const shifted = env.q?.some((r) => r?.e === "fetch failed") ? env.q.findIndex((r) => r?.e) : batch.length;
      batch.forEach((b, i) => (i > shifted ? call(conn, b.item, true).then(b.done, b.done) : b.done((one ? env : env.q?.[i]) ?? new Error("relay: no answer for this request"))));
    },
    (err: Error) => batch.forEach((b) => b.done(err)),
  );
}

/** The script fetches one request; `batch`: it may go with others (a GET without a body). */
function relayFetch(conn: Conn, item: Item, batch: boolean): Promise<Reply> {
  relayStats.relayed++;
  const got = (r: Reply): Reply => {
    if (typeof r.e === "string") throw new Error(`relay: ${r.e}`);
    return r;
  };
  if (!batch) return call(conn, item, item.m === "GET" && !item.b).then(got);
  return new Promise<Reply>((resolve, reject) => {
    queue.push({ item, done: (r) => (r instanceof Error ? reject(r) : resolve(r)) });
    if (queue.length >= 32) flush(conn);
    else timer ??= setTimeout(() => flush(conn), 15);
  }).then(got);
}

/** A body as the target sent it: Code.gs's own gzip undone, and the target's encoding too (fetched bodies usually come decoded, still labeled). */
function bodyOf(r: Reply): Buffer {
  const b = Buffer.from(r.b ?? "", "base64");
  return r.gz ? gunzipSync(b) : b;
}
function decoded(body: Buffer, encoding: string): Buffer {
  const head = body.subarray(0, 120);
  const plain = !head.includes(0) && Buffer.from(head.toString("utf8")).equals(head); // text: compressed bytes are rarely valid UTF-8
  try {
    if (/gzip/.test(encoding) && body[0] === 0x1f && body[1] === 0x8b) return gunzipSync(body);
    if (plain) return body;
    if (/deflate/.test(encoding)) return inflateSync(body);
    if (/br/.test(encoding)) return brotliDecompressSync(body);
  } catch {
    /* not encoded after all */
  }
  return body;
}

/** Apps Script may join several Set-Cookie values with ", ", the same comma a cookie's Expires date has: split only before a name=. Pure. */
export const splitCookies = (v: string): string[] => v.split(/,\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)/).map((s) => s.trim()).filter(Boolean);

// ── Lookups in global mode ──────────────────────────────────────────────────────────────────

// Global mode's DNS forwarder asks here (DoH to cloudflare-dns.com, through the proxy). The relay carries sites by
// name, so a name gets a made-up address in 198.19.0.0/16 (inside the tun's 198.18.0.0/15, past its own 198.18.0.1)
// at once, no lookup, and a connection to it is taken back to the name. Real lookups (direct sites, other record
// types) go through the relay.
const fakeByName = new Map<string, string>();
const nameByFake = new Map<string, string>();
let nextFake = 0;

function fakeIp(name: string): string {
  let ip = fakeByName.get(name);
  if (ip) return ip;
  nextFake = (nextFake % 65533) + 1;
  ip = `198.19.${nextFake >> 8}.${nextFake & 255}`;
  const old = nameByFake.get(ip);
  if (old) fakeByName.delete(old); // 65,533 names on: the oldest's address is reused
  fakeByName.set(name, ip);
  nameByFake.set(ip, name);
  return ip;
}

/** The name behind one of relay mode's made-up addresses, if `ip` is one. */
export const fakeName = (ip: string): string | undefined => nameByFake.get(ip);

// foxhole's own lookups that must stay real across a switch to Firefox VPN: its servers, and Google's front
const REAL = (name: string) => /(^|\.)fastly-masque\.net$/.test(name) || name === FRONT || name === FRONT_AT || !name.includes(".");

/** A DNS answer to `q` with these IPv4 addresses (none: "no such record", for AAAA and HTTPS records). Pure. */
export function dnsAnswer(q: Buffer, end: number, ips: string[], ttl: number): Buffer {
  const head = Buffer.from(q.subarray(0, 12));
  head[2] = 0x81 | (q[2] & 0x78); // an answer, recursion asked; the query's opcode
  head[3] = 0x80; // recursion available, no error
  head.writeUInt16BE(1, 4);
  head.writeUInt16BE(ips.length, 6);
  head.writeUInt32BE(0, 8);
  const answers = ips.map((ip) => {
    const a = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, ...ip.split(".").map(Number)]);
    a.writeUInt32BE(ttl, 6);
    return a;
  });
  return Buffer.concat([head, q.subarray(12, end), ...answers]);
}

/** A real answer to a DNS query, through the relay. */
async function realLookup(conn: Conn, q: Buffer): Promise<Buffer> {
  const item = { m: "POST", u: `https://${DOH_HOST}/dns-query`, h: { accept: "application/dns-message" }, r: false as const, b: q.toString("base64"), ct: "application/dns-message" };
  return bodyOf(await relayFetch(conn, item, false));
}

const realIps = new Map<string, { ip: string; until: number }>();
/** `name`'s real IPv4 address, looked up through the relay (cached); null if it has none. For connections that go direct in global mode. */
export async function realIp(conn: Conn, name: string): Promise<string | null> {
  const hit = realIps.get(name);
  if (hit && hit.until > Date.now()) return hit.ip;
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "latin1")]));
  const q = Buffer.concat([Buffer.from([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...labels, Buffer.from([0, 0, 1, 0, 1])]);
  try {
    const a = answerAddrs(await realLookup(conn, q))[0];
    if (!a) return null;
    realIps.set(name, { ip: a.ip, until: Date.now() + Math.max(a.ttl, 60) * 1000 });
    return a.ip;
  } catch (err) {
    problem(err as Error, `looking up ${name}`);
    return null;
  }
}

async function answerDns(conn: Conn, q: Buffer): Promise<Buffer> {
  const qi = question(q);
  if (!qi) throw new Error("bad DNS query");
  const real = REAL(qi.name) || viaOf(qi.name) === "direct";
  if (!real && qi.type === 1) return dnsAnswer(q, qi.end, [fakeIp(qi.name)], 2);
  if (!real && [28, 64, 65].includes(qi.type)) return dnsAnswer(q, qi.end, [], 2); // no IPv6 (the tun has none), no HTTPS records (no QUIC, no ECH)
  return realLookup(conn, q);
}

// ── Serving the browser ─────────────────────────────────────────────────────────────────────

/** Where a connection the browser opened was going. */
interface Ctx {
  conn: Conn;
  scheme: "http" | "https";
  host: string;
  port: number;
}
const ctxOf = new WeakMap<object, Ctx>();

// Hop-by-hop, or the relay's own business (it asks targets for unencoded bodies): not passed on
const DROP_REQ = new Set(["host", "connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "priority", "http2-settings"]);
const DROP_RES = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "trailer", "alt-svc", "content-length"]); // alt-svc: no HTTP/3, it's UDP

/** A request's headers to pass on, as one object; repeated ones joined (cookies with "; "). */
function headersOf(raw: string[], drop: (k: string) => boolean): Record<string, string> {
  const h: Record<string, string> = {};
  for (let i = 0; i < raw.length; i += 2) {
    const k = raw[i].toLowerCase();
    if (drop(k)) continue;
    h[k] = h[k] === undefined ? raw[i + 1] : `${h[k]}${k === "cookie" ? "; " : ", "}${raw[i + 1]}`;
  }
  return h;
}

function readBody(req: http.IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let n = 0;
    req.on("data", (c: Buffer) => {
      if ((n += c.length) > max) return req.destroy(new Error(`a request body over ${max >> 20} MB can't go through the relay`));
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);

/** Answers with a short page of foxhole's own (a browser shows it in place of the site). `body`: HTML. */
function page(res: http.ServerResponse, status: number, title: string, body: string): void {
  if (res.headersSent) return void res.destroy();
  const html = `<!doctype html><meta charset="utf-8"><title>Foxhole relay</title><body style="font:15px/1.5 system-ui,sans-serif;margin:3em auto;max-width:36em;padding:0 1em;color:#333"><h2>${title}</h2>${body}`;
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "content-length": Buffer.byteLength(html), "cache-control": "no-store" });
  res.end(html);
}

/** Answers with a short page saying what went wrong. */
function fail(res: http.ServerResponse, status: number, msg: string): void {
  page(res, status, "Foxhole relay couldn't load this", `<p>${esc(msg)}</p>`);
}

const DIRECT = "/.foxhole/direct"; // the bot-check page's button, on the site's own address

/** Cloudflare's bot check, which never passes through the relay: why, and the way round it (openDirect). */
function botCheck(res: http.ServerResponse, url: URL): void {
  const host = esc(url.hostname);
  page(
    res,
    403,
    `${host} checks for bots`,
    `<p>The relay can't pass that check: Google fetches each page for you as a script, from a different address each time, so the check would start over forever.</p>` +
      `<form method="post" action="${DIRECT}"><input type="hidden" name="u" value="${esc(url.pathname + url.search)}"><button style="font:inherit;color:#fff;background:#7c3aed;border:0;border-radius:8px;padding:.5em 1.2em;cursor:pointer">Open it directly</button></form>` +
      `<p style="color:#666;font-size:13px">Through your own connection, not the relay. Foxhole tries it first; if ${host} opens, it's added to Split tunneling as Direct. Your internet provider can see that you visit it.</p>` +
      `<p>Or use Firefox VPN for it: pick a country in Locations.</p>`,
  );
}

/** example.co.uk → co.uk's site, roughly: the last two labels, or three when the second-to-last is a short one like co. Pure. */
const siteOf = (host: string) => {
  const l = host.split(".");
  return l.slice(l.length > 2 && l[l.length - 2].length <= 3 ? -3 : -2).join(".");
};

/**
 * Apps Script can't send OPTIONS, so a CORS preflight is answered here: yes for its own site (app.x.com → api.x.com),
 * cookies and all; another site's only without cookies, so a page can't use relay mode to send credentialed requests
 * the target would have refused.
 */
function preflight(req: http.IncomingMessage, res: http.ServerResponse, host: string): void {
  const origin = req.headers.origin;
  let same = false;
  try {
    same = !!origin && siteOf(new URL(origin).hostname) === siteOf(host);
  } catch {
    /* not a URL: another site */
  }
  res.writeHead(204, {
    "access-control-allow-origin": origin ?? "*",
    "access-control-allow-methods": req.headers["access-control-request-method"] ?? "GET, POST, PUT, PATCH, DELETE",
    "access-control-allow-headers": req.headers["access-control-request-headers"] ?? "*",
    ...(same ? { "access-control-allow-credentials": "true" } : {}),
    "access-control-max-age": "600",
    vary: "origin",
  });
  res.end();
}

const RELAYED = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
// The image types Apps Script fetches: it throws "Unexpected error" on any other (AVIF, JPEG XL, APNG, HEIC), whatever the bytes
const KNOWN_IMAGE = /^\s*image\/(webp|png|jpeg|gif|svg\+xml|\*)\s*(;|$)/i;

async function viaRelay(c: Ctx, req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<void> {
  const method = req.method ?? "GET";
  if (!RELAYED.has(method)) return fail(res, 501, `The relay can't send ${method} requests.`);
  // a file of a type it doesn't fetch would only fail, and send the rest of its batch one by one; sites that offer one have a fallback
  // ponytail: one a server labels as something else would have come through; send those alone if that turns up
  if (/\.(avif|jxl|hei[cf])$/i.test(url.pathname)) return fail(res, 502, "The relay can't fetch AVIF, JPEG XL or HEIC pictures: Apps Script fails on them.");
  const body = await readBody(req, 40 << 20); // a 50 MB call, once in base64
  const item: Item = {
    m: method === "HEAD" ? "GET" : method, // UrlFetchApp can't send HEAD
    u: url.href,
    h: headersOf(req.rawHeaders, (k) => DROP_REQ.has(k) || k === "accept-encoding"),
    r: false,
    ...(body.length ? { b: body.toString("base64"), ...(req.headers["content-type"] ? { ct: req.headers["content-type"] } : {}) } : {}),
  };
  // sites are offered only the image types it fetches, so image CDNs send WebP or JPEG
  if (item.h.accept) item.h.accept = item.h.accept.split(",").filter((t) => !/^\s*image\//i.test(t) || KNOWN_IMAGE.test(t)).join(",") || "*/*";
  let reply: Reply;
  try {
    // ponytail: one script call per response, so ~50 MB at most (UrlFetchApp's cap); Range-chunked GETs if big downloads matter
    // a page itself goes alone: in a batch, the slowest of the others would hold it up
    reply = await relayFetch(c.conn, item, item.m === "GET" && !body.length && req.headers["sec-fetch-mode"] !== "navigate");
  } catch (err) {
    problem(err as Error, url.host);
    return fail(res, 502, relayProblem((err as Error).message) ?? (err as Error).message.replace(/^relay: (Exception: )?/, ""));
  }
  // a bot check (Cloudflare's "Performing security verification") never passes here: the page would check and reload forever
  if (req.headers["sec-fetch-mode"] === "navigate" && Object.entries(reply.h ?? {}).some(([k, v]) => k.toLowerCase() === "cf-mitigated" && /challenge/.test(String(v)))) {
    return botCheck(res, url);
  }
  let out = bodyOf(reply);
  const status = reply.s ?? 200;
  let encoding = "";
  for (const [k, v] of Object.entries(reply.h ?? {})) {
    const key = k.toLowerCase();
    const vals = (Array.isArray(v) ? v : [v]).map(String);
    if (key === "content-encoding") encoding = vals.join(",").toLowerCase();
    if (DROP_RES.has(key) || key === "content-encoding") continue;
    try {
      res.setHeader(key, key === "set-cookie" ? vals.flatMap(splitCookies) : vals.length > 1 ? vals : vals[0]);
    } catch {
      /* a value Node won't send: left out */
    }
  }
  out = decoded(out, encoding);
  const bodyless = status === 204 || status === 304 || status < 200;
  if (!bodyless) res.setHeader("content-length", out.length);
  res.writeHead(status);
  res.end(bodyless || method === "HEAD" ? undefined : out);
}

/** What a direct connection to `ip` needs to get past global mode's tun (proxy.ts sets it), or null when it can't. */
let directTo = async (_ip: string): Promise<{ localAddress?: string; family?: number } | null> => ({});
export const setDirectTo = (fn: typeof directTo): void => void (directTo = fn);

/** A direct connection to `host`, made as a site that Split tunneling sends direct gets one (proxy.ts sets it); null if none. */
let directDial = async (_conn: Conn, _host: string, _port: number): Promise<net.Socket | null> => null;
export const setDirectDial = (fn: typeof directDial): void => void (directDial = fn);

let saveSplit = (_split: Split): void => {};
/** Where the bot-check page's button saves a site as Direct: the TUI's and the app's Split tunneling. */
export const onRelaySplit = (fn: (split: Split) => void): void => void (saveSplit = fn);

/** Why `host` doesn't open from the user's own connection (the censor's reset or block page, no answer), or null when it does. */
async function opensDirectly(conn: Conn, host: string): Promise<string | null> {
  const s = await directDial(conn, host, 443);
  if (!s) return "no connection";
  return new Promise((resolve) => {
    const t = tls.connect({ socket: s, servername: host }); // its own certificate: not a block page's
    const done = (why: string | null) => (t.destroy(), resolve(why));
    t.setTimeout(10_000, () => done("no answer"));
    t.once("secureConnect", () => done(null));
    t.once("error", (err) => done(err.message));
  });
}

/**
 * The bot-check page's button: when the site opens from the user's own connection, it goes direct from now on (a
 * Split tunneling rule), so the browser does the check itself, and the browser is sent back to the page it was on.
 */
async function openDirect(c: Ctx, req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<void> {
  const back = new URL(new URLSearchParams((await readBody(req, 8192)).toString()).get("u") ?? "/", url);
  // only from that page: another site can't send one direct
  if (req.headers["sec-fetch-site"] !== "same-origin" || back.origin !== url.origin) return fail(res, 403, "That button only works on foxhole's own page.");
  const why = await opensDirectly(c.conn, url.hostname);
  if (why) {
    log(`relay: ${url.hostname} directly: ${why}`);
    return fail(res, 502, `${url.hostname} doesn't open from your own connection either: it's likely blocked where you are. Use Firefox VPN for it: pick a country in Locations.`);
  }
  const site = siteOf(url.hostname.replace(/^www\./, "")); // its API and other names too, where the check's cookie goes
  const split = currentSplit();
  saveSplit({ ...split, rules: [...split.rules.filter((r) => r.match !== site), { match: site, via: "direct" }] });
  if (viaOf(url.hostname) !== "direct") return fail(res, 500, `Couldn't add ${site} to Split tunneling. Add it there as Direct, then reload.`);
  tell(`${site} goes direct now (Split tunneling): its bot check can't pass through the relay.`);
  server.closeIdleConnections(); // the browser's open ones still lead to the relay
  res.writeHead(303, { location: back.href, connection: "close", "content-length": 0 });
  res.end();
}

/**
 * YouTube's videos come from its caches (googlevideo.com), which Google's front doesn't serve and the censor blocks by
 * name, not by address: straight to the cache, from the user's own address (the one the video links are tied to),
 * named www.google.com but held to its own certificate. Not through the script: no quota, and full speed.
 */
async function viaCache(c: Ctx, req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<void> {
  const ip = await realIp(c.conn, url.hostname); // the system's lookups are poisoned where it's blocked
  const out = ip ? await directTo(ip) : null;
  if (!ip || !out) return fail(res, 502, `Couldn't reach ${url.host} directly.`);
  const up = https.request(
    {
      host: ip,
      port: frontPort(c.conn), // Google's 443 (the test's mock front elsewhere)
      servername: FRONT,
      checkServerIdentity: (_name, cert) => tls.checkServerIdentity(url.hostname, cert),
      ...out,
      method: req.method,
      path: url.pathname + url.search,
      headers: { ...headersOf(req.rawHeaders, (k) => DROP_REQ.has(k) && k !== "content-length"), host: url.host },
      agent: cacheAgent,
      timeout: 60_000,
    },
    (r) => pass(r, res),
  );
  up.on("timeout", () => up.destroy(new Error("no answer in 60 s")));
  up.on("error", (err) => (log(`relay: ${url.host} from its cache: ${err.message}`), fail(res, 502, `Couldn't reach ${url.host}: ${err.message}`)));
  req.pipe(up);
}

/** Google's response, as it came (its body, length and encoding with it), minus what describes the hop. */
function pass(r: http.IncomingMessage, res: http.ServerResponse): void {
  const raw: string[] = [];
  for (let i = 0; i < r.rawHeaders.length; i += 2) {
    const k = r.rawHeaders[i].toLowerCase();
    if (!DROP_RES.has(k) || k === "content-length") raw.push(r.rawHeaders[i], r.rawHeaders[i + 1]);
  }
  try {
    res.writeHead(r.statusCode ?? 502, raw);
  } catch {
    r.destroy();
    return fail(res, 502, "Google sent headers that can't be passed on.");
  }
  r.pipe(res);
  r.on("error", () => res.destroy());
}

function viaFront(c: Ctx, req: http.IncomingMessage, res: http.ServerResponse, url: URL): void {
  relayStats.fronted++;
  const up = https.request(
    {
      host: frontAt(c.conn),
      port: frontPort(c.conn),
      servername: FRONT,
      method: req.method,
      path: url.pathname + url.search,
      headers: { ...headersOf(req.rawHeaders, (k) => DROP_REQ.has(k) && k !== "content-length"), host: url.host },
      agent: frontAgent,
      timeout: 60_000,
      maxHeaderSize: 256 * 1024, // what YouTube sends a browser (policies, origin trials, cookies) runs past Node's 16 KB
    },
    (r) => pass(r, res),
  );
  up.on("timeout", () => up.destroy(new Error("no answer in 60 s")));
  up.on("error", (err) => (log(`relay: ${url.host} via Google's front: ${err.message}`), fail(res, 502, `Couldn't reach ${url.host} through Google: ${err.message}`)));
  req.pipe(up);
}

// YouTube Music's page is refused to an Iranian address (fronted) and to the script's forced User-Agent alike, so it comes
// through Google Translate's site proxy, which fetches it from Google's own address with the browser's. Translate's own
// scripts are taken out (one would send the app's requests through the proxy, which only GETs). The app's API and its
// files go through the script, which answers them; its audio too (the links are tied to the address that asked).
// Translate drops cookies, so the page comes signed out: with YouTube's sign-in cookie it's marked signed in again (the
// app signs its API calls itself, from that cookie), and its signed-out home and sidebar are left out, so it asks for
// yours. ponytail: experimental; take the audio part out if songs never play
const TRANSLATED = "music-youtube-com.translate.goog";
const TRANSLATE_ADDED = /<script[^>]*translate_http[^>]*><\/script>|<script id="google-translate-element-script">[\s\S]*?<\/script>|<meta http-equiv="X-Translated-To"[^>]*>/g;
export const untranslated = (html: string, cookie = ""): string => {
  const out = html.replace(TRANSLATE_ADDED, "");
  if (!/(^|;\s*)SAPISID=/.test(cookie)) return out;
  return out.replace('"LOGGED_IN":false', '"LOGGED_IN":true,"SESSION_INDEX":"0"').replace(/initialData\.push\(\{path: '[^']*', params: JSON\.parse\('[^']*'\), data: '[^']*'\}\);/g, "");
};

function viaTranslate(c: Ctx, req: http.IncomingMessage, res: http.ServerResponse, url: URL): void {
  relayStats.fronted++;
  const q = new URLSearchParams(url.search);
  q.set("_x_tr_sl", "auto"), q.set("_x_tr_tl", "en"), q.set("_x_tr_hl", "en");
  const up = https.request(
    {
      host: frontAt(c.conn),
      port: frontPort(c.conn),
      servername: FRONT,
      path: `${url.pathname}?${q}`,
      headers: { ...headersOf(req.rawHeaders, (k) => DROP_REQ.has(k) || k === "cookie"), host: TRANSLATED, "accept-encoding": "identity" },
      agent: frontAgent,
      timeout: 60_000,
    },
    (r) => {
      const chunks: Buffer[] = [];
      r.on("data", (d: Buffer) => chunks.push(d));
      r.on("error", () => res.destroy());
      r.on("end", () => {
        if (r.statusCode !== 200) return fail(res, 502, `Google Translate answered HTTP ${r.statusCode} for YouTube Music's page.`);
        const body = Buffer.from(untranslated(Buffer.concat(chunks).toString("utf8"), req.headers.cookie));
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-length": body.length });
        res.end(body);
      });
    },
  );
  up.on("timeout", () => up.destroy(new Error("no answer in 60 s")));
  up.on("error", (err) => fail(res, 502, `Couldn't reach YouTube Music's page through Google Translate: ${err.message}`));
  up.end();
}

async function onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const c = ctxOf.get(req.socket);
  if (!c) return fail(res, 500, "lost track of this connection");
  const raw = req.url ?? "/";
  let url: URL;
  try {
    // an HTTP proxy's request names the whole URL; one in a connection we opened has only the path
    url = new URL(/^https?:\/\//i.test(raw) ? raw : `${c.scheme}://${req.headers.host ?? (c.port === (c.scheme === "https" ? 443 : 80) ? c.host : `${c.host}:${c.port}`)}${raw}`);
  } catch {
    return fail(res, 400, "That isn't a URL.");
  }
  const host = url.hostname.toLowerCase();
  if (host === DOH_HOST && url.pathname === "/dns-query" && req.method === "POST") {
    try {
      const a = await answerDns(c.conn, await readBody(req, 65_535));
      res.writeHead(200, { "content-type": "application/dns-message", "content-length": a.length });
      return void res.end(a);
    } catch (err) {
      return fail(res, 502, (err as Error).message);
    }
  }
  const music = host === "music.youtube.com" || req.headers.origin === "https://music.youtube.com";
  if (host.endsWith(".googlevideo.com")) return music ? viaRelay(c, req, res, url) : viaCache(c, req, res, url);
  if (host === "music.youtube.com" && req.method === "GET" && req.headers["sec-fetch-dest"] === "document") return viaTranslate(c, req, res, url);
  if (fronted(host) || GOOGLE_DIRECT.has(host)) return viaFront(c, req, res, url);
  if (req.method === "OPTIONS") return preflight(req, res, host);
  if (url.pathname === DIRECT && req.method === "POST") return openDirect(c, req, res, url);
  return viaRelay(c, req, res, url);
}

const server = http.createServer({ maxHeaderSize: 64 * 1024 }, (req, res) => void onRequest(req, res).catch((err: Error) => fail(res, 502, err.message)));
server.keepAliveTimeout = 30_000;
// WebSockets can't go through a script: say so, and the page falls back to polling where it can.
// ponytail: no WebSockets at all; they'd need a long-poll pair of calls per message, too slow for the daily quota
server.on("upgrade", (_req, sock: net.Socket) => sock.end("HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
server.on("clientError", (err: Error & { code?: string }, sock: net.Socket) => {
  // an app that doesn't trust Foxhole's certificate ends the handshake with an alert
  if (/alert (unknown ca|bad certificate|certificate unknown)/i.test(err.message)) {
    const host = ctxOf.get(sock)?.host ?? "a site";
    log(`relay: an app refused Foxhole's certificate for ${host}`);
    tell("Relay: an app refused Foxhole's certificate. Trust it once: Settings → VPN relay → Certificate.");
  }
  sock.destroy();
});

/**
 * Carries a connection the browser opened through the relay: `first`, its first bytes (a TLS hello or an HTTP
 * request), are put back first. host: the site (the TLS name, or what the connection was opened for).
 */
export function relayServe(conn: Conn, client: net.Socket, first: Buffer, to: { host: string; port: number; tls: boolean }): void {
  client.on("error", () => client.destroy());
  if (to.tls && GOOGLE_DIRECT.has(to.host)) {
    // Google itself: its own TLS, untouched, to the front
    const up = net.connect({ host: frontAt(conn), port: frontPort(conn) });
    up.once("connect", () => {
      up.write(first);
      client.pipe(up).pipe(client);
      client.resume();
    });
    up.on("error", () => client.destroy());
    up.on("close", () => client.destroy());
    client.on("close", () => up.destroy());
    return;
  }
  client.unshift(first);
  const c: Ctx = { conn, scheme: to.tls ? "https" : "http", host: to.host, port: to.port };
  if (!to.tls) {
    ctxOf.set(client, c);
    server.emit("connection", client);
    return void client.resume();
  }
  const sock = new tls.TLSSocket(client, {
    isServer: true,
    secureContext: siteContext(to.host),
    SNICallback: (name, cb) => cb(null, siteContext(name)),
    ALPNProtocols: ["http/1.1"],
  });
  ctxOf.set(sock, c);
  server.emit("connection", sock);
}

/** Checks the relay answers and fetches: Google's own connectivity check, so no other site's outage fails it. */
export async function relayCheck(conn: Conn): Promise<void> {
  const r = await relayFetch(conn, { m: "GET", u: "http://www.google.com/generate_204", h: {}, r: false }, false).catch((err: Error) => {
    throw new Error(relayProblem(err.message) ?? err.message.replace(/^relay: (Exception: )?/, "relay: "));
  });
  if (r.s !== 204) throw new Error(`relay: the test page answered HTTP ${r.s}`);
}

/**
 * Settings' check of the relay: it answers and fetches with this deployment and key (relayCheck), and its code is current.
 * Only the script, past its key check, answers an address it can't fetch with Apps Script's error naming it ("<" and all),
 * which an older Code.gs can't send back. Says only what it saw: no word on the code when that answer was something else.
 */
export async function relayVerdict(conn: Conn): Promise<{ tone: "ok" | "warn" | "error"; text: string }> {
  const t = Date.now();
  try {
    const [, code] = await Promise.all([
      relayCheck(conn).catch((err: Error) => Promise.reject(/^relay:/i.test(err.message) ? err : new Error(`Couldn't reach Google: ${err.message}`))),
      relayFetch(conn, { m: "GET", u: "https://<foxhole>/", h: {}, r: false }, false).then(
        () => "",
        (err: Error) => (/Exception:.*HTML/.test(err.message) ? "old" : err.message.includes("<foxhole>") ? "current" : ""),
      ),
    ]);
    if (code === "old") return { tone: "warn", text: "The deployment ID and auth key are right, but your Apps Script has older code that fails on many sites. Update it: Settings → VPN relay → Set up step by step." };
    const current = code === "current" ? ", and the script is up to date" : "";
    return { tone: "ok", text: `Relay works: the deployment ID and auth key are right${current} (answered in ${((Date.now() - t) / 1000).toFixed(1)} s).` };
  } catch (err) {
    return { tone: "error", text: (err as Error).message };
  }
}
