// Shield's YouTube switch: YouTube's ads taken out on the way. Where this device trusts Foxhole's certificate (relay
// mode's, mitm.ts), its browsers' connections to YouTube's pages are opened here (proxy.ts) and the answers edited as
// uBlock Origin's rules for Firefox edit them (uAssets quick-fixes, 2026-11): the ad keys in the player's answers renamed
// ("adPlacements" to "no_ads"), so the player finds no ads; Shorts' ads dropped from their sequence; the ad slots of the
// feed, search and pages hidden; the player's wait for blocked ads cut short (uBO's nano-stb), and an ad that still plays
// (one stitched into the video) sped through, muted. Everything else passes as it came. An app that refuses the
// certificate (one that trusts only its own, as YouTube's app) is known by its TLS fingerprint from then on and passes
// untouched. Relay mode, which opens YouTube anyway, makes the same edits (relaymode.ts).
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";
import { Transform, type Duplex } from "node:stream";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { siteContext } from "./mitm.js";
import { hot, type Hot } from "./hot.js";
import { log } from "./log.js";
import { userHome } from "./profile.js";

/** YouTube's pages, whose answers are edited. Its videos (googlevideo.com), pictures (ytimg.com) and apps' API (youtubei.googleapis.com) aren't. */
export const YOUTUBE = new Set(["www.youtube.com", "youtube.com", "m.youtube.com", "music.youtube.com", "www.youtube-nocookie.com"]);
/**
 * The ones taken over. Android: its mobile site and Music's, where its browsers go. Its apps' WebViews, which trust no
 * certificate a user adds, show YouTube inside them (Telegram's player) from www.youtube.com, with Chrome's own TLS
 * fingerprint: taken over, they'd fail. The proxy can't tell a phone's apps apart (proxy.ts appOf).
 */
export const TAKEN_OVER = process.platform === "android" ? new Set(["m.youtube.com", "music.youtube.com"]) : YOUTUBE;

let wanted = (): boolean => false;
let trusted = (): boolean => false;
/** `on`: the switch (the controller's; never on a TV); `ok`: this device trusts Foxhole's certificate (its last check, not one per connection). */
export function useYoutube(on: () => boolean, ok: () => boolean): void {
  wanted = on;
  trusted = ok;
}
/** YouTube's edits are wanted: relay mode makes them its own way. */
export const youtubeWanted = (): boolean => wanted();
/** `client`'s connections to YouTube are taken over: the switch on, the certificate trusted, and an app of this device's own. */
export const youtubeHere = (client: net.Socket): boolean => wanted() && trusted() && /^(127\.|::1$|::ffff:127\.)/.test(client.remoteAddress ?? "");

// ── Apps that refuse the certificate, by their TLS library's fingerprint: ~/.config/foxhole-vpn/youtube.json

const file = () => join(userHome(), ".config", "foxhole-vpn", "youtube.json");
let learned: { refuse: Set<string>; accept: Set<string> } | null = null;
function store(): { refuse: Set<string>; accept: Set<string> } {
  if (!learned) {
    let o: { refuse?: unknown; accept?: unknown } = {};
    try {
      o = JSON.parse(readFileSync(file(), "utf8"));
    } catch {
      /* none yet */
    }
    const set = (a: unknown) => new Set(Array.isArray(a) ? a.filter((x): x is string => typeof x === "string") : []);
    learned = { refuse: set(o.refuse), accept: set(o.accept) };
  }
  return learned;
}
function save(): void {
  const l = store();
  try {
    mkdirSync(dirname(file()), { recursive: true });
    writeFileSync(file(), JSON.stringify({ refuse: [...l.refuse], accept: [...l.accept] }));
  } catch (err) {
    log(`youtube: ${(err as Error).message}`);
  }
}

/** Forgets the apps found refusing: turning the switch on tries them again. */
export function forgetRefusers(): void {
  const l = store();
  if (l.refuse.size) l.refuse.clear(), save();
}

const notices: ((msg: string) => void)[] = [];
/** Calls `cb` with what to tell the user: an app was found refusing the certificate. */
export const onYoutubeNotice = (cb: (msg: string) => void): void => void notices.push(cb);

/** A ClientHello's cipher suites, GREASE left out, as a short hash: its app's TLS library, the same on each connection. Pure. */
export function fingerprint(hello: Buffer): string {
  try {
    const at = 44 + hello[43]; // record header 5, handshake header 4, version 2, random 32, then the session id
    const n = hello.readUInt16BE(at);
    const suites: number[] = [];
    for (let i = at + 2; i < at + 2 + n; i += 2) {
      const v = hello.readUInt16BE(i);
      if ((v & 0x0f0f) !== 0x0a0a || v >> 8 !== (v & 0xff)) suites.push(v);
    }
    return suites.length ? createHash("sha256").update(suites.join(",")).digest("hex").slice(0, 16) : "";
  } catch {
    return "";
  }
}

/** A connection whose first bytes are `hello`, to `name` (their SNI), is taken over: TLS to YouTube's pages, from an app not known to refuse. */
export const takesOver = (hello: Buffer, name: string | null | undefined): boolean =>
  hello[0] === 0x16 && !!name && TAKEN_OVER.has(name) && !store().refuse.has(fingerprint(hello));

// ── The edits

const KEYS = ["adPlacements", "adSlots", "playerAds", "enforcementMessageViewModel"];
let keysFor: Hot["youtube"] | null = null;
let keysRe = /$^/g;
let longest = 0;
/** The ad keys, quoted as JSON has them, also in a page's JS strings (\x22…\x22, \"…\"), with hot.json's more. */
function keys(): RegExp {
  const more = hot()?.youtube;
  if (more !== keysFor || !longest) {
    const all = [...KEYS, ...(more?.keys ?? [])];
    keysRe = new RegExp(String.raw`("|\\x22|\\")(${all.join("|")})\1`, "g");
    longest = 8 + Math.max(...all.map((k) => k.length));
    keysFor = more;
  }
  return keysRe;
}
const renamed = (s: string) => s.replace(keys(), (_, q: string) => `${q}no_ads${q}`);

/** The parts of YouTube's pages an ad's in (uBO's, 2026-11; not #player-ads, which YouTube watches), each its own rule so one a browser can't read leaves the rest. */
const HIDE = [
  "#masthead-ad", "ytd-ad-slot-renderer", "ytd-in-feed-ad-layout-renderer", "ytd-banner-promo-renderer", "ytd-statement-banner-renderer",
  "ytd-promoted-sparkles-web-renderer", "ytd-promoted-video-renderer", "ytd-compact-promoted-video-renderer", "ytd-display-ad-renderer",
  "ytd-action-companion-ad-renderer", "ytd-companion-slot-renderer", "ytd-player-legacy-desktop-watch-ads-renderer", "ytd-search-pyv-renderer",
  "ytd-video-masthead-ad-v3-renderer", "ytd-primetime-promo-renderer", "ytd-merch-shelf-renderer", 'ytd-engagement-panel-section-list-renderer[target-id="engagement-panel-ads"]',
  "ytm-promoted-sparkles-web-renderer", "ytm-promoted-video-renderer", "ytm-companion-ad-renderer", "ad-slot-renderer", ".ytp-ad-overlay-slot",
  "ytd-enforcement-message-view-model",
  // the card or dialog an ad's in (:has(): Chrome 105, Safari 15.4, Firefox 121)
  "ytd-rich-item-renderer:has(> #content > ytd-ad-slot-renderer)", "ytm-rich-item-renderer:has(> ad-slot-renderer)", "tp-yt-paper-dialog:has(> ytd-enforcement-message-view-model)",
];

/**
 * The page's own part, before YouTube's scripts (DOM methods only: its pages require Trusted Types): its 17-second wait
 * for blocked ads made 17 ms (uBO's nano-stb, [native code], 17000), and an ad that still plays, as one stitched into the
 * video, played muted at 16 times its speed (not skipped to its end, which would be the video's) and skipped when it can be.
 */
export const PAGE_SCRIPT = `(() => {
  const wait = window.setTimeout;
  window.setTimeout = new Proxy(wait, {
    apply(f, self, a) {
      if (a[1] === 17000 && typeof a[0] === "function" && String(a[0]).includes("[native code]")) a[1] = 17;
      return Reflect.apply(f, self, a);
    },
  });
  let before = null;
  setInterval(() => {
    const p = document.querySelector(".html5-video-player");
    const v = p && p.querySelector("video");
    if (!v) return;
    if (p.classList.contains("ad-showing")) {
      if (!before) before = { muted: v.muted, rate: v.playbackRate };
      v.muted = true;
      if (v.playbackRate !== 16) try { v.playbackRate = 16; } catch (e) {}
      const skip = p.querySelector(".ytp-skip-ad-button, .ytp-ad-skip-button, .ytp-ad-skip-button-modern");
      if (skip) skip.click();
    } else if (before) {
      v.muted = before.muted;
      if (v.playbackRate === 16) v.playbackRate = (typeof p.getPlaybackRate === "function" && p.getPlaybackRate()) || before.rate || 1;
      before = null;
    }
  }, 250);
})();`;

/** What goes after a page's <head>: the style hiding the ad slots, and the script where the page's policy lets it run. */
function headPart(csp: string): string {
  const style = `<style>${[...HIDE, ...(hot()?.youtube?.hide ?? [])].map((s) => `${s}{display:none!important}`).join("")}</style>`;
  const nonce = /'nonce-([A-Za-z0-9+/=_-]+)'/.exec(csp)?.[1];
  const limited = /(^|[;,])\s*(script-src|default-src)\s/i.test(csp);
  return style + (nonce ? `<script nonce="${nonce}">${PAGE_SCRIPT}</script>` : limited ? "" : `<script>${PAGE_SCRIPT}</script>`);
}

/** Shorts' sequence without its ads (uBO's json-prune, entries.[-].command.reelWatchEndpoint.adClientParams.isAd). Pure. */
function shorts(s: string): string {
  try {
    const o = JSON.parse(s);
    if (!Array.isArray(o?.entries)) return s;
    o.entries = o.entries.filter((e: { command?: { reelWatchEndpoint?: { adClientParams?: { isAd?: unknown } } } }) => !e?.command?.reelWatchEndpoint?.adClientParams?.isAd);
    return JSON.stringify(o);
  } catch {
    return s;
  }
}

const isShorts = (path: string) => path.startsWith("/youtubei/v1/reel/reel_watch_sequence");
const HEAD = /<head\b[^>]*>/i;

/** An answer of YouTube's, whole (`html`: a page, with its policy `csp`), edited; latin1 in and out, so bytes stay bytes. Pure but for hot.json. */
export function editedText(text: string, path: string, html: false | { csp: string }): string {
  const s = renamed(isShorts(path) ? shorts(text) : text);
  return html ? s.replace(HEAD, (m) => m + headPart(html.csp)) : s;
}

/** The edits on a stream (latin1), as it comes: what could be the start of a key is held back till the next chunk. */
class Editor extends Transform {
  #carry = "";
  #head: string | null; // what to put in after <head>, till it's put in
  constructor(head: string | null) {
    super();
    this.#head = head;
  }
  _transform(chunk: Buffer, _enc: BufferEncoding, cb: () => void): void {
    let s = this.#carry + chunk.toString("latin1");
    if (this.#head !== null) {
      const m = HEAD.exec(s);
      if (!m && s.length < 65536) return void ((this.#carry = s), cb()); // not come yet
      if (m) s = s.slice(0, m.index + m[0].length) + this.#head + s.slice(m.index + m[0].length);
      this.#head = null;
    }
    const re = keys();
    const cut = s.length - (longest - 1); // a key starting after this may be cut off
    let out = "";
    let last = 0;
    re.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = re.exec(s)) && m.index < cut; ) {
      out += s.slice(last, m.index) + `${m[1]}no_ads${m[1]}`;
      last = m.index + m[0].length;
    }
    const end = Math.max(cut, last);
    this.#carry = s.slice(end);
    this.push(Buffer.from(out + s.slice(last, end), "latin1"));
    cb();
  }
  _flush(cb: () => void): void {
    this.push(Buffer.from(renamed(this.#carry), "latin1"));
    cb();
  }
}

// Hop-by-hop, the server's framing (ours is our own), and alt-svc: its HTTP/3 is UDP, which wouldn't come this way
const DROP = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "trailer", "te", "alt-svc"]);
const EDITED = /^\s*(text\/html|application\/json)\b/i;

/** An Accept-Encoding with only what Node reads (Chrome offers zstd, which Node 18 can't): an answer to edit comes readable. */
export const readable = (ae: string | undefined): string | undefined =>
  ae === undefined ? undefined : ae.split(",").map((e) => e.trim()).filter((e) => /^(gzip|deflate|br|identity)\b/i.test(e)).join(", ") || "identity";

/** YouTube's answer `r` to a request for `path`, on to `res`: a page or JSON edited as it streams, anything else as it came. */
export function answerEdited(r: http.IncomingMessage, res: http.ServerResponse, path: string, method = "GET"): void {
  const status = r.statusCode ?? 502;
  const enc = String(r.headers["content-encoding"] ?? "identity").trim().toLowerCase();
  const decode = enc === "gzip" || enc === "x-gzip" ? zlib.createGunzip() : enc === "br" ? zlib.createBrotliDecompress() : enc === "deflate" ? zlib.createInflate() : enc === "identity" ? null : undefined;
  const html = /^\s*text\/html/i.test(String(r.headers["content-type"] ?? ""));
  const edit = method !== "HEAD" && status !== 204 && status !== 304 && decode !== undefined && EDITED.test(String(r.headers["content-type"] ?? ""));
  const raw: string[] = [];
  for (let i = 0; i < r.rawHeaders.length; i += 2) {
    const k = r.rawHeaders[i].toLowerCase();
    if (!DROP.has(k) && !(edit && (k === "content-length" || k === "content-encoding"))) raw.push(r.rawHeaders[i], r.rawHeaders[i + 1]);
  }
  try {
    res.writeHead(status, raw);
  } catch {
    r.destroy();
    return void res.destroy();
  }
  const fail = () => (r.destroy(), res.destroy());
  r.on("error", fail);
  if (!edit) return void r.pipe(res);
  const stages: Duplex[] = decode ? [decode] : [];
  if (isShorts(path)) {
    // whole: it's parsed
    const chunks: Buffer[] = [];
    const whole = new Transform({
      transform: (c: Buffer, _e, cb) => (chunks.push(c), cb()),
      flush: (cb) => cb(null, Buffer.from(editedText(Buffer.concat(chunks).toString("latin1"), path, false), "latin1")),
    });
    stages.push(whole);
  } else {
    const csp = [r.headers["content-security-policy"] ?? []].flat().join(",");
    stages.push(new Editor(html ? headPart(csp) : null));
  }
  let s: NodeJS.ReadableStream = r;
  for (const st of stages) (st.on("error", fail), (s = s.pipe(st)));
  s.pipe(res);
}

// ── The take-over

/** Makes a connection to YouTube's `host` (port 443) the way the proxy's rules give it, or null. */
export type Opener = (host: string) => Promise<net.Socket | null>;

/** A client connection's way to YouTube: its own connections, kept for its next requests. */
class Upstream extends https.Agent {
  #open: Opener;
  constructor(open: Opener) {
    super({ keepAlive: true });
    this.#open = open;
  }
  createConnection(opts: http.ClientRequestArgs, cb?: (err: Error | null, stream: Duplex) => void): undefined {
    const host = String((opts as { servername?: string }).servername ?? opts.host ?? "");
    this.#open(host).then(
      (raw) => {
        if (!raw) return cb?.(new Error(`couldn't reach ${host}`), undefined as unknown as Duplex);
        const t = tls.connect({ socket: raw, servername: host, ALPNProtocols: ["http/1.1"] }); // YouTube's own certificate, checked
        raw.on("close", () => t.destroy());
        cb?.(null, t);
      },
      (err: Error) => cb?.(err, undefined as unknown as Duplex),
    );
    return undefined;
  }
}

const ctxOf = new WeakMap<object, { host: string; agent: Upstream; fp: string }>();

function onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
  const c = ctxOf.get(req.socket);
  if (!c) return void res.destroy();
  // an app that asks for a page trusts the certificate: never learned as refusing (Node's own TLS checks it only after
  // the handshake, so a handshake done says nothing)
  const l = store();
  if (c.fp && !l.accept.has(c.fp)) l.accept.add(c.fp), save();
  const headers: Record<string, string> = {};
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const k = req.rawHeaders[i].toLowerCase();
    if (DROP.has(k)) continue;
    headers[k] = headers[k] === undefined ? req.rawHeaders[i + 1] : `${headers[k]}${k === "cookie" ? "; " : ", "}${req.rawHeaders[i + 1]}`;
  }
  const ae = readable(headers["accept-encoding"]);
  if (ae) headers["accept-encoding"] = ae;
  const path = req.url ?? "/";
  const up = https.request(
    { host: c.host, servername: c.host, port: 443, method: req.method, path, headers, agent: c.agent, maxHeaderSize: 256 * 1024, timeout: 60_000 },
    (r) => answerEdited(r, res, path.split("?")[0], req.method),
  );
  up.on("timeout", () => up.destroy(new Error("no answer in 60 s")));
  up.on("error", (err) => {
    log(`youtube: ${c.host}${path.split("?")[0]}: ${err.message}`);
    if (res.headersSent) return void res.destroy();
    res.writeHead(502, { "content-length": 0 });
    res.end();
  });
  req.pipe(up);
}

const server = http.createServer({ maxHeaderSize: 256 * 1024 }, onRequest);
server.keepAliveTimeout = 30_000;
// WebSockets aren't YouTube's pages' business: none are carried
server.on("upgrade", (_req, sock: net.Socket) => sock.end("HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
server.on("clientError", (err: Error, sock: net.Socket) => {
  const c = ctxOf.get(sock);
  // an app that doesn't trust the certificate ends the handshake with an alert: from then on it passes untouched
  if (c?.fp && /alert (unknown ca|bad certificate|certificate unknown|unsupported certificate)/i.test(err.message)) {
    const l = store();
    if (!l.accept.has(c.fp) && !l.refuse.has(c.fp)) {
      l.refuse.add(c.fp);
      save();
      log(`youtube: an app refused Foxhole's certificate for ${c.host} (${c.fp}): it gets YouTube as it is from now on`);
      for (const cb of notices) cb("An app that doesn't trust Foxhole's certificate (as YouTube's own app) gets YouTube as it is, ads and all.");
    }
  }
  sock.destroy();
});

/**
 * Takes over a connection to YouTube's `host` whose first bytes, `hello`, were read (they're put back first): opened with
 * Foxhole's certificate, its requests go to YouTube by `open`, and the answers come back edited.
 */
export function serveYoutube(client: net.Socket, hello: Buffer, host: string, open: Opener): void {
  client.on("error", () => client.destroy());
  client.unshift(hello);
  const fp = fingerprint(hello);
  const sock = new tls.TLSSocket(client, {
    isServer: true,
    secureContext: siteContext(host),
    SNICallback: (name, cb) => cb(null, siteContext(name)),
    ALPNProtocols: ["http/1.1"],
  });
  const agent = new Upstream(open);
  ctxOf.set(sock, { host, agent, fp });
  sock.once("close", () => agent.destroy());
  server.emit("connection", sock);
}
