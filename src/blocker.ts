// Shield: block lists (malware, ads and trackers, social networks, porn, gambling, clickbait, other VPNs, crypto
// miners) and the user's own rules, for every connection and DNS answer Foxhole carries: proxy.ts by name, dns.ts,
// smartdns.ts and relaymode.ts with "no such name" (NXDOMAIN), udp.ts by dropping, and on macOS the DNS relay in its own
// process (relay.ts), told the settings on its stdin. The lists are got at runtime, never shipped (HaGeZi's are
// GPL-3.0), and kept as sorted 52-bit hashes of their names, 8 bytes a name: a name is blocked when it, or a domain it's
// under, is on a list that's on. Only the app's main process gets them (refreshBlocker); others only read the files.
import net from "node:net";
import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { log } from "./log.js";
import { fetchText, folder as listsFolder } from "./smart.js";
import { parseSite, ruleFor } from "./split.js";

export const LIST_IDS = ["malware", "ads", "social", "porn", "gambling", "clickbait", "vpns", "crypto"] as const;
export type ListId = (typeof LIST_IDS)[number];

/** A user's own rule: a site (a domain with its subdomains, an IP address or CIDR: split.ts parseSite) blocked or let through. */
export interface BlockRule {
  match: string;
  via: "block" | "allow";
}

export interface Blocker {
  lists: ListId[]; // the lists on
  youtube?: true; // YouTube's ads taken out too (youtube.ts): computers only
  rules?: BlockRule[];
}

/** With no Shield settings yet: malware, and ads and trackers. */
export const DEFAULT_BLOCKER: Blocker = { lists: ["malware", "ads"] };
const OFF: Blocker = { lists: [] };

/** A settings file's Shield, the defaults where it has none. Pure. */
export const blockerOf = (b: Blocker | undefined): Blocker => b ?? DEFAULT_BLOCKER;

const DAY = 86_400_000;
const hagezi = (name: string) => [
  `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/${name}-onlydomains.txt`,
  `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/${name}-onlydomains.txt`,
];

/** A list's part: one file at its mirrors (tried in turn), the fewest names a whole one has, and whether the list goes on without it. */
interface Source {
  urls: string[];
  min: number;
  optional?: true;
}

/** Each list's parts, and how long a copy stays new: malware's by the day, as threats come and go. */
export const LISTS: Record<ListId, { from: Source[]; fresh: number }> = {
  malware: { from: [{ urls: hagezi("tif.mini"), min: 20_000 }], fresh: DAY },
  ads: { from: [{ urls: hagezi("pro"), min: 50_000 }], fresh: 7 * DAY },
  social: { from: [{ urls: hagezi("social"), min: 1000 }], fresh: 7 * DAY },
  porn: { from: [{ urls: hagezi("nsfw"), min: 10_000 }], fresh: 7 * DAY },
  gambling: { from: [{ urls: hagezi("gambling.medium"), min: 10_000 }], fresh: 7 * DAY },
  clickbait: {
    from: [
      { urls: hagezi("fake"), min: 1000 },
      // fake news; jsDelivr refuses the repository (too big) and githack sends it back to GitHub
      { urls: ["https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts"], min: 500, optional: true },
    ],
    fresh: 7 * DAY,
  },
  vpns: { from: [{ urls: hagezi("doh-vpn-proxy-bypass"), min: 1000 }], fresh: 7 * DAY },
  crypto: {
    from: [
      {
        urls: ["https://cdn.jsdelivr.net/gh/hoshsadiq/adblock-nocoin-list@master/hosts.txt", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"],
        min: 100,
      },
    ],
    fresh: 7 * DAY,
  },
};

/**
 * Foxhole's own hosts, never blocked: its DNS and IP checks (proxy.ts OWN_HOSTS), the VPN (Guardian), Mozilla's sign-in,
 * profile and server list, the hot config's mirrors (hot.ts MIRRORS) and the lists', updates, and relay mode's Apps
 * Script. Lists name some of them: HaGeZi's VPN bypass one has vpn.mozilla.org and cloudflare-dns.com.
 */
export const KEEP = new Set([
  "cloudflare-dns.com", "api.ipify.org", "www.cloudflare.com",
  "vpn.mozilla.org", "identity.mozilla.com", "accounts.firefox.com", "api.accounts.firefox.com", "profile.accounts.firefox.com",
  "accounts-static.cdn.mozilla.net", "firefox.settings.services.mozilla.com", "www.mozilla.org",
  "github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "raw.githubusercontent.com",
  "cdn.jsdelivr.net", "testingcf.jsdelivr.net", "raw.githack.com", "registry.npmjs.org", "www.wintun.net",
  "script.google.com", "script.googleusercontent.com",
]);
/** ...and every name under these: the VPN's servers, by country (whole-system mode's DNS is asked for them too). */
const KEEP_UNDER = ["fastly-masque.net"];
const kept = (host: string) => KEEP.has(host) || KEEP_UNDER.some((d) => host === d || host.endsWith(`.${d}`));

/** A name's 52-bit hash, exact in a double: FNV-1a's 32 bits, then 20 of a second mix. Pure. */
export function hashName(s: string): number {
  let a = 0x811c9dc5;
  let b = 0x2545f491;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x5bd1e995);
    b ^= b >>> 15;
  }
  return (a >>> 0) * 0x100000 + (b >>> 12);
}

/** The name a list's line gives: "x.com", or a hosts file's "0.0.0.0 x.com"; null for a comment, a blank, an address or a hosts file's own names. Pure. */
export function nameIn(line: string): string | null {
  const hash = line.indexOf("#");
  const parts = (hash >= 0 ? line.slice(0, hash) : line).trim().split(/\s+/);
  const n = (parts.length === 1 ? parts[0] : /^(0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]) ? parts[1] : "").toLowerCase().replace(/\.$/, "");
  return /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(n) && !net.isIP(n) && !/(^|\.)(localhost|localdomain|local)$/.test(n) ? n : null;
}

/** The sorted, deduped hashes of the names in `text`, yielding to the event loop now and then (a phone's proxy shares it). */
export async function hashList(text: string): Promise<Float64Array> {
  let out = new Float64Array(1 << 14);
  let n = 0;
  for (let i = 0, lines = 0; i < text.length; lines++) {
    let j = text.indexOf("\n", i);
    if (j < 0) j = text.length;
    const name = nameIn(text.slice(i, j));
    i = j + 1;
    if (name) {
      if (n === out.length) {
        const bigger = new Float64Array(n * 2);
        bigger.set(out);
        out = bigger;
      }
      out[n++] = hashName(name);
    }
    if (lines % 20_000 === 19_999) await new Promise((r) => setImmediate(r));
  }
  return unique(out.subarray(0, n));
}

/** `a` sorted with each value once, in a fresh array. */
function unique(a: Float64Array): Float64Array {
  a.sort();
  let k = 0;
  for (let i = 0; i < a.length; i++) if (!k || a[i] !== a[k - 1]) a[k++] = a[i];
  return a.slice(0, k);
}

/** True when sorted `a` has `h`. Pure. */
function has(a: Float64Array, h: number): boolean {
  for (let lo = 0, hi = a.length - 1; lo <= hi; ) {
    const mid = (lo + hi) >>> 1;
    if (a[mid] === h) return true;
    if (a[mid] < h) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

// ── The settings in force, and the lists' files

let current: () => Blocker = () => OFF;
let dir: string | null = null; // the lists' folder, when told (macOS's DNS relay runs as root, so its home isn't the user's)
const folder = () => dir ?? listsFolder();
const fileOf = (id: ListId) => join(folder(), `block-${id}.bin`);

/** The lists read, by id: null when there's no file (yet). */
const loaded = new Map<ListId, Float64Array | null>();

/** Where the settings come from, read live; `listsDir`: the lists' folder, read again from there (macOS's DNS relay). */
export function useBlocker(get: () => Blocker, listsDir?: string): void {
  current = get;
  if (listsDir) {
    dir = listsDir;
    loaded.clear();
  }
}

/** The Shield settings in force now. */
export const currentBlocker = (): Blocker => current();

/** The lists' folder, for macOS's DNS relay. */
export const blockerDir = (): string => folder();

/** True when anything can be blocked: the proxy then needs every connection's name. */
export const blockerOn = (b: Blocker = current()): boolean => b.lists.length > 0 || !!b.rules?.some((r) => r.via === "block");

/** A list's hashes, read on first use; null if it hasn't come yet. */
function hashesOf(id: ListId): Float64Array | null {
  if (!loaded.has(id)) {
    try {
      const raw = readFileSync(fileOf(id));
      const a = new Float64Array(raw.length >> 3); // a fresh copy: a small file's Buffer can sit at an unaligned offset
      new Uint8Array(a.buffer).set(raw.subarray(0, a.length * 8));
      loaded.set(id, a);
    } catch {
      loaded.set(id, null);
    }
  }
  return loaded.get(id) ?? null;
}

/**
 * What blocks a connection to `name` at the address `ip` (either may be unknown): the list's id, "rule" for the user's
 * own rule, or null when it may go. Foxhole's own hosts always may; else the most specific of the user's rules decides
 * (split.ts ruleFor: allowing x.com and blocking ads.x.com blocks only the ads), else the lists that are on.
 */
export function blocked(name?: string, ip?: string): ListId | "rule" | null {
  const b = current();
  const host = name && !net.isIP(name) ? name.toLowerCase().replace(/\.$/, "") : undefined;
  if (host && kept(host)) return null;
  if (b.rules?.length) {
    const r = ruleFor({ rules: b.rules }, host, ip ?? (name && net.isIP(name) ? name : undefined));
    if (r) return r.via === "block" ? "rule" : null;
  }
  if (!host || !b.lists.length) return null;
  const hashes: number[] = [];
  for (let d = host; ; d = d.slice(d.indexOf(".") + 1)) {
    hashes.push(hashName(d));
    if (!d.includes(".")) break;
  }
  for (const id of b.lists) {
    const a = hashesOf(id);
    if (a && hashes.some((h) => has(a, h))) return id;
  }
  return null;
}

/** The lists are to be read again from their files (macOS's DNS relay, told some came). */
export const reloadBlockLists = (): void => loaded.clear();

/** The Shield settings a file holds, each part checked; undefined for none (the defaults then). Pure. */
export function parseBlocker(v: unknown): Blocker | undefined {
  if (!v || typeof v !== "object") return undefined;
  const o = v as { lists?: unknown; youtube?: unknown; rules?: unknown };
  const lists = Array.isArray(o.lists) ? LIST_IDS.filter((id) => (o.lists as unknown[]).includes(id)) : [];
  const rules: BlockRule[] = [];
  for (const r of Array.isArray(o.rules) ? (o.rules as { match?: unknown; via?: unknown }[]) : []) {
    const match = typeof r?.match === "string" ? parseSite(r.match) : null;
    if (match && (r.via === "block" || r.via === "allow") && !rules.some((x) => x.match === match)) rules.push({ match, via: r.via });
  }
  return { lists, ...(o.youtube === true && { youtube: true }), ...(rules.length && { rules }) };
}

// ── Getting the lists

const getting = new Set<ListId>();
const failed = new Set<ListId>(); // the last try didn't get it
let refreshing: Promise<void> | null = null;
let retry: NodeJS.Timeout | undefined;
const listeners: ((written: boolean) => void)[] = [];

/** Calls `cb` when a list's state changes; `written`: a list's file is new (macOS's DNS relay reads it again then). */
export const onBlockerChange = (cb: (written: boolean) => void): void => void listeners.push(cb);
const changed = (written: boolean) => listeners.forEach((cb) => cb(written));

/** A list's file's age in ms, or null when there's none. */
function age(id: ListId): number | null {
  try {
    return Date.now() - statSync(fileOf(id)).mtimeMs;
  } catch {
    return null;
  }
}

/** A list that's on, as the window shows it: blocking (its names' count), being got, or not got. */
export function listState(id: ListId): { state: "ready" | "getting" | "failed"; count: number } {
  const a = hashesOf(id);
  if (a) return { state: "ready", count: a.length };
  return { state: failed.has(id) && !getting.has(id) ? "failed" : "getting", count: 0 };
}

/** `url`'s names' hashes, from the first mirror whose copy has at least `min`; null if none does. */
async function fetchSource(src: Source): Promise<Float64Array | null> {
  for (const url of src.urls) {
    const text = await fetchText(url);
    const hashes = text && (await hashList(text));
    if (hashes && hashes.length >= src.min) return hashes;
    log(`shield: ${url}: ${hashes ? `only ${hashes.length} names came` : "didn't come"}`);
  }
  return null;
}

/** Gets list `id` and saves it; true if it did. A required part that doesn't come keeps the old copy. */
async function getList(id: ListId): Promise<boolean> {
  const parts: Float64Array[] = [];
  for (const src of LISTS[id].from) {
    const hashes = await fetchSource(src);
    if (hashes) parts.push(hashes);
    else if (!src.optional) return false;
  }
  const all = new Float64Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((at, p) => (all.set(p, at), at + p.length), 0);
  const hashes = parts.length === 1 ? parts[0] : unique(all);
  mkdirSync(folder(), { recursive: true });
  writeFileSync(`${fileOf(id)}.new`, Buffer.from(hashes.buffer, hashes.byteOffset, hashes.byteLength));
  renameSync(`${fileOf(id)}.new`, fileOf(id));
  loaded.set(id, hashes);
  log(`shield: the ${id} list: ${hashes.length} names`);
  return true;
}

/**
 * Gets the lists that are on and missing or older than they stay new (through the VPN when connected, else directly:
 * smart.ts fetchText), one at a time; a list turned on meanwhile is got in the same go. One that doesn't come is tried
 * again 10 minutes on (or on the next call). Lists that are off are let go from memory. In the background: never throws.
 */
export function refreshBlocker(): Promise<void> {
  for (const id of loaded.keys()) if (!current().lists.includes(id)) loaded.delete(id);
  const stale = (id: ListId) => {
    const a = age(id);
    return a === null || a > LISTS[id].fresh;
  };
  return (refreshing ??= (async () => {
    const tried = new Set<ListId>();
    for (let id: ListId | undefined; (id = current().lists.find((l) => !tried.has(l) && stale(l))); ) {
      tried.add(id);
      getting.add(id);
      changed(false);
      const ok = await getList(id).catch((err: Error) => (log(`shield: the ${id} list: ${err.message}`), false));
      getting.delete(id);
      if (ok) failed.delete(id);
      else failed.add(id);
      changed(ok);
    }
  })().finally(() => {
    refreshing = null;
    clearTimeout(retry);
    if (current().lists.some((l) => failed.has(l))) retry = setTimeout(() => void refreshBlocker(), 10 * 60_000).unref();
  }));
}
