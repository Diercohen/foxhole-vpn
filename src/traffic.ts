// Data per site this month, through the VPN and direct: what this device's proxy carried, by site (smart.ts siteOf:
// a CDN's many hosts as one). The Data view lists the sites that spend the VPN's data most, to send the big ones direct.
// Kept in traffic.json (a new month starts it over), saved once a minute while it grows.
import net from "node:net";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { userHome } from "./profile.js";
import { siteOf } from "./smart.js";
import type { Via } from "./split.js";

export interface SiteTraffic {
  site: string;
  vpn: number; // bytes, both ways
  direct: number;
}

const file = () => join(userHome(), ".config", "foxhole-vpn", "traffic.json");
const month = (now = new Date()) => `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
const MAX_SITES = 1000; // the smallest go first past this: a long month of one-off sites

interface Book {
  month: string;
  since: number; // when counting began this month (ms)
  sites: Record<string, [number, number]>; // site → [vpn, direct]
}
let book: Book | null = null;
let dirty = false;

function current(): Book {
  if (!book) {
    try {
      const o = JSON.parse(readFileSync(file(), "utf8")) as Partial<Book>;
      if (o.month === month() && o.sites && typeof o.sites === "object") book = { month: o.month, since: Number(o.since) || Date.now(), sites: o.sites };
    } catch {
      /* none yet, or unreadable: from now */
    }
    book ??= { month: month(), since: Date.now(), sites: {} };
    setInterval(save, 60_000).unref();
  }
  if (book.month !== month()) (book = { month: month(), since: Date.now(), sites: {} }), (dirty = true);
  return book;
}

/** The key a site's data goes under: its site for a name, the address itself for an address. Pure. */
export const keyOf = (name?: string): string => (!name ? "(unnamed)" : net.isIP(name) ? name : siteOf(name.toLowerCase().replace(/\.$/, "")));

/** Adds `bytes` to `name`'s site, through `via`. */
export function count(name: string | undefined, via: Via, bytes: number): void {
  if (bytes <= 0) return;
  const sites = current().sites;
  const k = keyOf(name);
  const row = (sites[k] ??= [0, 0]);
  row[via === "vpn" ? 0 : 1] += bytes;
  dirty = true;
}

// Connections still open: counted as they go, not only once they close (a video can stream for an hour)
const live = new Set<{ socket: net.Socket; name?: string; via: Via; counted: number }>();

const flush = (c: { socket: net.Socket; name?: string; via: Via; counted: number }) => {
  const n = c.socket.bytesRead + c.socket.bytesWritten;
  count(c.name, c.via, n - c.counted);
  c.counted = n;
};

/** Counts what `client` (a proxy client's connection, spliced to the site) carries, to `name`'s site through `via`. */
export function track(client: net.Socket, name: string | undefined, via: Via): void {
  const c = { socket: client, name, via, counted: client.bytesRead + client.bytesWritten }; // its handshake isn't the site's
  live.add(c);
  client.once("close", () => (flush(c), live.delete(c)));
}

/** This month's data by site, the VPN's biggest first, and since when it's counted. */
export function traffic(): { since: number; sites: SiteTraffic[] } {
  for (const c of live) flush(c);
  const b = current();
  const sites = Object.entries(b.sites).map(([site, [vpn, direct]]) => ({ site, vpn, direct }));
  sites.sort((x, y) => y.vpn - x.vpn || y.direct - x.direct);
  return { since: b.since, sites };
}

/** Writes the month's counts, the biggest MAX_SITES. */
export function save(): void {
  if (!dirty || !book) return;
  for (const c of live) flush(c);
  const keep = Object.entries(book.sites).sort(([, a], [, b]) => b[0] + b[1] - (a[0] + a[1])).slice(0, MAX_SITES);
  book.sites = Object.fromEntries(keep);
  try {
    mkdirSync(join(userHome(), ".config", "foxhole-vpn"), { recursive: true });
    writeFileSync(file(), JSON.stringify(book));
    dirty = false;
  } catch {
    /* read-only home: counted for this run only */
  }
}

/** A size for people: "3.2 GB", "540 MB", "12 KB". Pure. */
export function sizeOf(n: number): string {
  const [v, unit] = n >= 1e9 ? [n / 1e9, "GB"] : n >= 1e6 ? [n / 1e6, "MB"] : [n / 1e3, "KB"];
  return `${v >= 10 || unit === "KB" ? Math.round(v) : v.toFixed(1)} ${unit}`;
}

/**
 * When the data left runs out at the rate the month has gone so far, or null if it lasts till it resets (or it's too
 * early to tell: under a day in). `reset` starts the next period; this one began a month before it. Pure.
 */
export function runsOut(max: bigint, remaining: bigint, reset: Date | null, now = Date.now()): Date | null {
  if (!reset || max <= 0n) return null;
  const start = new Date(reset);
  start.setMonth(start.getMonth() - 1);
  const used = Number(max - remaining);
  const days = (now - start.getTime()) / 86_400_000;
  if (used <= 0 || days < 1) return null;
  const at = now + (Number(remaining) / (used / days)) * 86_400_000;
  return at < reset.getTime() ? new Date(at) : null;
}
