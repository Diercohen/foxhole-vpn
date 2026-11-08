// Hot config: fixes for Iran's filtering that can't wait for a release (the 146.75 → 151.101 one needed one), and a
// notice for every user. The developer signs hot.json in the repo with an Ed25519 key (sign-hot.mjs); each run gets it
// from mirrors on three CDNs, through the VPN when connected, else directly, else through the user's relay, and keeps
// the newest that verifies in ~/.config/foxhole-vpn/hot.json. One older than that is refused, so a censor replaying an
// old file can't undo a fix. Without one (or after its "expires") the built-in values hold.
import { createPublicKey, verify } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { log } from "./log.js";
import { userHome } from "./profile.js";
import { fetchText } from "./smart.js";

/** What hot.json's "data" sets. */
export interface Hot {
  issued: string; // ISO time: a newer file replaces an older one, never the reverse
  expires?: string; // ISO time from which it's ignored
  notice?: string; // for every user: a dialog in the app, a line in the TUI and the CLI
  /** For Mozilla's hosts, addresses to try after the DNS answer's: one starting with a key adds each value, with its last number when the value ends in "." (dns.ts). */
  fallback?: Record<string, string[]>;
  fronted?: string[]; // more of Google's sites relay mode sends straight to Google (relaymode.ts)
}

const KEY = createPublicKey({ key: Buffer.from("MCowBQYDK2VwAyEAaI7LDlK8MSWd7EkfjgPqkgVVhFBvFFhmw7aGvppFVsQ=", "base64"), format: "der", type: "spki" });
const REPO = "Diercohen/foxhole-vpn";
/** Where hot.json is got from: GitHub's own, jsDelivr on Fastly and on Cloudflare, githack on Cloudflare (all answered from Iran, 2026-11). */
export const MIRRORS = [
  `https://raw.githubusercontent.com/${REPO}/main/hot.json`,
  `https://cdn.jsdelivr.net/gh/${REPO}@main/hot.json`,
  `https://testingcf.jsdelivr.net/gh/${REPO}@main/hot.json`,
  `https://raw.githack.com/${REPO}/main/hot.json`,
];
const file = () => join(userHome(), ".config", "foxhole-vpn", "hot.json");
const HOUR = 3600_000;

/** hot.json's data if its "sig" signs it (JSON.stringify of it) with `key`, with its fields as they should be; else null. Pure. */
export function parseHot(text: string | null, key = KEY): Hot | null {
  try {
    const { data, sig } = JSON.parse(text ?? "");
    if (typeof sig !== "string" || !verify(null, Buffer.from(JSON.stringify(data)), key, Buffer.from(sig, "base64"))) return null;
    const time = (t: unknown) => typeof t === "string" && Number.isFinite(Date.parse(t));
    const strings = (a: unknown): a is string[] => Array.isArray(a) && a.every((s) => typeof s === "string");
    if (!time(data.issued) || (data.expires !== undefined && !time(data.expires))) return null;
    return {
      issued: data.issued,
      ...(data.expires && { expires: data.expires }),
      ...(typeof data.notice === "string" && data.notice.trim() && { notice: data.notice.trim() }),
      ...(data.fallback && typeof data.fallback === "object" && Object.values(data.fallback).every(strings) && { fallback: data.fallback }),
      ...(strings(data.fronted) && { fronted: data.fronted }),
    };
  } catch {
    return null;
  }
}

/** `a` was issued after `b` (or there's no `b`): the one to keep. Pure. */
export const later = (a: Hot, b: Hot | null): boolean => !b || Date.parse(a.issued) > Date.parse(b.issued);

/** Of hot.json's texts from the mirrors, the newest that verifies with `key`; null if none does. Pure. */
export function newestHot(texts: (string | null)[], key = KEY): { text: string; hot: Hot } | null {
  let best: { text: string; hot: Hot } | null = null;
  for (const text of texts) {
    const h = parseHot(text, key);
    if (h && (!best || later(h, best.hot))) best = { text: text as string, hot: h };
  }
  return best;
}

let kept: Hot | null | undefined; // the one kept here, expired or not (an older one is still refused); undefined till read
function keptHot(): Hot | null {
  if (kept === undefined) {
    try {
      kept = parseHot(readFileSync(file(), "utf8"));
    } catch {
      kept = null;
    }
  }
  return kept;
}

/** The hot config in force: the newest that verified, till it expires; null: the built-in values. */
export function hot(): Hot | null {
  const h = keptHot();
  return h && !(h.expires && Date.parse(h.expires) <= Date.now()) ? h : null;
}

let seen: string | null | undefined; // the notice the app last showed on this device
const seenFile = () => join(userHome(), ".config", "foxhole-vpn", "hot-seen.txt");

/** The notice, unless the app here has shown it already (noticeShown); null if there's none. */
export function newNotice(): string | null {
  const n = hot()?.notice ?? null;
  if (seen === undefined) {
    try {
      seen = readFileSync(seenFile(), "utf8");
    } catch {
      seen = null;
    }
  }
  return n !== seen ? n : null;
}

/** The app has shown `text`: not again, till another notice comes. */
export function noticeShown(text: string): void {
  seen = text;
  writeFileSync(seenFile(), text); // beside hot.json, which had it
}

const listeners: (() => void)[] = [];
/** Calls `cb` when a newer hot config comes in. */
export const onHot = (cb: () => void): void => void listeners.push(cb);

let gotAt = 0;
let again: NodeJS.Timeout | undefined;

/** hot.json from every mirror at once, through the VPN when connected or else directly (smart.ts fetchText), and through the relay when none of those verifies: the newest. */
async function fetchHot(): Promise<{ text: string; hot: Hot } | null> {
  const got = newestHot(await Promise.all(MIRRORS.map((url) => fetchText(url))));
  if (got) return got;
  const [{ relayInUse }, { relayRequest }] = await Promise.all([import("./guardian.js"), import("./httprelay.js")]);
  const relay = relayInUse();
  return relay && newestHot(await Promise.all(MIRRORS.map((url) => relayRequest(relay, { method: "GET", url }).then((r) => (r.ok ? r.text() : null)).catch(() => null))));
}

/**
 * Keeps the newest hot.json, if it's newer than the one here. Each start calls it; then it's every 6 hours, or 10
 * minutes after one didn't come (by then it may come through the VPN). After one comes, not again for an hour. In
 * the background: it never throws.
 */
export const refreshHot = (): Promise<void> => refresh().catch((e) => log(`hot config: ${(e as Error).message}`));

async function refresh(): Promise<void> {
  if (Date.now() - gotAt < HOUR) return;
  clearTimeout(again);
  const got = await fetchHot();
  again = setTimeout(() => void refreshHot(), got ? 6 * HOUR : 10 * 60_000).unref();
  if (!got) return log("hot config: no mirror answered");
  gotAt = Date.now();
  if (!later(got.hot, keptHot())) return;
  kept = got.hot;
  try {
    mkdirSync(join(file(), ".."), { recursive: true });
    writeFileSync(`${file()}.new`, got.text); // as it came, signature and all: verified again when read
    renameSync(`${file()}.new`, file());
  } catch (e) {
    log(`hot config: not kept (${(e as Error).message}), for this run only`); // a background task: it mustn't throw
  }
  log(`hot config of ${got.hot.issued} in`);
  for (const cb of listeners) cb();
}
