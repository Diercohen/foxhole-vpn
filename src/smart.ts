// Smart split tunneling: Iranian sites and services go direct, the rest through the VPN. Iran's banks and payment
// gateways refuse foreign addresses, traffic inside Iran costs less (half price on most plans), and none of it should
// spend the VPN's monthly data. A site is Iranian by its name (.ir, or on bootmortis/iran-hosted-domains' list: 57,000
// names outside .ir) or by its address (Iran's, from ipverse/country-ip-blocks). Both ship in assets/lists. While smart
// is on, the first connection of a run gets new ones through the VPN once a week (refreshLists).
//
// Save data (split.probe): a site on neither list goes direct too when it opens that way, else through the VPN, and
// it's remembered as blocked for a few days (proxy.ts tries it). Sites that refuse Iranian addresses go through the VPN
// without a try: their refusal is inside TLS, where proxy.ts can't see it. Chocolate4U/Iran-v2ray-rules' sanctioned.txt
// names them. It's fetched, not shipped, since it's GPL.
import net from "node:net";
import { gunzipSync } from "node:zlib";
import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { userHome } from "./profile.js";
import { log } from "./log.js";
import type { Via } from "./split.js";

const shipped = (name: string) => fileURLToPath(new URL(`./assets/lists/${name}`, import.meta.url));
const folder = () => join(userHome(), ".config", "foxhole-vpn", "lists");

export const SOURCES = {
  domains: "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt",
  ips4: "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ir/ipv4-aggregated.txt",
  ips6: "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ir/ipv6-aggregated.txt",
  sanctioned: "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/sanctioned.txt",
};
const FRESH_MS = 7 * 24 * 3600_000;
const BLOCKED_MS = 3 * 24 * 3600_000; // a site found blocked uses the VPN without a try for this long

/** A list's names or ranges: no comments or blank lines, v2ray's "domain:"/"full:" dropped, lowercased. Pure. */
export function listLines(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split("\n")) {
    const l = raw.trim().toLowerCase().replace(/^(domain|full):/, "");
    if (l && !l.startsWith("#")) out.push(l);
  }
  return out;
}

/** A BlockList of the CIDRs in `lines` (malformed ones skipped). Pure. */
export function rangesOf(lines: string[]): net.BlockList {
  const list = new net.BlockList();
  for (const l of lines) {
    const [addr, bits] = l.split("/");
    const family = net.isIPv4(addr) ? "ipv4" : net.isIPv6(addr) ? "ipv6" : null;
    if (family && /^\d+$/.test(bits ?? "")) list.addSubnet(addr, Number(bits), family);
  }
  return list;
}

/** `name` or the domain it's under is in `set`. Pure. */
export function under(set: Set<string>, name: string): boolean {
  for (let d = name; ; ) {
    if (set.has(d)) return true;
    const i = d.indexOf(".");
    if (i < 0) return false;
    d = d.slice(i + 1);
  }
}

interface Lists {
  domains: Set<string>;
  ips: net.BlockList;
  sanctioned: Set<string>;
}
let lists: Lists | null = null;

// the lists that ship, by the name they're got under (sanctioned.txt doesn't: until it comes, nothing is skipped)
const SHIPPED: Record<string, string> = { "iran-domains.txt": "iran-domains.txt.gz", "iran-ips.txt": "iran-ips.txt" };

/** A list got lately, else the one shipped, else empty. */
function readList(name: string): string {
  try {
    return readFileSync(join(folder(), name), "utf8");
  } catch {
    if (!SHIPPED[name]) return "";
    try {
      const raw = readFileSync(shipped(SHIPPED[name]));
      return SHIPPED[name].endsWith(".gz") ? gunzipSync(raw).toString("utf8") : raw.toString("utf8");
    } catch {
      return "";
    }
  }
}

/** The lists, read on first use. */
function get(): Lists {
  return (lists ??= {
    domains: new Set(listLines(readList("iran-domains.txt"))),
    ips: rangesOf(listLines(readList("iran-ips.txt"))),
    sanctioned: new Set(listLines(readList("sanctioned.txt"))),
  });
}

const name = (host?: string) => (host && !net.isIP(host) ? host.toLowerCase().replace(/\.$/, "") : undefined);

/** True for an Iranian site: by its name (.ir, or on the list), else by its address (`ip`, or `host` as one). */
export function iranian(host?: string, ip?: string): boolean {
  const n = name(host);
  if (n && (n === "ir" || n.endsWith(".ir") || under(get().domains, n))) return true;
  const addr = ip ?? (host && net.isIP(host) ? host : undefined);
  return !!addr && get().ips.check(addr, net.isIPv4(addr) ? "ipv4" : "ipv6");
}

/** True for a site that refuses Iranian addresses (sanctions): never tried directly. */
export function sanctioned(host?: string): boolean {
  const n = name(host);
  return !!n && under(get().sanctioned, n);
}

/** Iran's DNS answers a blocked name with its filter's own address (a page saying it's blocked), 10.10.34.x, or for IPv6 one that spells it: 2001:4188:2:600:10:10:34:36. Pure. */
export const filterAddress = (ip: string): boolean => /^10\.10\.34\.\d{1,3}$/.test(ip) || /:10:10:34:[0-9a-f]{1,4}$/i.test(ip);

// ── Sites found blocked: a file of name → until when, so they use the VPN without a try

let blocked: Map<string, number> | null = null;
let saving: ReturnType<typeof setTimeout> | null = null;

function blockedMap(): Map<string, number> {
  if (blocked) return blocked;
  blocked = new Map();
  try {
    const o = JSON.parse(readFileSync(join(folder(), "blocked.json"), "utf8")) as Record<string, unknown>;
    for (const [k, v] of Object.entries(o)) if (typeof v === "number" && v > Date.now()) blocked.set(k, v);
  } catch {
    /* none yet */
  }
  return blocked;
}

/**
 * The site a name is part of, as the filter blocks it: "rr3---sn-4g5e.googlevideo.com": "googlevideo.com",
 * "www.bbc.co.uk": "bbc.co.uk". Pure.
 * ponytail: a guess at the public suffix list (a short label under a country's TLD is taken for one, "co.uk"); a
 * wrong guess only learns more or less than the site, so more of it is tried or goes through the VPN.
 */
export function siteOf(n: string): string {
  const l = n.split(".");
  return l.slice(l.length > 2 && l[l.length - 1].length === 2 && l[l.length - 2].length <= 3 ? -3 : -2).join(".");
}

/** True while `host`'s site is remembered as blocked. */
export function knownBlocked(host?: string): boolean {
  const n = name(host);
  return !!n && (blockedMap().get(siteOf(n)) ?? 0) > Date.now();
}

/** Remembers `host`'s site as blocked for BLOCKED_MS (saved a moment later, once for a burst). */
export function learnBlocked(host?: string): void {
  const h = name(host);
  if (!h) return;
  const n = siteOf(h);
  if (!knownBlocked(n)) log(`smart: ${n} is blocked here, so it uses the VPN`);
  blockedMap().set(n, Date.now() + BLOCKED_MS);
  saving ??= setTimeout(() => {
    saving = null;
    try {
      mkdirSync(folder(), { recursive: true });
      writeFileSync(join(folder(), "blocked.json"), JSON.stringify(Object.fromEntries(blockedMap())));
    } catch (err) {
      log(`smart: can't save the blocked sites: ${(err as Error).message}`);
    }
  }, 2000);
  saving.unref?.();
}

// ── Blocked or sanctioned? A site tried both ways, directly and through the VPN (proxy.ts checkSite)

/** One way's try of a site's page: the HTTP status it answered with, or why it didn't. */
export type Try = { status: number } | { fail: "filter" | "dns" | "cut" | "silent" | "tls" };
export type Verdict = "blocked" | "sanctioned" | "partly" | "open" | "down" | "unknown";

const answered = (t: Try | null): t is { status: number } => !!t && "status" in t;
const refused = (t: Try | null) => answered(t) && (t.status === 403 || t.status === 451);

/**
 * What a site's tries say (null: not tried): Iran's filter blocks it, it refuses Iran (sanctions: turned away
 * directly, let in through the VPN), partly (on the sanctioned list, which names a site for any part of it that
 * refuses Iran, GitHub's Copilot, ChatGPT's sign-in, yet its page opens), it opens directly, it opens neither way, or
 * it can't be told. Without a try, what the lists say. Pure but for them.
 */
export function verdictOf(site: string, direct: Try | null, vpn: Try | null): Verdict {
  const listed = sanctioned(site);
  if (!direct) return vpn && !answered(vpn) ? "down" : listed ? "partly" : knownBlocked(site) ? "blocked" : "unknown";
  if (answered(direct)) {
    if (!refused(direct)) return listed ? "partly" : "open";
    // a 403 through the VPN too is the site's own (a bot check), not Iran's
    return (answered(vpn) && !refused(vpn)) || listed ? "sanctioned" : "unknown";
  }
  if (direct.fail === "filter") return "blocked";
  if (answered(vpn)) return listed ? "sanctioned" : "blocked"; // a CDN turns Iran away as the filter does, dropping it
  if (vpn) return "down";
  return direct.fail === "cut" || knownBlocked(site) ? "blocked" : "unknown"; // a connection cut once the name's sent: the filter's way
}

/** A try for people: "opens", "refused (403)", "cut off"… Pure. */
export function tryText(t: Try | null): string {
  if (!t) return "not tried";
  if (answered(t)) return refused(t) ? `refused (${t.status})` : "opens";
  return { filter: "the filter's address", dns: "no such name", cut: "cut off", silent: "no answer", tls: "a wrong certificate" }[t.fail];
}

/** A verdict for people: what it is, and what that means (or why it can't be told). Pure. */
export function verdictText(v: Verdict, direct: Try | null, vpn: Try | null): [string, string] {
  if (v === "blocked") return ["Blocked by Iran's filter", "It opens only through the VPN."];
  if (v === "sanctioned") return ["Refuses Iran (sanctions)", "It turns Iranian addresses away: it needs the VPN."];
  if (v === "partly") return ["Partly sanctioned", direct ? "Its page opens; sign-in or parts of it may turn Iran away." : "It's on the sanctions list: some or all of it turns Iran away."];
  if (v === "open") return ["Not blocked", "It opens directly: it can skip the VPN, saving data."];
  if (v === "down") return ["Doesn't open", `${direct ? "Not directly, nor" : "Not"} through the VPN: it may be down.`];
  return [
    "Can't tell",
    !direct ? "Whole system mode on a Mac doesn't try sites directly." : !vpn ? "Connect, and it's tried through the VPN too, to compare." : "It turned the check away both ways, as a bot check does.",
  ];
}

/** The way a verdict wants its site to go, if any. Pure. */
export const wantOf = (v: Verdict): Via | null => (v === "open" ? "direct" : v === "blocked" || v === "sanctioned" ? "vpn" : null);

// ── Keeping the lists new

let via: { host: string; port: number } | null = null; // the proxy, to get them through the VPN
let refreshing: Promise<void> | null = null;

/** Where the proxy listens: new lists are got through it (proxy.ts sets this as it starts). */
export function listsVia(proxy: { host: string; port: number } | null): void {
  via = proxy;
}

/** `url`'s text, through the VPN when connected (else, or failing that, directly); null if neither way gets it. */
export async function fetchText(url: string): Promise<string | null> {
  const { download } = await import("./global.js"); // global.ts imports the proxy, which imports this: only at run time
  for (const proxy of via ? [via, undefined] : [undefined]) {
    try {
      return (await download(url, proxy)).toString("utf8");
    } catch {
      /* the next way */
    }
  }
  return null;
}

/**
 * Once an hour at most, gets the lists older than a week: through the VPN first, then directly. A download that doesn't
 * look like its list (a captive portal's page, a cut-off file) is dropped, and tried again on a call an hour on (first
 * called before connecting, GitHub may be out of reach). In the background; the old lists stay till then. Resolves
 * once the sanctioned list is in, or isn't coming (it's first: small, and a site's check waits for it).
 */
export function refreshLists(): Promise<void> {
  return (refreshing ??= new Promise<void>((sanctionedIn) => void (async () => {
    const stale = (file: string) => {
      try {
        return Date.now() - statSync(join(folder(), file)).mtimeMs > FRESH_MS;
      } catch {
        return true;
      }
    };
    const save = (file: string, lines: string[], min: number) => {
      if (lines.length < min) return log(`smart: ${file}: only ${lines.length} lines came, kept the old one`);
      mkdirSync(folder(), { recursive: true });
      writeFileSync(join(folder(), `${file}.new`), lines.join("\n") + "\n");
      renameSync(join(folder(), `${file}.new`), join(folder(), file));
      lists = null; // read again on the next use
    };
    if (stale("sanctioned.txt")) {
      const t = await fetchText(SOURCES.sanctioned);
      if (t) save("sanctioned.txt", listLines(t).filter((d) => /^[a-z0-9.-]+$/.test(d)), 500);
    }
    sanctionedIn();
    if (stale("iran-domains.txt")) {
      const t = await fetchText(SOURCES.domains);
      if (t) save("iran-domains.txt", listLines(t).filter((d) => !d.endsWith(".ir") && /^[a-z0-9.-]+$/.test(d)), 10_000);
    }
    if (stale("iran-ips.txt")) {
      const [v4, v6] = await Promise.all([fetchText(SOURCES.ips4), fetchText(SOURCES.ips6)]);
      if (v4 && v6) save("iran-ips.txt", listLines(v4 + "\n" + v6).filter((l) => l.includes("/")), 500);
    }
  })()
    .catch((err) => log(`smart: can't get new lists: ${(err as Error).message}`))
    .finally(() => (sanctionedIn(), setTimeout(() => (refreshing = null), 3600_000).unref()))));
}
