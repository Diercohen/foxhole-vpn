// Split tunneling: which sites use the VPN and which go direct. Decided per connection in
// foxhole's own proxy, which global mode's tun2socks feeds as well, so both modes agree.
import net from "node:net";
import { domainToASCII } from "node:url";
import { iranian, knownBlocked, refreshLists, sanctioned } from "./smart.js";

export type Via = "vpn" | "direct";
/** How a connection goes: as a rule or the default says, or (save data) direct if it opens that way, else the VPN. */
export type Route = Via | "probe";

export interface SplitRule {
  // a domain with its subdomains ("*.x" means the same as "x"), an IP address or CIDR, or an app ("app:Telegram"; on
  // Android its package, "app:org.telegram.messenger")
  match: string;
  via: Via;
}

export const APP = "app:";
/** The app a rule's match names, or null for a site. Pure. */
export const appOf = (match: string): string | null => (match.startsWith(APP) ? match.slice(APP.length) : null);

/** A typed app ("app:Telegram", "Telegram.exe", "Telegram.app": "app:Telegram"), case kept; null if it can't be one. Pure. */
export function parseApp(input: string): string | null {
  const s = input.trim().replace(/^app:\s*/i, "").replace(/\.(exe|app)$/i, "");
  return s && s.length <= 100 && !/[\x00-\x1f/\\]/.test(s) ? APP + s : null;
}

/** A typed rule: "app:…" an app, else a site (parseSite), else a word that can't be a site ("Telegram", "Google Chrome", "x.exe") an app. Pure. */
export function parseRule(input: string): string | null {
  const s = input.trim();
  if (/^app:/i.test(s) || /\.(exe|app)$/i.test(s)) return parseApp(s);
  return parseSite(s) ?? (/^[^.:/]+$/.test(s) ? parseApp(s) : null);
}

/** True when a rule names an app, so the proxy has to find out which app each connection is from. */
export const appsOn = (s: Split = current()): boolean => s.rules.some((r) => r.match.startsWith(APP));

export interface Split {
  default: Via; // for every site no rule matches
  rules: SplitRule[];
  // With the default "vpn": Iranian sites direct before it (smart.ts), and with `probe` (save data) every other site
  // too where it opens that way
  smart?: boolean;
  probe?: boolean;
}

/** The key smart's own decisions are counted under in `hits`. */
export const SMART = "smart:ir";

/** Smart is in force: on, with the rest through the VPN (with everything direct it decides nothing). Pure. */
export const smartOn = (s: Split): boolean => !!s.smart && s.default === "vpn";

export const NO_SPLIT: Split = { default: "vpn", rules: [] };

/**
 * A typed site as a rule's match: a domain ("*.x" or ".x": x and its subdomains; IDN as
 * punycode), a country's top-level domain ("ir"), an IP address or CIDR, or a pasted link's
 * host; null if none of these. Pure.
 */
export function parseSite(input: string): string | null {
  let s = input.trim().toLowerCase();
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    try {
      s = new URL(s).hostname.replace(/^\[|\]$/g, "");
    } catch {
      return null;
    }
  } else if (!net.isIP(s.split("/")[0])) s = s.split("/")[0]; // "bbc.co.uk/news": its host
  const [addr, bits, more] = s.split("/");
  if (net.isIP(addr)) {
    if (more !== undefined) return null;
    if (bits === undefined) return addr;
    return /^\d{1,3}$/.test(bits) && Number(bits) <= (net.isIPv4(addr) ? 32 : 128) ? `${addr}/${Number(bits)}` : null;
  }
  const wild = /^\*?\./.test(s);
  const domain = domainToASCII(s.replace(/^\*?\./, ""));
  if (!domain || domain.length > 253 || !domain.split(".").every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  // A lone label is a whole top-level domain: a country's ("ir"), else written "*.x", so a site
  // typed without its ending ("digikala") isn't taken for one.
  if (!wild && !domain.includes(".") && !/^[a-z]{2}$/.test(domain)) return null;
  return wild ? `*.${domain}` : domain;
}

const isAddr = (match: string) => net.isIP(match.split("/")[0]) !== 0;

// One BlockList per address rule, made on first use
const nets = new Map<string, { list: net.BlockList; bits: number }>();
function subnet(match: string): { list: net.BlockList; bits: number } {
  let s = nets.get(match);
  if (!s) {
    const [addr, b] = match.split("/");
    const family = net.isIPv4(addr) ? "ipv4" : "ipv6";
    const bits = b === undefined ? (family === "ipv4" ? 32 : 128) : Number(b);
    const list = new net.BlockList();
    list.addSubnet(addr, bits, family);
    nets.set(match, (s = { list, bits }));
  }
  return s;
}

/**
 * The rule for a connection from the app `app` (when known) to the site `name` (when known) at the address `ip` (when
 * known), or null for the default. An app's rule decides all its connections; else the most specific site rule wins,
 * so the order never matters: the longest matching domain, else the longest matching address prefix. Pure.
 */
export function ruleFor(split: Split, name?: string, ip?: string, app?: string): SplitRule | null {
  const a = app?.toLowerCase();
  const mine = a ? split.rules.find((r) => appOf(r.match)?.toLowerCase() === a) : undefined;
  if (mine) return mine;
  let best: SplitRule | null = null;
  let len = -1;
  const host = name?.toLowerCase().replace(/\.$/, "");
  if (host && !net.isIP(host)) {
    for (const r of split.rules) {
      if (isAddr(r.match) || appOf(r.match) !== null) continue;
      const d = r.match.replace(/^\*\./, "");
      if ((host === d || host.endsWith(`.${d}`)) && d.length > len) (best = r), (len = d.length);
    }
    if (best) return best;
  }
  const addr = ip ?? (host && net.isIP(host) ? host : undefined);
  if (!addr) return null;
  for (const r of split.rules) {
    if (!isAddr(r.match)) continue; // an app's match ("app:…") isn't an address either
    const s = subnet(r.match);
    if (s.bits > len && s.list.check(addr, net.isIPv4(addr) ? "ipv4" : "ipv6")) (best = r), (len = s.bits);
  }
  return best;
}

let current: () => Split = () => NO_SPLIT;

/** Where the rules come from, read live: a change applies to the next connection. */
export function useSplit(get: () => Split): void {
  current = get;
}

/** The rules in force now. */
export const currentSplit = (): Split => current();

/** True when any connection could go direct, so the proxy needs each site's name. */
export const splitOn = (s: Split = current()): boolean => s.rules.length > 0 || s.default === "direct" || smartOn(s);

/** True when sites are tried direct first (save data): each one's first bytes are needed to try it with. */
export const probeOn = (s: Split = current()): boolean => smartOn(s) && !!s.probe;

/** Connections each rule routed, by its match ("" for the default): the TUI shows them. */
export const hits = new Map<string, number>();

/** Site names seen lately, the newest first: suggestions when adding a rule. */
export const recentSites: string[] = [];

/** VPN, direct or (save data) "probe" for a connection (from `app`, when known), counted for the TUI. */
export function route(name?: string, ip?: string, app?: string): Route {
  const s = current();
  const r = ruleFor(s, name, ip, app);
  const smart = !r && smartOn(s) ? smartRoute(s, name, ip) : null;
  const key = r?.match ?? (smart === "direct" ? SMART : "");
  hits.set(key, (hits.get(key) ?? 0) + 1);
  if (name && !net.isIP(name)) {
    const n = name.toLowerCase();
    const i = recentSites.indexOf(n);
    if (i >= 0) recentSites.splice(i, 1);
    recentSites.unshift(n);
    recentSites.length = Math.min(recentSites.length, 50);
  }
  return r?.via ?? smart ?? s.default;
}

/** Smart's way for a site no rule names (smartOn): Iranian direct; else, saving data, a try unless that's no use. */
function smartRoute(s: Split, name?: string, ip?: string): Route {
  void refreshLists(); // once a run, in the background: new lists every week
  if (iranian(name, ip)) return "direct";
  return s.probe && !sanctioned(name) && !knownBlocked(name) ? "probe" : "vpn";
}

/** route's way for `name`, uncounted: how it goes now, for the Split sheet's check. */
export function wayOf(name: string): Route {
  const s = current();
  return ruleFor(s, name)?.via ?? (smartOn(s) ? smartRoute(s, name) : s.default);
}

/** VPN or direct for `name`, uncounted: a DNS lookup isn't a connection. A site tried first is looked up in the tunnel. */
export function viaOf(name: string): Via {
  const s = current();
  return ruleFor(s, name)?.via ?? (smartOn(s) && iranian(name) ? "direct" : s.default);
}

/** "3 sites direct", "1 site, 2 apps direct", "only 2 sites via VPN", "Iranian sites direct", or null when nothing is split: for the main screen. Pure. */
export function splitSummary(s: Split): string | null {
  const off = s.rules.filter((r) => r.via !== s.default);
  const apps = off.filter((r) => appOf(r.match) !== null).length;
  const count = (n: number, what: string) => (n ? `${n} ${what}${n === 1 ? "" : "s"}` : "");
  const sites = [count(off.length - apps, "site"), count(apps, "app")].filter(Boolean).join(", ");
  if (smartOn(s)) return [s.probe ? "smart, saving data" : "Iranian sites direct", sites && `${sites} direct`].filter(Boolean).join(", ");
  if (s.default === "vpn") return sites ? `${sites} direct` : null;
  return sites ? `only ${sites} via VPN` : "all direct";
}
