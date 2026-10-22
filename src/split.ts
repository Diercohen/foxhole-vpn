// Split tunneling: which sites use the VPN and which go direct. Decided per connection in
// foxhole's own proxy, which global mode's tun2socks feeds as well, so both modes agree.
import net from "node:net";
import { domainToASCII } from "node:url";

export type Via = "vpn" | "direct";

export interface SplitRule {
  match: string; // a domain with its subdomains ("*.x" means the same as "x"), or an IP address or CIDR
  via: Via;
}

export interface Split {
  default: Via; // for every site no rule matches
  rules: SplitRule[];
}

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
 * The rule for a connection to the site `name` (when known) at the address `ip` (when known), or
 * null for the default. The most specific wins, so the order never matters: the longest matching
 * domain, else the longest matching address prefix. Pure.
 */
export function ruleFor(split: Split, name?: string, ip?: string): SplitRule | null {
  let best: SplitRule | null = null;
  let len = -1;
  const host = name?.toLowerCase().replace(/\.$/, "");
  if (host && !net.isIP(host)) {
    for (const r of split.rules) {
      if (isAddr(r.match)) continue;
      const d = r.match.replace(/^\*\./, "");
      if ((host === d || host.endsWith(`.${d}`)) && d.length > len) (best = r), (len = d.length);
    }
    if (best) return best;
  }
  const addr = ip ?? (host && net.isIP(host) ? host : undefined);
  if (!addr) return null;
  for (const r of split.rules) {
    if (!isAddr(r.match)) continue;
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
export const splitOn = (s: Split = current()): boolean => s.rules.length > 0 || s.default === "direct";

/** Connections each rule routed, by its match ("" for the default): the TUI shows them. */
export const hits = new Map<string, number>();

/** Site names seen lately, the newest first: suggestions when adding a rule. */
export const recentSites: string[] = [];

/** VPN or direct for a connection, counted for the TUI. */
export function route(name?: string, ip?: string): Via {
  const s = current();
  const r = ruleFor(s, name, ip);
  const key = r?.match ?? "";
  hits.set(key, (hits.get(key) ?? 0) + 1);
  if (name && !net.isIP(name)) {
    const n = name.toLowerCase();
    const i = recentSites.indexOf(n);
    if (i >= 0) recentSites.splice(i, 1);
    recentSites.unshift(n);
    recentSites.length = Math.min(recentSites.length, 50);
  }
  return r?.via ?? s.default;
}

/** VPN or direct for `name`, uncounted: a DNS lookup isn't a connection. */
export function viaOf(name: string): Via {
  const s = current();
  return ruleFor(s, name)?.via ?? s.default;
}

/** "3 sites direct", "only 2 sites via VPN", or null when nothing is split: for the main screen. Pure. */
export function splitSummary(s: Split): string | null {
  const n = s.rules.filter((r) => r.via !== s.default).length;
  const sites = `${n} site${n === 1 ? "" : "s"}`;
  if (s.default === "vpn") return n ? `${sites} direct` : null;
  return n ? `only ${sites} via VPN` : "all direct";
}
