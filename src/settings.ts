// User settings, edited in the TUI's Settings popup and kept between runs.
// Command-line flags (--host, --port) still win for the run they're given on.
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { userHome } from "./profile.js";
import type { ProxyLogin } from "./proxy.js";
import { NO_SPLIT, parseSite, type Split, type Via } from "./split.js";

export interface Settings {
  share: boolean; // proxy reachable from other devices on this network (0.0.0.0), not just this computer
  port: number; // proxy port (SOCKS5 and HTTP)
  username: string; // proxy login asked from other devices; both empty: none
  password: string;
  split: Split; // split tunneling: which sites use the VPN, which go direct
  // Optional Apps Script relay for reaching Guardian where vpn.mozilla.org is blocked (see httprelay.ts). Hand-set
  // in this file or given via FOXHOLE_RELAY_ID/KEY; not shown or edited in the UI. The authKey is a shared secret.
  relay?: { deploymentId: string; authKey: string };
}

export const DEFAULTS: Settings = { share: false, port: 1080, username: "", password: "", split: NO_SPLIT };

const settingsFile = () => join(userHome(), ".config", "foxhole-vpn", "settings.json");

export const validPort = (n: unknown): n is number => Number.isInteger(n) && (n as number) >= 1 && (n as number) <= 65535;

const isVia = (v: unknown): v is Via => v === "vpn" || v === "direct";

/** The split rules a file holds, each checked like a typed one; anything else dropped. Pure. */
function parseSplit(v: unknown): Split {
  const o = (v && typeof v === "object" ? v : {}) as { default?: unknown; rules?: unknown };
  const rules: Split["rules"] = [];
  for (const r of Array.isArray(o.rules) ? (o.rules as { match?: unknown; via?: unknown }[]) : []) {
    const match = typeof r?.match === "string" ? parseSite(r.match) : null;
    if (match && isVia(r.via) && !rules.some((x) => x.match === match)) rules.push({ match, via: r.via });
  }
  return { default: isVia(o.default) ? o.default : NO_SPLIT.default, rules };
}

/** The relay a file holds, if both parts are non-empty strings; else undefined. Pure. */
function parseRelay(v: unknown): Settings["relay"] {
  const o = (v && typeof v === "object" ? v : {}) as { deploymentId?: unknown; authKey?: unknown };
  return typeof o.deploymentId === "string" && o.deploymentId && typeof o.authKey === "string" && o.authKey
    ? { deploymentId: o.deploymentId, authKey: o.authKey }
    : undefined;
}

/** Keeps only well-formed values, falling back to the defaults. Pure. */
export function parseSettings(json: string): Settings {
  let o: Partial<Record<keyof Settings, unknown>> = {};
  try {
    const v: unknown = JSON.parse(json);
    if (v && typeof v === "object") o = v;
  } catch {
    /* corrupt file: defaults */
  }
  return {
    share: typeof o.share === "boolean" ? o.share : DEFAULTS.share,
    port: validPort(o.port) ? o.port : DEFAULTS.port,
    username: typeof o.username === "string" ? o.username : DEFAULTS.username,
    password: typeof o.password === "string" ? o.password : DEFAULTS.password,
    split: parseSplit(o.split),
    // kept so a hand-added relay survives the next save; no key at all when unset, to keep the file clean
    ...(parseRelay(o.relay) ? { relay: parseRelay(o.relay) } : {}),
  };
}

/**
 * The login a proxy client at `address` must give, or null for none. Only other devices are
 * asked: apps on this computer, and foxhole's own tun2socks and DNS relay, connect freely. Pure.
 */
export function loginFor(s: Settings, address: string | undefined): ProxyLogin | null {
  if (!s.username && !s.password) return null;
  const local = !address || address.startsWith("127.") || address === "::1" || address.startsWith("::ffff:127.");
  return local ? null : { username: s.username, password: s.password };
}

export function loadSettings(): Settings {
  try {
    return parseSettings(readFileSync(settingsFile(), "utf8"));
  } catch {
    return { ...DEFAULTS };
  }
}

/** Throws if the file can't be written; the TUI shows why. Private (0600): it may hold the proxy password. */
export function saveSettings(s: Settings): void {
  mkdirSync(dirname(settingsFile()), { recursive: true, mode: 0o700 });
  writeFileSync(settingsFile(), JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
  chmodSync(settingsFile(), 0o600); // mode above only applies when the file is new
}

/** The address the proxy listens on. */
export const proxyHost = (s: Settings): string => (s.share ? "0.0.0.0" : "127.0.0.1");
