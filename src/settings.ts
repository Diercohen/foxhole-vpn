// User settings, edited in the TUI's Settings popup and kept between runs.
// Command-line flags (--host, --port) still win for the run they're given on.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { userHome } from "./profile.js";

export interface Settings {
  share: boolean; // proxy reachable from other devices on this network (0.0.0.0), not just this computer
  port: number; // proxy port (SOCKS5 and HTTP)
  autoConnect: boolean; // connect to the last country when the TUI starts
}

export const DEFAULTS: Settings = { share: false, port: 1080, autoConnect: false };

const settingsFile = () => join(userHome(), ".config", "foxhole-vpn", "settings.json");

export const validPort = (n: unknown): n is number => Number.isInteger(n) && (n as number) >= 1 && (n as number) <= 65535;

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
    autoConnect: typeof o.autoConnect === "boolean" ? o.autoConnect : DEFAULTS.autoConnect,
  };
}

export function loadSettings(): Settings {
  try {
    return parseSettings(readFileSync(settingsFile(), "utf8"));
  } catch {
    return { ...DEFAULTS };
  }
}

/** Throws if the file can't be written; the TUI shows why. */
export function saveSettings(s: Settings): void {
  mkdirSync(dirname(settingsFile()), { recursive: true, mode: 0o700 });
  writeFileSync(settingsFile(), JSON.stringify(s, null, 2) + "\n");
}

/** The address the proxy listens on. */
export const proxyHost = (s: Settings): string => (s.share ? "0.0.0.0" : "127.0.0.1");
