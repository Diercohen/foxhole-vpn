import type { Authenticator } from "./auth.js";
import {
  fetchPass,
  fetchUsage,
  shouldRotate,
  type ProxyPass,
  type Usage,
} from "./guardian.js";
import { fetchServerList, pickServer, type Country, type Server } from "./serverlist.js";
import type { RelayConfig } from "./httprelay.js";
import { FRONT_AT } from "./relaymode.js";

/** The Relay "location": where the location list, the saved last location and the tray name it. */
export const RELAY_CODE = "RELAY";

/**
 * Owns the live VPN session: the chosen upstream server and a proxy pass that
 * it refreshes before expiry. The proxy asks it for a valid pass per dial.
 * In relay mode (relaymode.ts) the "server" is Google's front, and no pass is needed.
 */
export class Connection {
  readonly #auth: Authenticator;
  #pass: ProxyPass | null = null;
  #usage: Usage | null = null;
  #server: Server | null = null;
  #relay: RelayConfig | null = null;
  #passPromise: Promise<ProxyPass> | null = null;

  constructor(auth: Authenticator) {
    this.#auth = auth;
  }

  get usage(): Usage | null {
    return this.#usage;
  }

  get server(): Server | null {
    return this.#server;
  }

  /** The Apps Script relay carrying the traffic, in relay mode; null on Firefox VPN. */
  get relay(): RelayConfig | null {
    return this.#relay;
  }

  /** Relay mode, through `relay`. `prepare` as for selectServer: global mode pins Google's front first. */
  async selectRelay(relay: RelayConfig, prepare?: (server: Server) => Promise<void>): Promise<Server> {
    const server: Server = { hostname: FRONT_AT, port: 443, quarantined: false };
    await prepare?.(server);
    this.#server = server;
    this.#relay = relay;
    return server;
  }

  /**
   * Chooses the upstream server for a country (or null = recommended/anycast). `prepare` runs
   * before the proxy can use it (global mode pins its IP), so a failure keeps the current one.
   */
  async selectServer(country: Country | null, prepare?: (server: Server) => Promise<void>): Promise<Server> {
    let server: Server | null = null;
    if (country) {
      server = pickServer(country);
      if (!server) throw new Error(`No usable server in ${country.name}`);
    } else {
      // Recommended/anycast: use the shared catch-all host Firefox falls back to.
      server = { hostname: "p.m1.fastly-masque.net", port: 2499, quarantined: false };
    }
    await prepare?.(server);
    this.#server = server;
    this.#relay = null;
    return server;
  }

  /** Returns a currently-valid pass, refreshing it if missing or near expiry. */
  async currentPass(signal?: AbortSignal): Promise<ProxyPass> {
    if (this.#pass && !shouldRotate(this.#pass)) return this.#pass;
    if (this.#passPromise) return this.#passPromise;
    this.#passPromise = (async () => {
      const token = await this.#auth.getAccessToken(signal);
      const { pass, usage } = await fetchPass(token, signal);
      this.#pass = pass;
      if (usage) this.#usage = usage;
      return pass;
    })();
    try {
      return await this.#passPromise;
    } finally {
      this.#passPromise = null;
    }
  }

  /** Refreshes just the usage figure (cheap). An answer without it keeps the last one. */
  async refreshUsage(signal?: AbortSignal): Promise<Usage | null> {
    const token = await this.#auth.getAccessToken(signal);
    this.#usage = (await fetchUsage(token, signal)) ?? this.#usage;
    return this.#usage;
  }
}

/** Convenience: fetch the list and find one country by ISO code. */
export async function findCountry(code: string): Promise<Country | null> {
  const list = await fetchServerList();
  const upper = code.toUpperCase();
  return list.find((c) => c.code === upper) ?? null;
}
