import type { Authenticator } from "./auth.js";
import {
  GuardianError,
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

/** Recommended/anycast: the shared catch-all host Firefox falls back to. A new one each time: global mode pins its IP on it. */
const anycast = (): Server => ({ hostname: "p.m1.fastly-masque.net", port: 2499, quarantined: false });

/**
 * Owns the live VPN session: the chosen upstream server and a proxy pass that
 * it refreshes before expiry. The proxy asks it for a valid pass per dial.
 * In relay mode (relaymode.ts) the "server" is Google's front, and no pass is needed.
 */
export class Connection {
  #auth: Authenticator;
  #pass: ProxyPass | null = null;
  #usage: Usage | null = null;
  #server: Server | null = null;
  #relay: RelayConfig | null = null;
  #passPromise: Promise<ProxyPass> | null = null;
  #ended: ((err: Error) => void) | null = null;
  #endedTold: Authenticator | null = null; // the account it was told for: once each

  constructor(auth: Authenticator) {
    this.#auth = auth;
  }

  /**
   * Told once per account when its sign-in turns out to have ended (FxA errno 110: signed out elsewhere, or expired) as a
   * token's asked for, on connecting or while connected: nothing gets through it till it's signed in to again.
   */
  onSignInEnded(fn: (err: Error) => void): void {
    this.#ended = fn;
  }

  /** The account's token; an ended sign-in told (onSignInEnded). */
  async #token(auth: Authenticator, signal?: AbortSignal): Promise<string> {
    try {
      return await auth.getAccessToken(signal);
    } catch (err) {
      if ((err as { errno?: number }).errno === 110 && auth === this.#auth && this.#endedTold !== auth) {
        this.#endedTold = auth;
        this.#ended?.(err as Error);
      }
      throw err;
    }
  }

  /**
   * Another account from now on (accounts.ts): the next pass is its own, so the proxy goes on through it; its data
   * left comes with that pass.
   */
  setAuth(auth: Authenticator): void {
    if (auth === this.#auth) return;
    this.#auth = auth;
    this.#pass = null;
    this.#usage = null;
    this.#passPromise = null; // one being fetched is the old account's
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
    } else server = anycast();
    await prepare?.(server);
    this.#server = server;
    this.#relay = null;
    return server;
  }

  /**
   * Where Firefox VPN is reached while it's off (an update's download, proxy.ts vpnTunnel): the server last picked, else
   * the catch-all; by its name, looked up anew (an address pinned for global mode was this network's then).
   */
  get anyServer(): Server {
    const { ip: _, ...server } = (!this.#relay && this.#server) || anycast();
    return server;
  }

  /** The pass in hand while it's still good, without renewing it: what Guardian's own calls through the VPN use (proxy.ts ownTunnel). */
  get passInHand(): ProxyPass | null {
    return this.#pass && Date.now() / 1000 < this.#pass.expires - 15 ? this.#pass : null;
  }

  /** Returns a currently-valid pass, refreshing it if missing or near expiry. */
  async currentPass(signal?: AbortSignal): Promise<ProxyPass> {
    if (this.#pass && !shouldRotate(this.#pass)) return this.#pass;
    if (this.#passPromise) return this.#passPromise;
    const auth = this.#auth;
    const fetching = (this.#passPromise = (async () => {
      let got: Awaited<ReturnType<typeof fetchPass>>;
      try {
        got = await fetchPass(await this.#token(auth, signal), signal);
      } catch (err) {
        // Guardian refused the token kept from before (its sign-in may have ended since): a new one, once, which says why
        if (!(err instanceof GuardianError && err.status === 401 && auth.forget)) throw err;
        auth.forget();
        got = await fetchPass(await this.#token(auth, signal), signal);
      }
      const { pass, usage } = got;
      if (this.#auth !== auth) return pass; // switched meanwhile: it's for this caller only
      this.#pass = pass;
      if (usage) this.#usage = usage;
      return pass;
    })());
    try {
      return await fetching;
    } finally {
      if (this.#passPromise === fetching) this.#passPromise = null;
    }
  }

  /** Refreshes just the usage figure (cheap). An answer without it keeps the last one. */
  async refreshUsage(signal?: AbortSignal): Promise<Usage | null> {
    const auth = this.#auth;
    const usage = await fetchUsage(await this.#token(auth, signal), signal);
    if (this.#auth === auth) this.#usage = usage ?? this.#usage;
    return this.#usage;
  }
}

/** Convenience: fetch the list and find one country by ISO code. */
export async function findCountry(code: string): Promise<Country | null> {
  const list = await fetchServerList();
  const upper = code.toUpperCase();
  return list.find((c) => c.code === upper) ?? null;
}
