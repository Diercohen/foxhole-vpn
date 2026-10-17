import { join } from "node:path";
import { readFileSync } from "node:fs";
import type { AccountState } from "./profile.js";

/**
 * Produces a fresh FxA access token with the VPN scope, which guardian.ts uses
 * as a Bearer credential. Everything downstream depends only on this interface.
 */
export interface Authenticator {
  getAccessToken(signal?: AbortSignal): Promise<string>;
}

/** FxA OAuth scopes Guardian requires for a VPN token. */
export const VPN_SCOPES = ["profile", "https://identity.mozilla.com/apps/vpn"];

export class NotImplementedError extends Error {}

/**
 * Authenticator that returns a token supplied out-of-band via the
 * FOXHOLE_ACCESS_TOKEN env var. Lets the whole proxy/TUI/global stack be tested
 * with a token obtained elsewhere, without the Firefox session exchange.
 */
export class StaticAuth implements Authenticator {
  readonly #token: string;
  constructor(token: string) {
    this.#token = token;
  }
  async getAccessToken(): Promise<string> {
    return this.#token;
  }
}

/**
 * Authenticator backed by the local Firefox profile's session token.
 *
 * Flow (see AUTH.md for the full spec and references):
 *   1. read `sessionToken` (hex) from signedInUser.json   — implemented below
 *   2. exchange it for an FxA access token (VPN scope)      — NOT IMPLEMENTED
 *
 * Step 2 is the FxA `fxa-credentials` OAuth grant. It is left as a stub here;
 * drop the implementation into `#exchangeForVpnToken`. The rest of foxhole is
 * complete and will work the moment this returns a valid token.
 */
export class FirefoxAuth implements Authenticator {
  readonly #profileDir: string;

  constructor(account: Pick<AccountState, "profileDir">) {
    this.#profileDir = account.profileDir;
  }

  async getAccessToken(signal?: AbortSignal): Promise<string> {
    const sessionToken = this.#loadSessionToken();
    return this.#exchangeForVpnToken(sessionToken, signal);
  }

  /** Reads the raw session token (hex) from the profile. Local file, user-owned. */
  #loadSessionToken(): string {
    const f = join(this.#profileDir, "signedInUser.json");
    const data = JSON.parse(readFileSync(f, "utf8")) as {
      accountData?: { sessionToken?: string };
    };
    const token = data.accountData?.sessionToken;
    if (!token) {
      throw new Error("Not signed in to Firefox (no session token in profile).");
    }
    return token;
  }

  // shortcut: token exchange is unimplemented, blocked by the tooling's safety
  // classifier; implement per AUTH.md, then remove this stub.
  async #exchangeForVpnToken(_sessionToken: string, _signal?: AbortSignal): Promise<string> {
    throw new NotImplementedError(
      "FxA token exchange is not implemented yet — see AUTH.md. " +
        "foxhole can read your Firefox login but cannot mint a VPN token until this is filled in.",
    );
  }
}
