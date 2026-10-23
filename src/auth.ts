import { join } from "node:path";
import { readFileSync } from "node:fs";
import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
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

/**
 * Authenticator that returns a token supplied out-of-band via the
 * FOXHOLE_ACCESS_TOKEN env var, or saved from an earlier run.
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

/** Firefox desktop's public FxA OAuth client id; Guardian accepts its VPN tokens. */
const FIREFOX_CLIENT_ID = "5882386c6d801776";
const FXA_TOKEN_URL = "https://api.accounts.firefox.com/v1/oauth/token";
const TOKEN_TTL = 86400; // what Firefox asks for: a day

/**
 * The HAWK id and key a session token signs requests with (FxA's onepw scheme):
 * HKDF-SHA256 with an empty salt and a fixed context string.
 */
export function sessionCredentials(sessionToken: string): { id: string; key: Buffer } {
  const out = Buffer.from(
    hkdfSync("sha256", Buffer.from(sessionToken, "hex"), Buffer.alloc(0), "identity.mozilla.com/picl/v1/sessionToken", 64),
  );
  return { id: out.subarray(0, 32).toString("hex"), key: out.subarray(32) };
}

/** A HAWK Authorization header for a JSON POST to `url`, at server time `ts` (epoch seconds). */
function hawkHeader(url: URL, body: string, creds: { id: string; key: Buffer }, ts: number): string {
  const nonce = randomBytes(6).toString("base64");
  const hash = createHash("sha256").update(`hawk.1.payload\napplication/json\n${body}\n`).digest("base64");
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  // The trailing empty line is the (unused) ext field.
  const normalized = `hawk.1.header\n${ts}\n${nonce}\nPOST\n${url.pathname}${url.search}\n${url.hostname}\n${port}\n${hash}\n\n`;
  const mac = createHmac("sha256", creds.key).update(normalized).digest("base64");
  return `Hawk id="${creds.id}", ts="${ts}", nonce="${nonce}", hash="${hash}", mac="${mac}"`;
}

/**
 * Authenticator backed by the local Firefox profile's session token: it signs
 * FxA's `fxa-credentials` OAuth grant with it, as Firefox does for its own VPN.
 * See AUTH.md. The token stays in memory; nothing is logged or written here.
 */
export class FirefoxAuth implements Authenticator {
  readonly #profileDir: string;
  #cached: { token: string; expires: number } | null = null; // expires: epoch ms

  constructor(account: Pick<AccountState, "profileDir">) {
    this.#profileDir = account.profileDir;
  }

  async getAccessToken(signal?: AbortSignal): Promise<string> {
    // Reused until 5 minutes before it expires: Connection asks on every pass and usage refresh.
    if (this.#cached && this.#cached.expires - Date.now() > 300_000) return this.#cached.token;
    const sessionToken = this.#loadSessionToken();
    const { token, expiresIn } = await this.#exchangeForVpnToken(sessionToken, signal);
    this.#cached = { token, expires: Date.now() + expiresIn * 1000 };
    return token;
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

  async #exchangeForVpnToken(sessionToken: string, signal?: AbortSignal): Promise<{ token: string; expiresIn: number }> {
    const url = new URL(FXA_TOKEN_URL);
    const body = JSON.stringify({
      client_id: FIREFOX_CLIENT_ID,
      grant_type: "fxa-credentials",
      scope: VPN_SCOPES.join(" "),
      ttl: TOKEN_TTL,
    });
    const creds = sessionCredentials(sessionToken);
    let ts = Math.floor(Date.now() / 1000);
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: hawkHeader(url, body, creds, ts) },
        body,
        signal,
      });
      const data = (await res.json().catch(() => ({}))) as {
        access_token?: unknown; expires_in?: unknown; errno?: number; message?: string; serverTime?: number;
      };
      if (res.ok && typeof data.access_token === "string") {
        return { token: data.access_token, expiresIn: typeof data.expires_in === "number" ? data.expires_in : TOKEN_TTL };
      }
      // errno 111: this computer's clock is off; retry once on the server's.
      if (data.errno === 111 && typeof data.serverTime === "number" && attempt === 0) {
        ts = data.serverTime;
        continue;
      }
      if (data.errno === 110) throw new Error("Firefox's login has expired — sign in to Firefox again (foxhole login).");
      throw new Error(`Firefox account server refused the VPN token: ${data.message ?? `HTTP ${res.status}`}`);
    }
  }
}
