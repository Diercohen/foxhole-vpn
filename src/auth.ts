import { join } from "node:path";
import { readFileSync } from "node:fs";
import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import type { AccountState } from "./profile.js";
import { mozillaFetch } from "./guardian.js";

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
export const FIREFOX_CLIENT_ID = "5882386c6d801776";
/** Mozilla's account server (FxA). */
export const FXA_API = "https://api.accounts.firefox.com/v1";
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

/**
 * A HAWK Authorization header for a request to `url`, at server time `ts` (epoch seconds): a JSON POST's `body` is
 * signed with it (its hash); a GET has none.
 */
function hawkHeader(method: "GET" | "POST", url: URL, body: string | null, creds: { id: string; key: Buffer }, ts: number): string {
  const nonce = randomBytes(6).toString("base64");
  const hash = body === null ? "" : createHash("sha256").update(`hawk.1.payload\napplication/json\n${body}\n`).digest("base64");
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  // The trailing empty line is the (unused) ext field.
  const normalized = `hawk.1.header\n${ts}\n${nonce}\n${method}\n${url.pathname}${url.search}\n${url.hostname}\n${port}\n${hash}\n\n`;
  const mac = createHmac("sha256", creds.key).update(normalized).digest("base64");
  return `Hawk id="${creds.id}", ts="${ts}", nonce="${nonce}", ${hash ? `hash="${hash}", ` : ""}mac="${mac}"`;
}

/** What FxA answers: the JSON, its errno and message on an error. */
export type FxaAnswer = { ok: boolean; status: number; data: Record<string, unknown> & { errno?: number; message?: string } };

/**
 * A request to FxA's `path` (e.g. "/oauth/token"): a JSON POST of `payload`, or a GET where it's null; signed with
 * `sessionToken` when given (HAWK), as Firefox makes it. Signed: again once on the server's clock if this one is off
 * (errno 111).
 */
async function fxaRequest(path: string, payload: object | null, sessionToken?: string, signal?: AbortSignal): Promise<FxaAnswer> {
  const url = new URL(FXA_API + path);
  const method = payload ? "POST" : "GET";
  const body = payload ? JSON.stringify(payload) : null;
  const creds = sessionToken ? sessionCredentials(sessionToken) : null;
  let ts = Math.floor(Date.now() / 1000);
  for (let attempt = 0; ; attempt++) {
    const headers: Record<string, string> = body === null ? {} : { "content-type": "application/json" };
    if (creds) headers.authorization = hawkHeader(method, url, body, creds, ts);
    const res = await mozillaFetch(url.href, { method, headers, ...(body !== null && { body }) }, signal); // through the relay where it's blocked
    const data = ((await res.json().catch(() => ({}))) ?? {}) as FxaAnswer["data"];
    if (creds && data.errno === 111 && typeof data.serverTime === "number" && attempt === 0) {
      ts = data.serverTime;
      continue;
    }
    return { ok: res.ok, status: res.status, data };
  }
}

/** A JSON POST to FxA's `path` (fxaRequest). */
export function fxaPost(path: string, payload: object, sessionToken?: string, signal?: AbortSignal): Promise<FxaAnswer> {
  return fxaRequest(path, payload, sessionToken, signal);
}

/** An error FxA gave: its errno with it (110: the session is gone, signed out or expired). */
export class FxaError extends Error {
  constructor(message: string, readonly errno?: number) {
    super(message);
  }
}

/**
 * Whether Mozilla has confirmed a session's sign-in, as Mozilla's sign-in page has it once it's done: the session
 * verified (as by a code from the email), the account's email too, and the second step where the account has one.
 * Throws where it can't say (FxaError 110: the session's gone, signed out or expired).
 */
export async function sessionVerified(sessionToken: string, signal?: AbortSignal): Promise<boolean> {
  const { ok, status, data } = await fxaRequest("/session/status", null, sessionToken, signal);
  if (!ok) throw new FxaError(`Mozilla's account server didn't say if the sign-in is confirmed: ${data.message ?? `HTTP ${status}`}`, data.errno);
  const details = (data.details ?? {}) as { accountEmailVerified?: boolean; sessionVerificationMeetsMinimumAAL?: boolean };
  return data.state === "verified" && details.accountEmailVerified !== false && details.sessionVerificationMeetsMinimumAAL !== false;
}

/**
 * Authenticator backed by a Mozilla account's session token: it signs FxA's `fxa-credentials` OAuth grant with it,
 * as Firefox does for its own VPN (AUTH.md). `load` reads the token (a file: Firefox's profile, or Foxhole's
 * accounts); it stays in memory, nothing is logged. `expired`: what to say when the session is gone (errno 110).
 */
export class SessionAuth implements Authenticator {
  readonly #load: () => string;
  readonly #expired: string;
  #cached: { token: string; expires: number } | null = null; // expires: epoch ms

  constructor(load: () => string, expired = "This sign-in has ended (signed out, or expired): sign in again.") {
    this.#load = load;
    this.#expired = expired;
  }

  async getAccessToken(signal?: AbortSignal): Promise<string> {
    // Reused until 5 minutes before it expires: Connection asks on every pass and usage refresh.
    if (this.#cached && this.#cached.expires - Date.now() > 300_000) return this.#cached.token;
    const { ok, status, data } = await fxaPost(
      "/oauth/token",
      { client_id: FIREFOX_CLIENT_ID, grant_type: "fxa-credentials", scope: VPN_SCOPES.join(" "), ttl: TOKEN_TTL },
      this.#load(),
      signal,
    );
    if (ok && typeof data.access_token === "string") {
      const expiresIn = typeof data.expires_in === "number" ? data.expires_in : TOKEN_TTL;
      this.#cached = { token: data.access_token, expires: Date.now() + expiresIn * 1000 };
      return data.access_token;
    }
    if (data.errno === 110) throw new FxaError(this.#expired, 110);
    throw new FxaError(`Firefox account server refused the VPN token: ${data.message ?? `HTTP ${status}`}`, data.errno);
  }

  /** A refresh token of this account for another device (a TV: tvpair.ts), VPN-only: it makes its own access tokens. */
  async refreshToken(signal?: AbortSignal): Promise<string> {
    const { ok, status, data } = await fxaPost(
      "/oauth/token",
      { client_id: FIREFOX_CLIENT_ID, grant_type: "fxa-credentials", scope: VPN_SCOPES.join(" "), access_type: "offline" },
      this.#load(),
      signal,
    );
    if (ok && typeof data.refresh_token === "string") return data.refresh_token;
    if (data.errno === 110) throw new FxaError(this.#expired, 110);
    throw new FxaError(`Mozilla refused a sign-in for the TV: ${data.message ?? `HTTP ${status}`}`, data.errno);
  }
}

/** An account's sign-in another device sent this one (tvpair.ts): a refresh token, VPN-only. */
export class RefreshAuth implements Authenticator {
  readonly #token: string;
  #cached: { token: string; expires: number } | null = null;

  constructor(refreshToken: string) {
    this.#token = refreshToken;
  }

  async getAccessToken(signal?: AbortSignal): Promise<string> {
    if (this.#cached && this.#cached.expires - Date.now() > 300_000) return this.#cached.token;
    const { ok, status, data } = await fxaPost(
      "/oauth/token",
      { client_id: FIREFOX_CLIENT_ID, grant_type: "refresh_token", refresh_token: this.#token, scope: VPN_SCOPES.join(" "), ttl: TOKEN_TTL },
      undefined,
      signal,
    );
    if (ok && typeof data.access_token === "string") {
      const expiresIn = typeof data.expires_in === "number" ? data.expires_in : TOKEN_TTL;
      this.#cached = { token: data.access_token, expires: Date.now() + expiresIn * 1000 };
      return data.access_token;
    }
    // 108, 110: the token's gone (signed out of, from the account's devices)
    if (data.errno === 108 || data.errno === 110 || status === 401) throw new FxaError("This sign-in has ended (signed out, or expired): sign in again.", 110);
    throw new FxaError(`Firefox account server refused the VPN token: ${data.message ?? `HTTP ${status}`}`, data.errno);
  }
}

/** Ends a refresh token at Mozilla (it leaves the account's devices list); quietly, as it goes from here anyway. */
export async function destroyToken(token: string): Promise<void> {
  await fxaPost("/oauth/destroy", { client_id: FIREFOX_CLIENT_ID, token }, undefined, AbortSignal.timeout(10_000)).catch(() => {});
}

/** The local Firefox profile's sign-in (its session token, read as each token is made). */
export class FirefoxAuth extends SessionAuth {
  constructor(account: Pick<AccountState, "profileDir">) {
    super(() => {
      const data = JSON.parse(readFileSync(join(account.profileDir, "signedInUser.json"), "utf8")) as { accountData?: { sessionToken?: string } };
      const token = data.accountData?.sessionToken;
      if (!token) throw new Error("Not signed in to Firefox (no session token in profile).");
      return token;
    }, "Firefox's login has expired — sign in to Firefox again (foxhole login).");
  }
}
