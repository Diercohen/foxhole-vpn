// Client for Mozilla's Guardian service, the backend behind Firefox's built-in
// VPN. Every call authenticates with an FxA access token (VPN scope) that the
// auth module provides; see auth.ts.
import https from "node:https";
import tls from "node:tls";
import type { Duplex } from "node:stream";
import { log } from "./log.js";
import { relayRequest, type RelayConfig } from "./httprelay.js";

export const GUARDIAN_HOST = "vpn.mozilla.org";

// Global mode routes this IPv4 around the tunnel. The tunnel needs a pass from Guardian,
// so getting one must not need the tunnel, nor the DNS that goes through it.
let pinnedIp: string | null = null;

/** Sends every later Guardian request to `ip` instead of looking the host up (global mode). */
export function pinGuardian(ip: string): void {
  pinnedIp = ip;
}

// Where vpn.mozilla.org is blocked (Iran), the one call that can't be reached directly goes through this relay.
let relay: RelayConfig | null = null;

/** Sets (or clears, with null) the relay guardian falls back to when vpn.mozilla.org won't connect. */
export function useRelay(r: RelayConfig | null): void {
  relay = r;
}

/** The relay set with useRelay(), if any (hot.ts gets its file through it when nothing else does). */
export const relayInUse = (): RelayConfig | null => relay;

// Once connected, the calls go through the VPN itself (proxy.ts ownTunnel): Mozilla neither blocks its exit nor refuses
// it (451), so the relay is only needed for the first pass, and isn't asked every few minutes for the data left.
type Tunnel = (host: string, port: number) => Promise<Duplex | null>;
let tunnel: Tunnel | null = null;

/** Sets (or clears, with null) the way through the VPN that Guardian's calls take first, while connected. */
export function useTunnel(t: Tunnel | null): void {
  tunnel = t;
}

/** The way set with useTunnel(), if any. */
export const tunnelInUse = (): Tunnel | null => tunnel;

/** A proxy pass: the short-lived JWT the proxy servers accept. */
export interface ProxyPass {
  token: string; // raw JWT
  notBefore: number; // epoch seconds
  expires: number; // epoch seconds
}

/** Remaining-data info, from the X-Quota-* response headers. */
export interface Usage {
  unlimited: boolean;
  max: bigint; // bytes
  remaining: bigint; // bytes
  reset: Date | null; // when the monthly quota resets
}

/** Account entitlement, from /api/v1/fpn/status. */
export interface Entitlement {
  subscribed: boolean;
  uid: number;
  maxBytes: bigint;
  limitedBandwidth: boolean;
}

function parseUsage(headers: Headers): Usage | null {
  if (headers.get("X-Quota-Unlimited") === "true") {
    return { unlimited: true, max: 0n, remaining: 0n, reset: null };
  }
  const limit = headers.get("X-Quota-Limit");
  const remaining = headers.get("X-Quota-Remaining");
  const reset = headers.get("X-Quota-Reset");
  if (limit === null || remaining === null || reset === null) return null;
  return {
    unlimited: false,
    max: BigInt(limit),
    remaining: BigInt(remaining),
    reset: new Date(reset),
  };
}

function parseJwtTimes(jwt: string): { nbf: number; exp: number } {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Malformed proxy pass JWT");
  const body = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as {
    nbf?: number;
    exp?: number;
  };
  if (typeof body.nbf !== "number" || typeof body.exp !== "number") {
    throw new Error("Proxy pass JWT missing nbf/exp");
  }
  return { nbf: body.nbf, exp: body.exp };
}

function bearer(accessToken: string): Record<string, string> {
  return {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };
}

/**
 * A Guardian request: direct, falling back to the relay (when one is set) if vpn.mozilla.org won't connect —
 * which is how it's blocked on Iranian IPs — or refuses this network's region (451, by the caller's address,
 * before any login is looked at: the relay asks from Google's). Only this control call is relayed, never the VPN's data.
 */
async function request(method: "GET" | "HEAD", path: string, accessToken: string, signal?: AbortSignal): Promise<Response> {
  // a VPN server that doesn't answer would hold the call as long as the proxy waits for one (15 s)
  const opening = tunnel?.(GUARDIAN_HOST, 443).catch(() => null);
  const through = opening && (await Promise.race([opening, new Promise<null>((r) => setTimeout(r, 6_000, null).unref())]));
  if (opening && !through) void opening.then((late) => late?.destroy());
  if (through)
    try {
      const res = await directRequest(method, path, accessToken, signal, through);
      if (res.status !== 451) return res;
    } catch (err) {
      if (signal?.aborted) throw err;
      log(`guardian: through the VPN failed (${(err as Error).message}), trying without it`);
    }
  let why: string;
  try {
    const res = await directRequest(method, path, accessToken, signal);
    if (res.status !== 451) return res;
    why = "refuses this region (451)";
  } catch (err) {
    if (!relay) throw !signal?.aborted && (await reachable(RELAY_HOST)) ? new GuardianBlocked(err as Error) : err;
    why = "unreachable";
  }
  // a 451 with no relay set: one is what gets around it, as where it's blocked (its code is what a failed connect shows)
  if (!relay) throw new GuardianBlocked(Object.assign(new Error(`${GUARDIAN_HOST} ${why}`), { code: "HTTP 451" }), true);
  log(`guardian: ${GUARDIAN_HOST} ${why}, relaying ${path} via Apps Script`);
  // UrlFetchApp has no HEAD, and here we only read the response's headers, so a HEAD goes through as GET.
  return relayRequest(
    relay,
    { method: method === "HEAD" ? "GET" : method, url: `https://${GUARDIAN_HOST}${path}`, headers: bearer(accessToken) },
    signal,
  );
}

/**
 * fetch() for Guardian, able to dial the pinned IP while TLS and the Host header keep
 * the hostname (as proxy.ts does for the VPN server). fetch() has no option for that.
 * `through`: a stream already open to vpn.mozilla.org:443 (the VPN's tunnel), its TLS and certificate checked on it.
 */
function directRequest(method: "GET" | "HEAD", path: string, accessToken: string, signal?: AbortSignal, through?: Duplex): Promise<Response> {
  return new Promise((resolve, reject) => {
    const fail = (err: Error) => reject(new Error(`can't reach ${GUARDIAN_HOST}`, { cause: err }));
    const req = https.request(
      {
        host: pinnedIp ?? GUARDIAN_HOST,
        servername: GUARDIAN_HOST,
        path,
        method,
        headers: { Host: GUARDIAN_HOST, ...bearer(accessToken) },
        signal,
        ...(through && { createConnection: () => tls.connect({ socket: through, servername: GUARDIAN_HOST }) }),
        // like fetch's connect timeout; a dead pinned IP would hang for minutes. Shorter with a relay to fall
        // back to, so a silently-dropped (blocked) connection gives up sooner.
        timeout: relay ? 6_000 : 10_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("error", fail);
        res.on("end", () => {
          try {
            const headers = new Headers();
            for (let i = 0; i < res.rawHeaders.length; i += 2) headers.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
            const body = chunks.length ? Buffer.concat(chunks).toString() : null;
            resolve(new Response(body, { status: res.statusCode, headers }));
          } catch (err) {
            fail(err as Error); // a status or header Response refuses
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timed out"))).on("error", fail).end();
  });
}

/**
 * fetch() for Mozilla's other hosts, on the same Fastly addresses as Guardian: its account server (auth.ts fxaPost: the
 * VPN's token, sign-ins) and the server list. Direct, else through the relay when one is set, as `request` does; with
 * none, GuardianBlocked when Google answers, so each UI offers the relay's setup. Only a request that gets no answer
 * is relayed: any answer, an error status too, is Mozilla's.
 */
export async function mozillaFetch(url: string, init: { method?: "GET" | "POST"; headers?: Record<string, string>; body?: string } = {}, signal?: AbortSignal): Promise<Response> {
  const via = relay;
  // with a relay to fall back to, a silently dropped (blocked) connection gives up sooner, as directRequest's does:
  // the relay's answer still comes within the callers' 15 s
  const ctrl = new AbortController();
  const stop = () => ctrl.abort(signal?.reason);
  if (signal?.aborted) stop();
  else signal?.addEventListener("abort", stop, { once: true });
  const cap = via ? setTimeout(() => ctrl.abort(new Error("timed out")), 6_000) : undefined;
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } catch (err) {
    const { hostname, pathname } = new URL(url);
    if (signal?.aborted) throw err;
    if (!via) throw (await reachable(RELAY_HOST)) ? new GuardianBlocked(err as Error, false, hostname) : err;
    const cause = (err as Error).cause as { code?: string } | undefined;
    log(`${hostname} unreachable (${cause?.code ?? (err as Error).message}), relaying ${pathname} via Apps Script`);
    // the script sets the body's type from ct
    const { "content-type": contentType, ...headers } = init.headers ?? {};
    return relayRequest(via, { method: init.method ?? "GET", url, headers, body: init.body, contentType }, signal);
  } finally {
    clearTimeout(cap);
    signal?.removeEventListener("abort", stop);
  }
}

/** Where a relay runs (httprelay.ts): Google's Apps Script. */
const RELAY_HOST = "script.google.com";

/**
 * A Mozilla host (`host`: Guardian's, or mozillaFetch's) won't connect while Google answers: the network is fine and
 * it's blocked on it (Iran), not offline; or (`region`) vpn.mozilla.org answers 451, refusing this network's country.
 * With no relay set, that's what to set up; each UI offers its setup (relaysetup.ts).
 */
export class GuardianBlocked extends Error {
  constructor(cause: Error, readonly region = false, readonly host = GUARDIAN_HOST) {
    super(region ? "Mozilla doesn't offer Firefox VPN in this region: set up a relay (Settings → VPN relay)" : `${host} seems blocked on this network: set up a relay (Settings → VPN relay)`, { cause });
  }
}

/** Whether host answers HTTPS at all (any status) within 5 seconds. */
function reachable(host: string): Promise<boolean> {
  return new Promise((resolve) => {
    https
      .request({ host, method: "HEAD", path: "/", timeout: 5000 }, (res) => (res.resume(), resolve(true)))
      .on("timeout", function (this: import("node:http").ClientRequest) {
        this.destroy();
      })
      .on("error", () => resolve(false))
      .end();
  });
}

/** A non-200 Guardian response; `status` lets callers spot 401 (token rejected). */
export class GuardianError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

/** Human-readable reason for a non-200 Guardian status. */
function statusError(status: number): string {
  switch (status) {
    case 401:
      return "login rejected (token invalid or expired)";
    case 403:
      return "account not entitled to the VPN";
    case 429:
      return "monthly data quota exceeded";
    case 451:
      return "VPN not available in this region";
    default:
      return status >= 500 ? "Guardian server error" : `unexpected status ${status}`;
  }
}

/** Fetches a fresh proxy pass and the current usage. */
export async function fetchPass(
  accessToken: string,
  signal?: AbortSignal,
): Promise<{ pass: ProxyPass; usage: Usage | null }> {
  const res = await request("GET", "/api/v1/fpn/token", accessToken, signal);
  const usage = parseUsage(res.headers);
  if (!res.ok) throw new GuardianError(`Proxy pass: ${statusError(res.status)}`, res.status);
  const data = (await res.json()) as { token?: string };
  if (!data.token) throw new Error("Proxy pass response had no token");
  const { nbf, exp } = parseJwtTimes(data.token);
  return { pass: { token: data.token, notBefore: nbf, expires: exp }, usage };
}

/** Fetches only the current usage (cheap HEAD request), or null if unavailable. */
export async function fetchUsage(
  accessToken: string,
  signal?: AbortSignal,
): Promise<Usage | null> {
  const res = await request("HEAD", "/api/v1/fpn/token", accessToken, signal);
  return res.ok ? parseUsage(res.headers) : null;
}

/** Fetches the account entitlement, or null if the account is not a VPN user. */
export async function fetchEntitlement(
  accessToken: string,
  signal?: AbortSignal,
): Promise<Entitlement | null> {
  const res = await request("GET", "/api/v1/fpn/status", accessToken, signal);
  if (res.status === 404) return null;
  if (!res.ok) throw new GuardianError(`Status: ${statusError(res.status)}`, res.status);
  const d = (await res.json()) as {
    subscribed?: boolean;
    uid?: number;
    maxBytes?: string;
    limited_bandwidth?: boolean;
  };
  return {
    subscribed: !!d.subscribed,
    uid: d.uid ?? 0,
    maxBytes: BigInt(d.maxBytes ?? "0"),
    limitedBandwidth: d.limited_bandwidth ?? true,
  };
}

/** True when the pass is within `skewSeconds` of expiry and should be rotated. */
export function shouldRotate(pass: ProxyPass, skewSeconds = 120): boolean {
  return Date.now() / 1000 >= pass.expires - skewSeconds;
}
