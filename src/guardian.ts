// Client for Mozilla's Guardian service, the backend behind Firefox's built-in
// VPN. Every call authenticates with an FxA access token (VPN scope) that the
// auth module provides; see auth.ts.
import https from "node:https";

export const GUARDIAN_HOST = "vpn.mozilla.org";

// Global mode routes this IPv4 around the tunnel. The tunnel needs a pass from Guardian,
// so getting one must not need the tunnel, nor the DNS that goes through it.
let pinnedIp: string | null = null;

/** Sends every later Guardian request to `ip` instead of looking the host up (global mode). */
export function pinGuardian(ip: string): void {
  pinnedIp = ip;
}

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
 * fetch() for Guardian, able to dial the pinned IP while TLS and the Host header keep
 * the hostname (as proxy.ts does for the VPN server). fetch() has no option for that.
 */
function request(method: "GET" | "HEAD", path: string, accessToken: string, signal?: AbortSignal): Promise<Response> {
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
        timeout: 10_000, // like fetch's connect timeout; a dead pinned IP would hang for minutes
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
