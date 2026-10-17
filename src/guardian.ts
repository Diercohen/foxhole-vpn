// Client for Mozilla's Guardian service, the backend behind Firefox's built-in
// VPN. Every call authenticates with an FxA access token (VPN scope) that the
// auth module provides; see auth.ts.
const GUARDIAN = "https://vpn.mozilla.org";

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
  const res = await fetch(`${GUARDIAN}/api/v1/fpn/token`, {
    method: "GET",
    headers: bearer(accessToken),
    signal,
  });
  const usage = parseUsage(res.headers);
  if (!res.ok) throw new Error(`Proxy pass: ${statusError(res.status)}`);
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
  const res = await fetch(`${GUARDIAN}/api/v1/fpn/token`, {
    method: "HEAD",
    headers: bearer(accessToken),
    signal,
  });
  return res.ok ? parseUsage(res.headers) : null;
}

/** Fetches the account entitlement, or null if the account is not a VPN user. */
export async function fetchEntitlement(
  accessToken: string,
  signal?: AbortSignal,
): Promise<Entitlement | null> {
  const res = await fetch(`${GUARDIAN}/api/v1/fpn/status`, {
    method: "GET",
    headers: bearer(accessToken),
    signal,
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Status: ${statusError(res.status)}`);
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
