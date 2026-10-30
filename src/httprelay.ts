// Reaching Mozilla's Guardian control API (vpn.mozilla.org) when it's blocked on this network, as it is on
// Iranian IPs: relay just those requests through a Google Apps Script web app — MasterHttpRelayVPN's Code.gs
// (https://github.com/masterking32/MasterHttpRelayVPN). script.google.com is reachable where vpn.mozilla.org
// isn't; the script fetches Guardian from Google's servers and returns the response. guardian.ts uses this only
// when the direct connection fails, and only for its own control calls (the proxy pass, usage, entitlement) —
// never the VPN's data, which flows straight through the tunnel to Fastly. The script sees the short-lived,
// VPN-scoped access token while relaying, so point it at a deployment you own.
//
// Protocol (Code.gs): POST JSON { k: authKey, u: url, m: method, h: headers, b: base64(body), ct } to the /exec
// endpoint; reply JSON { s: status, h: headers, b: base64(body), gz? } — or { e: error }. Apps Script's
// HtmlService wraps that reply in a bootstrap page that calls goog.script.init("<JS-escaped JSON>", …) whose
// userHtml field is our envelope; parseEnvelope() unwraps it.
import { gunzipSync } from "node:zlib";
import type { Settings } from "./settings.js";

/** A configured relay: the Apps Script /exec endpoint and its shared secret. */
export interface RelayConfig {
  url: string;
  key: string;
}

/** The web-app endpoint for an Apps Script deployment id. */
export const relayUrl = (deploymentId: string): string => `https://script.google.com/macros/s/${deploymentId}/exec`;

/** The relay from the FOXHOLE_RELAY_ID / FOXHOLE_RELAY_KEY env vars or the saved settings; null when not set up. */
export function loadRelay(settings?: Pick<Settings, "relay"> | null): RelayConfig | null {
  const id = process.env.FOXHOLE_RELAY_ID?.trim() || settings?.relay?.deploymentId;
  const key = process.env.FOXHOLE_RELAY_KEY?.trim() || settings?.relay?.authKey;
  return id && key ? { url: relayUrl(id), key } : null;
}

const tryJson = (s: string): Record<string, unknown> | null => {
  try {
    const v: unknown = JSON.parse(s);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
};

/**
 * Apps Script serves HtmlService output inside a page that calls goog.script.init("<JS-escaped JSON>", "", …);
 * the JSON's `userHtml` field holds our envelope. Returns that inner text, or null if the page isn't that shape.
 */
function unwrapAppsScript(text: string): string | null {
  const marker = 'goog.script.init("';
  const i = text.indexOf(marker);
  if (i < 0) return null;
  const start = i + marker.length;
  const end = text.indexOf('", "", undefined', start);
  if (end < 0) return null;
  // Undo the JS string escaping: \xNN hex, then \\ → \, then \/ → / (same order as the reference client).
  const inner = text
    .slice(start, end)
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\\\/g, "\\")
    .replace(/\\\//g, "/");
  const outer = tryJson(inner);
  return typeof outer?.userHtml === "string" ? outer.userHtml : null;
}

interface Envelope {
  s?: number; // target status
  h?: Record<string, string | string[]>; // target headers
  b?: string; // base64 target body
  gz?: number; // 1: the base64 body is gzip-compressed (the relay's own compression)
  e?: string; // the relay refused: unauthorized, bad url, quota, …
}

/** The JSON envelope from Code.gs, out of its wrapper — parsed directly, or from the Apps Script page, or a last-ditch {…} match. */
export function parseEnvelope(text: string): Envelope {
  const obj = tryJson(text) ?? tryJson(unwrapAppsScript(text) ?? "") ?? tryJson(text.match(/\{[\s\S]*\}/)?.[0] ?? "");
  // Apps Script's own error page: the script threw, and the message is in a monospace box
  const thrown = text.match(/font-family:monospace[^>]*>([^<]+)/)?.[1];
  if (!obj && thrown) throw new Error(`relay: ${thrown.replace(/&(quot|#39|lt|gt|amp);/g, (_, e: string) => ({ quot: '"', "#39": "'", lt: "<", gt: ">", amp: "&" })[e]!).slice(0, 200)}`);
  if (!obj) throw new Error(`relay: response wasn't the expected JSON (${text.slice(0, 120).replace(/\s+/g, " ")}…)`);
  if (typeof obj.e === "string") throw new Error(`relay: ${obj.e}`);
  return obj as Envelope;
}

// Dropped when rebuilding the target's headers: they describe the relay hop, not the decoded body we return.
const HOP = new Set(["content-length", "content-encoding", "transfer-encoding", "connection", "keep-alive"]);

/** The relay's envelope as a Response the caller reads like a direct one: the decoded body, status and headers. */
export function envelopeResponse(env: Envelope): Response {
  let body = Buffer.from(env.b ?? "", "base64");
  if (env.gz) body = gunzipSync(body);
  const headers = new Headers();
  for (const [k, v] of Object.entries(env.h ?? {})) {
    if (HOP.has(k.toLowerCase())) continue;
    for (const val of Array.isArray(v) ? v : [v]) headers.append(k, String(val));
  }
  return new Response(body, { status: env.s ?? 200, headers });
}

/**
 * Relays one request through the Apps Script and returns the target's response. Throws only when the relay itself
 * fails (network, wrong key, quota); a target HTTP error (401, 429, …) comes back as a normal non-ok Response.
 */
export async function relayRequest(
  relay: RelayConfig,
  req: { method: string; url: string; headers?: Record<string, string>; body?: string; contentType?: string },
  signal?: AbortSignal,
): Promise<Response> {
  const payload: Record<string, unknown> = { k: relay.key, u: req.url, m: req.method, h: req.headers ?? {} };
  if (req.body !== undefined) {
    payload.b = Buffer.from(req.body).toString("base64");
    payload.ct = req.contentType ?? "application/json";
  }
  // Apps Script can take a while; cap the wait, and still honour a caller's abort (AbortSignal.any isn't on Node 18).
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error("relay timed out")), 55_000);
  const onAbort = () => ctrl.abort(signal?.reason);
  if (signal?.aborted) ctrl.abort(signal.reason);
  else signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const res = await fetch(relay.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`relay: Apps Script returned HTTP ${res.status}`);
    return envelopeResponse(parseEnvelope(await res.text()));
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}
