// The ways foxhole gets its own updates (the desktop and phone apps' file from GitHub, the TUI's package from npm), in
// order: through Firefox VPN while it's on; else directly, then through Firefox VPN opened just for that, then the
// user's relay (their Apps Script, relaymode.ts), each when the one before can't get it. A way that brings the server's
// answer (any HTTP status) is the last one tried: another would get the same. A download that breaks off carries on
// through the next way from where it stopped.
import { createWriteStream, existsSync, rmSync, statSync, writeFileSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Connection } from "./connection.js";
import { httpsGet, type Tunnel } from "./global.js";
import { log } from "./log.js";
import { vpnTunnel } from "./proxy.js";
import { relayGet } from "./relaymode.js";

/** A way to the internet for an update. */
export type Way =
  | { via: "direct" }
  | { via: "vpn"; proxy: { host: string; port: number } } // the local proxy, while it carries Firefox VPN
  | { via: "vpn"; tunnel: Tunnel } // Firefox VPN opened for this, while it's off
  | { via: "relay"; conn: Pick<Connection, "relay" | "server"> }; // the user's Apps Script

/** What the ways depend on, as the app has it now. */
export interface WayState {
  /** The local proxy while it carries Firefox VPN: connected, and not in relay mode. */
  vpn?: { host: string; port: number } | null;
  /** The account in use, once signed in: Firefox VPN can then be opened for an update while it's off. */
  conn?: Pick<Connection, "anyServer" | "currentPass"> | null;
  /** The relay when one is set up: relay mode's connection while it's on (global mode pins its front). */
  relay?: Pick<Connection, "relay" | "server"> | null;
}

/** The ways an update comes, in order: Firefox VPN while it's on, then directly; else directly, then Firefox VPN opened for it; the relay last. Pure. */
export function updateWays(s: WayState): Way[] {
  const { vpn, conn, relay } = s;
  const ways: Way[] = vpn ? [{ via: "vpn", proxy: vpn }, { via: "direct" }] : [{ via: "direct" }];
  if (!vpn && conn) ways.push({ via: "vpn", tunnel: (host, port) => vpnTunnel(conn, { host, port }) });
  if (relay?.relay) ways.push({ via: "relay", conn: relay });
  return ways;
}

/** The way as the log and the window's words name it. */
export const wayName = (w: Pick<Way, "via">): string => (w.via === "direct" ? "directly" : w.via === "vpn" ? "through Firefox VPN" : "through your relay");

// The ways tried, as words: each order updateWays makes (written out whole, so each has its translation in the window)
const TRIED: Record<string, string> = {
  direct: "directly",
  "direct vpn": "directly or through Firefox VPN",
  "direct relay": "directly or through your relay",
  "direct vpn relay": "directly, through Firefox VPN or through your relay",
  "vpn direct": "through Firefox VPN or directly",
  "vpn direct relay": "through Firefox VPN, directly or through your relay",
};
/** The ways tried as one says them ("directly or through Firefox VPN"); null for an order updateWays doesn't make. Pure. */
export const triedText = (ways: Pick<Way, "via">[] = []): string | null => TRIED[ways.map((w) => w.via).join(" ")] ?? null;

/** The server answered with this status: no other way would get another answer. */
export const httpError = (status: number): Error & { status: number } => Object.assign(new Error(`HTTP ${status}`), { status });

/** A response read as a stream: an https one, or the relay's, from memory. */
export type Res = Readable & { statusCode?: number; headers: Record<string, string | string[] | undefined> };

/** GETs `url` by `way`; redirects come back, not followed. */
export async function get(url: string, way: Way, headers: Record<string, string> = {}): Promise<Res> {
  if (way.via === "relay") {
    const r = await relayGet(way.conn, url, headers);
    return Object.assign(Readable.from(r.body.length ? [r.body] : [], { objectMode: false }), { statusCode: r.status, headers: r.headers });
  }
  return httpsGet(url, way.via === "direct" ? undefined : "proxy" in way ? way.proxy : way.tunnel, headers);
}

/**
 * `fn` by each way in turn, till one gets the server's answer: an error with a `status` (the server's) ends it as any
 * answer does; a way's own failure (no connection, cut off, too slow) goes on to the next. `fn` hears whether its way
 * is the last (then nothing's given up on for being slow). Throws the last way's failure when none got through, with
 * `tried`: the ways it went by.
 */
export async function throughWays<T>(ways: Way[], fn: (way: Way, last: boolean) => Promise<T>, signal?: AbortSignal): Promise<T> {
  let failed: unknown = new Error("no way to the internet");
  for (const [i, way] of ways.entries()) {
    try {
      return await fn(way, i === ways.length - 1);
    } catch (err) {
      if ((err as { status?: number }).status || signal?.aborted) throw err;
      log(`update ${wayName(way)}: ${(err as Error).message}`);
      failed = err;
    }
  }
  throw Object.assign(failed as Error, { tried: ways });
}

// A way that brings less than this in 30 s can't get a release's file in good time (over an hour for 120 MB): the next
// way carries on from there. The last way is let run.
const SLOW = { ms: 30_000, bytes: 1 << 20 };
// Through the relay a file comes in pieces, a script call each (Apps Script fetches at most 50 MB a call), a few at once
const PIECE = 4 << 20;
const AT_ONCE = 3;

const sizeOf = (file: string) => (existsSync(file) ? statSync(file).size : 0);

/**
 * Downloads `url` to `file` by `way`, following redirects and carrying on from what an earlier try left there (by any
 * way); `progress(percent)` as it goes. `last`: no way after this one, so a slow one isn't given up on (`slow`: what's
 * too slow, for tests). An HTTP error has its `status`.
 */
export async function download(url: string, file: string, way: Way, progress: (percent: number) => void, { last = true, signal, slow = SLOW }: { last?: boolean; signal?: AbortSignal; slow?: typeof SLOW } = {}): Promise<void> {
  if (way.via === "relay") return inPieces(url, file, way.conn, progress, signal);
  for (let hops = 0; hops < 6; hops++) {
    signal?.throwIfAborted();
    const have = sizeOf(file);
    const res = await get(url, way, have ? { range: `bytes=${have}-` } : {});
    if (signal?.aborted) res.destroy();
    signal?.throwIfAborted(); // stopped while it connected
    const { statusCode = 0, headers } = res;
    if (statusCode >= 300 && statusCode < 400 && headers.location) {
      res.resume();
      url = new URL(String(headers.location), url).href;
      continue;
    }
    if (statusCode === 416 && have) {
      res.resume();
      if (Number(/\/(\d+)$/.exec(String(headers["content-range"] ?? ""))?.[1]) === have) return; // it's all there already
      rmSync(file); // what's there doesn't fit: from the start
      continue;
    }
    if (statusCode !== 200 && statusCode !== 206) {
      res.resume();
      throw httpError(statusCode);
    }
    const from = statusCode === 206 ? have : 0; // a 200 is the whole file again
    const total = statusCode === 206 ? Number(/\/(\d+)$/.exec(String(headers["content-range"] ?? ""))?.[1]) : Number(headers["content-length"]);
    if (!(total > 0)) {
      res.resume();
      throw new Error("the server didn't say the file's size");
    }
    const stop = () => res.destroy(signal?.reason as Error);
    signal?.addEventListener("abort", stop, { once: true });
    let got = from;
    let mark = { at: Date.now(), got };
    try {
      await pipeline(
        res,
        async function* (chunks: AsyncIterable<Buffer>) {
          for await (const c of chunks) {
            got += c.length;
            const now = Date.now();
            if (!last && now - mark.at >= slow.ms) {
              if (got - mark.got < slow.bytes) throw new Error(`too slow (${Math.round((got - mark.got) / 1024)} KB in ${Math.round((now - mark.at) / 1000)} s)`);
              mark = { at: now, got };
            }
            progress(Math.floor((got / total) * 100));
            yield c;
          }
        },
        createWriteStream(file, { flags: from ? "a" : "w" }),
      );
    } finally {
      signal?.removeEventListener("abort", stop);
    }
    if (sizeOf(file) !== total) throw new Error("download cut short");
    return;
  }
  throw new Error("too many redirects");
}

/** `url` to `file` through the relay, a piece a script call, a few at once and written in order, from what's there. */
async function inPieces(url: string, file: string, conn: Pick<Connection, "relay" | "server">, progress: (percent: number) => void, signal?: AbortSignal): Promise<void> {
  let at = url; // where the file is: GitHub's own address, then where it sends to (a link that runs out: asked anew)
  const once = async (from: number, to: number) => {
    for (let hops = 0; hops < 6; hops++) {
      const r = await relayGet(conn, at, { range: `bytes=${from}-${to}` });
      const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(r.headers["content-range"] ?? "");
      if (r.status >= 300 && r.status < 400 && r.headers.location) at = new URL(r.headers.location, at).href;
      else if (r.status === 206 && range && Number(range[1]) === from && r.body.length === Number(range[2]) - from + 1) return { body: r.body, total: Number(range[3]) };
      else if (r.status === 206) throw new Error("the relay brought a piece that doesn't fit");
      else if (r.status === 416) return { body: null, total: Number(/\/(\d+)$/.exec(r.headers["content-range"] ?? "")?.[1]) };
      else if (r.status === 200 && !from) return { body: r.body, total: r.body.length, whole: true }; // a server that doesn't do ranges
      else if (r.status === 200) throw new Error("the server sent the whole file, not the rest");
      else if (at !== url && r.status >= 400 && r.status < 500) at = url; // the link GitHub sent to ran out
      else throw httpError(r.status);
    }
    throw new Error("too many redirects");
  };
  // a script call that fails (a timeout at Google, a dropped connection) is tried twice more
  const piece = async (from: number, to: number) => {
    for (let tries = 1; ; tries++) {
      try {
        return await once(from, to);
      } catch (err) {
        if ((err as { status?: number }).status || tries === 3 || signal?.aborted) throw err;
        await new Promise((r) => setTimeout(r, 1000 * tries));
      }
    }
  };
  let have = sizeOf(file);
  let first = await piece(have, have + PIECE - 1);
  if (!first.body) {
    if (first.total === have) return; // it's all there already
    rmSync(file, { force: true }); // what's there doesn't fit: from the start
    have = 0;
    first = await piece(0, PIECE - 1);
  }
  const total = first.total;
  if (!(total > 0) || !first.body) throw new Error("the server didn't say the file's size");
  if ("whole" in first) {
    writeFileSync(file, first.body);
    return progress(100);
  }
  await appendFile(file, first.body);
  have += first.body.length;
  progress(Math.floor((have / total) * 100));
  let next = have;
  const ask = () => {
    const from = next;
    next = Math.min(total, from + PIECE);
    return piece(from, next - 1);
  };
  const flying: ReturnType<typeof piece>[] = [];
  try {
    while (have < total) {
      while (flying.length < AT_ONCE && next < total) flying.push(ask());
      const p = await flying.shift()!;
      signal?.throwIfAborted();
      if (!p.body || p.total !== total) throw new Error("the file changed as it came");
      await appendFile(file, p.body);
      have += p.body.length;
      progress(Math.floor((have / total) * 100));
    }
  } finally {
    for (const f of flying) f.catch(() => {}); // the pieces after one that failed: not waited for
  }
  if (sizeOf(file) !== total) throw new Error("download cut short");
}
