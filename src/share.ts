// Sharing Foxhole with the family's other devices, with no internet: its settings (the relay, split tunneling's sites)
// in a link, and on Android the app itself. The sharing device shows a QR code of its page on the local network (its
// Wi-Fi, or its phone's hotspot): a phone's camera opens it, to download the app (from an Android phone, its own APK)
// and to open the settings in Foxhole. The settings ride in the page link's #fragment, which a browser never sends:
// the page only hands them on. Elsewhere, the link goes as text (foxhole://settings?d=…), pasted into Foxhole.
import { createReadStream, statSync } from "node:fs";
import http from "node:http";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { deploymentId, keyOk } from "./relaysetup.js";
import { DEFAULTS, parseSettings, type Settings } from "./settings.js";
import { appOf, type Split } from "./split.js";

/** The port the page waits on (the TV's sign-in has 47533). */
export const SHARE_PORT = 47534;
const PACKAGE = "io.github.diercohen.foxhole";

/** What a link carries: split tunneling with its sites (apps are each device's own), the relay, or both. */
export interface Shared {
  split?: Split;
  relay?: { deploymentId: string; authKey: string };
}

/** Split tunneling as it's shared: its sites, not its apps; null when it's as it comes, with nothing to share. Pure. */
function sharedSplit(split: Split): Split | null {
  const s = { ...split, rules: split.rules.filter((r) => appOf(r.match) === null) };
  return s.rules.length || s.smart || s.probe || s.default !== "vpn" ? s : null;
}

/** The link's data: `s`'s split tunneling and, with `relay`, its relay, deflated, in base64url; null if neither is set. Pure. */
export function shareData(s: Settings, relay: boolean): string | null {
  const split = sharedSplit(s.split);
  const shared: Shared = { ...(split && { split }), ...(relay && s.relay && { relay: s.relay }) };
  return shared.split || shared.relay ? deflateRawSync(JSON.stringify(shared)).toString("base64url") : null;
}

/** The link to paste into Foxhole. Pure. */
export const shareLink = (data: string): string => `foxhole://settings?d=${data}`;

/** The settings in a link (foxhole://settings?d=…, or the page's http://…/#…), or in its data alone; null if none. Pure. */
export function parseShared(text: string): Shared | null {
  const t = text.replace(/\s+/g, ""); // a messenger may have broken it into lines
  const data = t.match(/(?:[?&]d=|#)([\w-]+)$/)?.[1] ?? (/^[\w-]+$/.test(t) ? t : null);
  if (!data) return null;
  try {
    // a link may come from any web page (Android opens Foxhole with it): no more than 1 MB out of it
    const o = JSON.parse(inflateRawSync(Buffer.from(data, "base64url"), { maxOutputLength: 1 << 20 }).toString("utf8"));
    if (!o || typeof o !== "object") return null;
    const s = parseSettings(JSON.stringify({ split: o.split, relay: o.relay })); // each part checked as the settings file's
    if (s.relay && (deploymentId(s.relay.deploymentId) !== s.relay.deploymentId || !keyOk(s.relay.authKey))) return null; // as the setup takes them
    const split = o.split ? sharedSplit(s.split) : null;
    return split || s.relay ? { ...(split && { split }), ...(s.relay && { relay: s.relay }) } : null;
  } catch {
    return null;
  }
}

/** What `sh` sets, a line each, as it would here (`mine`: what's set already). Pure. */
export function sharedWhat(sh: Shared, mine: Settings = DEFAULTS): string[] {
  const what: string[] = [];
  if (sh.relay) {
    const id = sh.relay.deploymentId;
    const same = mine.relay?.deploymentId === id && mine.relay.authKey === sh.relay.authKey;
    what.push(`VPN relay ${id.slice(0, 8)}…${id.slice(-4)}${same ? ", yours already" : mine.relay ? ", in place of yours" : ""}`);
  }
  if (sh.split) {
    const t = sh.split, own = mine.split;
    const fresh = t.rules.filter((r) => !own.rules.some((x) => x.match === r.match && x.via === r.via)).length;
    const parts = [
      ...(t.default !== own.default ? [t.default === "direct" ? "only the sites listed use the VPN" : "every other site through the VPN"] : []),
      ...(t.smart ? ["Iranian sites direct"] : []),
      ...(t.probe ? ["Save data"] : []),
      ...(t.rules.length ? [`${t.rules.length} site${t.rules.length === 1 ? "" : "s"}${fresh < t.rules.length ? ` (${fresh} new)` : ""}`] : []),
    ];
    what.push(`Split tunneling: ${parts.join(", ") || "as yours is"}`);
  }
  return what;
}

/**
 * `mine` with `sh` imported: its relay in place of mine, its sites with my rules (its own win), its default, and its
 * switches turned on (not mine off); and what that does, said. Pure.
 */
export function importPlan(mine: Settings, sh: Shared): { split?: Split; relay?: Shared["relay"]; what: string[] } {
  const t = sh.split, own = mine.split;
  const split: Split | undefined = t && {
    default: t.default,
    rules: [...own.rules.filter((r) => !t.rules.some((x) => x.match === r.match)), ...t.rules],
    ...((own.smart || t.smart) && { smart: true }),
    ...((own.probe || t.probe) && { probe: true }),
  };
  return { ...(split && { split }), ...(sh.relay && { relay: sh.relay }), what: sharedWhat(sh, mine) };
}

export interface ShareServer {
  close(): void;
}

/**
 * Serves the page a phone's camera opens from the QR code, on `port` of every interface, and `apk` (Android's own,
 * else null) for it to download. A download under way when it's closed still finishes.
 */
export async function serveShare(opts: { name: string; version: string; apk: string | null; port?: number }): Promise<ShareServer> {
  const file = `/Foxhole-${opts.version}.apk`;
  const server = http.createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0];
    let size = 0;
    try {
      size = opts.apk ? statSync(opts.apk).size : 0;
    } catch {
      /* gone: updated meanwhile */
    }
    if (req.method !== "GET") return void res.writeHead(405).end();
    if (path === file && size) {
      res.writeHead(200, { "content-type": "application/vnd.android.package-archive", "content-length": size, "content-disposition": `attachment; filename="Foxhole-${opts.version}.apk"` });
      return void createReadStream(opts.apk as string).pipe(res);
    }
    if (path !== "/") return void res.writeHead(404).end();
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(page(opts.name, opts.version, size ? file : null, size));
  });
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(opts.port ?? SHARE_PORT, "0.0.0.0", () => resolve()));
  return { close: () => void server.close() };
}

/** The page: the app to download (or where it's found), and the settings in its #fragment to open in Foxhole. */
function page(name: string, version: string, apk: string | null, size: number): string {
  const from = name.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const get = apk
    ? `<a class="btn" href="${apk}">Download Foxhole ${version}</a>
<p class="fine">For Android phones and TVs · ${Math.round(size / 1e6)} MB. Chrome warns before it downloads an app from outside Google Play: tap <b>Keep</b>, then <b>Download anyway</b>. Let it install apps when Android asks, install, then come back here.</p>`
    : `<p>Foxhole for Android, Windows, Mac and Linux is on <a href="https://github.com/Diercohen/foxhole-vpn/releases/latest">GitHub</a>; or get it from a phone that has it, on the same Wi-Fi: <b>Settings → Share Foxhole</b>.</p>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Foxhole</title><style>body{font:17px/1.5 system-ui,sans-serif;background:#07060c;color:#f6f3fb;margin:0;padding:32px 24px;text-align:center}
.btn{display:inline-block;margin:14px 0;padding:14px 26px;border-radius:14px;background:#ff7a1a;color:#fff;font-weight:700;text-decoration:none;border:0;font:inherit}
p{color:#cfc8dc}.fine{font-size:14px;color:#9d95ad}a{color:#ffb070}h3{margin-top:36px}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:10px;border:1px solid #3a3346;background:#15121d;color:#f6f3fb;font:13px ui-monospace,monospace}</style></head>
<body><h2>Foxhole ${from ? `from ${from}` : ""}</h2><p>Firefox's free VPN, on this device too.</p>
${get}
<div id="s" hidden><h3>Settings from ${from || "Foxhole"}</h3><p>Their VPN relay or split tunneling, for Foxhole here.</p>
<a class="btn" id="open" hidden>Open in Foxhole</a>
<p class="fine">Or copy this link, then in Foxhole: <b>Settings → Import settings</b>.</p>
<input id="link" readonly><button class="btn" id="copy" type="button">Copy the link</button></div>
<script>var d=location.hash.slice(1);if(/^[\\w-]+$/.test(d)){var l="foxhole://settings?d="+d,o=document.getElementById("open");
document.getElementById("s").hidden=false;document.getElementById("link").value=l;
if(/Android/i.test(navigator.userAgent)){o.hidden=false;o.href="intent://settings?d="+d+"#Intent;scheme=foxhole;package=${PACKAGE};S.browser_fallback_url="+encodeURIComponent(location.href)+";end"}
document.getElementById("copy").onclick=function(){var i=document.getElementById("link");i.select();document.execCommand("copy");this.textContent="Copied"}}</script>
</body></html>`;
}
