// The installed version, whether npm has a newer one, and updating to it: the TUI downloads its package by ways.ts's ways
// (through Firefox VPN while it's on; else directly, then Firefox VPN opened for it, then the relay), checks it against
// npm's checksum, then npm installs that file, needing no network itself.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { cyan, dim, green, under, yellow, REPO_URL } from "./ui.js";
import { download, get, httpError, throughWays, type Way } from "./ways.js";

export const VERSION: string = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;
// FOXHOLE_REGISTRY: a server laid out like npm's registry, for testing
const LATEST = `${process.env.FOXHOLE_REGISTRY ?? "https://registry.npmjs.org"}/foxhole-vpn/latest`;
let latest: string | null = null; // newer version on npm, once known
let pkg: { url: string; algo: string; digest: string } | null = null; // its package file, and the checksum npm has for it
let upToDate = false; // npm answered, and has nothing newer
let check: Promise<void> | undefined;
let wayCheck: Promise<void> | undefined;

// numeric x.y.z compare; parseInt drops a prerelease suffix ("0-beta" → 0)
export function newer(a: string, b: string): boolean {
  const x = a.split(".").map((n) => parseInt(n));
  const y = b.split(".").map((n) => parseInt(n));
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
  return false;
}

const ENTITY: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const unescape = (s: string) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e: string) =>
    e[0] === "#" ? String.fromCodePoint(parseInt(e.slice(e[1] === "x" ? 2 : 1), e[1] === "x" ? 16 : 10)) : ENTITY[e.toLowerCase()]);

/** A run of text and how it's set; `href` only for a link into this repo (all the window may open). */
export type Span = { text: string; b?: true; i?: true; code?: true; s?: true; href?: string };
/** A heading, paragraph, list item (`mark`: "•" or "3.") or code block; `depth`: how many lists it's in. */
export type Block = { kind: "h" | "p" | "li" | "pre"; depth: number; mark?: string; spans: Span[] };
export type Notes = { version: string; blocks: Block[] }[];

/** GitHub's release notes (Markdown, as GitHub's HTML) as blocks: up to their Downloads, the update gets the file itself. */
export function noteBlocks(html: string): Block[] {
  const out: Block[] = [];
  const lists: { ol: boolean; n: number }[] = [];
  const on = { b: 0, i: 0, code: 0, s: 0 };
  let href: string | undefined;
  let cur = null as Block | null;
  const start = (kind: Block["kind"], mark?: string): Block => {
    const b: Block = { kind, depth: lists.length, ...(mark && { mark }), spans: [] };
    out.push(b);
    return b;
  };
  for (const [tok, close, name = "", attrs] of html.matchAll(/<(\/?)([a-z][a-z0-9]*)([^>]*)>|[^<]+/gi)) {
    const t = name.toLowerCase();
    if (!t) {
      const pre = cur?.kind === "pre";
      let text = unescape(tok);
      if (!pre) text = text.replace(/\s+/g, " ");
      if (!cur && !text.trim()) continue;
      const c: Block = (cur ??= start("p"));
      if (!c.spans.length && !pre) text = text.trimStart();
      if (text) c.spans.push({ text, ...(on.b && { b: true }), ...(on.i && { i: true }), ...(on.code && { code: true }), ...(on.s && { s: true }), ...(href && { href }) } as Span);
      continue;
    }
    const n = close ? -1 : 1;
    if (t === "strong" || t === "b") on.b += n;
    else if (t === "em" || t === "i") on.i += n;
    else if (t === "code") on.code += n;
    else if (t === "del" || t === "s" || t === "strike") on.s += n;
    else if (t === "a") href = close ? undefined : unescape(/href="([^"]*)"/.exec(attrs)?.[1] ?? "");
    else if (t === "ul" || t === "ol") {
      if (close) lists.pop();
      else lists.push({ ol: t === "ol", n: Number(/start="(\d+)"/.exec(attrs)?.[1] ?? 1) });
      cur = null;
    } else if (t === "li") {
      const l = lists.at(-1);
      if (close) cur = null;
      else cur = start("li", l?.ol ? `${l.n++}.` : "•");
    } else if (close && /^(h\d|p|pre|blockquote)$/.test(t)) cur = null;
    else if (/^h\d$/.test(t)) cur = start("h");
    else if (t === "pre") cur = start("pre");
    else if (t === "br" || (t === "p" && !(cur?.kind === "li" && !cur.spans.length))) cur = start("p"); // a loose list's <li><p> is the item
  }
  const text = (b: Block) => b.spans.map((x) => x.text).join("").trim();
  const keep: Block[] = [];
  for (const b of out) {
    const last = b.spans.at(-1);
    if (last && b.kind !== "pre") last.text = last.text.trimEnd();
    if (b.kind === "pre" && last) last.text = last.text.replace(/\n$/, "");
    for (const x of b.spans) if (x.href && !x.href.startsWith(`${REPO_URL}/`)) delete x.href; // only this repo's pages open
    const t = text(b);
    if (b.kind === "h" && t === "Downloads") break;
    if (t && !(b.kind === "h" && /^What['’]s (new|changed)$/i.test(t)) && !t.startsWith("Full Changelog")) keep.push(b);
  }
  return keep;
}

/** What's new in each release after `from`, up to `to`, newest first, from GitHub's releases feed. */
export function releaseNotes(atom: string, from: string, to: string): Notes {
  const out: Notes = [];
  for (const [, entry] of atom.matchAll(/<entry>([\s\S]*?)<\/entry>/g)) {
    const version = /\/releases\/tag\/v?(\d+\.\d+\.\d+)"/.exec(entry)?.[1];
    if (!version || !newer(version, from) || newer(version, to)) continue;
    out.push({ version, blocks: noteBlocks(unescape(/<content type="html">([\s\S]*?)<\/content>/.exec(entry)?.[1] ?? "")) });
  }
  return out.sort((a, b) => (newer(a.version, b.version) ? -1 : 1));
}

/** The notes of the versions after this one, from GitHub (the TUI's: through `fetch`); null when GitHub can't be reached. */
export function fetchNotes(to: string): Promise<Notes | null> {
  return fetch(`${REPO_URL}/releases.atom`, { signal: AbortSignal.timeout(8000) })
    .then((r) => (r.ok ? r.text() : Promise.reject()))
    .then((atom) => releaseNotes(atom, VERSION, to), () => null);
}

/** What npm's latest says of the package: its version, and its file with the checksum it's published with. */
type Manifest = { version?: string; dist?: { tarball?: string; integrity?: string } };

/** Takes npm's answer: a newer version, with its file and checksum (the strongest npm gives), or none newer. */
function take({ version, dist }: Manifest): void {
  if (!version) return;
  if (!newer(version, VERSION)) return void (upToDate = true);
  latest = version;
  const sri = dist?.integrity?.split(/\s+/).map((s) => /^(sha512|sha384|sha256)-(.+)$/.exec(s)).find(Boolean);
  pkg = dist?.tarball && sri ? { url: dist.tarball, algo: sri[1], digest: sri[2] } : null;
}

/** npm's latest by `way`. */
async function manifest(way: Way): Promise<Manifest> {
  const res = await get(LATEST, way, { accept: "application/json" });
  if (res.statusCode !== 200) {
    res.resume();
    throw httpError(res.statusCode ?? 0);
  }
  let text = "";
  res.setEncoding("utf8");
  for await (const c of res) text += c;
  return JSON.parse(text) as Manifest;
}

/**
 * Asks npm once, directly within 3 s; later calls share that request. `ways` (the TUI's, ways.ts): when that got no
 * answer, npm is asked by them in turn. Best effort: offline or registry down just means no notice.
 */
export function checkUpdate(ways?: Way[]): Promise<void> {
  check ??= fetch(LATEST, { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json() as Promise<Manifest>)
    .then(take)
    .catch(() => {});
  if (!ways) return check;
  return (wayCheck ??= check.then(() => (latest || upToDate ? undefined : throughWays(ways, manifest).then(take, () => {}))));
}

/**
 * The newer version's package, downloaded by `ways` in turn (each carrying on from where the one before stopped) to a
 * folder of its own, and checked against npm's checksum: its file, for runUpdate. `onWay` hears each way as it's
 * tried, `progress(percent)` how far it got.
 */
export async function downloadUpdate(ways: Way[], { onWay = () => {}, progress = () => {}, signal }: { onWay?: (way: Way) => void; progress?: (percent: number) => void; signal?: AbortSignal } = {}): Promise<string> {
  if (!pkg) throw new Error("npm didn't say where the new version's package is");
  const { url, algo, digest } = pkg;
  const dir = mkdtempSync(join(tmpdir(), "foxhole-update-"));
  const file = join(dir, `foxhole-vpn-${latest}.tgz`);
  try {
    await throughWays(ways, (way, last) => (onWay(way), download(url, file, way, progress, { last, signal })), signal);
    if (createHash(algo).update(readFileSync(file)).digest("base64") !== digest) throw new Error("the download doesn't match npm's checksum");
    return file;
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

/** The newer version's package can be downloaded first (downloadUpdate): npm said where it is, and its checksum. */
export const canDownload = (): boolean => pkg !== null;

/** What the TUI's update does, under its buttons. */
export const updateHint = (): string => (canDownload() ? `downloads it, then runs ${sudo ? "sudo " : ""}npm install -g on it` : `runs ${UPDATE_COMMAND}`);

// run through npx: nothing is installed to update, the next npx foxhole-vpn@latest fetches it
export const viaNpx = () => process.env.npm_command === "exec";
// npm replaces the folder this package sits in; a root-owned global folder (system Node) needs sudo for that
const sudo = (() => {
  if (process.platform === "win32") return false; // npm's global folder is per-user; there's no sudo
  try {
    accessSync(new URL("../..", import.meta.url), constants.W_OK);
    return false;
  } catch {
    return true;
  }
})();
const INSTALL = "npm install -g foxhole-vpn@latest";
export const UPDATE_COMMAND = (sudo ? "sudo " : "") + INSTALL;
// npm is Node too: through a slow tunnel its downloads time out like fetch would without these
// (Node 18, Ubuntu's own, has no autoselection to turn off and refuses that flag)
const NODE_FIX = `${Number(process.versions.node.split(".")[0]) >= 19 ? "--no-network-family-autoselection " : ""}--dns-result-order=ipv4first`;

/** The newer version on npm, once known. */
export const latestVersion = () => latest;

/** A newer version is out, and npm can install it (under npx there's nothing installed to update). */
export const canUpdate = () => latest !== null && !viaNpx();

/**
 * Runs the update in this terminal (sudo asks for the password here): npm installs `file`, the package downloadUpdate
 * got, then the folder it's in goes; without one, npm gets the package itself. Returns npm's exit status.
 */
export function runUpdate(file?: string): number {
  // in the shell's double quotes: no character it would read otherwise
  const quotable = file && !(process.platform === "win32" ? /["%!]/ : /["$`\\]/).test(file);
  // the package has no dependencies: npm needs nothing from the network for it, not even its audit
  const install = quotable ? `npm install -g --offline --no-audit --no-fund "${file}"` : INSTALL;
  console.log(cyan((sudo ? "sudo " : "") + install));
  const NODE_OPTIONS = `${process.env.NODE_OPTIONS ?? ""} ${NODE_FIX}`.trim();
  // sudo clears the environment, so env sets NODE_OPTIONS on its side
  const status =
    spawnSync(sudo ? `sudo env NODE_OPTIONS="${NODE_FIX}" ${install}` : install, {
      shell: true,
      stdio: "inherit",
      env: { ...process.env, NODE_OPTIONS },
    }).status ?? 1;
  if (file) rmSync(dirname(file), { recursive: true, force: true });
  return status;
}

/**
 * Starts the app again, now the updated one, in this terminal (Node can't replace a running
 * process), and exits with its status once it's done.
 */
export function restart(): never {
  console.log(green("\nUpdated. Starting the new version…"));
  // It handles signals itself; this one ignores them and only waits, so the shell gets the terminal back after it.
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(sig, () => {});
  const r = spawnSync(process.execPath, [...process.execArgv, ...process.argv.slice(1)], { stdio: "inherit" });
  process.exit(r.status ?? 1);
}

/** "update available: …" and how to get it, once checkUpdate() found a newer version; onKey: a TUI screen that updates on 'u'. */
export function updateNotice(onKey = false): string[] | null {
  if (!latest) return null;
  return [
    `update available: ${VERSION} → ${latest}`,
    viaNpx()
      ? "quit, then run: npx foxhole-vpn@latest"
      : onKey
        ? `press ${under("u")} to see what's new and update`
        : `run: ${UPDATE_COMMAND}, then restart`,
  ];
}

/** Version line(s): the update notice in yellow, or the installed version in grey. */
export const versionLines = (onKey = false): string[] =>
  updateNotice(onKey)?.map(yellow) ?? [dim(`foxhole-vpn ${VERSION}${upToDate ? " · latest" : ""}`)];
