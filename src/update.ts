// The installed version, whether npm has a newer one, and updating to it.
import { spawnSync } from "node:child_process";
import { accessSync, constants, readFileSync } from "node:fs";
import { cyan, dim, green, under, yellow, REPO_URL } from "./ui.js";

export const VERSION: string = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;
let latest: string | null = null; // newer version on npm, once known
let upToDate = false; // npm answered, and has nothing newer
let check: Promise<void> | undefined;

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

/** Asks npm once; later calls share that request. Best effort: offline or registry down just means no notice. */
export function checkUpdate(): Promise<void> {
  check ??= fetch("https://registry.npmjs.org/foxhole-vpn/latest", { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json() as Promise<{ version?: string }>)
    .then(({ version }) => {
      if (version && newer(version, VERSION)) latest = version;
      else upToDate = Boolean(version);
    })
    .catch(() => {});
  return check;
}

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

/** Runs the update in this terminal (sudo asks for the password here); returns npm's exit status. */
export function runUpdate(): number {
  console.log(cyan(UPDATE_COMMAND));
  const NODE_OPTIONS = `${process.env.NODE_OPTIONS ?? ""} ${NODE_FIX}`.trim();
  // sudo clears the environment, so env sets NODE_OPTIONS on its side
  return (
    spawnSync(sudo ? `sudo env NODE_OPTIONS="${NODE_FIX}" ${INSTALL}` : INSTALL, {
      shell: true,
      stdio: "inherit",
      env: { ...process.env, NODE_OPTIONS },
    }).status ?? 1
  );
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
