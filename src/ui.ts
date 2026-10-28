import { spawn } from "node:child_process";
// Tiny zero-dependency terminal helpers (color, flags, sizes).

export const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const wrap = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

export const bold = wrap("1");
export const dim = wrap("2");
export const under = wrap("4");
// U+0336 over each letter: drawn by the font, so it works where SGR 9 strikethrough doesn't
export const strike = (s: string) => [...s].map((ch) => ch + "\u0336").join("");
export const red = wrap("31");
export const green = wrap("32");
export const yellow = wrap("33");
export const cyan = wrap("36");
export const lit = wrap("1;7;32"); // bold green, reversed: a switch that's on

/** --verbose: also print per-connection proxy failures and tun2socks logs. */
export const verbose = process.argv.includes("--verbose");
// code block: near-white text on dark grey, readable on light and dark terminals
export const code = wrap("48;5;236;38;5;255");

/** ISO 3166-1 alpha-2 → regional-indicator flag emoji. */
export function flag(code: string): string {
  if (code.length !== 2) return "  ";
  const A = 0x1f1e6;
  return String.fromCodePoint(A + (code.charCodeAt(0) - 65), A + (code.charCodeAt(1) - 65));
}

const displayNames =
  typeof Intl !== "undefined" && "DisplayNames" in Intl
    ? new Intl.DisplayNames(["en"], { type: "region" })
    : null;

/** Friendly country name for a code, falling back to the given name. */
export function countryName(code: string, fallback: string): string {
  try {
    // Fedora's Node has a minimal ICU: no names, so it echoes the code back
    const name = displayNames?.of(code);
    return name && name !== code ? name : fallback;
  } catch {
    return fallback;
  }
}

/** Formats a byte count as GB the way Firefox shows the VPN quota: 1 GB = 1024³ bytes, "50 GB", "47.4 GB". */
export function gb(bytes: bigint): string {
  const n = Number(bytes) / 1024 ** 3;
  return `${n.toFixed(1).replace(/\.0$/, "")} GB`;
}

/** A short date like "Nov 1". */
export function shortDate(d: Date): string {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

// ── Layout, after windscout's TUI: rounded boxes and tables, centered frames ──

// visible width: ANSI codes and combining marks take no space; flags and emoji take 2 columns
export const vw = (s: string) =>
  [...s.replace(/\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\|\p{M}/gu, "").replace(/[\u{1F1E6}-\u{1F1FF}]{2}|[\u{1F300}-\u{1FAFF}]/gu, "xx")].length;

/** s cut to n visible columns with a trailing …, keeping its colors. */
export function fit(s: string, n: number): string {
  if (vw(s) <= n) return s;
  let out = "";
  let w = 0;
  for (const part of s.split(/(\x1b\[[0-9;]*m)/)) {
    if (part.startsWith("\x1b[")) {
      out += part;
      continue;
    }
    for (const ch of part) {
      if (w + vw(ch) > n - 1) return out + "…\x1b[0m";
      out += ch;
      w += vw(ch);
    }
  }
  return out;
}

/**
 * The part of s between visible columns [from, to), keeping the colors active at
 * `from`. A wide character (flag, emoji) cut by an edge is dropped.
 */
export function sliceCols(s: string, from: number, to = Infinity): string {
  let out = "";
  let sgr = ""; // colors set before `from`, replayed at the start of the slice
  let w = 0;
  let started = false;
  for (const [t] of s.matchAll(/\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\|[\u{1F1E6}-\u{1F1FF}]{2}|\p{M}|./gsu)) {
    if (t.startsWith("\x1b")) {
      if (started) out += t;
      else sgr = t === "\x1b[0m" ? "" : sgr + t;
      continue;
    }
    const cw = vw(t);
    if (cw === 0) {
      if (started && w <= to) out += t; // a combining mark goes with the character before it
      continue;
    }
    if (w >= from && w + cw <= to) {
      if (!started) (out += sgr), (started = true);
      out += t;
    }
    w += cw;
    if (w >= to) break;
  }
  return started ? out + "\x1b[0m" : "";
}

/**
 * Lays `over` on top of `lines`, centered with a 1-cell clear margin: the covered columns are
 * replaced, and the page around it becomes a backdrop (faint, its colors dropped) so the popup stands out.
 */
export function overlay(lines: string[], box: string[], width: number): string[] {
  const bw = Math.max(...box.map(vw));
  const blank = " ".repeat(bw + 2);
  const over = [blank, ...box.map((l) => ` ${pad(l, bw)} `), blank];
  const ow = bw + 2;
  const x = Math.max(0, Math.floor((width - ow) / 2));
  const y = Math.max(0, Math.floor((lines.length - over.length) / 2));
  return lines.map((l, i) => {
    const back = dim(l.replace(/\x1b\[[0-9;]*m/g, ""));
    const o = over[i - y];
    if (o === undefined) return back;
    return pad(sliceCols(back, 0, x), x) + o + sliceCols(back, x + vw(o));
  });
}

/** Pads s with spaces to n visible columns. */
export const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - vw(s)));

/** s, indented to sit centered in width columns. */
export const centerIn = (s: string, width: number) => " ".repeat(Math.max(0, Math.floor((width - vw(s)) / 2))) + s;

/** Rounded box around lines; title and right sit in the top border. */
export function box(lines: string[], { title = "", right = "", width = 0 } = {}): string[] {
  const inner = Math.max(width, ...lines.map(vw), vw(title) + vw(right) + 6);
  const left = title ? dim("─ ") + title + " " : "";
  const tail = right ? " " + right + dim(" ─") : "";
  const fill = inner + 2 - vw(left) - vw(tail);
  return [
    dim("╭") + left + dim("─".repeat(fill)) + tail + dim("╮"),
    ...lines.map((l) => dim("│") + " " + pad(l, inner) + " " + dim("│")),
    dim("╰" + "─".repeat(inner + 2) + "╯"),
  ];
}

/** Rounded table with a caption row on top; the last column absorbs extra width. */
export function grid(titles: string[], rows: string[][], { caption = "", captionRight = "", minWidth = 0 } = {}): string[] {
  const w = titles.map((t, i) => Math.max(vw(t), ...rows.map((r) => vw(r[i]))));
  const total = () => w.reduce((a, n) => a + n + 3, 1);
  w[w.length - 1] += Math.max(0, vw(caption) + vw(captionRight) + 5 - total(), minWidth - total());
  const rule = (l: string, m: string, r: string) => dim(l + w.map((n) => "─".repeat(n + 2)).join(m) + r);
  const row = (cells: string[]) => dim("│") + cells.map((c, i) => " " + pad(c, w[i]) + " ").join(dim("│")) + dim("│");
  return [
    dim("╭" + "─".repeat(total() - 2) + "╮"),
    dim("│") + " " + pad(caption, total() - 4 - vw(captionRight)) + captionRight + " " + dim("│"),
    rule("├", "┬", "┤"),
    row(titles.map(bold)),
    rule("├", "┼", "┤"),
    ...rows.map(row),
    rule("╰", "┴", "╯"),
  ];
}

export const REPO_URL = "https://github.com/Diercohen/foxhole-vpn";
// OSC 8 makes the text a link in terminals that support it; clicks we receive ourselves are handled by linkAt()
export const repoLink = `\x1b]8;;${REPO_URL}\x1b\\${REPO_URL}\x1b]8;;\x1b\\`;

let link: { y: number; x: number } | null = null; // where draw() last put the repo link

/** True if the 0-based screen cell (x, y) is on the repo link drawn last. */
export const linkAt = (x: number, y: number) =>
  !!link && y === link.y && x >= link.x && x < link.x + REPO_URL.length;

/** Opens a URL in the default browser. */
export const openUrl = (url: string) =>
  // Windows: rundll32, not `cmd /c start`, which would split the URL at each `&`
  (process.platform === "win32"
    ? spawn("rundll32", ["url.dll,FileProtocolHandler", url], { stdio: "ignore", detached: true })
    : spawn(process.platform === "darwin" ? "open" : "xdg-open", [url], { stdio: "ignore", detached: true }))
    .on("error", () => {})
    .unref();

/**
 * Puts `text` on the system clipboard; true once a clipboard tool took it. Linux needs one
 * of wl-clipboard (Wayland), xclip or xsel (X11); without them the terminal is asked instead
 * (OSC 52), which many honor, but that can't be confirmed, so it counts as not copied.
 */
export async function copyText(text: string): Promise<boolean> {
  const tools: [string, string[]][] =
    process.platform === "darwin"
      ? [["pbcopy", []]]
      : process.platform === "win32"
        // stdin's raw bytes as UTF-8: no console code page in between, and no command-line length limit
        ? [["powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
            "$m = [IO.MemoryStream]::new(); [Console]::OpenStandardInput().CopyTo($m); Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString($m.ToArray()))"]]]
        : [
            ...(process.env.WAYLAND_DISPLAY ? [["wl-copy", []] as [string, string[]]] : []),
            ["xclip", ["-selection", "clipboard"]],
            ["xsel", ["--clipboard", "--input"]],
          ];
  for (const [cmd, args] of tools) if (await pipeTo(cmd, args, text)) return true;
  if (process.platform === "linux") process.stdout.write(`\x1b]52;c;${Buffer.from(text).toString("base64")}\x07`);
  return false;
}

/** Runs `cmd` with `input` on stdin; true if it exits 0 within 8 s (PowerShell can be slow to start). */
function pipeTo(cmd: string, args: string[], input: string): Promise<boolean> {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, {
      stdio: ["pipe", "ignore", "ignore"],
      windowsHide: true,
      detached: process.platform === "linux", // xclip, xsel and wl-copy stay behind to serve the clipboard: out of Ctrl+C's reach
      env: process.platform === "darwin" ? { ...process.env, LC_CTYPE: "UTF-8" } : process.env, // pbcopy reads text in the locale's encoding
    });
    const timer = setTimeout(() => (p.kill(), resolve(false)), 8000);
    p.on("error", () => (clearTimeout(timer), resolve(false))); // not installed
    p.on("exit", (code) => (clearTimeout(timer), resolve(code === 0)));
    p.stdin!.on("error", () => {}).end(input);
  });
}

/** Redraws in place, centered: home, each line cleared to its end, then clear below (no flicker). Returns where the lines landed, for mouse clicks. */
export function draw(lines: string[]): { top: number; left: number } {
  const cols = process.stdout.columns || 80, rows = process.stdout.rows || 24;
  const left = " ".repeat(Math.max(0, Math.floor((cols - Math.max(...lines.map(vw))) / 2)));
  const top = Math.max(0, Math.floor((rows - lines.length) / 2));
  const screen = [...Array<string>(top).fill(""), ...lines.map((l) => left + l)].slice(0, rows);
  const i = screen.findIndex((l) => l.includes(REPO_URL));
  link = i < 0 ? null : { y: i, x: vw(screen[i].slice(0, screen[i].indexOf("\x1b]8;;"))) };
  process.stdout.write("\x1b[H" + screen.map((l) => paint(l, cols)).join("\n") + "\x1b[J");
  return { top, left: left.length };
}

// Terminals disagree on a flag's width (1 or 2 cells), which would shift everything after it.
// So draw the line with 2 spaces in its place, then jump back and paint the flag at its column.
// Terminal.app also draws everything after a flag one cell to the left, over the space after
// it: there a flag gets a spare third cell, which that shift takes back.
// ponytail: so there a flag's line is a cell longer than it looks, and wraps in a terminal exactly as wide as the frame.
const FLAG_CELLS = process.env.TERM_PROGRAM === "Apple_Terminal" ? 3 : 2;
function paint(line: string, cols: number): string {
  let flags = "";
  let spare = 0; // cells the flags before this one took beyond their 2
  const text = line.replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, (f: string, i: number) => {
    const at = vw(line.slice(0, i)) + spare + 1;
    if (at < cols) flags += `\x1b[${at}G${f}`; // past a narrow window's edge: left out, not squeezed into its last cell
    spare += FLAG_CELLS - 2;
    return " ".repeat(FLAG_CELLS);
  });
  // The cursor goes back after the flags: the clear-below ending the screen mustn't erase the rest of its last line.
  return text + "\x1b[K" + (flags && `\x1b7${flags}\x1b8`);
}
