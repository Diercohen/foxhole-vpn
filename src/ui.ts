import { spawn } from "node:child_process";
// Tiny zero-dependency terminal helpers (color, flags, sizes).

const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
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
    return displayNames?.of(code) ?? fallback;
  } catch {
    return fallback;
  }
}

/** Formats a byte count as GB with one decimal. */
export function gb(bytes: bigint): string {
  const n = Number(bytes) / 1e9;
  return `${n.toFixed(1)} GB`;
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
  spawn(process.platform === "darwin" ? "open" : "xdg-open", [url], { stdio: "ignore", detached: true })
    .on("error", () => {})
    .unref();

/** Redraws in place, centered: home, each line cleared to its end, then clear below (no flicker). */
export function draw(lines: string[]): void {
  const cols = process.stdout.columns || 80, rows = process.stdout.rows || 24;
  const left = " ".repeat(Math.max(0, Math.floor((cols - Math.max(...lines.map(vw))) / 2)));
  const top = Math.max(0, Math.floor((rows - lines.length) / 2));
  const screen = [...Array<string>(top).fill(""), ...lines.map((l) => left + l)].slice(0, rows);
  const i = screen.findIndex((l) => l.includes(REPO_URL));
  link = i < 0 ? null : { y: i, x: vw(screen[i].slice(0, screen[i].indexOf("\x1b]8;;"))) };
  process.stdout.write("\x1b[H" + screen.map(paint).join("\n") + "\x1b[J");
}

// Terminals disagree on a flag's width (1 or 2 cells), which would shift everything after it.
// So draw the line with 2 spaces in its place, then jump back and paint the flag at its column.
function paint(line: string): string {
  let flags = "";
  const text = line.replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, (f: string, i: number) => {
    flags += `\x1b[${vw(line.slice(0, i)) + 1}G${f}`;
    return "  ";
  });
  return text + "\x1b[K" + flags;
}
