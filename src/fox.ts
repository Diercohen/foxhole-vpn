import { useColor } from "./ui.js";
// The TUI's fox: the app icon's, in half-block pixels (a cell is a top and a bottom pixel: ▀ in two
// colors), with a mood for each state of the connection. Each frame comes from the time passed in.

/** off: disconnected · waiting: connecting, or anything else in progress · proxy: connected · global: TUN on */
export type Mood = "off" | "waiting" | "proxy" | "global";

// 31×26 pixels: o fur, l forehead, m n r the snout from top to bottom, w cheeks, W their rim (it keeps
// them apart from a light background), k ears and nose. The eyes are drawn over it, as they change.
const ART = [
  "..o.........................o..",
  ".ooo.......................ooo.",
  ".ooooo...................ooooo.",
  ".ookoooo...............ooookoo.",
  ".ookkkoooo...........ooookkkoo.",
  ".oookkkoooolllllllllooookkkooo.",
  "ooookkkkoooolllllllooookkkkoooo",
  "oooooooooooollllllloooooooooooo",
  "WoooooooooooolllllooooooooooooW",
  ".WwoooooooooollllloooooooooowW.",
  ".WwwwooooooooolllooooooooowwwW.",
  ".WwwwwwooooooooloooooooowwwwwW.",
  "..WwwwwwwmmmmmmlmmmmmmwwwwwwW..",
  "..WwwwwwwmmmmmmmmmmmmmwwwwwwW..",
  "..WwwwwwwwmmmmmmmmmmmwwwwwwwW..",
  "...WwwwwwwwnnnnnnnnnwwwwwwwW...",
  "...WwwwwwwwnnnnnnnnnwwwwwwwW...",
  "....WwwwwwwwnnnnnnnwwwwwwwW....",
  ".....WWwwwwwwrrrrrwwwwwwWW.....",
  ".......WwwwwwrrrrrwwwwwW.......",
  "........WwwwwwrrrwwwwwW........",
  ".........WWwwwwrwwwwWW.........",
  "...........WwwwrwwwW...........",
  "............WwkkkwW............",
  ".............WkkkW.............",
  "...............k...............",
];
const M = 6; // columns beside the art on each side, for the z's, sparkles and the dot
export const FOX_W = ART[0].length + 2 * M;
export const FOX_H = ART.length / 2;

// 256-color palettes: the icon's orange, and grey for asleep (as the tray's fox when off)
const FUR: Record<string, number> = { o: 208, l: 215, m: 208, n: 202, r: 202, w: 230, W: 223, k: 236 };
const ASH: Record<string, number> = { o: 245, l: 248, m: 245, n: 244, r: 244, w: 252, W: 249, k: 238 };
const LIGHTER: Record<number, number> = { 208: 214, 215: 222, 202: 208, 230: 231, 223: 230 }; // the shimmer

// The left eye, open (a slit slanting down to the nose) and shut; the right one mirrors it.
const OPEN = [[8, 11], [9, 11], [9, 12], [10, 12], [11, 12]];
const SHUT = [[8, 12], [9, 12], [10, 12], [11, 12]];
// A round dot by the chin, as on the tray's icon: its color is the state's
const DOT = [[1, 0], [2, 0], [0, 1], [1, 1], [2, 1], [3, 1], [0, 2], [1, 2], [2, 2], [3, 2], [1, 3], [2, 3]];
// Asleep, z's rise by the ear: [column, row] in cells
const ZZZ: [number, number, string][] = [[37, 4, "z"], [39, 2, "z"], [41, 0, "Z"]];
// In global mode, stars twinkle around: [x, y] in pixels, and each frame's pixels around it
const SPARKS = [[21, 2], [3, 8], [39, 5], [5, 19], [37, 14]];
const TWINKLE = [[[0, 0]], [[0, 0], [-1, 0], [1, 0], [0, -1], [0, 1]], [[0, 0]], [], [], [], []];

/**
 * The fox in a mood at time t (ms): FOX_H lines, each FOX_W columns wide. plain: its shape alone, no colors (always,
 * with NO_COLOR). relay: relay mode's purple where Firefox VPN's green and pink go.
 */
export function fox(mood: Mood, t: number, plain = false, relay = false): string[] {
  plain ||= !useColor;
  const pal = mood === "off" ? ASH : FUR;
  const px = ART.map((row) => Array.from({ length: FOX_W }, (_, x) => pal[row[x - M]] ?? null));
  if (mood === "waiting") {
    // a band of light sweeping across, again and again
    const at = (t / 25) % 90;
    for (const [y, row] of px.entries())
      for (const [x, c] of row.entries()) if (c !== null && LIGHTER[c] && Math.abs(x + y - at) < 2.5) row[x] = LIGHTER[c];
  }

  const blink = t % 4000 < 150;
  const glance = mood === "waiting" ? [0, -1, 0, 1][Math.floor(t / 600) % 4] : 0; // looking around
  const eye = mood === "off" || blink ? SHUT : OPEN;
  const eyeColor = mood === "global" && !plain ? (relay ? [183, 189] : [213, 219])[Math.floor(t / 500) % 2] : pal.k; // glowing in global mode
  for (const [x, y] of eye) {
    px[y][M + x + glance] = eyeColor;
    px[y][M + ART[0].length - 1 - x + glance] = eyeColor;
  }

  const dot = { off: null, waiting: t % 800 < 400 ? 220 : null, proxy: relay ? [141, 135, 99, 135] : [49, 43, 37, 43], global: relay ? [177, 171, 135, 171] : [204, 198, 162, 198] }[mood];
  const dotColor = Array.isArray(dot) ? dot[Math.floor(t / 400) % 4] : dot;
  if (dotColor !== null) for (const [x, y] of DOT) px[20 + y][M + 24 + x] = dotColor;
  if (mood === "global")
    for (const [i, [x, y]] of SPARKS.entries())
      for (const [dx, dy] of TWINKLE[(Math.floor(t / 180) + i * 3) % TWINKLE.length]) px[y + dy][x + dx] = i % 2 ? 222 : relay ? 183 : 213;

  const text = new Map<string, [number, string]>();
  if (mood === "off") for (const [x, y, z] of ZZZ.slice(0, Math.floor(t / 700) % 4)) text.set(`${x},${y}`, [z === "Z" ? 252 : 248, z]);
  return cells(px, text, plain ? pal.k : null);
}

/** Pixel rows in pairs, as lines of cells; `text` puts a character in a cell. Plain (no colors) when given the dark color: its pixels are holes. */
function cells(px: (number | null)[][], text: Map<string, [number, string]>, dark: number | null): string[] {
  const lines: string[] = [];
  for (let y = 0; y < px.length; y += 2) {
    let line = "";
    let style = "";
    for (let x = 0; x < FOX_W; x++) {
      let [top, bottom] = [px[y][x], px[y + 1][x]];
      if (dark !== null) [top, bottom] = [top, bottom].map((c) => (c === null || c === dark ? null : 0)); // a cell's two halves alike: █
      const tx = text.get(`${x},${y / 2}`);
      const [fg, bg, ch] = tx
        ? [tx[0], null, tx[1]]
        : top === null
          ? [bottom, null, bottom === null ? " " : "▄"]
          : [top, bottom === top ? null : bottom, bottom === top ? "█" : "▀"];
      const next = dark === null ? [fg === null ? "" : `38;5;${fg}`, bg === null ? "" : `48;5;${bg}`].filter(Boolean).join(";") : "";
      if (next !== style) line += `\x1b[0${next && ";"}${next}m`;
      style = next;
      line += ch;
    }
    lines.push(style ? line + "\x1b[0m" : line);
  }
  return lines;
}
