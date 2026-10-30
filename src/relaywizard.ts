// The TUI's step-by-step setup of the Apps Script relay (httprelay.ts), a popup over Settings. The wording, the
// script and the screenshots are relaysetup.ts's, shared with the desktop app. Screenshots are the real picture
// where the terminal draws pictures (kitty's graphics, iTerm2's inline images, sixels), else ▀ half blocks (two
// pixels a cell, fore- and background color): plain text, so it works in any terminal on any OS.
import type readline from "node:readline";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { STEPS, KEY_PLACEHOLDER, KEY_CHARS, keyOk, newAuthKey, relayScript, relayTemplate, highlightJs, deploymentId, relayAsset, type Token } from "./relaysetup.js";
import { bold, dim, cyan, green, yellow, red, magenta, useColor, fit, pad, box, openUrl, copyText } from "./ui.js";
import { userHome } from "./profile.js";

const IMG_W = 30, IMG_H = 9; // a 16:9 screenshot in cells: 30 × 18 pixels
const PIC_W = 40, PIC_H = 12; // a real picture: as wide as fits beside the text, 16:9 in cells about twice as tall as wide

/** Where the real picture goes, in the popup's lines (its border included); null when it's half blocks or none. */
export interface Picture { file: string; row: number; col: number; cols: number; rows: number }

/** What a key did: close the wizard, finish with this relay, or nothing to tell (redraw). */
export type WizardResult = "close" | { deploymentId: string; authKey: string } | undefined;

export class RelayWizard {
  #step = 0;
  #shot = 0; // in a step with a screenshot a line: the line, and its screenshot, being shown
  #key = newAuthKey();
  #editKey = false; // the key is being typed
  #id = ""; // the last step's input
  #scroll = 0; // the code's first line shown
  #codeRows = 6; // how many the last render showed
  #note = "";
  picture: Picture | null = null; // the last render's: the TUI draws it there (pictureAt) after the text
  readonly #redraw: () => void;

  constructor(redraw: () => void) {
    this.#redraw = redraw;
  }

  key(s: string, key: readline.Key): WizardResult {
    const n = key.name;
    this.#note = "";
    if (this.#editKey) {
      if (n === "return" || n === "escape") {
        this.#editKey = false;
        if (!keyOk(this.#key)) this.#note = red("A key needs at least 16 letters, digits, - or _.");
      } else if (n === "backspace") this.#key = this.#key.slice(0, -1);
      else if (s && KEY_CHARS.test(s) && this.#key.length < 128) this.#key += s;
      return;
    }
    if (n === "escape") return "close";
    if (n === "left") {
      if (this.#shot > 0) return void (this.#shot -= 1);
      this.#step = Math.max(0, this.#step - 1);
      return void (this.#shot = Math.max(0, STEPS[this.#step].shots.length - 1)); // back onto its last line
    }
    const last = this.#step === STEPS.length - 1;
    if (n === "right" || n === "return") {
      if (this.#shot < STEPS[this.#step].shots.length - 1) return void (this.#shot += 1);
      if (!last) {
        if (this.#step === 1 && !keyOk(this.#key)) return void (this.#note = red("Make a key first: press r."));
        return void ((this.#step += 1), (this.#shot = 0), (this.#scroll = 0));
      }
      if (n === "right") return;
      const id = deploymentId(this.#id);
      if (!id) return void (this.#note = red(this.#id.trim() ? "That isn't a Deployment ID or web app URL: copy it again from Google." : "Paste the Deployment ID first."));
      return { deploymentId: id, authKey: this.#key };
    }
    if (last) {
      // the input: typed or pasted (a paste arrives as keypresses, one a character)
      if (n === "backspace") this.#id = this.#id.slice(0, -1);
      else if (s && s.length === 1 && s > " " && !key.ctrl && !key.meta && this.#id.length < 300) this.#id += s;
      return;
    }
    if (n === "o") return void openUrl(this.#image());
    if (this.#step === 0 && n === "b") return void openUrl("https://script.google.com/home");
    if (this.#step !== 1) return;
    const lines = relayTemplate().split("\n").length;
    const page = Math.max(1, this.#codeRows - 1);
    if (n === "up" || n === "k") this.#scroll -= 1;
    else if (n === "down" || n === "j") this.#scroll += 1;
    else if (n === "pageup") this.#scroll -= page;
    else if (n === "pagedown" || n === "space") this.#scroll += page;
    else if (n === "r") this.#key = newAuthKey();
    else if (n === "e") this.#editKey = true;
    else if (n === "c") void this.#copy();
    this.#scroll = Math.max(0, Math.min(this.#scroll, lines - this.#codeRows));
  }

  /** The screenshot shown now. */
  #image = () => relayAsset(STEPS[this.#step].shots[this.#shot]);

  /** The code on the clipboard; without a clipboard tool, in a file to copy it from. */
  async #copy(): Promise<void> {
    const code = relayScript(this.#key);
    if (await copyText(code)) this.#note = green("✓ Copied. Paste it into the Apps Script editor.");
    else {
      const dir = join(userHome(), ".config", "foxhole-vpn");
      try {
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, "Code.gs"), code);
        openUrl(join(dir, "Code.gs"));
        this.#note = yellow(`No clipboard here: copy it from ${join(dir, "Code.gs")}`);
      } catch (err) {
        this.#note = red(`Couldn't copy: ${(err as Error).message}`);
      }
    }
    this.#redraw();
  }

  /** The popup, at most `cols` wide and `rows` tall. */
  render(cols: number, rows: number): string[] {
    const inner = Math.max(56, Math.min(96, cols - 6));
    const st = STEPS[this.#step];
    const stepper = STEPS.map((x, i) =>
      i === this.#step ? bold(cyan(`● ${i + 1} ${x.short}`)) : i < this.#step ? green(`✓ ${i + 1} ${x.short}`) : dim(`○ ${i + 1} ${x.short}`),
    ).join(dim("  ──  "));
    const keys = [
      this.#step > 0 ? "← back" : "",
      this.#step < STEPS.length - 1 ? "⏎ next" : "⏎ finish",
      ...(this.#step === 0 ? ["b open script.google.com"] : []),
      ...(this.#step === 1 ? (this.#editKey ? ["type the key · ⏎ done"] : ["c copy code", "↑↓ scroll", "r new key", "e edit key"]) : []),
      "esc close",
    ].filter(Boolean);
    const many = st.shots.length > 1;
    const head = ["", stepper, "", bold(`${this.#step + 1}. ${st.title}`) + (many ? dim(` · ${this.#shot + 1} of ${st.shots.length}`) : ""), ""];
    // the keys on as few lines as fit the width
    const keyLines = keys.reduce<string[]>((ls, k) => (ls.length && ls[ls.length - 1].length + 3 + k.length <= inner ? (ls[ls.length - 1] += " · " + k) : ls.push(k), ls), []);
    const foot = [this.#note, ...keyLines.map(dim)];
    const room = rows - 2 - head.length - foot.length; // inside the border

    // The text, with the screenshot beside it when there's room for both and (step 2) the code below
    const extra = this.#step === 1 ? 2 + 5 : this.#step === STEPS.length - 1 ? 2 : 0; // key + gap + 5 lines of code; the input
    const real = canDraw(this.#image());
    const [iw, ih] = real ? [PIC_W, PIC_H] : [IMG_W, IMG_H];
    const img = inner >= 64 ? (real ? Array<string>(ih).fill("") : halfBlocks(this.#image(), iw, ih)) : null; // a real one's room is left blank
    const textW = img ? inner - iw - 3 : inner;
    // a step of several clicks: ▸ at the line its screenshot shows, the lines done dim
    const text = (w: number) => st.lines.flatMap((l, i) => {
      if (!many) return wrap(`${i + 1}. ${l}`, w, 3);
      const ls = wrap(`${i + 1}. ${l}`, w - 2, 3).map((x, j) => (j || i !== this.#shot ? "  " : cyan("▸ ")) + x);
      return i < this.#shot ? ls.map((x) => dim(x.replace(/\x1b\[[0-9;]*m/g, ""))) : ls;
    });
    const beside = text(textW);
    // under the picture, the key that opens it full size (the last step's typing takes every key)
    const open = this.#step < STEPS.length - 1 && !this.#editKey && existsSync(this.#image());
    if (img && open) img[ih] = " ".repeat(Math.floor((iw - 19) / 2)) + dim("o → full screenshot");
    const h = Math.max(beside.length, img?.length ?? 0);
    const fits = img && h + extra <= room;
    const body = fits
      ? Array.from({ length: h }, (_, i) => pad(beside[i] ?? "", textW) + "   " + (img[i] ?? ""))
      : text(inner);
    // below the top border and the head, after the left border and its space, the text and the gap
    this.picture = fits && real ? { file: this.#image(), row: 1 + head.length, col: 2 + textW + 3, cols: iw, rows: ih } : null;

    if (this.#step === 1) {
      const k = this.#editKey ? this.#key + cyan("▏") : this.#key ? bold(yellow(this.#key)) : dim("none");
      body.push("", `${dim("Your secret key")}  ${k}`);
      this.#codeRows = Math.max(2, room - body.length - 1); // the code's own heading takes a row
      body.push(...this.#code(inner, this.#codeRows));
    } else if (this.#step === STEPS.length - 1) {
      const id = this.#id.length > inner - 22 ? "…" + this.#id.slice(-(inner - 23)) : this.#id;
      body.push("", `${dim("Deployment ID")}  ${id}${cyan("▏")}${this.#id ? "" : dim(" paste it here")}`);
    }
    return box([...head, ...body.slice(0, Math.max(0, room)), ...foot], { title: bold(cyan("Set up the VPN relay")), right: dim(`step ${this.#step + 1} of ${STEPS.length}`), width: inner });
  }

  /** `rows` of the script from the scroll position under a heading: highlighted, numbered, cut to the width, a scrollbar on the right. */
  #code(width: number, rows: number): string[] {
    const lines = colorLines(highlightJs(relayTemplate()), this.#key);
    this.#scroll = Math.max(0, Math.min(this.#scroll, lines.length - rows));
    const thumb = Math.round((this.#scroll / Math.max(1, lines.length - rows)) * (rows - 1));
    const out = [dim(`╶ Code.gs · lines ${this.#scroll + 1}–${Math.min(lines.length, this.#scroll + rows)} of ${lines.length} `.padEnd(width, "─"))];
    for (let i = 0; i < rows; i++) {
      const n = this.#scroll + i;
      const l = lines[n] ?? "";
      out.push(dim(String(n + 1).padStart(4) + " │ ") + pad(fit(l, width - 9), width - 9) + " " + (i === thumb ? cyan("┃") : dim("│")));
    }
    return out;
  }
}

const TONE: Record<Token[0], (s: string) => string> = { "": (s) => s, c: dim, s: green, re: yellow, n: yellow, kw: magenta, fn: cyan };

/** The tokens as colored lines (each line opens and closes its own colors); the key bold in the script. */
function colorLines(tokens: Token[], key: string): string[] {
  let all = "";
  for (const [kind, text] of tokens) {
    const tone = text.includes(KEY_PLACEHOLDER) ? (s: string) => bold(yellow(s)) : TONE[kind];
    all += text.replace(KEY_PLACEHOLDER, key).split("\n").map((p) => (p ? tone(p) : p)).join("\n");
  }
  return all.split("\n");
}

/** s wrapped at width; **…** turns bold, across a line break too. Lines after the first start `hang` spaces in. */
export function wrap(s: string, width: number, hang = 0): string[] {
  const vis = (t: string) => t.replace(/\*\*/g, "").length;
  const lines: string[] = [];
  let line = "";
  for (const word of s.split(" ")) {
    if (line.trim() && vis(line) + 1 + vis(word) > width) (lines.push(line), (line = " ".repeat(hang) + word));
    else line += (line.trim() ? " " : "") + word;
  }
  lines.push(line);
  let on = false;
  return lines.map((l) => l.split("**").map((part, i) => ((on = i ? !on : on), on && part ? bold(part) : part)).join(""));
}

// ── Screenshots in the terminal ──────────────────────────────────────────────────────────────

// Truecolor, except in a Terminal.app that doesn't say it has it (before macOS 26 it shows 24-bit colors wrong): the 256-color cube there.
const TRUECOLOR = process.env.TERM_PROGRAM !== "Apple_Terminal" || /truecolor|24bit/.test(process.env.COLORTERM ?? "");
const sgr = (fg: boolean, [r, g, b]: number[]) =>
  `${fg ? 38 : 48};` + (TRUECOLOR ? `2;${r};${g};${b}` : `5;${16 + 36 * Math.round(r / 51) + 6 * Math.round(g / 51) + Math.round(b / 51)}`);

const drawn = new Map<string, string[] | null>();

/** The PNG at path fit into cols × rows cells, centered; null if there's none, it can't be read, or no colors. */
export function halfBlocks(path: string, cols: number, rows: number): string[] | null {
  if (!useColor) return null;
  const id = `${path}:${cols}x${rows}`;
  if (!drawn.has(id)) {
    let lines: string[] | null = null;
    try {
      const img = decodePng(readFileSync(path));
      if (img) lines = blocks(img, cols, rows);
    } catch {
      /* no screenshot for this step */
    }
    drawn.set(id, lines);
  }
  return drawn.get(id)!;
}

/** img scaled to tw × th: each target pixel the average of a 3×3 sample of the source pixels it covers. */
const scaled = (img: Png, tw: number, th: number) => (x: number, y: number) => {
  const sum = [0, 0, 0];
  for (let j = 0; j < 3; j++)
    for (let i = 0; i < 3; i++) {
      const p = img.px(Math.floor(((x + (i + 0.5) / 3) * img.w) / tw), Math.floor(((y + (j + 0.5) / 3) * img.h) / th));
      for (let k = 0; k < 3; k++) sum[k] += p[k];
    }
  return sum.map((v) => Math.round(v / 9));
};

function blocks(img: Png, cols: number, rows: number): string[] {
  const scale = Math.min(cols / img.w, (rows * 2) / img.h);
  const tw = Math.max(1, Math.round(img.w * scale)), th = Math.max(2, 2 * Math.round((img.h * scale) / 2)); // even: no half-empty last row
  const at = scaled(img, tw, th);
  const left = " ".repeat(Math.floor((cols - tw) / 2));
  const out: string[] = [];
  for (let y = 0; y < th; y += 2) {
    let line = left;
    for (let x = 0; x < tw; x++) line += `\x1b[${sgr(true, at(x, y))};${sgr(false, at(x, y + 1))}m▀`;
    out.push(line + "\x1b[0m");
  }
  const top = Math.floor((rows - out.length) / 2);
  return [...Array<string>(top).fill(""), ...out];
}

export interface Png {
  w: number;
  h: number;
  px: (x: number, y: number) => number[]; // RGB, transparency over black
}

/** A minimal PNG decoder: 8- and 16-bit gray, RGB, palette, with or without alpha. Null for the rest (interlaced, < 8 bit). */
export function decodePng(buf: Buffer): Png | null {
  if (buf.length < 8 || buf.readUInt32BE(0) !== 0x89504e47) return null;
  let at = 8, w = 0, h = 0, depth = 0, type = 0, interlaced = false;
  let plte: Buffer | null = null;
  const idat: Buffer[] = [];
  while (at + 8 <= buf.length) {
    const len = buf.readUInt32BE(at), name = buf.toString("latin1", at + 4, at + 8), data = buf.subarray(at + 8, at + 8 + len);
    if (name === "IHDR") [w, h, depth, type, interlaced] = [data.readUInt32BE(0), data.readUInt32BE(4), data[8], data[9], data[12] !== 0];
    else if (name === "PLTE") plte = data;
    else if (name === "IDAT") idat.push(data);
    else if (name === "IEND") break;
    at += 12 + len;
  }
  const channels = ({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 } as Record<number, number>)[type];
  // ponytail: no interlaced or sub-byte PNGs (screenshots never are); add Adam7 if one turns up
  if (!channels || interlaced || !w || !h || (depth !== 8 && depth !== 16) || (type === 3 && (depth !== 8 || !plte))) return null;
  const bpp = (channels * depth) / 8, stride = w * bpp;
  const raw = inflateSync(Buffer.concat(idat));
  const px = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], src = y * (stride + 1) + 1, row = y * stride;
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? px[row + i - bpp] : 0, b = y ? px[row - stride + i] : 0, c = i >= bpp && y ? px[row - stride + i - bpp] : 0;
      const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
      px[row + i] = raw[src + i] + [0, a, b, (a + b) >> 1, pa <= pb && pa <= pc ? a : pb <= pc ? b : c][f]; // wraps mod 256, as PNG wants
    }
  }
  const step = depth / 8; // 16-bit: the high byte
  return {
    w, h,
    px(x, y) {
      const o = y * stride + x * bpp, s = (k: number) => px[o + k * step];
      const [rgb, alpha] =
        type === 0 ? [[s(0), s(0), s(0)], 255]
        : type === 2 ? [[s(0), s(1), s(2)], 255]
        : type === 3 ? [[plte![s(0) * 3], plte![s(0) * 3 + 1], plte![s(0) * 3 + 2]], 255]
        : type === 4 ? [[s(0), s(0), s(0)], s(1)]
        : [[s(0), s(1), s(2)], s(3)];
      return (rgb as number[]).map((v) => Math.round((v * (alpha as number)) / 255));
    },
  };
}

// ── Real pictures, where the terminal draws them ─────────────────────────────────────────────

/**
 * How this terminal draws pictures: kitty's graphics protocol (kitty, Ghostty), iTerm2's inline images (iTerm2,
 * WezTerm), sixels (foot, mlterm, Konsole, Windows Terminal); null: half blocks. FOXHOLE_IMAGES=kitty, iterm,
 * sixel or blocks says it for a terminal not known here. None get through tmux or screen as they're set up by default.
 */
export const GRAPHICS = ((): "kitty" | "iterm" | "sixel" | null => {
  const e = process.env;
  if (!useColor) return null;
  if (e.FOXHOLE_IMAGES) return (["kitty", "iterm", "sixel"] as const).find((g) => g === e.FOXHOLE_IMAGES) ?? null;
  if (e.TMUX || e.STY) return null;
  if (e.KITTY_WINDOW_ID || e.TERM === "xterm-kitty" || e.TERM_PROGRAM === "ghostty") return "kitty";
  if (e.TERM_PROGRAM === "iTerm.app" || e.LC_TERMINAL === "iTerm2" || e.TERM_PROGRAM === "WezTerm") return "iterm";
  if (/^(foot|mlterm|contour)/.test(e.TERM ?? "") || e.KONSOLE_VERSION || e.WT_SESSION) return "sixel";
  return null;
})();

/**
 * Sixels are pixels, so they need a cell's size: the TUI asks the terminal (CSI 16 t: a cell; CSI 14 t: the
 * window, for one that only answers that) and hands the answer to cellSize. Until one comes, half blocks.
 */
export const CELL_QUERY = "\x1b[16t\x1b[14t";
let cell: { w: number; h: number } | null = null;
export function cellSize(w: number, h: number): void {
  if (w > 0 && h > 0) cell = { w, h };
}

const pngs = new Map<string, Png | null>();
const png = (file: string) => {
  if (!pngs.has(file)) {
    try {
      pngs.set(file, decodePng(readFileSync(file)));
    } catch {
      pngs.set(file, null);
    }
  }
  return pngs.get(file)!;
};

/** Whether file is drawn as the real picture here. */
const canDraw = (file: string) => !!GRAPHICS && (GRAPHICS !== "sixel" || !!cell) && !!png(file);

let kittyShown = false; // a kitty picture is on the screen: kitty keeps it over whatever text comes, until it's deleted
const kittyIds = new Map<string, number>(); // the pictures sent to kitty, kept there to place again by their number
const sixels = new Map<string, string>();

/**
 * What draws p with its popup's top-left corner at (row, col), 0-based screen cells, after the text: the cursor
 * stays where it was. With p null, what takes a kitty picture away. Called after each redraw (the text goes over the picture).
 */
export function pictureAt(p: Picture | null, row: number, col: number): string {
  let out = "";
  if (kittyShown) (out += "\x1b_Ga=d,d=a,q=2\x1b\\"), (kittyShown = false); // its placements, not the pictures
  if (!p || !canDraw(p.file)) return out;
  const at = `\x1b7\x1b[${row + p.row + 1};${col + p.col + 1}H`;
  if (GRAPHICS === "iterm") {
    const data = readFileSync(p.file);
    return out + `${at}\x1b]1337;File=inline=1;size=${data.length};width=${p.cols};height=${p.rows};preserveAspectRatio=1:${data.toString("base64")}\x07\x1b8`;
  }
  if (GRAPHICS === "kitty") {
    let id = kittyIds.get(p.file);
    if (!id) {
      id = 0x46580000 + Math.floor(Math.random() * 0xffff); // ponytail: random, so another program's pictures in this window aren't overwritten
      kittyIds.set(p.file, id);
      const b64 = readFileSync(p.file).toString("base64");
      for (let i = 0; i < b64.length; i += 4096) {
        const more = i + 4096 < b64.length ? 1 : 0;
        out += `\x1b_G${i ? "" : `a=t,f=100,i=${id},q=2,`}m=${more};${b64.slice(i, i + 4096)}\x1b\\`;
      }
    }
    kittyShown = true;
    return out + `${at}\x1b_Ga=p,i=${id},c=${p.cols},C=1,q=2\x1b\\\x1b8`; // c alone: the rows follow its shape
  }
  const key = `${p.file}:${p.cols}x${p.rows}:${cell!.w}x${cell!.h}`;
  if (!sixels.has(key)) sixels.set(key, sixel(png(p.file)!, p.cols * cell!.w, p.rows * cell!.h));
  return out + at + sixels.get(key)! + "\x1b8";
}

/** img as sixels, as large as fits w × h pixels: its colors rounded to a 6×6×6 cube (216 of the 256 registers). */
export function sixel(img: Png, w: number, h: number): string {
  const scale = Math.min(w / img.w, h / img.h);
  const tw = Math.max(1, Math.round(img.w * scale)), th = Math.max(1, Math.round(img.h * scale));
  const at = scaled(img, tw, th);
  const idx = new Uint8Array(tw * th);
  const used = new Set<number>();
  for (let y = 0; y < th; y++)
    for (let x = 0; x < tw; x++) {
      const [r, g, b] = at(x, y).map((v) => Math.round(v / 51));
      used.add((idx[y * tw + x] = 36 * r + 6 * g + b));
    }
  let out = `\x1bP0;1;0q"1;1;${tw};${th}`;
  for (const c of used) out += `#${c};2;${[Math.floor(c / 36), Math.floor(c / 6) % 6, c % 6].map((v) => v * 20).join(";")}`; // in percent
  for (let y0 = 0; y0 < th; y0 += 6) {
    const band = new Set<number>();
    for (let i = y0 * tw; i < Math.min(th, y0 + 6) * tw; i++) band.add(idx[i]);
    const rows: string[] = [];
    for (const c of band) {
      // each column's six pixels of this color as one character, repeats run-length coded (!n)
      let line = "", prev = "", n = 0;
      const flush = () => (line += n > 3 ? `!${n}${prev}` : prev.repeat(n));
      for (let x = 0; x < tw; x++) {
        let bits = 0;
        for (let k = 0; k < 6 && y0 + k < th; k++) if (idx[(y0 + k) * tw + x] === c) bits |= 1 << k;
        const ch = String.fromCharCode(63 + bits);
        if (ch === prev) n++;
        else (flush(), (prev = ch), (n = 1));
      }
      flush();
      rows.push(`#${c}${line}`);
    }
    out += rows.join("$") + "-"; // $: back to the band's start for the next color; -: the next band
  }
  return out + "\x1b\\";
}
