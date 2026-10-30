// The TUI's step-by-step setup of the Apps Script relay (httprelay.ts), a popup over Settings. The wording, the
// script and the screenshots are relaysetup.ts's, shared with the desktop app. Screenshots are drawn with ▀ half
// blocks (two pixels a cell, fore- and background color): plain text, so it works in any terminal on any OS.
import type readline from "node:readline";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { STEPS, KEY_PLACEHOLDER, KEY_CHARS, keyOk, newAuthKey, relayScript, relayTemplate, highlightJs, deploymentId, stepImage, type Token } from "./relaysetup.js";
import { bold, dim, cyan, green, yellow, red, magenta, useColor, fit, pad, box, openUrl, copyText } from "./ui.js";
import { userHome } from "./profile.js";

const IMG_W = 30, IMG_H = 9; // a 16:9 screenshot in cells: 30 × 18 pixels

/** What a key did: close the wizard, finish with this relay, or nothing to tell (redraw). */
export type WizardResult = "close" | { deploymentId: string; authKey: string } | undefined;

export class RelayWizard {
  #step = 0;
  #key = newAuthKey();
  #editKey = false; // the key is being typed
  #id = ""; // the last step's input
  #scroll = 0; // the code's first line shown
  #codeRows = 6; // how many the last render showed
  #note = "";
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
    if (n === "left") return void (this.#step = Math.max(0, this.#step - 1));
    const last = this.#step === STEPS.length - 1;
    if (n === "right" || n === "return") {
      if (!last) {
        if (this.#step === 1 && !keyOk(this.#key)) return void (this.#note = red("Make a key first: press r."));
        return void ((this.#step += 1), (this.#scroll = 0));
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
    if (n === "o") return void openUrl(stepImage(this.#step + 1));
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
      ...(this.#step < STEPS.length - 1 && !this.#editKey && existsSync(stepImage(this.#step + 1)) ? ["o full screenshot"] : []),
      "esc close",
    ].filter(Boolean);
    const head = ["", stepper, "", bold(`${this.#step + 1}. ${st.title}`), ""];
    // the keys on as few lines as fit the width
    const keyLines = keys.reduce<string[]>((ls, k) => (ls.length && ls[ls.length - 1].length + 3 + k.length <= inner ? (ls[ls.length - 1] += " · " + k) : ls.push(k), ls), []);
    const foot = [this.#note, ...keyLines.map(dim)];
    const room = rows - 2 - head.length - foot.length; // inside the border

    // The text, with the screenshot beside it when there's room for both and (step 2) the code below
    const extra = this.#step === 1 ? 2 + 5 : this.#step === STEPS.length - 1 ? 2 : 0; // key + gap + 5 lines of code; the input
    const img = inner >= 64 ? halfBlocks(stepImage(this.#step + 1), IMG_W, IMG_H) : null;
    const textW = img ? inner - IMG_W - 3 : inner;
    const text = (w: number) => st.lines.flatMap((l, i) => wrap(`${i + 1}. ${l}`, w, 3));
    const beside = text(textW);
    const h = Math.max(beside.length, IMG_H);
    const body = img && h + extra <= room
      ? Array.from({ length: h }, (_, i) => pad(beside[i] ?? "", textW) + "   " + (img[i] ?? ""))
      : text(inner);

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

function blocks(img: Png, cols: number, rows: number): string[] {
  const scale = Math.min(cols / img.w, (rows * 2) / img.h);
  const tw = Math.max(1, Math.round(img.w * scale)), th = Math.max(2, 2 * Math.round((img.h * scale) / 2)); // even: no half-empty last row
  // each target pixel: the average of a 3×3 sample of the source pixels it covers
  const at = (x: number, y: number) => {
    const sum = [0, 0, 0];
    for (let j = 0; j < 3; j++)
      for (let i = 0; i < 3; i++) {
        const p = img.px(Math.floor(((x + (i + 0.5) / 3) * img.w) / tw), Math.floor(((y + (j + 0.5) / 3) * img.h) / th));
        for (let k = 0; k < 3; k++) sum[k] += p[k];
      }
    return sum.map((v) => Math.round(v / 9));
  };
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

interface Png {
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
