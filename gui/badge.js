// The app's own icon shows the state, as the tray's does: an amber dot with dots in turn while it connects or works,
// mint with a plug on the proxy, pink with a screen for the whole system. In the Dock on macOS, on the window's icon
// (the taskbar button's) on Windows and Linux. A dock that draws an app's own icon instead (Windows' for a pinned app,
// Ubuntu's) keeps it: Windows' overlay badge shows there, smaller and softer, as Windows enlarges it from 16 px.
import { app, nativeImage, screen, shell } from "electron";
import { readdirSync } from "node:fs";
import { join } from "node:path";

// busy: the window's amber; on and global: the tray icons' dots
// relay mode: the window's purples
const COLORS = { busy: [0xff, 0xc2, 0x47], on: [0x2d, 0xf1, 0xaf], global: [0xfe, 0x4c, 0x7c], relay: [0xb7, 0x6b, 0xff], relayGlobal: [0xd3, 0x5c, 0xff] };
const INK = { busy: [0x1d, 0x12, 0x00], on: [0x03, 0x15, 0x0f], global: [0xff, 0xff, 0xff], relay: [0x1a, 0x03, 0x26], relayGlobal: [0xff, 0xff, 0xff] }; // the glyph's, as on the window's mode switch
const RING = [0x07, 0x06, 0x0c]; // the app's dark, between the dot and the icon
const LABEL = { busy: "Working", on: "Connected", global: "Whole system", relay: "Relay", relayGlobal: "Relay, whole system" }; // Windows reads an overlay out
// One red pixel: where its byte lands gives this platform's channel order in bitmaps (BGRA on macOS and Windows)
const RED = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";
let rgb = null; // where red, green and blue sit in a pixel

// The glyphs, drawn on the window's 24-unit icon grid (renderer/index.html's #i-plug and #i-monitor): how far a
// point is from their strokes, in units
const seg = (x, y, ax, ay, bx, by) => {
  const [dx, dy] = [bx - ax, by - ay];
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - ax - t * dx, y - ay - t * dy);
};
const frame = (x, y, x0, y0, x1, y1, rr) => { // a rounded rectangle's outline
  const qx = Math.abs(x - (x0 + x1) / 2) - (x1 - x0) / 2 + rr, qy = Math.abs(y - (y0 + y1) / 2) - (y1 - y0) / 2 + rr;
  return Math.abs(Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - rr);
};
const cup = (x, y, cx, cy, r) => // a circle's lower half
  y >= cy ? Math.abs(Math.hypot(x - cx, y - cy) - r) : Math.min(Math.hypot(x - cx + r, y - cy), Math.hypot(x - cx - r, y - cy));
const GLYPHS = {
  // three dots, the f-th the biggest
  busy: (x, y, f) => Math.min(...[6.5, 12, 17.5].map((cx, i) => Math.hypot(x - cx, y - 12) - (i === f ? 1.5 : 0.6))),
  on: (x, y) => Math.min(seg(x, y, 9, 3, 9, 7), seg(x, y, 15, 3, 15, 7), seg(x, y, 6, 7, 18, 7), seg(x, y, 6, 7, 6, 10.5),
    seg(x, y, 18, 7, 18, 10.5), cup(x, y, 12, 10.5, 6), seg(x, y, 12, 16.5, 12, 21)), // a plug
  global: (x, y) => Math.min(frame(x, y, 3, 4, 21, 16.5, 2.5), seg(x, y, 8.5, 20.5, 15.5, 20.5), seg(x, y, 12, 16.5, 12, 20.5)), // a screen
};
GLYPHS.relay = GLYPHS.on;
GLYPHS.relayGlobal = GLYPHS.global;
export const FRAMES = { busy: 3 }; // its dots light up in turn

/** A copy of `img` with the dot for `key` (in frame f) centered at (cx, cy), radius r (pixels): lit at its top left, ringed in the dark, its glyph on it. */
export function withDot(img, key, cx, cy, r, f = 0) {
  rgb ??= nativeImage.createFromDataURL(RED).toBitmap()[0] === 255 ? [0, 1, 2] : [2, 1, 0];
  const { width: w, height: h } = img.getSize();
  const px = Buffer.from(img.toBitmap()); // premultiplied: an opaque color over it is a plain mix
  const cover = (v) => Math.max(0, Math.min(1, v + 0.5)); // a pixel's share of an edge v pixels inside it
  const over = (i, c, a) => {
    for (let k = 0; k < 3; k++) px[i + rgb[k]] = c[k] * a + px[i + rgb[k]] * (1 - a);
    px[i + 3] = 255 * a + px[i + 3] * (1 - a);
  };
  const outer = r * 1.24, unit = r * 0.062, stroke = Math.max(2.4 * unit, 1.3); // the glyph: 24 units over 1.5 radii, bolder than in the window
  for (let y = Math.max(0, Math.floor(cy - outer)); y < Math.min(h, Math.ceil(cy + outer)); y++)
    for (let x = Math.max(0, Math.floor(cx - outer)); x < Math.min(w, Math.ceil(cx + outer)); x++) {
      const [u, v] = [x + 0.5 - cx, y + 0.5 - cy], d = Math.hypot(u, v), i = (y * w + x) * 4;
      over(i, RING, cover(outer - d));
      const lit = Math.max(0, 1 - Math.hypot(u + r * 0.35, v + r * 0.4) / (r * 1.15)) ** 1.5;
      over(i, COLORS[key].map((c) => c + (255 - c) * lit * 0.55), cover(r - d));
      over(i, INK[key], cover(stroke / 2 - GLYPHS[key](u / unit + 12, v / unit + 12, f) * unit) * cover(r - d));
    }
  return nativeImage.createFromBitmap(px, { width: w, height: h });
}

/** The icon, `size` px across, with the dot for `key` (off: none) over its tile's corner: bigger on a taskbar's small icon than in the Dock. */
export function badgedIcon(icon, key, f = 0, size = 512, taskbar = false) {
  const base = icon.resize({ width: size, height: size, quality: "best" });
  const [at, r] = taskbar ? [0.8, 0.14] : [0.82, 0.115];
  return key === "off" ? base : withDot(base, key, size * at, size * at, size * r, f);
}

/** The dot alone, `size` px across, for Windows' overlay badge (null: none). */
export function overlayDot(key, f = 0, size = 16) {
  return key === "off" ? null : withDot(nativeImage.createFromBitmap(Buffer.alloc(size * size * 4), { width: size, height: size }), key, size / 2, size / 2, size * 0.39, f);
}

// Windows keeps the shortcuts of apps pinned to the taskbar here
const PINS = process.platform === "win32" ? join(process.env.APPDATA ?? "", "Microsoft", "Internet Explorer", "Quick Launch", "User Pinned", "TaskBar") : "";
/** Whether this app is pinned to the Windows taskbar: its button then shows the pin's icon, whatever the window's. */
function pinned() {
  try {
    return readdirSync(PINS).some((f) => f.endsWith(".lnk") && shell.readShortcutLink(join(PINS, f)).target?.toLowerCase() === process.execPath.toLowerCase());
  } catch {
    return false;
  }
}

/** Keeps the app's icon in step with the state (controller.js state()): update(state) on each change. */
export function createBadge(win, file) {
  const icon = nativeImage.createFromPath(file); // 1024 px, its tile from 100 to 923
  const made = new Map();
  const once = (id, make) => (made.has(id) ? made.get(id) : made.set(id, make()).get(id));
  let key = null, f = 0, pin = false, timer = null;
  const apply = () => {
    // The Dock draws up to 256 px: its frames at that, quick to swap 3 times a second (at 1024 px, one takes 80 ms)
    if (process.platform === "darwin") return app.dock?.setIcon(once(`dock ${key} ${f}`, () => badgedIcon(icon, key, f, FRAMES[key] ? 256 : 512)));
    const shown = pin ? "off" : key; // pinned, the window's icon goes unseen: the overlay shows the state
    win.setIcon(once(`icon ${shown} ${shown === key ? f : 0}`, () => badgedIcon(icon, shown, f, 256, true)));
    if (process.platform !== "win32") return;
    const n = Math.round(16 * screen.getDisplayMatching(win.getBounds()).scaleFactor);
    win.setOverlayIcon(pin ? once(`overlay ${key} ${f} ${n}`, () => overlayDot(key, f, n)) : null, pin ? LABEL[key] ?? "" : "");
  };
  // Windows drops the overlay with the taskbar button when the window hides (to the tray); pinning shows on the next
  if (process.platform === "win32") win.on("show", () => key && ((pin = pinned()), apply()));
  return {
    update(s) {
      const next = s.busy || s.restoring ? "busy" : s.globalOn ? (s.relayOn ? "relayGlobal" : "global") : s.active ? (s.relayOn ? "relay" : "on") : "off";
      if (next === key) return;
      [key, f, pin] = [next, 0, process.platform === "win32" && pinned()];
      clearInterval(timer);
      timer = FRAMES[key] ? setInterval(() => ((f = (f + 1) % FRAMES[key]), apply()), 350) : null;
      apply();
    },
  };
}
