// The tray icon (in the menu bar, on macOS): the state at a glance, and the main actions without the window.
import { Tray, Menu, nativeImage, systemPreferences } from "electron";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { flag } from "./dist/ui.js";

/** A country as the menu names it: its flag is the item's picture (flagIcon). */
const named = (s, code) => s.countries.find((c) => c.code === code)?.name ?? code;

/** A country's flag picture (build/flags, made by flag-icons.mjs; Electron finds its @2x), or null. */
const flagFiles = new Map();
const flagFile = (code) => {
  if (!code) return null;
  if (!flagFiles.has(code)) {
    const file = fileURLToPath(new URL(`./build/flags/${code.toLowerCase()}.png`, import.meta.url));
    flagFiles.set(code, existsSync(file) ? file : null);
  }
  return flagFiles.get(code);
};
/** The flag as a menu item's picture, or nothing. */
const flagIcon = (code) => (flagFile(code) ? { icon: flagFile(code) } : {});

/** What the tray shows for a state (controller.js state()): icon, the text beside it (macOS), tooltip, menu. Pure. */
export function trayView(s, act) {
  const status = s.restoring
    ? "Restoring networking…"
    : s.busy
      ? s.connecting ? `Connecting to ${named(s, s.connecting)}…` : "Working…"
      : s.globalOn
        ? `Whole system · ${named(s, s.global)}`
        : s.active ? `Connected · ${named(s, s.active)}` : "Not connected";
  const ready = s.auth.stage === "ready" && !s.busy && !s.restoring;
  const here = s.active ?? s.selected; // where Connect goes, and the location ticked
  return {
    // relay mode: a purple dot where Firefox VPN's is mint or pink (on macOS, monochrome: "Relay" beside it)
    icon: s.globalOn ? (s.relayOn ? "relayGlobal" : "global") : s.active ? (s.relayOn ? "relay" : "on") : "off",
    title: s.busy ? "…" : s.relayOn ? "Relay" : s.active && !flagFile(s.active) ? flag(s.active) : "", // a flag with a picture goes into the icon (macOS)
    flag: !s.busy && flagFile(s.active) ? s.active : null,
    tooltip: `Foxhole · ${status}`,
    menu: [
      { label: status, enabled: false, ...flagIcon(!s.restoring && (s.connecting ?? (s.globalOn ? s.global : s.active))) },
      ...(s.active && s.ip ? [{ label: `IP ${s.ip}`, enabled: false }] : []),
      { type: "separator" },
      // each click in its own arrow: Electron calls it with (menuItem, window, event)
      s.active
        ? { label: "Disconnect", enabled: ready, click: () => act.disconnect() }
        : { label: here ? `Connect to ${named(s, here)}` : "Connect", enabled: ready && !!here, click: () => act.connect(), ...flagIcon(here) },
      { label: "Whole system", type: "checkbox", checked: s.globalOn, enabled: ready, click: () => act.toggleGlobal() },
      {
        label: "Location",
        enabled: ready && s.countries.length > 0,
        submenu: s.countries
          .filter((c) => c.available || c.locked)
          .flatMap((c) => [
            { label: named(s, c.code), type: "radio", checked: c.code === here, click: () => act.connect(c.code), ...flagIcon(c.code) },
            ...(c.code === "RELAY" ? [{ type: "separator" }] : []), // the relay, first, apart from the countries
          ]),
      },
      { type: "separator" },
      ...(s.update?.ready
        ? [{ label: `Restart to Update (${s.update.version})`, click: () => act.update() }]
        : s.update
          ? [s.update.auto
            ? { label: s.update.phase ? `Updating to ${s.update.version}…` : `Update to Foxhole ${s.update.version}`, enabled: !s.update.phase, click: () => act.getUpdate() }
            : { label: `Get Foxhole ${s.update.version}…`, click: () => act.releases() }]
          : []),
      { label: "Show Foxhole", click: () => act.show() },
      { label: "Quit Foxhole", click: () => act.quit() },
    ],
  };
}

/** The tray, redrawn by update() when what it shows changed. `icon(name)`: the file for off, on, global, relay or relayGlobal. */
export function createTray(controller, act, icon) {
  const images = Object.fromEntries(["off", "on", "global", "relay", "relayGlobal"].map((n) => [n, nativeImage.createFromPath(icon(n))]));
  const mac = process.platform === "darwin";
  // The menu bar's own appearance: the app's is dark whatever the system's (main.js), so nativeTheme can't tell
  const darkBar = () => systemPreferences.getUserDefault("AppleInterfaceStyle", "string") === "Dark";
  let dark = mac && darkBar();
  const drawn = new Map(); // icon + flag pictures made so far
  const tray = new Tray(images.off);
  if (process.platform !== "darwin") tray.on("click", () => act.show()); // macOS opens the menu on a click
  let shown = "";
  const update = () => {
    const v = trayView(controller.state(), act);
    const sig = JSON.stringify(v); // the visible part: the click handlers drop out
    if (sig === shown) return; // the state comes each second: redraw only what changed
    shown = sig;
    tray.setImage(mac && v.flag ? withFlag(v.icon, v.flag) : images[v.icon]);
    tray.setToolTip(v.tooltip);
    if (process.platform === "darwin") tray.setTitle(v.title);
    tray.setContextMenu(Menu.buildFromTemplate(v.menu));
  };
  /**
   * macOS: the state's icon with the connected country's flag beside it, one picture made here (a tray's title can
   * only be text). The flag's colors mean macOS can't color it as a template, so the icon is drawn white on a dark
   * menu bar and black on a light one here. ponytail: follows dark mode, not a menu bar tinted by the wallpaper.
   */
  function withFlag(name, code) {
    const id = `${name}:${code}:${dark}`;
    if (!drawn.has(id)) {
      const base = images[name], flagImg = nativeImage.createFromPath(flagFile(code));
      const bw = base.getSize().width * 2, bh = base.getSize().height * 2, fw = flagImg.getSize().width * 2, fh = flagImg.getSize().height * 2;
      const gap = 6, w = bw + gap + fw, h = Math.max(bh, fh);
      const out = Buffer.alloc(w * h * 4); // 4 bytes a pixel, premultiplied: a template's black at alpha a becomes white as (a, a, a, a)
      const put = (src, sw, sh, x0, tint) => {
        const y0 = Math.floor((h - sh) / 2);
        for (let y = 0; y < sh; y++)
          for (let x = 0; x < sw; x++) {
            const i = (y * sw + x) * 4, o = ((y0 + y) * w + x0 + x) * 4;
            for (let k = 0; k < 4; k++) out[o + k] = tint ? (k === 3 || dark ? src[i + 3] : 0) : src[i + k];
          }
      };
      put(base.toBitmap({ scaleFactor: 2 }), bw, bh, 0, true);
      put(flagImg.toBitmap({ scaleFactor: 2 }), fw, fh, bw + gap, false);
      drawn.set(id, nativeImage.createFromBitmap(out, { width: w, height: h, scaleFactor: 2 }));
    }
    return drawn.get(id);
  }

  if (mac) {
    // the system switching between light and dark: the icon follows
    systemPreferences.subscribeNotification("AppleInterfaceThemeChangedNotification", () => {
      dark = darkBar();
      shown = "";
      update();
    });
  }
  update();
  return { update };
}
