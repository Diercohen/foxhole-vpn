// The tray icon (in the menu bar, on macOS): the state at a glance, and the main actions without the window.
import { Tray, Menu, nativeImage } from "electron";
import { flag } from "./dist/ui.js";

/** A country as the menu names it; Windows draws no flag emoji, just two letters. */
const named = (s, code) => {
  const name = s.countries.find((c) => c.code === code)?.name ?? code;
  return process.platform === "win32" ? name : `${flag(code)} ${name}`;
};

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
    icon: s.globalOn ? "global" : s.active ? "on" : "off",
    title: s.busy ? "…" : s.active ? flag(s.active) : "",
    tooltip: `Foxhole · ${status}`,
    menu: [
      { label: status, enabled: false },
      ...(s.active && s.ip ? [{ label: `IP ${s.ip}`, enabled: false }] : []),
      { type: "separator" },
      // each click in its own arrow: Electron calls it with (menuItem, window, event)
      s.active
        ? { label: "Disconnect", enabled: ready, click: () => act.disconnect() }
        : { label: here ? `Connect to ${named(s, here)}` : "Connect", enabled: ready && !!here, click: () => act.connect() },
      { label: "Whole system", type: "checkbox", checked: s.globalOn, enabled: ready, click: () => act.toggleGlobal() },
      {
        label: "Location",
        enabled: ready && s.countries.length > 0,
        submenu: s.countries
          .filter((c) => c.available || c.locked)
          .map((c) => ({ label: named(s, c.code), type: "radio", checked: c.code === here, click: () => act.connect(c.code) })),
      },
      { type: "separator" },
      ...(s.update?.ready
        ? [{ label: `Restart to Update (${s.update.version})`, click: () => act.update() }]
        : s.update && !s.update.auto
          ? [{ label: `Get Foxhole ${s.update.version}…`, click: () => act.releases() }]
          : []),
      { label: "Show Foxhole", click: () => act.show() },
      { label: "Quit Foxhole", click: () => act.quit() },
    ],
  };
}

/** The tray, redrawn by update() when what it shows changed. `icon(name)`: the file for off, on or global. */
export function createTray(controller, act, icon) {
  const images = Object.fromEntries(["off", "on", "global"].map((n) => [n, nativeImage.createFromPath(icon(n))]));
  const tray = new Tray(images.off);
  if (process.platform !== "darwin") tray.on("click", () => act.show()); // macOS opens the menu on a click
  let shown = "";
  const update = () => {
    const v = trayView(controller.state(), act);
    const sig = JSON.stringify(v); // the visible part: the click handlers drop out
    if (sig === shown) return; // the state comes each second: redraw only what changed
    shown = sig;
    tray.setImage(images[v.icon]);
    tray.setToolTip(v.tooltip);
    if (process.platform === "darwin") tray.setTitle(v.title);
    tray.setContextMenu(Menu.buildFromTemplate(v.menu));
  };
  update();
  return { update };
}
