// Foxhole's desktop app: one window and a tray icon over the Controller, which runs the VPN in this (main) process.
import { app, BrowserWindow, ipcMain, clipboard, dialog, shell, nativeTheme, Notification, powerMonitor } from "electron";
import { accessSync, constants, statSync } from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Controller } from "./controller.js";
import { createTray } from "./tray.js";
import { createBadge } from "./badge.js";
import { Updater } from "./updater.js";
import { REPO_URL } from "./dist/ui.js";

// Two copies would fight over the proxy's port and the routes: a second one only brings up the first.
if (!app.requestSingleInstanceLock()) process.exit(0);

// As cli.ts: Node gives each server address only 250 ms; far VPN servers take 600-900 ms to answer.
net.setDefaultAutoSelectFamilyAttemptTimeout(3000);

const LINKS = {
  repo: REPO_URL, releases: `${REPO_URL}/releases`, firefox: "https://www.mozilla.org/firefox/new/",
  relay: `${REPO_URL}#where-vpnmozillaorg-is-blocked-eg-iran`,
  gas: "https://script.google.com/home", // Google Apps Script, for the relay's setup
};
// What the window may ask for: the Controller's actions, nothing else of it
const ACTIONS = new Set([
  "state", "power", "connect", "disconnect", "toggleGlobal", "submitPassword", "cancelPassword",
  "setShare", "setPort", "setLogin", "setRelay", "relaySetup", "openSettings", "openSplit", "setSplitDefault", "addRule", "toggleRule", "removeRule",
  "logs", "copy", "copyLogs", "openFirefox", "copySnippet", "switchAccount", "keepAccount", "reloadList",
]);

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

/** This app's .app folder when an update can be swapped in there: a packaged Mac app in a folder it may write
 *  (not run from the disk image), on the same disk as the downloads. Otherwise updates are a link to the download. */
function ownBundle() {
  if (process.platform !== "darwin" || !app.isPackaged) return null;
  const bundle = resolve(process.execPath, "../../..");
  try {
    accessSync(dirname(bundle), constants.W_OK);
    accessSync(bundle, constants.W_OK);
    return statSync(bundle).dev === statSync(homedir()).dev ? bundle : null;
  } catch {
    return null;
  }
}

const updater = new Updater({ dir: join(app.getPath("userData"), "update"), bundle: ownBundle(), via: () => controller.via(), changed: () => controller.emit("change") });
const controller = new Controller({ copy: (text) => clipboard.writeText(text), updates: updater });
let win = null;
let done = false; // global mode's routes are back and the proxy closed: free to quit
let relaunch = false; // the quit is a restart into the downloaded version

/** "Restart to update": the quit swaps the new version in, then it starts. */
function restartToUpdate() {
  relaunch = true;
  app.quit();
}

function show() {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

app.on("second-instance", show);
app.on("activate", show); // macOS: a click on the Dock icon

app.whenReady().then(() => {
  nativeTheme.themeSource = "dark"; // the window frame and scrollbars on Windows and Linux
  win = new BrowserWindow({
    width: 1120,
    height: 740,
    minWidth: 980,
    minHeight: 660,
    show: false,
    title: "Foxhole",
    backgroundColor: "#07060c",
    autoHideMenuBar: true,
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    trafficLightPosition: { x: 20, y: 20 },
    icon: here("build/icon.png"),
    webPreferences: { preload: here("preload.cjs"), sandbox: true, contextIsolation: true },
  });
  const badge = createBadge(win, here("build/icon.png")); // the app's icon, with a dot while connected
  badge.update(controller.state());
  win.once("ready-to-show", () => win.show());
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (e) => e.preventDefault());
  // Closing the window leaves Foxhole running in the tray; it quits from there (or Cmd+Q).
  let told = false; // Windows and Linux hide tray icons easily: say once where it went
  win.on("close", (e) => {
    if (done) return;
    e.preventDefault();
    win.hide();
    if (told || process.platform === "darwin" || !Notification.isSupported()) return;
    told = true;
    new Notification({ title: "Foxhole is still running", body: "It's in the tray: open it or quit it from there.", icon: here("build/icon.png") }).show();
  });
  void win.loadFile(here("renderer/index.html"));

  const tray = createTray(
    controller,
    {
      connect: (code) => controller.connect(code),
      disconnect: () => controller.disconnect(),
      toggleGlobal: () => controller.toggleGlobal(),
      show,
      update: restartToUpdate,
      releases: () => shell.openExternal(LINKS.releases),
      quit: () => app.quit(),
    },
    // macOS: monochrome "Template" images, drawn in the menu bar's own color
    (name) => here(`build/tray/${name}${process.platform === "darwin" ? "Template" : ""}.png`),
  );

  // State goes to the window and the tray at most every 50 ms, and each second anyway (split tunneling's counts climb as sites load).
  let timer = null;
  controller.on("change", () => {
    timer ??= setTimeout(() => {
      timer = null;
      if (win.isDestroyed()) return;
      const state = controller.state();
      win.webContents.send("state", state);
      tray.update();
      badge.update(state);
      // The password popup or a sign-in, asked for from the tray: they're in the window
      if ((state.pw || !["checking", "ready"].includes(state.auth.stage)) && !win.isVisible()) show();
    }, 50);
  });
  setInterval(() => controller.emit("change"), 1000);
  // Log lines in batches: tun2socks can log many a second
  let lines = [];
  controller.on("log", (line) => {
    if (lines.push(line) > 1) return; // a batch is already on its way
    setTimeout(() => {
      if (!win.isDestroyed()) win.webContents.send("log", lines);
      lines = [];
    }, 150);
  });

  ipcMain.handle("act", (e, name, ...args) => {
    if (e.sender !== win.webContents || !(ACTIONS.has(name) || name === "restartToUpdate")) throw new Error(`no such action: ${name}`);
    return name === "restartToUpdate" ? restartToUpdate() : controller[name](...args);
  });
  ipcMain.handle("open", (e, which) => e.sender === win.webContents && LINKS[which] && shell.openExternal(LINKS[which]));

  // Shutting down or restarting with global mode on: hold it until the routes and DNS are back (Linux, macOS)
  powerMonitor.on("shutdown", (e) => {
    e.preventDefault();
    app.quit();
  });

  controller.start({ global: process.argv.includes("--whole-system") }).catch((err) => {
    dialog.showErrorBox("Foxhole couldn't start", err.message);
    app.quit();
  });
  updater.start();
});

// Quit from the tray, Cmd+Q, a signal, shutting down: put global mode's routes and DNS back first.
let quitting = false;
app.on("before-quit", (e) => {
  if (done) return;
  e.preventDefault();
  if (quitting) return;
  quitting = true;
  const whole = controller.state().globalOn;
  if (whole) show(); // the window says what's happening meanwhile
  void controller.shutdown().finally(() => {
    done = true;
    updater.install(); // a downloaded version goes in on any quit
    // the restart into it turns whole-system mode back on if it was
    if (relaunch) app.relaunch({ args: [...process.argv.slice(1).filter((a) => a !== "--whole-system"), ...(whole ? ["--whole-system"] : [])] });
    app.exit(0); // a dial or IP check still in flight mustn't hold the quit
  });
});
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => app.quit());
