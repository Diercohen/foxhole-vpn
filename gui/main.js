// Foxhole's desktop app: one window and a tray icon over the Controller, which runs the VPN in this (main) process.
import { app, BrowserWindow, ipcMain, clipboard, dialog, shell, nativeTheme, nativeImage, Notification, powerMonitor } from "electron";
import { accessSync, constants, existsSync, statSync } from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Controller } from "./controller.js";
import { createTray } from "./tray.js";
import "./renderer/fa.js"; // foxholeWords: for Settings → Language
import "./renderer/ru.js";
import { createBadge } from "./badge.js";
import { Updater } from "./updater.js";
import { AUTOSTART_FLAG, loginItem } from "./autostart.js";
import { REPO_URL } from "./dist/ui.js";
import { FULL_DISK_ACCESS } from "./dist/profile.js";
import { useFastlyFallback } from "./dist/dns.js";
import { saveDesktopApp } from "./dist/fxalogin.js";
import { closeSignIn, openSignIn } from "./signinwindow.js";

// Two copies would fight over the proxy's port and the routes: a second one only brings up the first.
if (!app.requestSingleInstanceLock()) process.exit(0);
// where the terminal's foxhole finds this app, to sign in in its window (start.js --sign-in): started as this one was
saveDesktopApp(process.env.APPIMAGE ?? process.execPath, [...(app.isPackaged ? [] : [app.getAppPath()]), ...process.argv.filter((a) => a === "--no-sandbox")]);

// As cli.ts: Node gives each server address only 250 ms; far VPN servers take 600-900 ms to answer.
net.setDefaultAutoSelectFamilyAttemptTimeout(3000);
useFastlyFallback(); // where the network drops Fastly's addresses Mozilla's hosts get (dns.ts)

const TELEGRAM = /^tg:\/\/socks\?server=127\.0\.0\.1&port=\d{1,5}$/;
const LINKS = {
  repo: REPO_URL, releases: `${REPO_URL}/releases`, firefox: "https://www.mozilla.org/firefox/new/",
  relay: `${REPO_URL}#where-vpnmozillaorg-is-blocked-eg-iran`,
  gas: "https://script.google.com/home", // Google Apps Script, for the relay's setup
  fda: FULL_DISK_ACCESS, // macOS: where the app is allowed to read Firefox's profile
  // Location, which shows apps the Wi-Fi's name (app.js wifi-modal)
  location: "ms-settings:privacy-location",
};
// What the window may ask for: the Controller's actions, nothing else of it
const ACTIONS = new Set([
  "state", "power", "connect", "disconnect", "toggleGlobal", "submitPassword", "cancelPassword",
  "setShare", "setLang", "setSmartDns", "allowRouter", "setPort", "setLogin", "setRelay", "checkRelay", "relaySetup", "openSettings", "openSplit", "appIcons", "traffic", "hideSite", "setSplitDefault", "setSmart", "checkSite", "shareOpen", "importCheck", "importSettings", "newsShown", "setNetRule", "addRule", "toggleRule", "removeRule",
  "logs", "copy", "copyLogs", "openFirefox", "copySnippet", "reloadList",
  "addAccount", "useAccount", "removeAccount", "refreshAccounts", "dismissLow", "retrySignIn", "checkEntitled", "tvWait", "tvFind", "tvSend", "showWifiName",
  "trustCa", "untrustCa", "dismissTrust", "copyEnv",
]);

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

const writable = (...paths) => {
  try {
    for (const p of paths) accessSync(p, constants.W_OK);
    return true;
  } catch {
    return false;
  }
};

/** How this copy updates itself (updater.js), or null where it can't: then the window links to the download. */
function updateTarget() {
  if (!app.isPackaged) return null;
  if (process.platform === "darwin") {
    // a Mac app in a folder it may write (not run from the disk image), on the same disk as the downloads
    const bundle = resolve(process.execPath, "../../..");
    return writable(dirname(bundle), bundle) && statSync(bundle).dev === statSync(homedir()).dev ? { kind: "mac", bundle } : null;
  }
  if (process.platform === "win32") return process.arch === "ia32" ? null : { kind: "win", exe: process.execPath };
  if (process.platform === "linux" && process.arch === "x64") {
    // an AppImage in a folder it may write; or the .deb, installed with dpkg
    const file = process.env.APPIMAGE;
    if (file) return writable(dirname(file), file) ? { kind: "appimage", file } : null;
    if (existsSync("/var/lib/dpkg/info/foxhole-desktop.list")) return { kind: "deb" };
  }
  return null;
}

/** Starting at login, for a copy that stays where it is: not in development, nor from the Mac's disk image. */
function autostartItem() {
  if (!app.isPackaged || (process.platform === "darwin" && /^\/Volumes\/|\/AppTranslocation\//.test(process.execPath))) return null;
  // an AppImage from its file, the way it was started: Ubuntu 24.04 may only run it with --no-sandbox
  return loginItem(process.env.APPIMAGE ?? process.execPath, { electron: app, args: process.argv.filter((a) => a === "--no-sandbox") });
}
const autostart = autostartItem();
const startHidden = process.argv.includes(AUTOSTART_FLAG);
// a restart (an update, Full Disk Access) is one the user asked for: with the window
const restartArgs = () => process.argv.slice(1).filter((a) => a !== AUTOSTART_FLAG && a !== "--whole-system" && a !== "--reconnect");

const updater = new Updater({ dir: join(app.getPath("userData"), "update"), downloads: app.getPath("downloads"), target: updateTarget(), ways: () => controller.updateWays(), changed: () => controller.emit("change") });
const controller = new Controller({
  copy: (text) => clipboard.writeText(text),
  updates: updater,
  openSignIn: () =>
    openSignIn({ title: foxholeWords(controller.state().settings.lang)`Sign in to your Mozilla account`, parent: win ?? undefined, done: (account) => controller.signedIn(account) }),
  // split tunneling's app chips: an .app's or .exe's own icon. macOS's getFileIcon gives a stand-in for apps
  // (a grey square), its Quick Look thumbnail the real one.
  fileIcon: (path) =>
    (process.platform === "darwin" ? nativeImage.createThumbnailFromPath(path, { width: 40, height: 40 }) : app.getFileIcon(path, { size: "normal" })).then(
      (i) => (i.isEmpty() ? null : i.toDataURL()),
    ),
});
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

app.on("second-instance", (_e, argv) => argv.includes(AUTOSTART_FLAG) || show());
app.on("activate", show); // macOS: a click on the Dock icon

app.whenReady().then(() => {
  nativeTheme.themeSource = "dark"; // the window frame and scrollbars on Windows and Linux
  if (autostart?.on()) autostart.set(true); // a moved AppImage or app: at its new path from now on
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
    // started hidden, the window's animations mustn't run: by default a window that hasn't been shown yet counts as visible
    paintWhenInitiallyHidden: !startHidden,
    webPreferences: { preload: here("preload.cjs"), sandbox: true, contextIsolation: true },
  });
  const badge = createBadge(win, here("build/icon.png")); // the app's icon, with a dot while connected
  badge.update(controller.state());
  if (!startHidden) win.once("ready-to-show", () => win.show());
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  // nowhere else, but the page may reload itself: Settings → Language draws it anew (Electron counts a reload as a navigation)
  win.webContents.on("will-navigate", (e, url) => url !== win.webContents.getURL() && e.preventDefault());
  // Closing the window leaves Foxhole running in the tray; it quits from there (or Cmd+Q).
  let told = false; // Windows and Linux hide tray icons easily: say once where it went
  win.on("close", (e) => {
    if (done) return;
    e.preventDefault();
    win.hide();
    if (told || process.platform === "darwin" || !Notification.isSupported()) return;
    told = true;
    const t = foxholeWords(controller.state().settings.lang);
    new Notification({ title: t`Foxhole is still running`, body: t`It's in the tray: open it or quit it from there.`, icon: here("build/icon.png") }).show();
  });
  void win.loadFile(here("renderer/index.html"));

  const tray = createTray(
    controller,
    {
      connect: (code) => controller.pick(code),
      disconnect: () => controller.disconnect(),
      toggleGlobal: () => controller.setMode(),
      show,
      update: restartToUpdate,
      // the window's Update button: what's new, then its button downloads it
      getUpdate: () => (show(), void win?.webContents.executeJavaScript('document.getElementById("update").click()')),
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
      // signed in with the sign-in window's session: it's done
      if (state.auth.stage === "ready") closeSignIn();
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
    if (e.sender !== win.webContents || !(ACTIONS.has(name) || ["restartToUpdate", "relaunch", "update", "installUpdateFile", "showUpdateFile", "autostart"].includes(name))) throw new Error(`no such action: ${name}`);
    // with no argument, only asks; null: this copy can't
    if (name === "autostart") return autostart && (args.length && autostart.set(args[0] === true), autostart.on());
    if (name === "update") return updater.update(); // resolves once the new version is ready (true) or the try failed
    // the downloaded update, to install by hand
    if (name === "installUpdateFile") return void (updater.installByHand() && app.quit()); // opened once the app has quit
    if (name === "showUpdateFile") return updater.file() && void shell.showItemInFolder(updater.file());
    if (name === "relaunch") return void (app.relaunch({ execPath: process.env.APPIMAGE ?? process.execPath, args: [...restartArgs(), ...(controller.state().active ? ["--reconnect"] : [])] }), app.quit()); // macOS applies Full Disk Access to a new process
    if (name === "connect") return controller.pick(...args);
    if (name === "toggleGlobal") return controller.setMode();
    return name === "restartToUpdate" ? restartToUpdate() : controller[name](...args);
  });
  // a named link, or a page of the repo (the update's notes link its pull requests)
  // a named link, a page of the repo, or Telegram's own link to this computer's proxy (the proxy card's button)
  const link = (which) => LINKS[which] ?? (typeof which === "string" && (which.startsWith(`${REPO_URL}/`) || TELEGRAM.test(which)) ? which : null);
  ipcMain.handle("open", (e, which) => e.sender === win.webContents && link(which) && shell.openExternal(link(which)));

  // Shutting down or restarting with global mode on: hold it until the routes and DNS are back (Linux, macOS)
  powerMonitor.on("shutdown", (e) => {
    e.preventDefault();
    app.quit();
  });

  // opened by hand it waits for the user; at login, or a restart it was connected before, it connects
  const whole = process.argv.includes("--whole-system");
  const connect = startHidden || whole || process.argv.includes("--reconnect");
  (startHidden ? controller.wholeWithoutAsking() : Promise.resolve(whole)).then((global) => controller.start({ connect, global })).catch((err) => {
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
  const whole = controller.state().globalOn, active = controller.state().active;
  if (whole) show(); // the window says what's happening meanwhile
  void controller.shutdown().finally(() => {
    done = true;
    // the restart into it turns whole-system mode back on if it was
    const args = [...restartArgs(), ...(whole ? ["--whole-system"] : active ? ["--reconnect"] : [])];
    // a downloaded version goes in (Windows: only on a restart, its installer then starts it)
    const started = updater.install({ relaunch, args });
    // an AppImage from its file: the folder it runs from goes away with it
    if (relaunch && !started) app.relaunch({ execPath: process.env.APPIMAGE ?? process.execPath, args });
    app.exit(0); // a dial or IP check still in flight mustn't hold the quit
  });
});
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => app.quit());
