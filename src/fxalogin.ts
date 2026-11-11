// Foxhole's own Mozilla sign-in in a terminal: Mozilla's sign-in in a window of its own, the account kept by Foxhole
// (accounts.ts OwnAccount), not by the Firefox in use. Where the desktop app is, the window is its sign-in window
// (gui/signinwindow.js): its internal sign-in app (gui/start.js --sign-in) hands the session to this foxhole only, on a
// pipe. Elsewhere it's a Firefox of its own (a fresh profile, deleted after) on Firefox's own sign-in, the session read
// from that profile as from the one in use (auth.ts FirefoxAuth). Since 2026-11 Mozilla's edge turns away an app's own
// sign-in with the password (HTTP 406, whatever the account or network), and its page a browser driven from outside
// (its "Client Challenge" fails in a Chrome run over its DevTools pipe): it's signed in to in a browser as people use one.
import { spawn, spawnSync, type ChildProcess, type SpawnOptions } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { firefoxCommand, userHome } from "./profile.js";
import { REPO_URL } from "./ui.js";

/** A session signed in. */
export interface FxaLogin {
  uid: string;
  email: string;
  sessionToken: string;
}

const appFile = () => join(userHome(), ".config", "foxhole-vpn", "desktop-app.json");

/** Where the desktop app runs from, said as it starts (main.js): its sign-in app is started the same way. */
export function saveDesktopApp(path: string, args: string[]): void {
  try {
    mkdirSync(dirname(appFile()), { recursive: true, mode: 0o700 });
    writeFileSync(appFile(), JSON.stringify({ path, args }));
  } catch {
    // the terminal's sign-in goes without it
  }
}

/** What opens the window: a binary, and what comes before its own arguments. */
type App = { path: string; args: string[] };

/**
 * The desktop app to sign in with: as it last started here, if it's still there; else, in a copy of the repo, the
 * repo's own (gui/, on its development Electron: what `npm start` there runs). Null where there's neither.
 */
export function desktopApp(): App | null {
  try {
    const { path, args } = JSON.parse(readFileSync(appFile(), "utf8")) as { path?: unknown; args?: unknown };
    if (typeof path === "string" && existsSync(path) && Array.isArray(args) && args.every((a) => typeof a === "string")) return { path, args };
  } catch {
    // no up-to-date desktop app has run here
  }
  const gui = fileURLToPath(new URL("../gui/", import.meta.url)); // not in the npm package
  try {
    if (existsSync(join(gui, "start.js"))) return { path: createRequire(join(gui, "package.json"))("electron") as string, args: [gui] }; // electron's main is its binary's path
  } catch {
    // its Electron isn't installed
  }
  return null;
}

/** Firefox here: the window where the desktop app isn't. */
export function firefox(): App | null {
  const cmd = firefoxCommand();
  return cmd && { path: cmd[0], args: cmd.slice(1) };
}

/** A session as the window gave it, checked. */
function session(a: unknown): FxaLogin | null {
  const { uid, email, sessionToken } = (a ?? {}) as Record<string, unknown>;
  return typeof uid === "string" && typeof email === "string" && typeof sessionToken === "string" && /^[0-9a-f]{64}$/i.test(sessionToken) ? { uid, email, sessionToken } : null;
}

const parse = (s: string): unknown => {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
};

const unavailable = (why: string) => new Error(`Signing in in a window isn't available right now: ${why}.`);

/**
 * Signs in to a Mozilla account in a window: the session, or null if the window's closed first (or `signal` aborts:
 * it's closed then). Throws, said for the user, where no window can open here. `proxy`: what it loads through, as
 * http://host:port (the VPN's proxy). `app` and `ff`: what opens the window, the desktop app first.
 */
export async function signInWindow(signal?: AbortSignal, proxy?: string, app = desktopApp(), ff = firefox()): Promise<FxaLogin | null> {
  if (process.platform === "linux" && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) throw unavailable("there's no screen here for its window (as in a container, or over SSH)");
  if (app) return appSignIn(app, signal, proxy);
  if (ff) return firefoxSignIn(ff, signal, proxy);
  throw unavailable(`it's the window of Foxhole's desktop app, or a Firefox of its own, and neither is on this computer. Get one of them: the desktop app from ${REPO_URL}/releases (then start it once), or Firefox`);
}

/**
 * Runs `app`, its stderr's last line kept for what went wrong. `signal` ends it (`end`, at once: an exit handler can't
 * wait), and so does this foxhole's exit: the window doesn't outlive it.
 */
function run(app: App, args: string[], options: SpawnOptions & { stdio: ("ignore" | "pipe")[] }, signal?: AbortSignal, end: (child: ChildProcess) => void = (c) => c.kill()) {
  const child = spawn(app.path, [...app.args, ...args], options);
  let err = "";
  child.stderr!.setEncoding("utf8").on("data", (s: string) => (err = (err + s).slice(-4000)));
  const stop = () => end(child);
  signal?.addEventListener("abort", stop, { once: true });
  process.once("exit", stop);
  child.on("close", () => {
    signal?.removeEventListener("abort", stop);
    process.removeListener("exit", stop);
  });
  return { child, stop, lastError: () => err.trim().split("\n").at(-1)?.slice(0, 160) };
}

/** The window, in the desktop app: its sign-in app says "open", then the session, on its stdout. */
function appSignIn(app: App, signal?: AbortSignal, proxy?: string): Promise<FxaLogin | null> {
  return new Promise((resolve, reject) => {
    const { child, lastError } = run(app, ["--sign-in", ...(proxy ? [`--proxy-server=${proxy}`] : [])], { stdio: ["ignore", "pipe", "pipe"] }, signal);
    let opened = false, got: FxaLogin | null = null, out = "";
    child.stdout!.setEncoding("utf8").on("data", (s: string) => {
      out += s;
      for (let i; (i = out.indexOf("\n")) >= 0; out = out.slice(i + 1)) {
        const line = out.slice(0, i).trim();
        if (line === "open") opened = true;
        else got ??= session(parse(line));
      }
    });
    child.on("error", (e) => reject(unavailable(`the desktop app wouldn't start (${e.message})`)));
    child.on("close", () => {
      if (got || opened || signal?.aborted) return resolve(got);
      const last = lastError();
      reject(unavailable(`the desktop app's window didn't open${last ? ` (${last})` : ""}`));
    });
  });
}

/** Where a Firefox of its own keeps its profile: a snap's or a Flatpak's sees only its own part of the home folder. */
function profilesDir(ff: App): string {
  const own =
    process.platform !== "linux" ? null
    : ff.path === "flatpak" ? join(userHome(), ".var", "app", "org.mozilla.firefox")
    : existsSync("/snap/bin/firefox") ? join(userHome(), "snap", "firefox", "common") // the snap's own /tmp isn't this one
    : null;
  if (own) mkdirSync(own, { recursive: true });
  return own ?? tmpdir();
}

/**
 * The window, as a Firefox of its own: a fresh profile (deleted after) opens Firefox's own sign-in
 * (about:preferences#sync, as `foxhole login` opens it in the Firefox in use), and once the session it keeps is
 * verified (as by a code from the email), it's taken and that Firefox closed. Its Sync gets no token: nothing of the
 * account's comes down to it. It loads through `proxy`, where there's one.
 */
function firefoxSignIn(ff: App, signal?: AbortSignal, proxy?: string): Promise<FxaLogin | null> {
  const dir = mkdtempSync(join(profilesDir(ff), "foxhole-sign-in-"));
  const via = proxy ? new URL(proxy) : null;
  const prefs = {
    // a first start shows and asks nothing else
    "browser.shell.checkDefaultBrowser": false,
    "browser.aboutwelcome.enabled": false,
    "browser.startup.homepage_override.mstone": "ignore",
    "datareporting.policy.dataSubmissionPolicyBypassNotification": true,
    "identity.sync.tokenserver.uri": "https://127.0.0.1:9/",
    ...(via && { "network.proxy.type": 1, "network.proxy.http": via.hostname, "network.proxy.http_port": Number(via.port || 80), "network.proxy.ssl": via.hostname, "network.proxy.ssl_port": Number(via.port || 80) }),
  };
  writeFileSync(join(dir, "user.js"), Object.entries(prefs).map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});\n`).join(""));
  // over the terminal (macOS); Windows' firefox.exe hands over to the browser and goes, unless it's to wait for it
  const own = process.platform === "darwin" ? ["--foreground"] : process.platform === "win32" ? ["--wait-for-browser"] : [];
  // An update waiting for the Firefox in use isn't put in by this one: it would change the files under that one, and
  // restart this one away from the process started (Firefox 160 has the switch).
  const env = { ...process.env, MOZ_DISABLE_UPDATE_PROCESSING: "1" };
  // Closed at once, with all it started (a wrapper's, as a snap's, and its own processes): nothing in it is kept.
  const closeAll = (c: ChildProcess) => {
    if (process.platform === "win32") spawnSync("taskkill", ["/T", "/F", "/PID", String(c.pid)], { stdio: "ignore" });
    else
      try {
        process.kill(-c.pid!, "SIGKILL"); // its own process group (detached), the one started gone or not
      } catch {
        // none left
      }
  };
  return new Promise((resolve, reject) => {
    const args = ["--no-remote", "--profile", dir, ...own, "about:preferences#sync"];
    const { child, stop, lastError } = run(ff, args, { stdio: ["ignore", "ignore", "pipe"], env, detached: process.platform !== "win32" }, signal, closeAll);
    let got: FxaLogin | null = null;
    const check = () => {
      let a: { verified?: boolean } | undefined;
      try {
        a = (JSON.parse(readFileSync(join(dir, "signedInUser.json"), "utf8")) as { accountData?: { verified?: boolean } } | null)?.accountData;
      } catch {
        // not signed in yet, or half-written
      }
      if (a?.verified) got ??= session(a);
    };
    const poll = setInterval(() => (check(), got && stop()), 500);
    child.on("error", (e) => reject(unavailable(`Firefox wouldn't start (${e.message})`)));
    child.on("close", (code) => {
      clearInterval(poll);
      check(); // signed in as it was closed
      try {
        rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
      } catch {
        // a file still held (Windows): it's in the temp folder
      }
      if (got || code === 0 || signal?.aborted) return resolve(got); // its window closed (0), or stopped: not signed in
      const last = lastError();
      reject(unavailable(`Firefox's window didn't open${last ? ` (${last})` : ""}`));
    });
  });
}
