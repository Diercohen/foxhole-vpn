// Foxhole's core on Android: the desktop app's Controller (gui/controller.js) in the Node the app starts (Core.kt),
// its window the same page in a WebView. One socket to the app carries lines of JSON both ways: the window's actions
// and their answers, the state and the log out; and what only the phone does (its VPN, clipboard, sign-in page),
// asked of the app.
import net from "node:net";
import { mkdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Controller } from "./controller.js";
import { Updater } from "./updater.js";
import { publicIp } from "./dist/netinfo.js";
import { caPem, loadCa } from "./dist/mitm.js";
import { log } from "./dist/log.js";

net.setDefaultAutoSelectFamilyAttemptTimeout(3000); // as cli.ts: far VPN servers take 600-900 ms to answer

// What the window may ask for, as gui/main.js (less the desktop's own: updates, relaunch)
const ACTIONS = new Set([
  "state", "power", "connect", "disconnect", "toggleGlobal",
  "setShare", "setPort", "setLogin", "setRelay", "checkRelay", "relaySetup", "openSettings", "openSplit", "setSplitDefault", "addRule", "toggleRule", "removeRule",
  "logs", "copy", "copyLogs", "openFirefox", "switchAccount", "keepAccount", "reloadList",
  "trustCa", "untrustCa", "dismissTrust",
]);

const app = new net.Socket({ fd: Number(process.argv[2]), readable: true, writable: true });
const send = (msg) => app.write(`${JSON.stringify(msg)}\n`);

let seq = 0;
const asked = new Map(); // id → { resolve, reject }
/** Asks the app for what only the phone does; resolves with its answer. */
const ask = (cmd, args = {}) =>
  new Promise((resolve, reject) => {
    asked.set(++seq, { resolve, reject });
    send({ t: "ask", id: seq, cmd, args });
  });

// The sign-in, where findAccount() looks for Firefox's: the app's sign-in page gives the session (App.tsx)
const SESSION = join(homedir(), ".mozilla", "firefox", "foxhole.default", "signedInUser.json");
const sessionStamp = () => {
  try {
    return statSync(SESSION).mtimeMs;
  } catch {
    return 0;
  }
};
function saveSession({ email, sessionToken, uid, verified }) {
  if (typeof sessionToken !== "string" || !/^[0-9a-f]{64}$/.test(sessionToken)) return log("sign-in: no session in the answer");
  mkdirSync(dirname(SESSION), { recursive: true, mode: 0o700 });
  writeFileSync(`${SESSION}.tmp`, JSON.stringify({ version: 1, accountData: { email, sessionToken, uid, verified: verified !== false } }), { mode: 0o600 });
  renameSync(`${SESSION}.tmp`, SESSION);
}

let vpn = null; // whole-system mode's session while Android's VPN is up: told when Android stops it
/** Android's VPN for whole-system mode, as GlobalSession: it sends all apps' connections to the proxy (but this app's own). */
function globalSession({ proxyPort }) {
  let exited = () => {};
  const session = {
    async start() {
      await ask("vpnStart", { port: proxyPort });
      vpn = session;
    },
    async stop() {
      if (vpn === session) vpn = null;
      await ask("vpnStop");
    },
    onExit: (cb) => (exited = cb),
    onNetworkChange() {}, // Android moves the VPN to the new network itself
    async addServer() {}, // the proxy's own connections are outside the VPN: nothing to pin
    splitChanged() {}, // direct sites go direct from the proxy, outside the VPN
    // through the proxy: this app's own connections don't go through its VPN
    verifyExitIp: (relay) => publicIp({ host: "127.0.0.1", port: proxyPort }, 3, relay),
    exit(why) {
      vpn = null;
      exited(why);
    },
  };
  return session;
}

// a new version on GitHub: the window links to its releases page (target null: no update in place)
const updater = new Updater({ dir: join(homedir(), "update"), downloads: join(homedir(), "update"), target: null, via: () => controller.via(), changed: () => controller.emit("change") });
const controller = new Controller({
  copy: (text) => void ask("copy", { text }).catch(() => {}),
  updates: updater,
  android: {
    openSignIn: () => send({ t: "signIn" }),
    sessionStamp,
    globalSession,
    network: () => ask("network").catch(() => null),
    caTrusted: () => (caPem() ? ask("caTrusted", { pem: caPem() }).catch(() => false) : Promise.resolve(false)),
    setCaTrust: (add) => ask(add ? "caInstall" : "caRemove", { pem: add ? loadCa().pem : caPem() }),
  },
});

// The state to the window at most every 50 ms, and each second while it's on screen (split tunneling's counts climb);
// the notification that keeps Foxhole running while connected (or paused, to resume from it) follows it.
let shown = true; // the app is on screen
let timer = null;
let kept = "";
let paused = null; // paused from the notification: { code, global }, what its Resume connects to again

/** The state, with the notification's pause in it (the window says so). */
function view() {
  const s = controller.state();
  if (s.active) paused = null; // connected again: by Resume, or in the app
  return { ...s, paused };
}

function push() {
  timer = null;
  const s = view();
  if (shown) send({ t: "state", s });
  const place = (code) => s.countries.find((c) => c.code === code)?.name ?? ""; // the relay's row is "Relay"
  const note = s.active
    ? JSON.stringify({ title: `${s.globalOn ? "Whole system" : "Proxy"} · ${place(s.global ?? s.active)}`, text: s.proxy ? `${s.proxy.addr} · SOCKS5 + HTTP` : "" })
    : paused
      ? JSON.stringify({
          title: `${s.connecting ? "Connecting…" : "Paused"} · ${place(paused.code)}`,
          text: s.connecting ? "" : paused.global ? "Apps go direct until you resume" : "The proxy is off until you resume",
          paused: true,
        })
      : "";
  if (note !== kept) {
    kept = note;
    void ask("keepAlive", note ? JSON.parse(note) : { off: true }).catch((err) => log(`notification: ${err.message}`));
  }
}

/** The notification's Pause: disconnects, remembering how for its Resume, the notification (and its icon) kept. */
async function pause() {
  const s = controller.state();
  if (!s.active || s.busy) return;
  const was = { code: s.active, global: s.globalOn };
  await controller.disconnect();
  if (!controller.state().active) paused = was; // before push() runs: it would take the notification away
  controller.emit("change");
}

/** The notification's Resume, and the window's connect while paused (to `code`): connected as before, whole-system mode too. */
async function resume(code) {
  const was = paused;
  if (!was) return;
  await controller.connect(code ?? was.code);
  if (was.global && controller.state().active) await controller.toggleGlobal();
}
controller.on("change", () => (timer ??= setTimeout(push, 50)));
setInterval(() => shown && controller.emit("change"), 1000);
let lines = [];
controller.on("log", (line) => {
  if (lines.push(line) > 1) return; // a batch is already on its way
  setTimeout(() => {
    send({ t: "log", lines });
    lines = [];
  }, 150);
});

function handle(msg) {
  switch (msg.t) {
    case "act": // the window's, through the app
      if (!ACTIONS.has(msg.name)) return send({ t: "reply", id: msg.id, error: `no such action: ${msg.name}` });
      return void Promise.resolve()
        .then(() => {
          const args = Array.isArray(msg.args) ? msg.args : [];
          if (msg.name === "state") return view();
          // paused from the notification: the power button, or a country picked, resumes as its Resume does
          if (paused && (msg.name === "power" || msg.name === "connect")) return resume(args[0]);
          return controller[msg.name](...args);
        })
        .then((v) => send({ t: "reply", id: msg.id, v: v ?? null }), (err) => send({ t: "reply", id: msg.id, error: err.message }));
    case "answer": {
      const a = asked.get(msg.id);
      asked.delete(msg.id);
      return msg.error ? a?.reject(new Error(msg.error)) : a?.resolve(msg.v);
    }
    case "signedIn":
      return saveSession(msg.account ?? {});
    case "vpnStopped": // Android took the VPN down: the user, or another VPN app
      return vpn?.exit("another VPN app, or Settings");
    // the notification's buttons (FoxholeService)
    case "pause":
      return void pause();
    case "resume":
      return void resume();
    case "disconnect": // paused, the notification just goes
      paused = null;
      controller.emit("change");
      return void controller.disconnect();
    case "ui": // the app came to the screen or left it
      shown = !!msg.on;
      if (shown) controller.openSettings(); // e.g. back from Settings, where the certificate was installed
      return;
  }
}

let buf = "";
app.setEncoding("utf8");
app.on("data", (chunk) => {
  buf += chunk;
  for (let i; (i = buf.indexOf("\n")) >= 0; ) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    try {
      if (line) handle(JSON.parse(line));
    } catch (err) {
      log(`app: ${err.message}`);
    }
  }
});
app.on("error", (err) => log(`app: ${err.message}`));

// Node's own exit would end the whole app (and its VPN): a stray error is logged instead
process.on("uncaughtException", (err) => log(`error: ${err.stack ?? err.message}`));
process.on("unhandledRejection", (err) => log(`error: ${err?.stack ?? err}`));

controller.start().catch((err) => log(`couldn't start: ${err.stack ?? err.message}`));
updater.start();
