// Foxhole's core on a phone: the desktop app's Controller (gui/controller.js) in the Node the app starts (Core.kt on
// Android, FoxholeModule.mm on iOS), its window the same page in a WebView. One socket to the app carries lines of JSON
// both ways: the window's actions and their answers, the state and the log out; and what only the phone does (its VPN,
// clipboard, sign-in page), asked of the app.
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Controller } from "./controller.js";
import { Updater } from "./updater.js";
import { publicIp } from "./dist/netinfo.js";
import { caPem, loadCa } from "./dist/mitm.js";
import { useFastlyFallback } from "./dist/dns.js";
import { currentSplit, appOf } from "./dist/split.js";
import { PageSignIn } from "./dist/fxalogin.js";
import { log } from "./dist/log.js";
import "./fa.js"; // foxholeCountry, foxholeWords: for Settings → Language (prepare.mjs copies them from gui/renderer)
import "./ru.js";

net.setDefaultAutoSelectFamilyAttemptTimeout(3000); // as cli.ts: far VPN servers take 600-900 ms to answer
useFastlyFallback(); // where the network drops Fastly's addresses Mozilla's hosts get (dns.ts)

// iOS's Node runs V8 without JIT, so without WebAssembly, which Node 18's fetch() reads HTTP with (undici): there the
// core's fetch() goes over node:http(s), as guardian.ts's directRequest() does, following redirects as fetch() does
// (Apps Script answers the relay's POST with a 302)
if (typeof WebAssembly === "undefined")
  globalThis.fetch = function request(url, { method = "GET", headers, body, signal } = {}, hops = 0) {
    const u = new URL(url);
    return new Promise((resolve, reject) => {
      const req = (u.protocol === "http:" ? http : https).request(u, { method, headers, signal }, (res) => {
        const status = res.statusCode;
        if (res.headers.location && [301, 302, 303, 307, 308].includes(status) && hops < 20) {
          res.resume();
          const get = (status === 303 && method !== "HEAD") || (status < 303 && method === "POST");
          const to = new URL(res.headers.location, u);
          const init = { method: get ? "GET" : method, headers: to.origin === u.origin ? headers : undefined, body: get ? undefined : body, signal };
          return resolve(request(to, init, hops + 1));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c)).on("error", reject).on("end", () => {
          try {
            const all = new Headers();
            for (let i = 0; i < res.rawHeaders.length; i += 2) all.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
            resolve(new Response(chunks.length ? Buffer.concat(chunks) : null, { status, headers: all }));
          } catch (err) {
            reject(err); // a status or header Response refuses
          }
        });
      });
      req.on("error", reject).end(body);
    });
  };

// What the window may ask for, as gui/main.js (less the desktop's own: relaunch, an update to install by hand)
const ACTIONS = new Set([
  "update", "restartToUpdate",
  "state", "power", "connect", "disconnect", "toggleGlobal", "retryOffline", "cancelOffline", "connectAnyway",
  "setShare", "setLang", "setPort", "setLogin", "setRelay", "checkRelay", "relaySetup", "openSettings", "openSplit", "appIcons", "traffic", "hideSite", "setSplitDefault", "setSmart", "checkSite", "shareOpen", "importCheck", "importSettings", "newsShown", "setNetRule", "addRule", "toggleRule", "removeRule",
  "logs", "copy", "copyLogs", "reloadList",
  "addAccount", "useAccount", "removeAccount", "refreshAccounts", "dismissLow", "retrySignIn", "checkEntitled", "tvWait", "tvFind", "tvSend", "showWifiName",
  "trustCa", "untrustCa", "dismissTrust",
  "disguise", // the phone's own: Look like a calculator
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

/**
 * Split tunneling's apps, as Android's VPN takes them (its packages): `skip` stay out of it; `only`, when any, are the
 * only ones in it (everything else direct, some apps via VPN). Pure.
 */
function vpnApps(split) {
  const apps = (via) => split.rules.filter((r) => r.via === via && appOf(r.match) !== null).map((r) => appOf(r.match));
  return split.default === "vpn" ? { skip: apps("direct"), only: [] } : { skip: [], only: apps("vpn") };
}

let vpn = null; // whole-system mode's session while Android's VPN is up: told when Android stops it
/** Android's VPN for whole-system mode, as GlobalSession: it sends all apps' connections to the proxy (but this app's own, and split tunneling's direct apps). */
function globalSession({ proxyPort }) {
  let exited = () => {};
  let apps = "";
  const up = () => ((apps = JSON.stringify(vpnApps(currentSplit()))), ask("vpnStart", { port: proxyPort, ...JSON.parse(apps) }));
  const session = {
    async start() {
      await up();
      vpn = session;
    },
    async stop() {
      if (vpn === session) vpn = null;
      await ask("vpnStop");
    },
    onExit: (cb) => (exited = cb),
    onNetworkChange() {}, // Android moves the VPN to the new network itself
    async addServer() {}, // the proxy's own connections are outside the VPN: nothing to pin
    // direct sites go direct from the proxy, outside the VPN; a change of apps needs Android's VPN made again
    splitChanged() {
      if (vpn === session && JSON.stringify(vpnApps(currentSplit())) !== apps) void up().catch((err) => log(`apps: ${err.message}`));
    },
    // through the proxy: this app's own connections don't go through its VPN
    verifyExitIp: (relay) => publicIp({ host: "127.0.0.1", port: proxyPort }, 3, relay),
    exit(why) {
      vpn = null;
      exited(why);
    },
  };
  return session;
}

// iOS installs a certificate from Safari only: the app opens it there, served from here
let caServed = null;
const caUrl = () =>
  (caServed ??= new Promise((resolve) => {
    const server = http.createServer((_, res) => res.writeHead(200, { "content-type": "application/x-x509-ca-cert" }).end(loadCa().pem));
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}/foxhole-relay-ca.crt`));
  }));

// a new version on GitHub: on Android the APK, downloaded here, checked and installed by the app (Phone.kt); on iOS the
// window links to the releases page (target null: no update in place)
const apk = process.platform === "android" && {
  kind: "apk",
  check: (file, version) => ask("apkCheck", { path: file, version }),
  open: (file) => ask("apkInstall", { path: file }),
};
// The app's sign-in page (App.tsx): what it hands over, kept till Mozilla has confirmed it (fxalogin.ts PageSignIn),
// then added to the accounts and in use; once it's signed in with, the page is put away.
let page = null;
const newPage = () => new PageSignIn((account) => controller.signedIn(account));
function openSignIn() {
  void page?.closed(); // one opened before, its page lost unclosed (the app's screen made anew): looked at once more
  page = newPage();
  send({ t: "signIn" });
}

// what this device is: a TV (Android TV) signs in from another device (tvpair.ts); its name is shown on both
const device = {};
const deviceKnown = process.platform === "android" ? ask("device").then((d) => (Object.assign(device, d), controller.emit("change")), () => {}) : Promise.resolve();
const updater = new Updater({ dir: join(homedir(), "update"), downloads: join(homedir(), "apk"), target: apk || null, ways: () => controller.updateWays(), changed: () => controller.emit("change") });
const controller = new Controller({
  copy: (text) => void ask("copy", { text }).catch(() => {}),
  updates: updater,
  android: { // the phone's part (iOS's too), and a TV's
    get tv() {
      return !!device.tv;
    },
    get name() {
      return typeof device.name === "string" ? device.name : "";
    },
    openSignIn, // its session comes back as "signedIn"
    globalSession,
    apps: () => ask("apps"), // split tunneling's: [{ id: its package, name }] (Phone.kt)
    network: () => ask("network").catch(() => null),
    // Settings → On this network (controller.js #joined): paused there as the notification's Pause does, so Foxhole
    // keeps running to see the phone leave it
    netPaused: () => !!paused?.net,
    pause: (net) => pause(net),
    resume: () => resume(),
    connect: () => connect(),
    wifiAccess: () => ask("wifiAccess"), // Android's question for the Wi-Fi's name (Phone.kt)
    caTrusted: () => (caPem() ? ask("caTrusted", { pem: caPem() }).catch(() => false) : Promise.resolve(false)),
    setCaTrust: async (add) =>
      ask(add ? "caInstall" : "caRemove", { pem: add ? loadCa().pem : caPem(), url: add && process.platform === "ios" ? await caUrl() : undefined }),
  },
});

// The state to the window at most every 50 ms, and each second while it's on screen (split tunneling's counts climb);
// the notification that keeps Foxhole running while connected (or paused, to resume from it) follows it.
let shown = true; // the app is on screen
let timer = null;
let kept = "";
let told = ""; // the tile's and the widget's status, as last sent (Status.kt)
let paused = null; // paused from the notification: { code, global, net? }, what its Resume connects to again (net: by that network's rule)

// The mode last picked in the window, Proxy only or Whole system: connecting goes back to it, after a restart too.
// iOS has no whole-system mode; a TV has nothing else (nothing on it can be set to use a proxy): see global().
const MODE = join(homedir(), "mode");
let wantGlobal = process.platform === "android" && (() => {
  try {
    return readFileSync(MODE, "utf8") === "global";
  } catch {
    return true; // nothing picked yet
  }
})();
function saveMode(global) {
  if (global === wantGlobal) return;
  wantGlobal = global;
  try {
    writeFileSync(MODE, global ? "global" : "proxy");
  } catch (err) {
    log(`mode: ${err.message}`);
  }
}

/** Whole-system mode wanted: the mode last picked, and always on a TV. */
const global = () => wantGlobal || !!device.tv;

/**
 * The power button or a country picked while off: connects in the mode last picked. A TV left in proxy mode (Android's
 * VPN refused) disconnects. With no internet it waits for it, then connects (controller.js #wait).
 */
async function connect(code) {
  await controller.connect(code, { again: () => connect(code) });
  const s = controller.state();
  if (global() && s.active && !s.globalOn) await controller.toggleGlobal();
  if (device.tv && controller.state().active && !controller.state().globalOn) await controller.disconnect();
}

/** The window's Proxy only / Whole system: switched while on; while off, only remembered for the next connect. A TV has no switch. */
async function setMode() {
  if (device.tv) return;
  if (!controller.state().active) return saveMode(!wantGlobal);
  await controller.toggleGlobal();
  const s = controller.state();
  if (s.active) saveMode(s.globalOn); // what it is now: Android's VPN refused leaves the proxy
}

/** The state, with the notification's pause in it (the window says so), and the mode to show while off. */
function view() {
  const s = controller.state();
  if (s.active) paused = null; // connected again: by Resume, or in the app
  return { ...s, paused, wantGlobal: global(), disguise: device.disguise ?? null };
}

/** Settings → Look like a calculator (Disguise.kt): disguised, opened with `code`; or null, Foxhole again. */
async function disguise(code) {
  await ask("disguise", { code: code ?? null });
  device.disguise = code ?? null;
  controller.emit("change");
  return true;
}

function push() {
  timer = null;
  const s = view();
  if (shown) send({ t: "state", s });
  if (page?.given && s.auth?.stage === "ready") {
    page = null; // signed in with what the sign-in page handed over: it's done
    send({ t: "signIn", open: false });
  }
  const t = foxholeWords(s.settings?.lang);
  // in the language Settings has (no Intl here for country names: fa.js and ru.js have them); the relay's row is "Relay"
  const place = (code) => foxholeCountry(s.settings?.lang, code) || (s.countries.find((c) => c.code === code)?.name ?? "");
  // with no internet: connected, it carries on by itself once it's back (s.lost); a connect waits for it (s.offline),
  // kept running meanwhile, its Resume a Try again and its Disconnect a Cancel
  const note = s.active
    ? JSON.stringify({
        title: `${s.globalOn ? t`Whole system` : t`Proxy`} · ${place(s.global ?? s.active)}`,
        text: s.lost === "cut" ? t`International internet cut off · reconnects by itself once it's back` : s.lost ? t`Offline · reconnects by itself once you're back online` : s.proxy ? `${s.proxy.addr} · SOCKS5 + HTTP` : "",
      })
    : s.offline
      ? JSON.stringify({
          title: s.offline.code ? `${t`Waiting for the internet`} · ${place(s.offline.code)}` : t`Waiting for the internet`,
          text: s.offline.why === "cut" ? t`International internet cut off · connects by itself once it's back` : t`Offline · connects by itself once you're back online`,
          paused: true,
        })
    : paused
      ? JSON.stringify({
          title: `${s.connecting ? t`Connecting…` : t`Paused`} · ${place(paused.code)}`,
          text: s.connecting ? "" : paused.net ? t`On ${paused.net}: back on when you leave it` : paused.global ? t`Apps go direct until you resume` : t`The proxy is off until you resume`,
          paused: true,
        })
      : "";
  if (process.platform === "android") {
    const u = s.usage;
    const status = JSON.stringify({
      on: !!s.active,
      busy: !!s.connecting || !!s.offline, // waiting for the internet to connect: a tap cancels it
      paused: !!paused,
      where: place(s.active ? (s.global ?? s.active) : (s.connecting ?? s.offline?.code ?? paused?.code)),
      left: !u ? "" : u.unlimited ? t`Unlimited` : t`${u.left} left`,
      fraction: !u ? -1 : u.unlimited ? 1 : u.fraction,
      signedIn: s.auth?.stage === "ready",
      lang: s.settings?.lang ?? "en", // the tile's, widget's and notification buttons' own words (Status.kt words)
    });
    if (status !== told) {
      told = status;
      void ask("status", JSON.parse(status)).catch((err) => log(`status: ${err.message}`));
    }
  }
  // after the status: the notification's buttons are in its language
  if (note !== kept) {
    kept = note;
    void ask("keepAlive", note ? JSON.parse(note) : { off: true }).catch((err) => log(`notification: ${err.message}`));
  }
}

/** The notification's Pause (or a network's rule, `net`): disconnects, remembering how for its Resume, the notification (and its icon) kept. */
async function pause(net) {
  const s = controller.state();
  if (!s.active || s.busy) return;
  const was = { code: s.active, global: s.globalOn, ...(net && { net }) };
  await controller.disconnect();
  if (!controller.state().active) paused = was; // before push() runs: it would take the notification away
  controller.emit("change");
}

/** The notification's Resume, and the window's connect while paused (to `code`): connected as before, whole-system mode too. */
async function resume(code) {
  const was = paused;
  if (!was) return;
  await controller.connect(code ?? was.code, { again: () => resume(code) });
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
          if (msg.name === "update") return updater.update(); // resolves once it's ready (true) or the try failed
          if (msg.name === "restartToUpdate") return void updater.install();
          // paused from the notification: the power button, or a country picked, resumes as its Resume does
          if (paused && (msg.name === "power" || msg.name === "connect")) return resume(args[0]);
          if (msg.name === "toggleGlobal") return setMode();
          if (msg.name === "disguise") return disguise(args[0]);
          if ((msg.name === "power" || msg.name === "connect") && !controller.state().active) return connect(args[0]);
          return controller[msg.name](...args);
        })
        .then((v) => send({ t: "reply", id: msg.id, v: v ?? null }), (err) => send({ t: "reply", id: msg.id, error: err.message }));
    case "answer": {
      const a = asked.get(msg.id);
      asked.delete(msg.id);
      return msg.error ? a?.reject(new Error(msg.error)) : a?.resolve(msg.v);
    }
    case "signedIn": // the app's sign-in page's session (App.tsx), confirmed or with a code from the email to type
      return (page ??= newPage()).login(msg.account);
    case "signInDone": // the page's last step: the sign-in's confirmed
      return page?.confirmed();
    case "signInClosed": { // closed first: Mozilla's asked once more
      const closing = page;
      return void closing?.closed().finally(() => page === closing && !closing.given && (page = null));
    }
    case "vpnStopped": // Android took the VPN down: the user, or another VPN app
      return vpn?.exit("another VPN app, or Settings");
    // the notification's buttons (FoxholeService)
    case "pause":
      return void pause();
    case "resume": // waiting for the internet: a look at once
      return void (controller.state().offline ? controller.retryOffline() : resume());
    case "tile": // Quick Settings' tile (FoxholeTile.kt), maybe as it started the core: once it's ready, as the power button
      return void started
        .then(() => (paused ? resume() : connect()))
        .catch((err) => log(`tile: ${err.message}`))
        .finally(() => ((told = ""), push())); // the tile shows "Connecting…" till it hears
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
process.on("unhandledRejection", (err) => {
  // but undici's own, on iOS: loaded for Response and Headers, its HTTP reader (unused there: fetch() above) can't be
  if (err instanceof ReferenceError && err.message === "WebAssembly is not defined") return;
  log(`error: ${err?.stack ?? err}`);
});

const started = deviceKnown.then(() => controller.start()); // signed in, and the locations listed
started.catch((err) => log(`couldn't start: ${err.stack ?? err.message}`));
updater.start();
