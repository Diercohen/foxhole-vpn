// The desktop app's state and actions, on the same modules as the TUI (src/tui.ts, which this
// follows step by step): the main process owns them, the window shows state() and asks for actions.
import { EventEmitter } from "node:events";
import { hostname } from "node:os";
import { readFile } from "node:fs/promises";
import { findAccount, openBrowser, macApp } from "./dist/profile.js";
import { fetchServerList } from "./dist/serverlist.js";
import { Connection, RELAY_CODE } from "./dist/connection.js";
import { FirefoxAuth, RefreshAuth, StaticAuth, destroyToken } from "./dist/auth.js";
import { askTv, findTvs, parseTvLink, sendToTv, waitForSignIn } from "./dist/tvpair.js";
import { qrSvgPath } from "./dist/qr.js";
import { SHARE_PORT, serveShare, shareData, shareLink, parseShared, sharedWhat, importPlan } from "./dist/share.js";
import { newNotice, noticeShown, onHot, refreshHot } from "./dist/hot.js";
import { FIREFOX, LOW_DATA, authFor, loadAccounts, peekFirefox, saveAccounts, signOut, withFirefox, withOwn, without } from "./dist/accounts.js";
import { fetchEntitlement, fetchUsage } from "./dist/guardian.js";
import { GuardianError, GuardianBlocked, useRelay } from "./dist/guardian.js";
import { loadRelay, relayUrl } from "./dist/httprelay.js";
import { STEPS, KEY_PLACEHOLDER, relayTemplate, highlightJs, deploymentId } from "./dist/relaysetup.js";
import { network, publicIp, lanIp, firewallHint } from "./dist/netinfo.js";
import { helperFor, helperInstalled, helperReady } from "./dist/helper.js";
import { loadSettings, saveSettings, proxyHost, validPort, loginFor, telegramLink, onJoin, ruleable, withNetRule } from "./dist/settings.js";
import { startTokenReceiver, loadSavedToken, saveToken, forgetToken, tokenProblem } from "./dist/tokenserver.js";
import { startProxy, onProxyWarning, checkSite, netState, onNetState } from "./dist/proxy.js";
import { startSmartDns, smartDnsHost, smartDnsProblem } from "./dist/smartdns.js";
import { log, logLines, onLog } from "./dist/log.js";
import { useSplit, splitSummary, parseRule, parseSite, appOf, wayOf, hits, recentSites, SMART } from "./dist/split.js";
import { traffic, runsOut, sizeOf } from "./dist/traffic.js";
import { knownBlocked, sanctioned, verdictOf, verdictText, tryText, wantOf } from "./dist/smart.js";
import { listApps } from "./dist/apps.js";
import { GlobalSession, sudoPriv, adminPriv, isPrivileged, validateSudo, sudoUsesTouchId, touchIdSudo, ensureTun2socks, dialHost } from "./dist/global.js";
import { VERSION } from "./dist/update.js";
import { countryName, gb, shortDate } from "./dist/ui.js";
import { order, loadLastCountry, saveLastCountry } from "./dist/tui.js";
import { relayCheck, relayVerdict, relayStats, onRelayNotice, onRelaySplit } from "./dist/relaymode.js";
import { caTrusted, setCaTrust, envLines } from "./dist/catrust.js";
import { loadCa } from "./dist/mitm.js";

const SYNC = "about:preferences#sync"; // Firefox's own sign-in: the VPN needs the browser signed in, not a website
const flip = (v) => (v === "vpn" ? "direct" : "vpn");
const label = (c) => countryName(c.code, c.name);
/** The Relay "location", first in the list once a relay is set up: the web through the user's own Apps Script (relaymode.ts). */
const RELAY_ROW = { code: RELAY_CODE, name: "Relay", locked: false, available: true, servers: [] };
/** No relay on a phone (the user's call): it's never set up there, so it carries nothing and isn't offered. */
const NO_RELAY = process.platform === "android" || process.platform === "ios";
// Smart DNS (smartdns.ts) needs ports 53, 443 and 80, which a phone's apps can't have
const SMART_DNS = ["darwin", "win32", "linux"].includes(process.platform);
/** Split tunneling by app: a computer's proxy finds each connection's app (apps.ts), Android's VPN leaves apps out or takes only some; iOS can't tell apps apart. */
const APPS = process.platform !== "ios";

/** Data left, as the window shows it. */
const usageView = (u) =>
  !u ? null
    : u.unlimited ? { unlimited: true }
    : { left: gb(u.remaining), max: gb(u.max), reset: u.reset ? shortDate(u.reset) : null, fraction: u.max ? Number((u.remaining * 1000n) / u.max) / 1000 : 0, runsOut: runsOutView(u) };

/** When the data left runs out at this month's rate, if before it resets (traffic.ts runsOut); else null. */
const runsOutView = (u) => {
  const d = runsOut(u.max, u.remaining, u.reset);
  return d ? shortDate(d) : null;
};

/** Two accounts' emails are the same one (Mozilla's are case-insensitive); an unknown one matches none. */
const sameEmail = (a, b) => !!a && !!b && a.toLowerCase() === b.toLowerCase();

export class Controller extends EventEmitter {
  #copy; // puts text on the clipboard
  #settings = loadSettings();
  #host = proxyHost(this.#settings);
  #port = this.#settings.port;
  #conn = null;
  #countries = [];
  #blocked = 0; // times vpn.mozilla.org was found blocked here: the window says so (with the relay's setup) as it goes up
  #blockedTold = false; // said once already: a background check doesn't say it again, a connect does
  #listError = null;
  #selected = loadLastCountry(); // where the power button connects
  #proxy = null;
  #proxyAt = ""; // the address the running proxy was started on
  #proxyStale = false; // the running proxy still has the old address (changed during global mode)
  #active = null;
  #global = null;
  #leavingGlobal = false; // whole-system mode is being taken down
  #globalCountry = null;
  #tun2socksPath = null;
  #busy = false;
  #connecting = null; // the country being connected to
  #message = null; // { tone: info | ok | warn | error, text, id }
  #notice = null; // { text, id }: the window shows it as an alert (an account already on the list)
  #auth = { stage: "checking" };
  #email = null;
  #net; // undefined: not read yet
  #netPaused = null; // the location a network's rule paused (Settings → On this network), connected again on leaving it
  #ip; // undefined: checking
  #ipNote = "";
  #netSeq = 0; // drops answers from an older check
  #pw = null; // the administrator password popup: { error, checking, for: global | trust | untrust }
  #trustAsk = false; // the window asks to trust foxhole's certificate (relay mode)
  #caOk; // whether this computer trusts it; undefined: not checked yet
  #fwHint = null;
  #smartDns = null; // the home's DNS server, while Settings has it on and the account's signed in (smartdns.ts)
  #smartDnsAt = null; // the address it listens on
  #smartDnsError = null;
  #smartDnsYields = false; // a Mac's whole-system mode has port 53 for its own DNS relay
  #smartDnsTurn = Promise.resolve(); // one start or stop at a time
  #settingsNote = null;
  #splitNote = null;
  #apps = []; // split tunneling's apps to pick from: [{ id, name }] (on Android the id is its package)
  #appsLoading = false; // being looked up: the picker says so, not "no apps"
  #icons = new Map(); // their icons, by id: data: URLs (null: none), asked for by the window apart from the state (appIcons)
  #fileIcon; // the desktop app's: an .app's or .exe's icon as a data: URL (Electron draws it)
  #restoring = false;
  #receiver = null;
  #accounts = loadAccounts(); // accounts.js: the list, and the one in use
  #gen = 0; // the account choice's: a change ends the sign-in's wait, which starts over with the new one
  #signing = null; // the sign-in under way
  #tokenSource = null; // the account in use's token source
  #entitled = null; // whether the account in use may use the VPN (null: not known yet)
  #switchTo = null; // an account picked (useAccount), until it's signed in with
  #switched = 0; // counts the switches done: the window closes Settings on each
  #unentitledAsk = 0; // counts the times it's found not to: each shows the window's how-to again
  #tvIn = null; // a TV's wait for a sign-in from another device (tvpair.ts): a promise of it
  #tvHandle = null; // ...and the wait itself, once it's started
  #tvError = null; // why it couldn't wait
  #tvQr = null; // { link, qr }: its QR code, drawn once per link
  #tgQr = null; // { link, qr }: Telegram's link to this proxy for other devices (sharing on), drawn once per link
  #share = null; // the Share dialog's page on the local network, while it's open (share.ts): a promise of its server
  #shareRelay = false; // its link carries the relay too
  #shareError = null; // why the page couldn't be served
  #shareQr = null; // { url, qr }: its QR code, drawn once per link
  #tvsFound = []; // the TVs found waiting on this device's network (tvFind), for a code typed
  #firefoxEmail = null; // Firefox's sign-in's, once read (peekFirefox: where reading it asks nothing)
  #others = new Map(); // an account's id → { usage, error }: the data left of those not in use (refreshAccounts)
  #openSignIn; // opens Foxhole's own Mozilla sign-in: the desktop's window (gui/main.js), the phone's page
  #updates; // updater.js: a new version of the app
  /**
   * On a phone (mobile/node/main.mjs), what it does in place of the desktop's ways; null elsewhere: openSignIn() its
   * own Mozilla sign-in, whose session comes back by signedIn(); globalSession() Android's VPN, with GlobalSession's methods; network();
   * caTrusted() and setCaTrust(add), relay mode's certificate in Android's store (setCaTrust says what's left to do);
   * tv: it's a TV (Android TV), which signs in from another device (tvWait); name: the device's.
   */
  #android;

  constructor({ copy, updates, android = null, openSignIn = null, fileIcon = null }) {
    super();
    this.#fileIcon = fileIcon;
    this.#copy = copy;
    this.#updates = updates;
    this.#android = android;
    this.#openSignIn = openSignIn ?? android?.openSignIn ?? null;
    this.#firefoxEmail = peekFirefox();
  }

  #network = () => (this.#android?.network ?? network)();
  #caTrusted = () => (this.#android?.caTrusted ?? caTrusted)();

  /** connect: to the last location, on a start at login or a restart (opened by hand, it waits for the user); global: going on to whole-system mode. */
  async start({ connect = false, global = false } = {}) {
    useRelay(this.#relay()); // where vpn.mozilla.org is blocked, relay Guardian's control calls (httprelay.ts)
    useSplit(() => this.#settings.split); // live: a change applies to the next connection
    onLog(() => this.emit("log", logLines[logLines.length - 1]));
    onProxyWarning((msg) => this.#say("error", `proxy: ${msg}`));
    onNetState((said) => this.#say(said ? "error" : "ok", said ?? "the internet is back")); // cut off or offline while connected
    onRelayNotice((msg) => this.#say("warn", msg));
    onRelaySplit((split) => this.#saveSplit(split)); // a bot-check page's "Open it directly"
    onHot(() => this.#changed()); // its notice, for the window to show
    void refreshHot(); // the network's newest fixes (hot.ts), before Mozilla's hosts are needed
    void this.#caTrusted().then((ok) => ((this.#caOk = ok), this.#changed()));
    const list = this.reloadList(); // needs no login: ready once the sign-in is
    this.#refreshNet();
    // A network switch changes the public IP too; the LAN address catches switches the name can't show.
    let lan = lanIp();
    setInterval(() => {
      void this.#network().then((n) => {
        const was = lan;
        lan = lanIp();
        if (this.#net !== undefined && (n !== this.#net || lan !== was)) this.#refreshNet();
      });
    }, 5000).unref();
    await this.#resignIn();
    await list;
    if (connect && this.#rows().some((c) => c.code === loadLastCountry())) void this.connect(loadLastCountry()).then(() => global && this.#active && this.toggleGlobal());
    setInterval(() => (this.#refreshUsage(), this.#entitled === false && this.#checkEntitled(false)), 3 * 60_000).unref();
  }

  /** Signs in (again) with the account in use, ending a sign-in still waiting for the one before. */
  #resignIn() {
    this.#gen++;
    return (this.#signing ??= this.#signIn().finally(() => (this.#signing = null)));
  }

  /** The VPN token from the account in use, then the Connection on it (the proxy carries on through it); the window shows what's needed meanwhile. */
  async #signIn() {
    for (;;) {
      const gen = this.#gen;
      this.#auth = { stage: "checking" };
      this.#entitled = null;
      this.#changed();
      const auth = await this.#ensureAuth(gen);
      if (gen !== this.#gen) continue; // another account picked meanwhile
      if (this.#conn) this.#conn.setAuth(auth);
      else this.#conn = new Connection(auth);
      this.#email = this.#currentEmail();
      this.#auth = { stage: "ready" };
      this.#followSmartDns();
      this.#tokenSource = auth;
      if (this.#switchTo === this.#accounts.current) {
        this.#switchTo = null;
        this.#switched++;
        this.#say("ok", `switched to ${this.#email ?? "Firefox's account"}`);
      }
      this.#refreshUsage();
      void this.#checkEntitled();
      this.#changed();
      return;
    }
  }

  #currentEmail() {
    const a = this.#accounts;
    return a.current === FIREFOX ? this.#firefoxEmail : (a.own.find((x) => x.uid === a.current)?.email ?? null);
  }

  /** A token source for the account in use, once there's one that works; null if the choice changed meanwhile. */
  async #ensureAuth(gen) {
    for (let error = ""; gen === this.#gen; ) {
      const a = this.#accounts;
      if (!a.current) {
        // none yet (a first start, or all removed): how to sign in. Firefox's account named where reading it asks nothing
        this.#auth = { stage: "choose", firefox: this.#android ? null : { email: peekFirefox() }, error };
        this.#changed();
        await this.#until(() => false, gen);
        continue;
      }
      if (a.current === FIREFOX) return this.#firefoxAuth(gen);
      const auth = authFor(a, a.current);
      try {
        await auth.getAccessToken(AbortSignal.timeout(15_000));
        return auth;
      } catch (err) {
        const email = this.#currentEmail();
        // signed out elsewhere, or expired: signing in again brings it back (or another account)
        this.#switchTo = null; // it didn't take: no "switched" when it's signed in to again
        if (err.errno === 110) this.#auth = { stage: "expired", email, id: a.current };
        else this.#auth = { stage: "offline", email, error: `Couldn't get the VPN's token: ${err.message}` }; // tried again in a while
        this.#changed();
        const since = Date.now();
        await this.#until(() => this.#auth.stage === "offline" && Date.now() - since > 20_000, gen);
      }
    }
    return null;
  }

  /** As cli.ts's ensureAuth: Firefox's session, else a saved token, else waits for a sign-in or the Browser Console. */
  async #firefoxAuth(gen) {
    while (gen === this.#gen) {
      const errors = [];
      const account = findAccount();
      if (account?.signedIn) {
        this.#firefoxEmail = account.email;
        const auth = new FirefoxAuth(account);
        try {
          await auth.getAccessToken(AbortSignal.timeout(15_000));
          return auth;
        } catch (err) {
          // no answer (offline, a timeout): the login is fine, so try again in a while rather than the Browser Console
          if (["TypeError", "TimeoutError", "AbortError"].includes(err.name)) {
            const cause = err.cause?.code ?? err.cause?.message;
            this.#auth = { stage: "offline", email: account.email, error: `Couldn't get the VPN's token: ${err.message}${cause ? ` (${cause})` : ""}` };
            this.#changed();
            const since = Date.now();
            await this.#until(() => Date.now() - since > 20_000, gen);
            continue;
          }
          errors.push(`Couldn't get a token from your Firefox login: ${err.message}`);
        }
      }
      const saved = loadSavedToken();
      if (saved) {
        const problem = await tokenProblem(saved);
        if (!problem) return new StaticAuth(saved);
        forgetToken();
        errors.push(`Your saved token ${problem}.`);
      }
      if (account?.blocked) {
        // macOS won't let the app read Firefox's profile: the window says how to allow it (Full Disk Access)
        this.#auth = { stage: "blocked", error: account.blocked.message, app: macApp() }; // app: the one macOS asks about
        this.#changed();
        await this.#until(() => !findAccount()?.blocked, gen); // allowed without a restart: carry on
        continue;
      }
      if (account?.signedIn) return this.#captureToken(errors.join("\n"), gen);
      // Signed out: the sign-in is all it takes, as the token then comes from that login.
      openBrowser(SYNC);
      this.#auth = { stage: "signin", error: errors.join("\n") };
      this.#changed();
      await this.#until(() => findAccount()?.signedIn, gen);
    }
    return null;
  }

  /** Signed in, but the login gave no token: the Browser Console snippet posts one to a loopback receiver. */
  async #captureToken(error, gen) {
    const rec = (this.#receiver = await startTokenReceiver(2 ** 31 - 1)); // no timeout: the window waits
    this.#copy(rec.snippet);
    this.#auth = { stage: "console", error, email: this.#firefoxEmail, snippet: rec.snippet };
    this.#changed();
    const token = await Promise.race([rec.token, this.#until(() => false, gen)]);
    this.#receiver = null;
    if (!token) {
      rec.close(); // another account picked
      return null;
    }
    saveToken(token);
    return new StaticAuth(token);
  }

  /** Resolves once `ok()` holds (checked every second), or the account choice changes (`gen` given). */
  #until(ok, gen) {
    return new Promise((resolve) => {
      const timer = setInterval(() => {
        if (!ok() && (gen === undefined || gen === this.#gen)) return;
        clearInterval(timer);
        resolve();
      }, 1000);
    });
  }

  /** Opens Firefox's sign-in again. */
  openFirefox() {
    openBrowser(SYNC);
  }

  /** Copies the Browser Console snippet again. */
  copySnippet() {
    if (this.#auth.snippet) this.#copy(this.#auth.snippet);
  }

  // ── Accounts (accounts.js) ─────────────────────────────────────────────────────────────────

  #saveAccounts(next) {
    this.#accounts = next;
    try {
      saveAccounts(next);
    } catch (err) {
      this.#say("error", `couldn't save the accounts: ${err.message}`);
    }
  }

  /**
   * Whether the account in use may use the VPN: Mozilla answers 403 until it's turned on once, in Firefox signed in to
   * it (the VPN button in the toolbar, then Get started). Not: the window shows how (`tell`: again, if it's put away).
   */
  async #checkEntitled(tell = true) {
    const auth = this.#tokenSource, gen = this.#gen;
    let ok;
    try {
      ok = !!(await fetchEntitlement(await auth.getAccessToken(AbortSignal.timeout(15_000)), AbortSignal.timeout(15_000)));
    } catch (err) {
      if (!(err instanceof GuardianError && err.status === 403)) return; // offline, blocked: not known
      ok = false;
    }
    if (gen === this.#gen) this.#setEntitled(ok, tell);
  }

  #setEntitled(ok, tell) {
    if (!ok && tell) this.#unentitledAsk++;
    this.#entitled = ok;
    this.#changed();
  }

  /** The how-to's Check again: once it's turned on in Firefox, the window goes back to its colors. */
  async checkEntitled() {
    await this.#checkEntitled(false);
    this.#say(this.#entitled === false ? "error" : "ok", this.#entitled === false ? "the VPN isn't turned on for this account yet" : this.#entitled ? "the VPN is turned on for this account" : "couldn't check: try again in a moment");
  }

  // ── A TV's sign-in from another device (tvpair.ts) ──────────────────────────────────────────────────────────

  /** The TV's sign-in screen shown (on) or put away: meanwhile it waits for a sign-in from a computer or phone. */
  async tvWait(on) {
    if (!on) {
      const h = await this.#tvIn;
      this.#tvIn = this.#tvHandle = null;
      h?.stop();
      return this.#changed();
    }
    this.#tvError = null;
    this.#tvIn ??= waitForSignIn({
      name: this.#android?.name || "TV",
      host: () => lanIp(),
      accept: (account, from) => this.#tvAccept(account, from),
      changed: () => this.#changed(),
    }).then(
      (h) => ((this.#tvHandle = h), this.#changed(), h),
      (err) => {
        this.#tvIn = null;
        this.#tvError = err.code === "EADDRINUSE" ? "Another app on this TV is using Foxhole's sign-in port (47533)." : err.message;
        this.#changed();
        return null;
      },
    );
  }

  /** What another device sent: checked with Mozilla (the sender's told if it doesn't work), then added and in use. */
  async #tvAccept({ uid, email, refreshToken }, from) {
    await new RefreshAuth(refreshToken).getAccessToken(AbortSignal.timeout(15_000));
    await this.disconnect(); // as a switch of accounts does
    const old = this.#accounts.own.find((x) => x.uid === uid);
    this.#saveAccounts(withOwn(this.#accounts, { uid, email, refreshToken }));
    if (old) void signOut(old); // the sign-in it replaces
    this.#others.delete(uid);
    setTimeout(() => void this.tvWait(false)); // once the sender has its answer
    this.#alert(`You're signed in with ${email}${from ? `, sent from ${from}` : ""}, and it's the account in use now.`, "Signed in");
    void this.#resignIn();
  }

  /** Telegram's link that sets this proxy on another device, with its sign-in, and its QR code; null unless shared. */
  #telegram() {
    const s = this.#settings, lan = lanIp();
    if (!s.share || !lan) return null;
    const link = telegramLink(lan, s.port, loginFor(s, lan));
    if (this.#tgQr?.link !== link) this.#tgQr = { link, qr: qrSvgPath(link) };
    return this.#tgQr;
  }

  /**
   * The Share dialog opened (`relay`: its link carries the relay too, as ticked) or closed. While it's open, its page
   * is on the local network, for a phone's camera to open from its QR code: the app to download, the settings to take.
   */
  async shareOpen(on, relay) {
    if (on !== true) {
      const server = await this.#share;
      this.#share = null;
      this.#shareError = null;
      server?.close();
      return void this.#changed();
    }
    this.#shareRelay = relay === true;
    this.#shareError = null;
    // on Android its own APK (Core.kt), for a phone without Foxhole
    this.#share ??= serveShare({ name: this.#deviceName(), version: VERSION, apk: process.env.FOXHOLE_APK || null }).catch((err) => {
      this.#share = null;
      this.#shareError = err.code === "EADDRINUSE" ? `Another app here is using Foxhole's sharing port (${SHARE_PORT}).` : err.message;
      this.#changed();
      return null;
    });
    this.#changed();
  }

  /** The Share dialog's: its QR code (of the page, with the settings in it), the link to send elsewhere, what it shares. */
  #shareView() {
    if (!this.#share && !this.#shareError) return null;
    const s = this.#settings, lan = lanIp();
    const data = shareData(s, this.#shareRelay);
    const url = lan ? `http://${lan}:${SHARE_PORT}/${data ? `#${data}` : ""}` : null;
    if (this.#shareQr?.url !== url) {
      let qr = null;
      try {
        qr = url && qrSvgPath(url);
      } catch {
        /* too much for a QR code: the link is sent instead */
      }
      this.#shareQr = { url, qr };
    }
    return {
      error: this.#shareError,
      host: lan,
      qr: this.#shareQr.qr,
      link: data && shareLink(data),
      what: data ? sharedWhat(parseShared(data)) : [],
      apk: !!process.env.FOXHOLE_APK,
      relay: this.#shareRelay && !!s.relay,
      hasRelay: !!s.relay,
    };
  }

  /** What importing a shared settings link would change here (share.ts), a line each, to show first; throws if it isn't one. */
  importCheck(text) {
    return importPlan(this.#settings, this.#shared(text)).what;
  }

  /** Imports a shared settings link: its relay in place of this one, its sites with these rules (its own win), its switches on. */
  async importSettings(text) {
    const plan = importPlan(this.#settings, this.#shared(text));
    if (plan.split && !this.#saveSplit(plan.split)) throw new Error(this.#splitNote?.text ?? "Couldn't save.");
    if (plan.relay && (await this.#changeSetting({ relay: plan.relay })) !== true) throw new Error(this.#settingsNote?.text ?? "Couldn't save.");
    log(`settings imported: ${plan.what.join("; ")}`);
    return plan.what;
  }

  #shared(text) {
    const shared = parseShared(String(text ?? ""));
    if (!shared) throw new Error("That isn't a Foxhole settings link: copy all of it again.");
    return shared;
  }

  /** This device's name, as other devices are shown it (a TV signed in from here, the Share page). */
  #deviceName() {
    return this.#android?.name || hostname().replace(/\.local$/, "");
  }

  /** The TV's screen: its code and QR code (drawn once each), or why it can't wait. */
  #tvView() {
    if (!this.#tvHandle) return this.#tvError ? { error: this.#tvError } : null;
    const w = this.#tvHandle.waiting();
    if (w.link && this.#tvQr?.link !== w.link) this.#tvQr = { link: w.link, qr: qrSvgPath(w.link) };
    return { code: w.code, host: w.host, qr: w.link ? this.#tvQr.qr : null };
  }

  /**
   * The window's "Show the name" (the user was told why first): the system asked to show Foxhole the Wi-Fi's name
   * (Android's own question; Windows' Settings page). "allowed", "denied", "settings" (for the window to open), or on
   * Android "opened" (Settings is on screen) and "approximate" (the name needs Precise location).
   */
  async showWifiName() {
    const how = this.#android ? await this.#android.wifiAccess() : "settings"; // Windows has no question per desktop app
    this.#refreshNet();
    return how;
  }

  /** "Sign in a TV": the TVs waiting on this device's network. */
  async tvFind() {
    this.#tvsFound = await findTvs();
    return this.#tvsFound.map(({ host, name }) => ({ host, name }));
  }

  /**
   * Sends a TV a sign-in of the account `id` (a VPN-only one of its own: auth.ts refreshToken), to the TV in its QR
   * code's `link`, or to the one found waiting with the `code` typed. Resolves with the TV's name.
   */
  async tvSend({ code, link } = {}, id = this.#accounts.current) {
    let tvs;
    if (link) {
      const tv = parseTvLink(link);
      if (!tv) throw new Error("That QR code isn't a Foxhole TV's.");
      const there = await askTv(tv);
      if (!there) throw new Error(`Can't reach the TV at ${tv.host}: is this ${this.#android ? "phone" : "computer"} on the TV's Wi-Fi?`);
      if (there.pub !== tv.pub) throw new Error("That QR code is an old one: the TV shows a new one now.");
      tvs = [{ ...tv, name: there.name }];
    } else {
      if (!this.#tvsFound.length) await this.tvFind();
      tvs = this.#tvsFound;
      if (!tvs.length) throw new Error("No TV is waiting on this network. Is the TV on the same Wi-Fi, showing its code?");
    }
    const auth = authFor(this.#accounts, id);
    if (typeof auth?.refreshToken !== "function") throw new Error("This account's sign-in came from another device: sign in to it here first, or send the TV another account.");
    const a = this.#accounts;
    const email = id === FIREFOX ? (findAccount()?.email ?? this.#firefoxEmail) : a.own.find((x) => x.uid === id)?.email;
    const uid = id === FIREFOX ? findAccount()?.uid : id;
    if (!uid || !email) throw new Error("Couldn't read this account's details: try another one.");
    const refreshToken = await auth.refreshToken(AbortSignal.timeout(15_000));
    const from = this.#deviceName();
    let lastErr;
    for (const tv of tvs)
      try {
        await sendToTv(tv, { code }, { uid, email, refreshToken }, from);
        this.#say("ok", `${tv.name} is signed in with ${email}`);
        return tv.name;
      } catch (err) {
        lastErr = err;
      }
    void destroyToken(refreshToken); // no TV took it
    throw lastErr;
  }

  /** Another account: "mozilla", Foxhole's own sign-in (it comes back by signedIn()); "firefox", Firefox's sign-in. */
  addAccount(how) {
    if (how === "mozilla") return void this.#openSignIn?.();
    if (how !== "firefox" || this.#android) return;
    const twin = this.#accounts.own.find((x) => sameEmail(x.email, findAccount()?.email));
    if (twin) return this.#alert(`You're already signed in with ${twin.email}, so it isn't added again.`);
    this.#saveAccounts(withFirefox(this.#accounts));
    void this.#resignIn();
  }

  /** Foxhole's own sign-in's session (the desktop's window, the phone's page): added, and in use. */
  signedIn({ email, sessionToken, uid } = {}) {
    if (typeof uid !== "string" || !uid || typeof sessionToken !== "string" || !/^[0-9a-f]{64}$/.test(sessionToken)) return log("sign-in: no session in the answer");
    email = typeof email === "string" ? email : "";
    // already on the list (and its sign-in hasn't ended: then this one renews it): said so, not added twice
    const twin = this.#accounts.own.find((x) => x.uid === uid || sameEmail(x.email, email));
    if (twin?.sessionToken === sessionToken) return; // the same sign-in handed over again (the phone's page: at login, then when it's done)
    const ended = (id) => (this.#auth.stage === "expired" && this.#auth.id === id) || this.#others.get(id)?.error === "signed out";
    if ((twin && !ended(twin.uid)) || (!twin && this.#accounts.firefox && sameEmail(email, findAccount()?.email))) {
      void signOut({ sessionToken }); // the new session isn't kept
      return this.#alert(`You're already signed in with ${email || twin?.email}${twin ? "" : " (Firefox's sign-in)"}, so it isn't added again.`);
    }
    this.#saveAccounts(withOwn(this.#accounts, { uid, email, sessionToken }));
    this.#others.delete(uid);
    this.#alert(`You're signed in with ${email || "your account"}, and it's the account in use now.`, "Signed in");
    void this.#resignIn();
  }

  /** Uses another account on the list, from now on (the next start too); connected, it disconnects first. */
  async useAccount(id) {
    if (id === this.#accounts.current || !this.#ids().includes(id)) return;
    if (this.#busy) return this.#say("warn", "wait for it to connect (or disconnect), then switch");
    await this.disconnect();
    this.#saveAccounts({ ...this.#accounts, current: id });
    this.#switchTo = id;
    void this.#resignIn();
  }

  /** Signs an account out of Foxhole (Firefox's: Foxhole stops reading it; Firefox stays signed in). */
  removeAccount(id) {
    const own = this.#accounts.own.find((x) => x.uid === id);
    if (own) void signOut(own);
    const was = this.#accounts.current;
    this.#saveAccounts(without(this.#accounts, id));
    this.#others.delete(id);
    if (id === FIREFOX) forgetToken(); // the token got from it
    if (id === was) void this.#resignIn();
    else this.#changed();
  }

  /** The data left of the accounts not in use (the one in use's comes with its passes): when Settings opens. */
  refreshAccounts() {
    for (const id of this.#ids()) {
      if (id === this.#accounts.current) continue;
      if (id === FIREFOX) this.#firefoxEmail = findAccount()?.email ?? this.#firefoxEmail; // on the list: reading it was allowed
      const auth = authFor(this.#accounts, id);
      if (!auth) {
        this.#others.set(id, { usage: null, error: "signed out" });
        continue;
      }
      void auth
        .getAccessToken(AbortSignal.timeout(15_000))
        .then((token) => fetchUsage(token, AbortSignal.timeout(15_000)))
        .then(
          (usage) => this.#others.set(id, { usage, error: null }),
          (err) => this.#others.set(id, { usage: this.#others.get(id)?.usage ?? null, error: err.errno === 110 ? "signed out" : "couldn't check" }),
        )
        .then(() => this.#changed());
    }
    if (process.platform !== "darwin" && !this.#android) this.#firefoxEmail = peekFirefox() ?? this.#firefoxEmail; // asks nothing there
    this.#changed();
  }

  /** "Try again" after Mozilla couldn't be reached. */
  retrySignIn() {
    void this.#resignIn();
  }

  /** Puts the low-data warning away for this account until its data renews. */
  dismissLow() {
    const id = this.#accounts.current;
    const u = this.#conn?.usage;
    if (!id || !u) return;
    this.#saveAccounts({ ...this.#accounts, lowSeen: { ...this.#accounts.lowSeen, [id]: u.reset?.toISOString() ?? "" } });
    this.#changed();
  }

  #ids() {
    const a = this.#accounts;
    return [...(a.firefox ? [FIREFOX] : []), ...a.own.map((x) => x.uid)];
  }

  /** The list, as the window shows it: each one's email and data left. */
  #accountList() {
    const a = this.#accounts;
    return this.#ids().map((id) => {
      const current = id === a.current;
      const usage = current ? this.#conn?.usage : this.#others.get(id)?.usage;
      return {
        id, current, firefox: id === FIREFOX,
        send: id === FIREFOX || !!a.own.find((x) => x.uid === id)?.sessionToken, // can sign in a TV (tvSend)
        email: id === FIREFOX ? this.#firefoxEmail : a.own.find((x) => x.uid === id).email,
        usage: usageView(usage),
        error: current ? null : (this.#others.get(id)?.error ?? null),
      };
    });
  }

  /** The account in use has less than LOW_DATA left (and the warning wasn't put away this month): offer another. */
  #low() {
    const u = this.#conn?.usage;
    const id = this.#accounts.current;
    if (this.#auth.stage !== "ready" || !u || u.unlimited || u.remaining >= LOW_DATA) return null;
    if (this.#accounts.lowSeen[id] === (u.reset?.toISOString() ?? "")) return null;
    return { email: this.#email, left: gb(u.remaining) };
  }

  async reloadList() {
    this.#listError = null;
    this.#changed();
    try {
      this.#countries = order(await fetchServerList());
      if (!this.#rows().some((c) => c.code === this.#selected)) this.#selected = this.#countries.find((c) => !c.locked && c.available)?.code ?? null;
    } catch (err) {
      this.#listError = `server list failed: ${err.message}`;
    }
    this.#changed();
  }

  /** Re-reads the network and the public IP: the VPN exit's when connected, else the real one. */
  #refreshNet() {
    const seq = ++this.#netSeq;
    if (this.#settings.smartDns) void this.#followSmartDns(); // to the network's new address
    const country = this.#global ? this.#globalCountry : this.#active;
    // Proxy mode: ask through the proxy. Global mode tunnels the direct check already (not on Android: the app's own
    // connections stay out of its VPN, or the proxy's would loop through it)
    const proxy = this.#global && !this.#android ? undefined : this.via();
    this.#ip = undefined;
    this.#changed();
    void this.#network().then((n) => {
      if (seq !== this.#netSeq) return;
      const joined = this.#net !== undefined && n !== this.#net; // not the first look, at the start
      this.#net = n;
      this.#changed();
      if (joined) this.#joined(n);
    });
    // relay mode: HTTP, as HTTPS in global mode would meet foxhole's own certificate, which Node doesn't trust
    void publicIp(proxy, 3, country === RELAY_ROW).then((ip) => {
      if (seq !== this.#netSeq) return;
      this.#ip = ip;
      this.#ipNote = country === RELAY_ROW ? "Google's · sites can still see yours" : country ? `VPN · ${label(country)}` : "not via Foxhole";
      this.#changed();
    });
  }

  /** The proxy into the VPN, once connected: for downloads (GitHub can be slow or blocked where the user is). */
  via() {
    return this.#proxy && this.#active ? { host: dialHost(this.#host), port: this.#proxy.port } : undefined;
  }

  /** Re-reads the data used, quietly: a failed check keeps what's shown. */
  #refreshUsage() {
    this.#conn?.refreshUsage().then(() => this.#changed(), (err) => !this.#blockedTold && this.#saysBlocked(err) && this.#changed());
  }

  async connect(code = this.#selected) {
    const country = this.#rows().find((c) => c.code === code);
    if (!country || this.#busy || !this.#conn) return;
    const relay = country === RELAY_ROW ? this.#relay() : null;
    this.#busy = true;
    this.#connecting = this.#selected = country.code;
    this.#say("info", relay ? "connecting through your relay…" : `connecting to ${label(country)}…`);
    // between Firefox VPN and the relay: connections open now would go on the old way, so the proxy drops them
    const switching = !!this.#active && !!relay !== !!this.#conn.relay;
    try {
      // Global on: the new server's IP is pinned first, or the proxy's dial to it would loop through the tunnel.
      const session = this.#global;
      if (relay) {
        await relayCheck({ relay, server: null }); // it answers, before anything moves to it
        await this.#conn.selectRelay(relay, session ? (s) => session.addServer(s) : undefined);
      } else {
        await this.#conn.currentPass(); // warm the pass; surfaces auth/quota errors now, while the relay (if on) still works
        await this.#conn.selectServer(country.locked ? country : country.available ? country : null, session ? (s) => session.addServer(s) : undefined);
      }
      if (!this.#proxy) this.#proxy = await this.#startProxy();
      else if (switching) this.#proxy.reset();
      this.#active = country;
      if (this.#global) this.#globalCountry = country;
      saveLastCountry(country.code);
      this.#say("ok", relay ? "connected through your relay" : "connected");
      if (relay) void this.#askTrust();
      else this.#refreshUsage();
    } catch (err) {
      if (err.code === "EADDRINUSE") this.#say("error", `port ${this.#port} is in use by another app (a VPN or proxy?) — quit it, or pick another port in Settings`);
      else if (relay) this.#say("error", err.message);
      else if (err instanceof GuardianError && err.status === 401) {
        forgetToken(); // so the next start asks for a new one
        this.#say("error", "token rejected (expired) — quit and open Foxhole again to get a new one");
      } else if (err instanceof GuardianError && err.status === 403) {
        this.#setEntitled(false, true);
        this.#say("error", "this account hasn't turned on Firefox's VPN yet");
      } else {
        const blocked = this.#saysBlocked(err);
        // fetch's own message is just "fetch failed"; the network reason is in its cause
        const cause = err.cause;
        const hint = this.#rows()[0] === RELAY_ROW ? " · or pick Relay, first in Locations" : "";
        this.#say("error", `connect failed: ${err.message}${cause ? ` (${cause.code ?? cause.message})` : ""}${hint}`);
        const id = this.#message.id;
        if (!blocked) void netState().then((said) => said && this.#message.id === id && this.#say("error", said)); // why, when it's the network (nothing said since)
      }
      if (this.#proxy && !this.#active) {
        await this.#proxy.close();
        this.#proxy = null;
      }
    } finally {
      this.#busy = false;
      this.#connecting = null;
      this.#refreshNet();
    }
    // Settings saved another relay while this ran (its fields save as they're typed): relay mode follows it now
    if (relay && JSON.stringify(this.#relay()) !== JSON.stringify(relay)) this.#followRelay();
  }

  /** Counts err when it says vpn.mozilla.org is blocked here (with no relay set), for the window to say so; whether it did. */
  #saysBlocked(err) {
    if (!(err instanceof GuardianBlocked)) return false;
    this.#blocked++;
    this.#blockedTold = true;
    return true;
  }

  async disconnect() {
    if (this.#busy) return;
    this.#netPaused = null;
    if (this.#global) await this.#disableGlobal();
    if (!this.#proxy) return;
    await this.#proxy.close();
    this.#proxy = null;
    this.#proxyStale = false;
    this.#active = null;
    this.#say("info", "disconnected");
    this.#refreshUsage();
    this.#refreshNet();
  }

  /** The power button: on to the selected country, or off. */
  power() {
    return this.#active ? this.disconnect() : this.pick();
  }

  /** A location picked or the power button (the desktop's: a phone has its own, mobile/node/main.mjs): while off, connects in the mode last picked. */
  async pick(code) {
    this.#netPaused = null; // the user's choice from now on
    const off = !this.#active;
    await this.connect(code);
    if (!off || !this.#active || this.#settings.proxyOnly || this.#global) return;
    // relay mode's certificate first: its question and the password's would come up together
    if (this.#conn?.relay && !(await this.#caTrusted())) return;
    await this.toggleGlobal();
  }

  /** The desktop's Proxy only / Whole system: while off, only remembered for the next connect; while on, switches too. */
  async setMode() {
    if (this.#busy) return;
    const whole = !(this.#active ? this.#global : !this.#settings.proxyOnly);
    const { proxyOnly: _, ...rest } = this.#settings;
    this.#settings = whole ? rest : { ...rest, proxyOnly: true };
    saveSettings(this.#settings);
    this.#changed();
    if (this.#active && whole !== !!this.#global) await this.toggleGlobal();
  }

  /** At a start at login: whether whole-system mode can come on with nothing to ask. */
  async wholeWithoutAsking() {
    if (this.#settings.proxyOnly) return false;
    return (process.platform === "win32" && helperInstalled()) || (await helperReady()) || (await isPrivileged());
  }

  /** Whole-system routing on or off (asks for the administrator password). */
  async toggleGlobal() {
    if (this.#busy) return;
    if (this.#global) return this.#disableGlobal();
    // Global needs a live proxy + chosen server; connect first if needed.
    if (!this.#proxy || !this.#active) {
      await this.connect();
      if (!this.#active) return; // connect failed; message already set
    }
    // Already root: nothing to ask. Windows has no sudo either: its own admin prompt (UAC) comes up
    // as whole-system mode starts, unless Foxhole runs as Administrator.
    if (this.#android || process.platform === "win32" || (await isPrivileged())) return this.#enableGlobal(null);
    if (await helperReady()) return this.#enableGlobal(""); // the network helper needs no password (helper.ts)
    let note = null;
    if (sudoUsesTouchId()) {
      // sudo takes the fingerprint here, so a typed password would go unused
      this.#busy = true;
      this.#say("warn", "confirm with Touch ID to go global…");
      const ok = await touchIdSudo();
      this.#busy = false;
      if (ok) return this.#enableGlobal("");
      this.#message = null;
      note = "No Touch ID: type your password instead."; // cancelled, or no sensor (lid closed)
    }
    this.#pw = { error: note, checking: false, for: "global" };
    this.#changed();
  }

  cancelPassword() {
    if (this.#pw?.checking) return;
    this.#pw = null;
    this.#say("info", "cancelled");
  }

  /** Checks the password with the popup still open: a wrong one shows an error there and can be retyped. */
  async submitPassword(password) {
    if (!this.#pw || this.#pw.checking || typeof password !== "string") return;
    const what = this.#pw.for;
    this.#pw = { error: null, checking: true, for: what };
    this.#changed();
    if (!(await validateSudo(password))) {
      this.#pw = { error: "Incorrect password, try again.", checking: false, for: what };
      return this.#changed();
    }
    this.#pw = null;
    if (what === "global") void this.#enableGlobal(password);
    else void this.#trust(what === "trust", sudoPriv(password));
  }

  /** password: for sudo; null when none is asked for here (root, or Windows). */
  async #enableGlobal(password) {
    const server = this.#conn.server;
    if (!server || !this.#proxy) return;
    this.#busy = true;
    let session = null;
    try {
      if (this.#android) {
        this.#say("info", "going global… if Android asks, allow Foxhole's VPN");
        session = this.#android.globalSession({ server, proxyHost: this.#host, proxyPort: this.#proxy.port });
      } else {
        this.#say("info", "preparing tun2socks…");
        // a download goes through the VPN, its progress in the status line
        const tun2socks = async () => (this.#tun2socksPath ??= await ensureTun2socks({ proxy: this.via(), say: (msg) => this.#say("info", msg) }));
        if (process.platform === "win32") this.#say("info", "going global… if Windows asks, allow PowerShell (Foxhole's network helper)");
        const helper = await helperFor(password, tun2socks);
        if (!helper) await tun2socks();
        this.#say("info", process.platform === "win32" ? "going global… if Windows asks, allow PowerShell (Foxhole's network helper)" : "going global…");
        session = new GlobalSession({
          priv: helper?.priv ?? (password === null ? await adminPriv(true) : sudoPriv(password)),
          server,
          proxyHost: this.#host,
          proxyPort: this.#proxy.port,
          tun2socksPath: helper?.tun2socksPath ?? this.#tun2socksPath,
          force: false,
        });
      }
      session.onExit((code) => {
        // tun2socks died: tear down the routes so the system keeps working.
        this.#global = null;
        this.#globalCountry = null;
        const stopped = `${this.#android ? "Android's VPN" : "tun2socks"} stopped (${code})`;
        this.#say("error", `${stopped} — restoring networking…`);
        void session?.stop().finally(() => {
          this.#say("error", `${stopped} — global off`);
          this.#smartDnsBack();
          this.#refreshNet();
        });
      });
      session.onNetworkChange((event, detail) => {
        if (event === "lost") return this.#say("warn", `global: ${detail}`);
        this.#say("ok", `global ON · rerouted ${detail}`);
        this.#refreshNet();
      });
      if (process.platform === "darwin") {
        this.#smartDnsYields = true; // its DNS relay is about to have port 53
        await this.#followSmartDns();
      }
      await session.start();
      this.#global = session;
      this.#globalCountry = this.#active;
      this.#say("info", "verifying…");
      const ip = await session.verifyExitIp(this.#relayOn());
      if (ip) this.#say("ok", `global ON · exit IP ${ip}`);
      else this.#say("warn", `global on, but internet check failed — DNS or ${this.#relayOn() ? "relay" : "VPN"} issue`);
    } catch (err) {
      this.#say("error", `global failed: ${err.message}`);
      await session?.stop().catch(() => {});
      this.#global = null;
      this.#smartDnsBack();
    } finally {
      this.#busy = false;
      this.#refreshNet();
    }
  }

  async #disableGlobal() {
    if (!this.#global) return;
    this.#busy = true;
    this.#leavingGlobal = true; // the switch stays on Whole system until the routes are really back
    this.#say("info", "restoring networking…");
    this.#changed();
    const session = this.#global;
    this.#global = null;
    try {
      await session.stop();
      this.#say("info", "global off (SOCKS proxy still on)");
    } finally {
      this.#smartDnsBack();
      this.#globalCountry = null;
      this.#leavingGlobal = false;
      this.#busy = false;
      this.#refreshNet();
    }
    if (this.#proxyStale) await this.#restartProxy();
  }

  /** The proxy address; one port serves both SOCKS5 and HTTP. Shared: the one other devices use. */
  #proxyAddr() {
    const host = this.#host === "0.0.0.0" ? (lanIp() ?? this.#host) : this.#host;
    return `${host}:${this.#proxy?.port ?? this.#port}`;
  }

  setShare(on) {
    return this.#changeSetting({ share: on === true });
  }

  /** Settings → On this network: what joining `net` does from now on ("connect", "pause", or null for nothing). */
  setNetRule(net, rule) {
    if (ruleable(net)) return this.#changeSetting({ networks: withNetRule(this.#settings.networks, net, rule) });
  }

  /** The device joined network `n`: its rule pauses or connects, or leaving the one that paused connects again (onJoin). */
  #joined(n) {
    const a = this.#android;
    const what = onJoin(this.#settings.networks, n, { active: !!this.#active, paused: a ? a.netPaused() : !!this.#netPaused });
    if (!what || this.#busy) return;
    log(`${n}: ${what} (Settings → On this network)`);
    if (a) return void a[what](n); // the phone's own, which its notification shows (mobile/node/main.mjs)
    if (what === "pause") {
      const code = this.#active;
      return void this.disconnect().then(() => (this.#netPaused = code));
    }
    const code = this.#netPaused;
    void this.pick(code ?? undefined);
  }

  /** Settings → Language: the window's (it draws itself anew), the tray's and the notification's. */
  setLang(lang) {
    if (lang === "en" || lang === "fa" || lang === "ru") return this.#changeSetting({ lang });
  }

  /** Smart DNS for the home's TV, console or iPhone: blocked and sanctioned sites through the VPN, set as their DNS server. */
  setSmartDns(on) {
    if (SMART_DNS) return this.#changeSetting({ smartDns: on === true || undefined });
  }

  /**
   * Starts or stops Smart DNS as Settings has it, out of a Mac's whole-system mode's way, and moves it to the network's
   * new address. Resolves once done. A port it can't have is said in Settings.
   */
  /** Whole-system mode is over: Smart DNS has port 53 again, if it stepped aside. */
  #smartDnsBack() {
    if (!this.#smartDnsYields) return;
    this.#smartDnsYields = false;
    void this.#followSmartDns();
  }

  #followSmartDns() {
    return (this.#smartDnsTurn = this.#smartDnsTurn.then(async () => {
      const want = SMART_DNS && !!this.#settings.smartDns && !!this.#conn && !this.#smartDnsYields;
      const host = smartDnsHost(lanIp());
      if (this.#smartDns && (!want || this.#smartDnsAt !== host)) {
        this.#smartDns.close();
        this.#smartDns = null;
      }
      if (!want) this.#smartDnsError = null;
      if (!want || this.#smartDns) return this.#changed();
      try {
        if (!host) throw new Error("This computer isn't on a local network.");
        this.#smartDns = await startSmartDns(this.#conn, { host, self: () => lanIp(), vpn: () => !!this.#active && this.#active !== RELAY_ROW });
        this.#smartDnsAt = host;
        this.#smartDnsError = null;
      } catch (err) {
        this.#smartDnsError = smartDnsProblem(err);
      }
      this.#changed();
    }));
  }

  setPort(port) {
    if (!validPort(port)) return void this.#note("settings", "error", "A port is a number from 1 to 65535.");
    return this.#changeSetting({ port });
  }

  /** The login other devices give; both empty: none. HTTP Basic splits the username from the password at the first ":". */
  setLogin(username, password) {
    if (typeof username !== "string" || typeof password !== "string") return;
    if (username.includes(":")) return void this.#note("settings", "error", "A username can't contain “:”.");
    if (Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255) return void this.#note("settings", "error", "255 bytes at most.");
    return this.#changeSetting({ username, password });
  }
  /** The Apps Script relay for a blocked vpn.mozilla.org (httprelay.ts): both parts set it, both empty clear it. The ID may be the web app's URL. */
  setRelay(id, authKey) {
    const text = String(id ?? "").trim();
    // an empty key field keeps the saved key ("type to replace"): the window never has it
    const key = String(authKey ?? "").trim() || (text ? (this.#settings.relay?.authKey ?? "") : "");
    if (Boolean(text) !== Boolean(key)) return void this.#note("settings", "error", "Enter both the deployment ID and the auth key, or clear both to turn the relay off.");
    if (text && !deploymentId(text)) return void this.#note("settings", "error", "That isn't a Deployment ID or web app URL: copy it again from Google.");
    return this.#changeSetting({ relay: text ? { deploymentId: deploymentId(text), authKey: key } : undefined });
  }
  /**
   * Settings' Check (relaymode.ts relayVerdict) of the relay as its fields have it, saved or not: the deployment ID typed
   * there, and the auth key typed there or else the saved one (the window never gets that, so its field shows empty).
   */
  async checkRelay(id, authKey) {
    const saved = this.#settings.relay;
    const text = String(id ?? "").trim();
    const did = deploymentId(text);
    const key = String(authKey ?? "").trim() || saved?.authKey;
    if (!did) return { tone: "error", text: text ? "That isn't a Deployment ID or web app URL: copy it again from Google." : "Type the Deployment ID first." };
    if (!key) return { tone: "error", text: "Type the auth key first." };
    const v = await relayVerdict({ relay: { url: relayUrl(did), key }, server: null });
    const unsaved = did !== saved?.deploymentId || key !== saved?.authKey;
    return unsaved && v.tone !== "error" ? { ...v, text: `${v.text} Not saved yet.` } : v;
  }
  /** The setup wizard's content (relaysetup.ts): its steps, and the script as highlighted tokens with the key's placeholder. */
  relaySetup() {
    return { steps: STEPS, tokens: highlightJs(relayTemplate()), placeholder: KEY_PLACEHOLDER };
  }

  /** Saves a change and applies it: a new address or port restarts a running proxy. */
  async #changeSetting(patch) {
    const next = { ...this.#settings, ...patch };
    try {
      saveSettings(next);
    } catch (err) {
      return void this.#note("settings", "error", `Couldn't save: ${err.message}`);
    }
    this.#settings = next;
    this.#settingsNote = null;
    if ("relay" in patch) {
      useRelay(this.#relay()); // takes effect at once, no restart
      this.#followRelay();
    }
    if ("smartDns" in patch) this.#followSmartDns();
    if ("share" in patch || "port" in patch) {
      this.#host = proxyHost(next);
      this.#port = next.port;
      this.#checkFirewall();
      await this.#restartProxy();
    }
    this.#changed();
    return true;
  }

  /** The Settings panel opened: an old note goes, and the firewall is looked at again. */
  openSettings() {
    this.#settingsNote = null;
    this.refreshAccounts();
    this.#checkFirewall();
    void this.#caTrusted().then((ok) => ((this.#caOk = ok), this.#changed()));
    this.#changed();
  }

  /** The Split tunneling panel opened: an old note goes, and the apps to pick from are looked up again. */
  openSplit() {
    this.#splitNote = null;
    this.#changed();
    if (!APPS) return;
    this.#appsLoading = true;
    const apps = this.#android ? this.#android.apps() : listApps().then((list) => list.map((a) => ({ id: a.name, ...a })));
    void apps.then(
      (a) => {
        this.#apps = a.map(({ id, name }) => ({ id, name }));
        this.#appsLoading = false;
        this.#changed();
        return this.#loadIcons(a);
      },
      (err) => {
        this.#appsLoading = false;
        this.#changed();
        log(`apps: ${err.message}`);
      },
    );
  }

  /** The icons of apps not seen before; `icon`: where it is (apps.ts), or Android's, drawn there already. */
  async #loadIcons(apps) {
    const fresh = apps.filter((a) => !this.#icons.has(a.id));
    if (!fresh.length) return;
    for (const a of fresh) this.#icons.set(a.id, null); // one look each
    await Promise.all(fresh.map(async (a) => this.#icons.set(a.id, await this.#iconOf(a.icon).catch(() => null))));
    this.#changed();
  }

  /** An icon as a data: URL, or null. */
  async #iconOf(src) {
    if (typeof src !== "string" || !src) return null;
    if (/^data:image\/png;base64,/.test(src)) return src;
    const svg = /\.svg$/i.test(src);
    if (svg || /\.png$/i.test(src)) {
      const b = await readFile(src);
      return b.length <= 256 * 1024 ? `data:image/${svg ? "svg+xml" : "png"};base64,${b.toString("base64")}` : null;
    }
    return this.#fileIcon ? this.#fileIcon(src) : null;
  }

  /** The apps' icons known so far: { id: data: URL }. Apart from the state, which goes to the window every second. */
  appIcons() {
    return Object.fromEntries([...this.#icons].filter(([, url]) => url));
  }

  /** An app rule's name, as the list shows it: on Android its label, not its package. */
  #appName(id) {
    return this.#apps.find((a) => a.id === id)?.name ?? id;
  }

  /** Looks up, in the background, whether a firewall would keep other devices off the proxy's port. */
  #checkFirewall() {
    void firewallHint(this.#settings.port).then((hint) => ((this.#fwHint = hint), this.#changed()));
  }

  /** Starts the proxy on the current address, and remembers which that is. */
  #startProxy() {
    this.#proxyAt = `${this.#host}:${this.#port}`;
    return startProxy(this.#conn, this.#host, this.#port, (address) => loginFor(this.#settings, address)); // live: a change applies to the next client
  }

  /** Moves a running proxy to the current address and port. Not in global mode: tun2socks is tied to the old one. */
  async #restartProxy() {
    if (!this.#proxy) return;
    if (this.#global) {
      // only a real change waits for global off (sharing switched on and back off isn't one)
      this.#proxyStale = `${this.#host}:${this.#port}` !== this.#proxyAt;
      if (this.#proxyStale) this.#settingsNote = { tone: "warn", text: "Applies when whole-system mode is turned off." };
      return;
    }
    this.#proxyStale = false;
    this.#busy = true;
    this.#changed();
    try {
      await this.#proxy.close();
      this.#proxy = null;
      this.#proxy = await this.#startProxy();
      this.#say("ok", `proxy now on ${this.#proxyAddr()}`);
    } catch (err) {
      // e.g. the port is taken: nothing listens now, so say disconnected
      this.#active = null;
      this.#say("error", `proxy couldn't start on ${this.#host}:${this.#port}: ${err.message} — disconnected`);
    } finally {
      this.#busy = false;
      this.#refreshNet();
    }
  }

  /** This month's data by site through the VPN (traffic.ts), the biggest first: the Data sheet, which asks while open. */
  traffic() {
    const { since, sites } = traffic();
    const sp = this.#settings.split;
    const rules = new Map(sp.rules.map((r) => [r.match, r.via]));
    return {
      since: shortDate(new Date(since)),
      direct: sites.some((x) => x.direct) ? sizeOf(sites.reduce((n, x) => n + x.direct, 0)) : "",
      canSend: sp.default === "vpn", // "send direct" adds a rule, the other way from everything else
      // stuck: blocked here (save data found it so) or refusing Iran, so it'd stop working direct
      sites: sites.filter((x) => x.vpn > 0).slice(0, 15).map((x) => ({ site: x.site, vpn: x.vpn, size: sizeOf(x.vpn), rule: rules.get(x.site) ?? null, stuck: knownBlocked(x.site) || sanctioned(x.site) })),
    };
  }

  setSplitDefault(via) {
    if (via === "vpn" || via === "direct") this.#saveSplit({ ...this.#settings.split, default: via });
  }

  /** Iranian sites direct (smart.ts), and save data: the rest tried directly first. Save data is kept for the next time smart's on. */
  setSmart(smart, probe = !!this.#settings.split.probe) {
    const { smart: _, probe: __, ...sp } = this.#settings.split;
    this.#saveSplit({ ...sp, ...(smart === true && { smart: true }), ...(probe === true && { probe: true }) });
  }

  toggleRule(match) {
    const sp = this.#settings.split;
    this.#saveSplit({ ...sp, rules: sp.rules.map((r) => (r.match === match ? { ...r, via: flip(r.via) } : r)) });
  }

  removeRule(match) {
    const sp = this.#settings.split;
    this.#saveSplit({ ...sp, rules: sp.rules.filter((r) => r.match !== match) });
  }

  /**
   * Adds a typed site or app, going the other way than everything else, or `via` (the check's offer, which switches
   * the site's rule if it has one). True once it's in the list.
   */
  addRule(text, via) {
    const sp = this.#settings.split;
    const t = String(text ?? "").trim();
    let match = typeof text === "string" ? parseRule(text) : null;
    const app = match && appOf(match);
    if (app !== null && !APPS) match = null; // iOS: only sites
    else if (app !== null && this.#android) {
      // Android's rules name packages: a typed name is the app's label
      const a = this.#apps.find((x) => x.id === app) ?? this.#apps.find((x) => x.name.toLowerCase() === app.toLowerCase());
      if (!a) {
        this.#note("split", "error", `No app called “${app.slice(0, 40)}” on this ${this.#android.tv ? "TV" : "phone"}: pick one below.`);
        return false;
      }
      match = `app:${a.id}`;
    }
    if (!match) {
      const apps = APPS ? ", or an app" : "";
      this.#note("split", "error", t ? `Not a site${apps}: “${t.slice(0, 40)}”. Try bbc.co.uk, *.ir or 1.2.3.4${APPS ? " or Telegram" : ""}.` : `Type a site${apps} first.`);
      return false;
    }
    const had = sp.rules.find((r) => r.match.toLowerCase() === match.toLowerCase());
    if (had && (via === "vpn" || via === "direct")) return this.#saveSplit({ ...sp, rules: sp.rules.map((r) => (r === had ? { ...r, via } : r)) });
    if (had) {
      this.#note("split", "warn", `${appOf(match) !== null ? this.#appName(appOf(match)) : match} is already in the list.`);
      return false;
    }
    return this.#saveSplit({ ...sp, rules: [...sp.rules, { match, via: via === "vpn" || via === "direct" ? via : flip(sp.default) }] });
  }

  /**
   * Blocked or sanctioned? `text`'s site tried directly and, connected, through the VPN (proxy.ts checkSite): the verdict,
   * each way's try, how it goes now, and the way to offer when that's not what the verdict wants. Null if not a site.
   */
  async checkSite(text) {
    const site = parseSite(String(text ?? ""));
    if (!site || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(site)) {
      this.#note("split", "error", "Type a site's name to check it, like x.com.");
      return null;
    }
    const { direct, vpn } = await checkSite(this.#active && this.#active !== RELAY_ROW ? this.#conn : null, site);
    const verdict = verdictOf(site, direct, vpn);
    const [title, more] = verdictText(verdict, direct, vpn);
    const now = wayOf(site);
    const want = wantOf(verdict);
    return {
      site,
      verdict,
      title,
      more,
      direct: tryText(direct),
      vpn: tryText(vpn),
      now, // "probe": save data decides, the way the verdict wants
      offer: want && now !== "probe" && now !== want ? want : null,
    };
  }

  /** Saves the rules: the proxy reads them live, so the next connection follows them. */
  #saveSplit(split) {
    const next = { ...this.#settings, split };
    try {
      saveSettings(next);
    } catch (err) {
      this.#note("split", "error", `Couldn't save: ${err.message}`);
      return false;
    }
    this.#settings = next;
    this.#global?.splitChanged();
    this.#splitNote = null;
    this.#changed();
    return true;
  }

  /** The Locations: the relay first when one is set up, then the countries. */
  #rows() {
    return this.#relay() ? [RELAY_ROW, ...this.#countries] : this.#countries;
  }

  /** Relay mode follows the relay's settings: through the new relay, or off without one. */
  #followRelay() {
    if (this.#active === RELAY_ROW) void (this.#relay() ? this.connect(RELAY_CODE) : this.disconnect());
  }

  /** The relay as set up in Settings, or null: none, or on a phone. */
  #relay() {
    return NO_RELAY ? null : loadRelay(this.#settings);
  }

  /** Connected through the relay (relaymode.ts), not Firefox VPN. */
  #relayOn() {
    return this.#active === RELAY_ROW && !!this.#conn?.relay;
  }

  /** After connecting to the relay: asks to trust foxhole's certificate, if this computer doesn't yet (sites won't open). */
  async #askTrust() {
    this.#caOk = await this.#caTrusted();
    this.#trustAsk = !this.#caOk && this.#relayOn();
    this.#changed();
  }

  /** The trust question's "Not now". */
  dismissTrust() {
    this.#trustAsk = false;
    this.#changed();
  }

  trustCa() {
    return this.#trust(true);
  }

  untrustCa() {
    return this.#trust(false);
  }

  /** Trusts foxhole's certificate (`add`), or stops: macOS and Windows ask in a window of their own, Linux for the password here. */
  async #trust(add, priv) {
    if (this.#busy) return;
    this.#trustAsk = false;
    if (process.platform === "linux" && !priv) {
      if (!(await isPrivileged())) return void ((this.#pw = { error: null, checking: false, for: add ? "trust" : "untrust" }), this.#changed());
      priv = await adminPriv(true);
    }
    this.#busy = true;
    this.#say("info", process.platform === "darwin" ? "macOS asks for your password…" : process.platform === "win32" ? "Windows asks you to confirm: choose Yes…" : add ? "trusting the certificate…" : "removing the certificate…");
    try {
      const todo = await (this.#android?.setCaTrust ?? setCaTrust)(add, priv); // Android: the rest is in its Settings
      this.#caOk = await this.#caTrusted();
      if (todo) this.#say("warn", todo);
      else if (!add) this.#say("info", "certificate removed");
      else if (this.#caOk) this.#say("ok", "Certificate trusted. Restart your browser, then sites open through the relay.");
      else this.#say("warn", "certificate added, but not trusted yet");
    } catch (err) {
      this.#say("error", `certificate ${add ? "not trusted" : "not removed"}: ${err.message}`);
    } finally {
      this.#busy = false;
      this.#changed();
    }
  }

  /** Copies what makes terminal tools trust relay mode's certificate and use the proxy (as `foxhole env` prints). */
  copyEnv() {
    loadCa(); // the files it names must be there
    this.#copy(envLines(`127.0.0.1:${this.#proxy?.port ?? this.#port}`).join("\n") + "\n");
  }

  logs() {
    return logLines;
  }

  copy(text) {
    if (typeof text === "string") this.#copy(text);
  }

  /** Copies every log line; false when there's none yet. */
  copyLogs() {
    if (!logLines.length) return false;
    this.#copy(logLines.join("\n") + "\n");
    return true;
  }

  /** Quitting: puts global mode's routes and DNS back, then closes the proxy. */
  async shutdown() {
    if (this.#global) {
      this.#restoring = true;
      this.#changed();
      await this.#global.stop().catch(() => {});
    }
    await this.#proxy?.close();
    this.#receiver?.close();
    this.#smartDns?.close();
    void this.#share?.then((server) => server?.close());
  }

  /** The window showed the hot config's notice, and it was closed: not again. */
  newsShown(text) {
    if (text === newNotice()) noticeShown(text);
    this.#changed();
  }

  #alert(text, title = "Already signed in") {
    this.#notice = { title, text, id: (this.#notice?.id ?? 0) + 1 };
    this.#changed();
  }

  #say(tone, text) {
    this.#message = { tone, text, id: (this.#message?.id ?? 0) + 1 };
    this.#changed();
  }

  #note(where, tone, text) {
    if (where === "split") this.#splitNote = { tone, text };
    else this.#settingsNote = { tone, text };
    this.#changed();
  }

  #changed() {
    this.emit("change");
  }

  /** Everything the window shows. */
  state() {
    const u = this.#conn?.usage;
    const sp = this.#settings.split;
    const listed = new Set(sp.rules.map((r) => r.match));
    const gc = this.#globalCountry;
    return {
      version: VERSION,
      news: newNotice(), // the hot config's notice, till the window has shown it (newsShown)
      netRules: this.#settings.networks ?? {},
      update: this.#updates?.state() ?? null,
      platform: process.platform,
      auth: this.#auth,
      email: this.#email,
      countries: this.#rows().map((c) => ({ code: c.code, name: label(c), locked: c.locked, available: c.available })),
      listError: this.#listError,
      selected: this.#selected,
      active: this.#active?.code ?? null,
      global: this.#global || this.#leavingGlobal ? (gc?.code ?? null) : null,
      globalOn: !!this.#global || this.#leavingGlobal,
      busy: this.#busy,
      connecting: this.#connecting,
      message: this.#message,
      usage: usageView(u),
      accounts: this.#accountList(),
      firefoxEmail: this.#firefoxEmail,
      low: this.#low(),
      notice: this.#notice,
      entitled: this.#entitled,
      unentitledAsk: this.#unentitledAsk,
      switched: this.#switched,
      tv: !!this.#android?.tv,
      tvWait: this.#tvView(),
      share: this.#shareView(),
      net: this.#net ?? null,
      netChecking: this.#net === undefined,
      ip: this.#ip ?? null,
      ipChecking: this.#ip === undefined,
      ipNote: this.#ipNote,
      proxy: this.#active ? { addr: this.#proxyAddr(), shared: this.#host === "0.0.0.0" } : null,
      splitSummary: splitSummary(sp),
      // the relay's auth key stays in the main process, out of the window; the id (it's in a URL) and whether a key is set are shown
      helper: ["linux", "darwin", "win32"].includes(process.platform) ? helperInstalled() : null, // null: no network helper here
      wantGlobal: !this.#settings.proxyOnly, // the mode shown while off
      settings: { ...this.#settings, relay: this.#settings.relay ? { deploymentId: this.#settings.relay.deploymentId, set: true } : null },
      lanIp: lanIp(),
      shareTg: this.#telegram(),
      smartDns: SMART_DNS ? { on: !!this.#smartDns, error: this.#smartDnsError, yields: this.#smartDnsYields } : null, // null: not on a phone
      fwHint: this.#fwHint,
      settingsNote: this.#settingsNote,
      split: {
        default: sp.default,
        defaultHits: hits.get("") ?? 0,
        smart: !!sp.smart,
        probe: !!sp.probe,
        smartHits: hits.get(SMART) ?? 0,
        rules: sp.rules.map((r) => ({ ...r, hits: hits.get(r.match) ?? 0, app: appOf(r.match) !== null ? this.#appName(appOf(r.match)) : null })),
        recent: recentSites.filter((s) => !listed.has(s)).slice(0, 30),
        apps: APPS ? this.#apps.filter((a) => !listed.has(`app:${a.id}`)) : null, // null: no apps here (iOS)
        appsLoading: this.#appsLoading,
        canTypeApp: APPS && !this.#android, // a computer's rules take any app's name, one not running too; Android's name installed ones
        icons: [...this.#icons.values()].filter(Boolean).length, // more drawn: the window asks for them (appIcons)
      },
      splitNote: this.#splitNote,
      pw: this.#pw,
      relayOn: this.#relayOn(),
      relayStats: this.#relayOn() ? { ...relayStats } : null,
      caOk: this.#caOk ?? null,
      trustAsk: this.#trustAsk,
      restoring: this.#restoring,
      blocked: this.#blocked,
    };
  }
}
