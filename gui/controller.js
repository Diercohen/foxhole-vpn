// The desktop app's state and actions, on the same modules as the TUI (src/tui.ts, which this
// follows step by step): the main process owns them, the window shows state() and asks for actions.
import { EventEmitter } from "node:events";
import { findAccount, openBrowser, macApp } from "./dist/profile.js";
import { fetchServerList } from "./dist/serverlist.js";
import { Connection, RELAY_CODE } from "./dist/connection.js";
import { FirefoxAuth, StaticAuth } from "./dist/auth.js";
import { FIREFOX, LOW_DATA, authFor, loadAccounts, peekFirefox, saveAccounts, signOut, withFirefox, withOwn, without } from "./dist/accounts.js";
import { fetchEntitlement, fetchUsage } from "./dist/guardian.js";
import { GuardianError, GuardianBlocked, useRelay } from "./dist/guardian.js";
import { loadRelay, relayUrl } from "./dist/httprelay.js";
import { STEPS, KEY_PLACEHOLDER, relayTemplate, highlightJs, deploymentId } from "./dist/relaysetup.js";
import { network, publicIp, lanIp, firewallHint } from "./dist/netinfo.js";
import { loadSettings, saveSettings, proxyHost, validPort, loginFor } from "./dist/settings.js";
import { startTokenReceiver, loadSavedToken, saveToken, forgetToken, tokenProblem } from "./dist/tokenserver.js";
import { startProxy, onProxyWarning } from "./dist/proxy.js";
import { log, logLines, onLog } from "./dist/log.js";
import { useSplit, splitSummary, parseSite, hits, recentSites } from "./dist/split.js";
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

/** Data left, as the window shows it. */
const usageView = (u) =>
  !u ? null
    : u.unlimited ? { unlimited: true }
    : { left: gb(u.remaining), max: gb(u.max), reset: u.reset ? shortDate(u.reset) : null, fraction: u.max ? Number((u.remaining * 1000n) / u.max) / 1000 : 0 };

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
  #globalCountry = null;
  #tun2socksPath = null;
  #busy = false;
  #connecting = null; // the country being connected to
  #message = null; // { tone: info | ok | warn | error, text, id }
  #notice = null; // { text, id }: the window shows it as an alert (an account already on the list)
  #auth = { stage: "checking" };
  #email = null;
  #net; // undefined: not read yet
  #ip; // undefined: checking
  #ipNote = "";
  #netSeq = 0; // drops answers from an older check
  #pw = null; // the administrator password popup: { error, checking, for: global | trust | untrust }
  #trustAsk = false; // the window asks to trust foxhole's certificate (relay mode)
  #caOk; // whether this computer trusts it; undefined: not checked yet
  #fwHint = null;
  #settingsNote = null;
  #splitNote = null;
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
  #firefoxEmail = null; // Firefox's sign-in's, once read (peekFirefox: where reading it asks nothing)
  #others = new Map(); // an account's id → { usage, error }: the data left of those not in use (refreshAccounts)
  #openSignIn; // opens Foxhole's own Mozilla sign-in: the desktop's window (gui/main.js), the phone's page
  #updates; // updater.js: a new version of the app
  /**
   * On a phone (mobile/node/main.mjs), what it does in place of the desktop's ways; null elsewhere: openSignIn() its
   * own Mozilla sign-in, whose session comes back by signedIn(); globalSession() Android's VPN, with GlobalSession's methods; network();
   * caTrusted() and setCaTrust(add), relay mode's certificate in Android's store (setCaTrust says what's left to do).
   */
  #android;

  constructor({ copy, updates, android = null, openSignIn = null }) {
    super();
    this.#copy = copy;
    this.#updates = updates;
    this.#android = android;
    this.#openSignIn = openSignIn ?? android?.openSignIn ?? null;
    this.#firefoxEmail = peekFirefox();
  }

  #network = () => (this.#android?.network ?? network)();
  #caTrusted = () => (this.#android?.caTrusted ?? caTrusted)();

  /** global: turn whole-system mode on once connected (the restart into an update, when it was on). */
  async start({ global = false } = {}) {
    useRelay(this.#relay()); // where vpn.mozilla.org is blocked, relay Guardian's control calls (httprelay.ts)
    useSplit(() => this.#settings.split); // live: a change applies to the next connection
    onLog(() => this.emit("log", logLines[logLines.length - 1]));
    onProxyWarning((msg) => this.#say("error", `proxy: ${msg}`));
    onRelayNotice((msg) => this.#say("warn", msg));
    onRelaySplit((split) => this.#saveSplit(split)); // a bot-check page's "Open it directly"
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
    // Connects at once to the last country used; a first run waits for a pick.
    if (this.#rows().some((c) => c.code === loadLastCountry())) void this.connect(loadLastCountry()).then(() => global && this.#active && this.toggleGlobal());
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
      void signOut(sessionToken); // the new session isn't kept
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
    if (own) void signOut(own.sessionToken);
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
    const country = this.#global ? this.#globalCountry : this.#active;
    // Proxy mode: ask through the proxy. Global mode tunnels the direct check already (not on Android: the app's own
    // connections stay out of its VPN, or the proxy's would loop through it)
    const proxy = this.#global && !this.#android ? undefined : this.via();
    this.#ip = undefined;
    this.#changed();
    void this.#network().then((n) => {
      if (seq !== this.#netSeq) return;
      this.#net = n;
      this.#changed();
    });
    // relay mode: HTTP, as HTTPS in global mode would meet foxhole's own certificate, which Node doesn't trust
    void publicIp(proxy, 3, country === RELAY_ROW).then((ip) => {
      if (seq !== this.#netSeq) return;
      this.#ip = ip;
      this.#ipNote = country === RELAY_ROW ? "Google's · sites can still see yours" : country ? `VPN · ${label(country)}` : "your real IP";
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
        this.#saysBlocked(err);
        // fetch's own message is just "fetch failed"; the network reason is in its cause
        const cause = err.cause;
        const hint = this.#rows()[0] === RELAY_ROW ? " · or pick Relay, first in Locations" : "";
        this.#say("error", `connect failed: ${err.message}${cause ? ` (${cause.code ?? cause.message})` : ""}${hint}`);
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
    return this.#active ? this.disconnect() : this.connect();
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
        this.#tun2socksPath ??= await ensureTun2socks({ proxy: this.via(), say: (msg) => this.#say("info", msg) });
        this.#say("info", process.platform === "win32" ? "going global… if Windows asks, allow PowerShell (Foxhole's network helper)" : "going global…");
        session = new GlobalSession({
          priv: password === null ? await adminPriv(true) : sudoPriv(password),
          server,
          proxyHost: this.#host,
          proxyPort: this.#proxy.port,
          tun2socksPath: this.#tun2socksPath,
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
          this.#refreshNet();
        });
      });
      session.onNetworkChange((event, detail) => {
        if (event === "lost") return this.#say("warn", `global: ${detail}`);
        this.#say("ok", `global ON · rerouted ${detail}`);
        this.#refreshNet();
      });
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
    } finally {
      this.#busy = false;
      this.#refreshNet();
    }
  }

  async #disableGlobal() {
    if (!this.#global) return;
    this.#busy = true;
    this.#say("info", "restoring networking…");
    const session = this.#global;
    this.#global = null;
    this.#globalCountry = null;
    try {
      await session.stop();
      this.#say("info", "global off (SOCKS proxy still on)");
    } finally {
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

  /** The Split tunneling panel opened: an old note goes. */
  openSplit() {
    this.#splitNote = null;
    this.#changed();
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

  setSplitDefault(via) {
    if (via === "vpn" || via === "direct") this.#saveSplit({ ...this.#settings.split, default: via });
  }

  toggleRule(match) {
    const sp = this.#settings.split;
    this.#saveSplit({ ...sp, rules: sp.rules.map((r) => (r.match === match ? { ...r, via: flip(r.via) } : r)) });
  }

  removeRule(match) {
    const sp = this.#settings.split;
    this.#saveSplit({ ...sp, rules: sp.rules.filter((r) => r.match !== match) });
  }

  /** Adds a typed site, going the other way than everything else. True once it's in the list. */
  addRule(text) {
    const sp = this.#settings.split;
    const match = typeof text === "string" ? parseSite(text) : null;
    if (!match) {
      const t = String(text ?? "").trim();
      this.#note("split", "error", t ? `Not a site: “${t.slice(0, 40)}”. Try bbc.co.uk, *.ir or 1.2.3.4.` : "Type a site first.");
      return false;
    }
    if (sp.rules.some((r) => r.match === match)) {
      this.#note("split", "warn", `${match} is already in the list.`);
      return false;
    }
    return this.#saveSplit({ ...sp, rules: [...sp.rules, { match, via: flip(sp.default) }] });
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
      update: this.#updates?.state() ?? null,
      platform: process.platform,
      auth: this.#auth,
      email: this.#email,
      countries: this.#rows().map((c) => ({ code: c.code, name: label(c), locked: c.locked, available: c.available })),
      listError: this.#listError,
      selected: this.#selected,
      active: this.#active?.code ?? null,
      global: this.#global ? (gc?.code ?? null) : null,
      globalOn: !!this.#global,
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
      net: this.#net ?? null,
      netChecking: this.#net === undefined,
      ip: this.#ip ?? null,
      ipChecking: this.#ip === undefined,
      ipNote: this.#ipNote,
      proxy: this.#active ? { addr: this.#proxyAddr(), shared: this.#host === "0.0.0.0" } : null,
      splitSummary: splitSummary(sp),
      // the relay's auth key stays in the main process, out of the window; the id (it's in a URL) and whether a key is set are shown
      settings: { ...this.#settings, relay: this.#settings.relay ? { deploymentId: this.#settings.relay.deploymentId, set: true } : null },
      lanIp: lanIp(),
      fwHint: this.#fwHint,
      settingsNote: this.#settingsNote,
      split: {
        default: sp.default,
        defaultHits: hits.get("") ?? 0,
        rules: sp.rules.map((r) => ({ ...r, hits: hits.get(r.match) ?? 0 })),
        recent: recentSites.filter((s) => !listed.has(s)).slice(0, 30),
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
