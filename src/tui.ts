import readline from "node:readline";
import { PassThrough } from "node:stream";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { userHome, findAccount } from "./profile.js";
import { fetchServerList, type Country } from "./serverlist.js";
import { Connection } from "./connection.js";
import { GuardianError, GuardianBlocked, useRelay } from "./guardian.js";
import { network, publicIp, lanIp, firewallHint } from "./netinfo.js";
import { loadSettings, saveSettings, proxyHost, validPort, loginFor, type Settings } from "./settings.js";
import { forgetToken } from "./tokenserver.js";
import { startProxy, onProxyWarning, type ProxyHandle } from "./proxy.js";
import { logLines, onLog } from "./log.js";
import { useSplit, splitOn, splitSummary, parseSite, hits, recentSites, type Split, type Via } from "./split.js";
import { GlobalSession, sudoPriv, adminPriv, isPrivileged, validateSudo, sudoUsesTouchId, touchIdSudo, ensureTun2socks, dialHost } from "./global.js";
import { checkUpdate, canUpdate, runUpdate, restart, versionLines, UPDATE_COMMAND } from "./update.js";
import { bold, dim, under, strike, green, red, yellow, cyan, lit, flag, EMOJI, emoji, countryName, gb, shortDate, vw, fit, box, grid, centerIn, draw, overlay, repoLink, REPO_URL, linkAt, openUrl, copyText } from "./ui.js";
import { fox, FOX_W, FOX_H, type Mood } from "./fox.js";
import { loadRelay } from "./httprelay.js";
import { newAuthKey } from "./relaysetup.js";
import { RelayWizard, GRAPHICS, CELL_QUERY, cellSize, pictureAt } from "./relaywizard.js";

const ESC = "\x1b[";
// alternate screen + hidden cursor + mouse reports (SGR): clicks and the wheel, see #mouse()
// ?7l: no autowrap, so a window narrower than the frame cuts its lines at the edge instead of wrapping them into a mess
const ALT_ON = `${ESC}?1049h${ESC}?25l${ESC}?7l${ESC}?1000h${ESC}?1006h`;
const ALT_OFF = `${ESC}?1000l${ESC}?1006l${ESC}?7h${ESC}?25h${ESC}?1049l`;
let screenOn = false;
/** Back to the normal screen with mouse reports off; also runs on exit, so a crash doesn't leave them on. */
function leaveScreen(): void {
  if (!screenOn) return;
  screenOn = false;
  process.stdout.write(ALT_OFF);
}
process.on("exit", leaveScreen);

const LOGOUT_ASK = yellow("press O again to log out and switch accounts");
const onOff = (v: boolean) => (v ? green("on") : dim("off"));
const flip = (v: Via): Via => (v === "vpn" ? "direct" : "vpn");

// Side by side, the fox and the details are in a panel this wide inside its border (its title fits
// " GLOBAL TUN ON  🇬🇧 United Kingdom"), beside the table of countries; the window needs SIDE_W columns
// for it (one spare: Terminal.app draws a flag's line a cell longer). Narrower, the table goes below.
const LEFT_W = 53;
const TABLE_W = 44;
const SIDE_W = LEFT_W + 4 + 1 + TABLE_W + 1;

/** The Settings popup's rows, in order. */
const SETTINGS = [
  { key: "share", label: "Share with devices on this network" },
  { key: "port", label: "Proxy port" },
  { key: "username", label: "Username" },
  { key: "password", label: "Password" },
  { key: "relaySetup", label: "VPN relay · set up" },
  { key: "relayId", label: "VPN relay · deployment ID" },
  { key: "relayKey", label: "VPN relay · auth key" },
] as const;

/** A country's name with its flag in front, where the TUI shows flags (EMOJI). */
const flagged = (code: string, name: string) => (EMOJI ? `${flag(code)} ${name}` : name);

/** Merges a relay change into the current config; undefined (off) once both parts are empty. */
const relayWith = (cur: Settings["relay"], patch: { deploymentId?: string; authKey?: string }): Settings["relay"] => {
  const r = { deploymentId: cur?.deploymentId ?? "", authKey: cur?.authKey ?? "", ...patch };
  return r.deploymentId || r.authKey ? r : undefined;
};

/** The last country connected to; the next start puts the cursor on it. */
const lastCountryFile = () => join(userHome(), ".config", "foxhole-vpn", "country");

export function loadLastCountry(): string | null {
  try {
    return readFileSync(lastCountryFile(), "utf8").trim() || null;
  } catch {
    return null;
  }
}

export function saveLastCountry(code: string): void {
  try {
    mkdirSync(dirname(lastCountryFile()), { recursive: true, mode: 0o700 });
    writeFileSync(lastCountryFile(), code);
  } catch {
    // only a convenience; never fail a connect over it
  }
}

/** Sort order: free & usable first, then paid, each alphabetical. */
export function order(list: Country[]): Country[] {
  return [...list].sort((a, b) => {
    const rank = (c: Country) => (!c.locked && c.available ? 0 : c.locked ? 2 : 1);
    return rank(a) - rank(b) || countryName(a.code, a.name).localeCompare(countryName(b.code, b.name));
  });
}

export class Tui {
  readonly #conn: Connection;
  #host: string;
  #port: number;
  #settings: Settings = loadSettings();
  #settingsOpen = false; // the Settings popup is open
  #wizard: RelayWizard | null = null; // the relay's setup, over Settings
  #blocked = false; // the popup saying vpn.mozilla.org is blocked here, with the relay's setup a key away
  #blockedTold = false; // said once already: a background check doesn't say it again, a connect does
  #setSel = 0;
  #edit: { key: "port" | "username" | "password" | "relayId" | "relayKey"; text: string } | null = null; // the setting being typed
  readonly #login = (address: string | undefined) => loginFor(this.#settings, address); // live: a change applies to the next client
  #settingsNote = "";
  #fwHint: string[] | null = null; // commands that open the proxy's port in an active firewall (Linux)
  #proxyStale = false; // the running proxy still has the old address (changed during global mode)
  #proxyAt = ""; // the address the running proxy was started on
  #countries: Country[] = [];
  #sel = 0;
  #proxy: ProxyHandle | null = null;
  #active: Country | null = null;
  #message = "";
  #busy = false;
  #global: GlobalSession | null = null;
  #globalCountry: Country | null = null;
  #tun2socksPath: string | null = null;
  #pwMode = false; // the password popup is open
  #pw = "";
  #pwError = "";
  #pwChecking = false;
  #splitOpen = false; // the Split tunneling popup is open
  #splitSel = 0; // 0: "Everything else", then the rules, then "+ add a site"
  #splitStart = 0; // the first row shown, when the list scrolls
  #splitShown = 0; // how many rows are shown
  #splitEdit: string | null = null; // the site being typed
  #splitTab: { query: string; i: number } | null = null; // Tab going through recent sites
  #splitNote = "";
  #logsOpen = false; // the Logs popup is open
  #logsNote = ""; // how copying the logs went
  #restoring = false; // quitting: global mode's routes are being put back
  #loading = true; // the server list isn't in yet
  #renderTimer: NodeJS.Timeout | null = null;
  // where the last render put the fox on the screen, for its next frames (null: not shown, or under a popup)
  #foxAt: { x: number; y: number; cols: number; rows: number } | null = null;
  #foxDrawn: string[] = []; // its frame on the screen now, line by line
  #net: string | null | undefined; // undefined: not read yet
  #ip: string | null | undefined; // undefined: checking
  #ipNote = "";
  #netSeq = 0; // drops answers from an older check
  // where the last render put the clickable parts; rows are frame lines, x columns in the frame
  #hit = { top: 0, left: 0, rowsTop: 0, rowsLeft: 0, start: 0, rows: 0, width: 0, buttonsY: -1, buttons: "", setTop: -1, setX: 0, setW: 0 };
  readonly #email = findAccount()?.email ?? null; // the Firefox account the token came from

  constructor(conn: Connection, host: string, port: number) {
    this.#conn = conn;
    this.#host = host;
    this.#port = port;
  }

  /** Resolves "logout" when the user logged out, so the caller can forget the token. */
  async run(): Promise<"logout" | undefined> {
    useSplit(() => this.#settings.split); // live: a change applies to the next connection
    setInterval(() => this.#splitOpen && this.#render(), 1000).unref(); // its counts climb as sites load
    setInterval(() => this.#animate(), 100).unref();
    onLog(() => this.#logsOpen && this.#renderSoon());
    onProxyWarning((msg) => {
      this.#message = red(`proxy: ${msg}`);
      this.#render();
    });
    // A closed terminal fails every write and read (EIO): that must not crash the quit that
    // puts global mode's routes back (it comes as SIGHUP, with nothing left to draw on).
    process.stdout.on("error", () => {});
    process.stdin.on("error", () => {});
    screenOn = true;
    process.stdout.write(ALT_ON);
    this.#message = dim("loading…");
    this.#render();
    try {
      this.#countries = order(await fetchServerList());
      this.#sel = Math.max(0, this.#countries.findIndex((c) => c.code === loadLastCountry()));
      this.#message = "";
    } catch (err) {
      this.#message = existsSync("/sys/class/net/foxhole0")
        ? red("offline: a killed global session's routes are still on — quit and run  foxhole restore")
        : red(`server list failed: ${(err as Error).message}`);
    }
    this.#loading = false;
    // Connects at once to the last country used; never to whatever sorts first (a first run waits for a pick).
    if (this.#countries[this.#sel]?.code === loadLastCountry()) void this.#connect();
    this.#refreshUsage();
    setInterval(() => this.#refreshUsage(), 3 * 60_000).unref(); // also after each connect and disconnect
    this.#refreshNet();
    // A network switch changes the public IP too; the network is cheap to poll. The
    // LAN address catches switches the name can't show (when macOS hides it).
    let lan = lanIp();
    setInterval(() => {
      void network().then((n) => {
        const was = lan;
        lan = lanIp();
        if (this.#net !== undefined && (n !== this.#net || lan !== was)) this.#refreshNet();
      });
    }, 5000).unref();
    void checkUpdate().then(() => this.#render()); // show the update notice once npm answers
    this.#render();
    return (await this.#loop()) === "logout" ? "logout" : undefined;
  }

  /** Re-reads the network and the public IP: the VPN exit's when connected, else the real one. */
  #refreshNet(): void {
    const seq = ++this.#netSeq;
    const country = this.#global ? this.#globalCountry : this.#active;
    // Proxy mode: ask through the proxy. Global mode tunnels the direct check already.
    const proxy = this.#proxy && this.#active && !this.#global
      ? { host: dialHost(this.#host), port: this.#proxy.port }
      : undefined;
    this.#ip = undefined;
    void network().then((n) => {
      if (seq !== this.#netSeq) return;
      this.#net = n;
      this.#render();
    });
    void publicIp(proxy).then((ip) => {
      if (seq !== this.#netSeq) return;
      this.#ip = ip;
      this.#ipNote = country ? `VPN · ${flagged(country.code, countryName(country.code, country.name))}` : "your real IP";
      this.#render();
    });
  }

  /** Re-reads the data used, quietly: a failed check keeps what's shown. */
  #refreshUsage(): void {
    this.#conn.refreshUsage().then(() => this.#render(), (err) => !this.#blockedTold && this.#saysBlocked(err) && this.#render());
  }

  #loop(): Promise<"update" | "logout" | undefined> {
    return new Promise((resolve) => {
      // stdin minus mouse reports: readline would split those into stray keypresses ("0", ";", "M"…).
      // SGR mouse report: ESC [ < button ; col ; row (M = press, m = release)
      // ponytail: assumes a report never straddles two reads, true for terminals in practice
      const input = new PassThrough();
      readline.emitKeypressEvents(input);
      const onData = (buf: Buffer) => {
        const rest = buf.toString().replace(/\x1b\[<(\d+);(\d+);(\d+)([Mm])/g, (_, b: string, x: string, y: string, kind: string) => {
          // as a keypress, so it goes where a key would (and nowhere once quitting)
          if (kind === "M") this.#mouse(Number(b), Number(x) - 1, Number(y) - 1, (name) => input.emit("keypress", undefined, { name }));
          return "";
        }).replace(/\x1b\[([46]);(\d+);(\d+)t/g, (_, what: string, h: string, w: string) => {
          // CELL_QUERY's answers, in pixels: a cell (6), or the window (4) to divide by its cells
          const [cols, rows] = what === "6" ? [1, 1] : [process.stdout.columns || 80, process.stdout.rows || 24];
          cellSize(Math.floor(Number(w) / cols), Math.floor(Number(h) / rows));
          return "";
        });
        if (rest) input.write(rest);
      };
      process.stdin.on("data", onData);
      if (process.stdin.isTTY) process.stdin.setRawMode(true);
      process.stdin.resume();
      if (GRAPHICS === "sixel") process.stdout.write(CELL_QUERY); // the wizard's pictures need a cell's size in pixels
      const onResize = () => this.#render();
      process.stdout.on("resize", onResize);

      // Ctrl+C outside raw mode, a closed terminal or a kill: quit properly, so the
      // screen and mouse mode are restored and global mode puts the routes back.
      // SIGBREAK: Ctrl+Break on Windows.
      const signals = ["SIGINT", "SIGTERM", "SIGHUP", ...(process.platform === "win32" ? ["SIGBREAK"] as const : [])];
      const onSignal = () => void quit();
      for (const sig of signals) process.on(sig, onSignal);
      // A closed terminal ends stdin for every process reading it, signalled or not: its SIGHUP goes
      // to the terminal's first process only (after an update, the old version waiting behind this one).
      process.stdin.once("end", onSignal);

      let quitting = false;
      const quit = async (action?: "update" | "logout") => {
        // Once: a signal or the terminal's end can follow the first. The listeners stay, as without
        // any a late signal would kill the process midway through putting the routes back.
        if (quitting) return;
        quitting = true;
        input.removeListener("keypress", onKey); // keys now do nothing
        if (this.#global) {
          // Stay on our screen with a popup until everything is closed: stdin is still read raw
          // and swallowed, so keys and clicks pressed meanwhile aren't echoed as ^[[<0;… junk.
          this.#restoring = true;
          this.#render();
          await this.#global.stop().catch(() => {});
        }
        await this.#proxy?.close();
        process.stdin.removeListener("data", onData);
        process.stdout.removeListener("resize", onResize);
        try {
          if (process.stdin.isTTY) process.stdin.setRawMode(false);
        } catch {
          /* the terminal is gone */
        }
        process.stdin.pause();
        leaveScreen();
        if (action === "update") {
          // runs npm in this terminal (asks for sudo if needed), then the new version in its place
          if (runUpdate() === 0) restart();
          console.log(red(`\nNot updated (see above). To try again: ${UPDATE_COMMAND}`));
        }
        resolve(action);
      };

      const onKey = (s: string, key: readline.Key) => {
        if (!key) return;
        if (key.ctrl && key.name === "c") return void quit();
        if (this.#pwMode) return this.#pwKey(s, key);
        if (this.#logsOpen) {
          // the popup only copies and closes; other keys stay with it, so nothing happens behind it
          if (key.name === "escape" || key.name === "l") (this.#logsOpen = false), this.#render();
          else if (key.name === "c") void this.#copyLogs();
          return;
        }
        if (this.#wizard) return this.#wizardKey(s, key);
        if (this.#blocked) {
          if (key.name === "return") this.#wizard = new RelayWizard(() => this.#render());
          if (key.name === "return" || key.name === "escape") (this.#blocked = false), this.#render();
          return;
        }
        if (this.#settingsOpen) return this.#settingsKey(s, key);
        if (this.#splitOpen) return this.#splitKey(s, key);
        if (key.name === "q") return void quit();
        if (key.name === "l") return void ((this.#logsOpen = true), (this.#logsNote = ""), this.#render());
        if (this.#busy) return;
        if (key.name === "s") {
          this.#settingsOpen = true;
          this.#settingsNote = "";
          this.#checkFirewall();
          return this.#render();
        }
        if (key.name === "t") {
          this.#splitOpen = true;
          this.#splitNote = "";
          return this.#render();
        }
        switch (key.name) {
          case "up":
          case "k":
            this.#sel = (this.#sel - 1 + this.#countries.length) % this.#countries.length;
            break;
          case "down":
          case "j":
            this.#sel = (this.#sel + 1) % this.#countries.length;
            break;
          case "return":
            void this.#connect();
            return;
          case "g":
            void this.#toggleGlobal();
            return;
          case "d":
            void this.#disconnect();
            return;
          case "u":
            if (canUpdate()) return void quit("update");
            break;
          case "o":
            // asks first: the token is gone after this, and getting a new one takes a few steps
            if (this.#message === LOGOUT_ASK) return void quit("logout");
            this.#message = LOGOUT_ASK;
            break;
        }
        this.#render();
      };
      input.on("keypress", onKey);
    });
  }

  /**
   * A mouse press at the 0-based screen cell (x, y). The wheel moves the selection; a click
   * on a country selects it (again: connects), on a button or setting presses it.
   */
  #mouse(b: number, x: number, y: number, press: (name: string) => void): void {
    if (b === 64 || b === 65) return press(b === 64 ? "up" : "down");
    if (b !== 0 || this.#pwMode || this.#logsOpen || this.#restoring || this.#wizard || this.#blocked) return;
    const h = this.#hit;
    const fx = x - h.left, fy = y - h.top;
    if (this.#settingsOpen) {
      const i = fy - h.setTop;
      if (this.#edit || i < 0 || i >= SETTINGS.length || fx < h.setX || fx >= h.setX + h.setW) return;
      this.#setSel = i;
      return press("return");
    }
    if (this.#splitOpen) {
      const i = fy - h.setTop;
      if (this.#splitEdit !== null || i < 0 || i >= this.#splitShown || fx < h.setX || fx >= h.setX + h.setW) return;
      this.#splitSel = this.#splitStart + i;
      return press("return");
    }
    if (linkAt(x, y)) return openUrl(REPO_URL);
    const k = fy - h.rowsTop;
    if (k >= 0 && k < h.rows && fx >= h.rowsLeft && fx < h.rowsLeft + h.width) {
      if (this.#busy) return;
      if (h.start + k === this.#sel) return press("return");
      this.#sel = h.start + k;
      return this.#render();
    }
    if (fy === h.buttonsY) {
      // the [...] around the click, if any
      const a = h.buttons.lastIndexOf("[", fx), z = h.buttons.indexOf("]", fx);
      if (a < 0 || z < 0 || h.buttons.lastIndexOf("]", fx - 1) > a) return;
      const label = h.buttons.slice(a + 1, z);
      press(label.startsWith("⏎") ? "return" : label.startsWith("Split") ? "t" : label[0].toLowerCase());
    }
  }

  async #connect(): Promise<void> {
    const country = this.#countries[this.#sel];
    if (!country) return;
    this.#busy = true;
    this.#message = dim(`connecting to ${countryName(country.code, country.name)}…`);
    this.#render();
    try {
      // Global on: the new server's IP is pinned first, or the proxy's dial to it would loop through the tunnel.
      const session = this.#global;
      await this.#conn.selectServer(country.locked ? country : country.available ? country : null, session ? (s) => session.addServer(s) : undefined);
      if (!this.#proxy) this.#proxy = await this.#startProxy();
      await this.#conn.currentPass(); // warm the pass; surfaces auth/quota errors now
      this.#active = country;
      if (this.#global) this.#globalCountry = country;
      saveLastCountry(country.code);
      this.#message = green("connected");
      this.#refreshUsage();
    } catch (err) {
      if (err instanceof GuardianError && err.status === 401) {
        forgetToken(); // so the next start shows the token window
        this.#message = red("token rejected (expired) — quit and run foxhole again to get a new one");
      } else {
        this.#saysBlocked(err);
        // fetch's own message is just "fetch failed"; the network reason is in its cause
        const cause = (err as Error).cause as { code?: string; message?: string } | undefined;
        this.#message = red(`connect failed: ${(err as Error).message}${cause ? ` (${cause.code ?? cause.message})` : ""}`);
      }
      if (this.#proxy && !this.#active) {
        await this.#proxy.close();
        this.#proxy = null;
      }
    } finally {
      this.#busy = false;
      this.#refreshNet();
      this.#render();
    }
  }

  async #disconnect(): Promise<void> {
    if (this.#global) await this.#disableGlobal();
    if (!this.#proxy) return;
    await this.#proxy.close();
    this.#proxy = null;
    this.#proxyStale = false;
    this.#active = null;
    this.#message = dim("disconnected");
    this.#refreshUsage();
    this.#refreshNet();
    this.#render();
  }

  /** Toggle whole-system routing for the selected country (asks for sudo). */
  async #toggleGlobal(): Promise<void> {
    if (this.#global) return void this.#disableGlobal();
    // Global needs a live proxy + chosen server; connect first if needed.
    if (!this.#proxy || !this.#active) {
      await this.#connect();
      if (!this.#active) return; // connect failed; message already set
    }
    // Already root (e.g. in the Docker sandbox, which has no sudo): nothing to ask. Windows has no sudo
    // either: its own admin prompt (UAC) comes up as global mode starts, unless foxhole runs as Administrator.
    if (process.platform === "win32" || (await isPrivileged())) return void this.#enableGlobal(null);
    let note = "";
    if (sudoUsesTouchId()) {
      // sudo takes the fingerprint here, so a password typed in the popup would go unused
      this.#busy = true;
      this.#message = yellow("confirm with Touch ID to go global…");
      this.#render();
      const ok = await touchIdSudo();
      this.#busy = false;
      if (ok) return void this.#enableGlobal("");
      this.#message = "";
      note = "No Touch ID: type your password instead."; // cancelled, or no sensor (lid closed)
    }
    this.#pwMode = true;
    this.#pw = "";
    this.#pwError = note;
    this.#render();
  }

  /** Keystrokes while the password popup is open. */
  #pwKey(s: string, key: readline.Key): void {
    if (this.#pwChecking) return;
    if (key.name === "escape") {
      this.#pwMode = false;
      this.#pw = "";
      this.#message = dim("cancelled");
    } else if (key.name === "return") {
      void this.#submitPassword();
      return;
    } else if (key.name === "backspace") {
      this.#pw = this.#pw.slice(0, -1);
    } else if (s && s.length === 1 && s >= " " && !key.ctrl && !key.meta) {
      this.#pw += s;
    }
    this.#render();
  }

  /** Checks the password with the popup still open: a wrong one shows an error there and can be retyped. */
  async #submitPassword(): Promise<void> {
    const pw = this.#pw;
    this.#pwChecking = true;
    this.#pwError = "";
    this.#render();
    const ok = await validateSudo(pw);
    this.#pwChecking = false;
    this.#pw = "";
    if (!ok) {
      this.#pwError = "Incorrect password, try again.";
      this.#render();
      return;
    }
    this.#pwMode = false;
    void this.#enableGlobal(pw);
  }

  /** password: for sudo; null when none is asked for here (root, or Windows). */
  async #enableGlobal(password: string | null): Promise<void> {
    const server = this.#conn.server;
    if (!server || !this.#proxy) return;
    this.#busy = true;
    this.#message = dim("preparing tun2socks…");
    this.#render();
    let session: GlobalSession | null = null;
    try {
      // a download goes through the VPN (GitHub can be slow or blocked), its progress in the status line
      const via = { host: dialHost(this.#host), port: this.#proxy.port };
      this.#tun2socksPath ??= await ensureTun2socks({ proxy: via, say: (msg) => ((this.#message = dim(msg)), this.#render()) });
      this.#message = dim(process.platform === "win32" ? "going global… if Windows asks, allow PowerShell" : "going global…");
      this.#render();
      session = new GlobalSession({
        priv: password === null ? await adminPriv(true) : sudoPriv(password),
        server,
        proxyHost: this.#host,
        proxyPort: this.#proxy.port,
        tun2socksPath: this.#tun2socksPath,
        force: false,
      });
      session.onExit((code) => {
        // tun2socks died: tear down the routes so the system keeps working.
        this.#global = null;
        this.#globalCountry = null;
        this.#message = red(`tun2socks stopped (${code}) — restoring networking…`);
        this.#render();
        void session?.stop().finally(() => {
          this.#message = red(`tun2socks stopped (${code}) — global off`);
          this.#refreshNet();
          this.#render();
        });
      });
      session.onNetworkChange((event, detail) => {
        this.#message = event === "lost" ? yellow(`global: ${detail}`) : green(`global ON · rerouted ${detail}`);
        if (event === "restored") this.#refreshNet();
        this.#render();
      });
      await session.start();
      this.#global = session;
      this.#globalCountry = this.#active;
      this.#message = dim("verifying…");
      this.#render();
      const ip = await session.verifyExitIp();
      this.#message = ip
        ? green(`global ON · exit IP ${ip}`)
        : yellow("global on, but internet check failed — DNS or VPN issue");
    } catch (err) {
      this.#message = red(`global failed: ${(err as Error).message}`);
      await session?.stop().catch(() => {});
      this.#global = null;
    } finally {
      this.#busy = false;
      this.#refreshNet();
      this.#render();
    }
  }

  async #disableGlobal(): Promise<void> {
    if (!this.#global) return;
    this.#busy = true;
    this.#message = dim("restoring networking…");
    this.#render();
    const session = this.#global;
    this.#global = null;
    this.#globalCountry = null;
    try {
      await session.stop();
      this.#message = dim("global off (SOCKS proxy still on)");
    } finally {
      this.#busy = false;
      this.#refreshNet();
      this.#render();
    }
    if (this.#proxyStale) await this.#restartProxy();
  }

  /** The proxy address; one port serves both SOCKS5 and HTTP. Shared: the one other devices use. */
  #proxyAddr(): string {
    const host = this.#host === "0.0.0.0" ? (lanIp() ?? this.#host) : this.#host;
    return `${host}:${this.#proxy?.port ?? this.#port}`;
  }

  /** Keystrokes while the Settings popup is open. */
  #settingsKey(s: string, key: readline.Key): void {
    const e = this.#edit;
    if (e) {
      if (key.name === "escape") this.#edit = null;
      else if (key.name === "backspace") e.text = e.text.slice(0, -1);
      else if (key.name === "return") {
        if (e.key === "port" && !validPort(Number(e.text))) this.#settingsNote = red("A port is a number from 1 to 65535.");
        else {
          this.#edit = null;
          return void this.#changeSetting(
            e.key === "port"
              ? { port: Number(e.text) }
              : e.key === "username"
                ? { username: e.text }
                : e.key === "password"
                  ? { password: e.text }
                  : { relay: relayWith(this.#settings.relay, e.key === "relayId" ? { deploymentId: e.text.trim() } : { authKey: e.text.trim() }) },
          );
        }
      } else if (e.key === "relayKey" && key.name === "tab") {
        e.text = newAuthKey(); // a strong key, to paste into Code.gs's AUTH_KEY
      } else if (e.key === "port") {
        if (/^\d$/.test(s) && e.text.length < 5) e.text += s;
      } else if (s && s.length === 1 && s >= " " && !key.ctrl && !key.meta && Buffer.byteLength(e.text + s) <= 255) {
        // HTTP Basic splits the username from the password at the first ":"
        if (e.key === "username" && s === ":") this.#settingsNote = red("A username can't contain “:”.");
        else e.text += s;
      }
      return this.#render();
    }
    switch (key.name) {
      case "escape":
      case "s":
        this.#settingsOpen = false;
        break;
      case "up":
      case "k":
        this.#setSel = (this.#setSel - 1 + SETTINGS.length) % SETTINGS.length;
        break;
      case "down":
      case "j":
        this.#setSel = (this.#setSel + 1) % SETTINGS.length;
        break;
      case "return":
      case "space": {
        const item = SETTINGS[this.#setSel].key;
        if (item === "share") return void this.#changeSetting({ share: !this.#settings.share });
        if (item === "relaySetup") return void ((this.#wizard = new RelayWizard(() => this.#render())), this.#render());
        // typed in place: the username and relay id start from the current value, the rest from scratch
        this.#edit = { key: item, text: item === "username" ? this.#settings.username : item === "relayId" ? (this.#settings.relay?.deploymentId ?? "") : "" };
        this.#settingsNote = "";
      }
    }
    this.#render();
  }

  /** Keystrokes while the relay's setup is open; it finishes by saving the relay, back in Settings. */
  #wizardKey(s: string, key: readline.Key): void {
    const done = this.#wizard!.key(s, key);
    if (done) this.#wizard = null;
    if (done && done !== "close") {
      return void this.#changeSetting({ relay: done }).then(() => {
        // in Settings, or (opened from the blocked popup) the status line
        if (this.#settings.relay) this.#settingsNote = this.#message = green("✓ Relay set up. foxhole uses it whenever vpn.mozilla.org is blocked.");
        this.#render();
      });
    }
    this.#render();
  }

  /** Keystrokes while the Split tunneling popup is open. */
  #splitKey(s: string, key: readline.Key): void {
    const sp = this.#settings.split;
    const n = sp.rules.length;
    const e = this.#splitEdit;
    if (e !== null) {
      if (key.name === "tab") return void (this.#nextRecent(), this.#render());
      this.#splitTab = null;
      if (key.name === "escape") this.#splitEdit = null;
      else if (key.name === "return") return this.#addRule(e);
      else if (key.name === "backspace") this.#splitEdit = e.slice(0, -1);
      else if (s && s.length === 1 && s > " " && !key.ctrl && !key.meta && e.length < 253) this.#splitEdit = e + s;
      return this.#render();
    }
    const sel = this.#splitSel;
    switch (key.name) {
      case "escape":
      case "t":
        this.#splitOpen = false;
        break;
      case "up":
      case "k":
        this.#splitSel = (sel - 1 + n + 2) % (n + 2);
        break;
      case "down":
      case "j":
        this.#splitSel = (sel + 1) % (n + 2);
        break;
      case "return":
      case "space":
        if (sel === 0) return this.#saveSplit({ ...sp, default: flip(sp.default) });
        if (sel <= n) return this.#saveSplit({ ...sp, rules: sp.rules.map((r, i) => (i === sel - 1 ? { ...r, via: flip(r.via) } : r)) });
        this.#splitEdit = "";
        this.#splitNote = "";
        break;
      case "a":
        this.#splitSel = n + 1;
        this.#splitEdit = "";
        this.#splitNote = "";
        break;
      case "x":
      case "delete":
      case "backspace":
        if (sel >= 1 && sel <= n) return this.#saveSplit({ ...sp, rules: sp.rules.filter((_, i) => i !== sel - 1) });
        break;
      case "i":
        if (!n && sp.default === "vpn") return this.#addRule("*.ir");
    }
    this.#render();
  }

  /** Adds a typed site, going the other way than everything else. */
  #addRule(text: string): void {
    const sp = this.#settings.split;
    const match = parseSite(text);
    if (!match) {
      this.#splitNote = red(text.trim() ? `Not a site: “${fit(text.trim(), 24)}”. Try bbc.co.uk, *.ir or 1.2.3.4.` : "Type a site first.");
      return this.#render();
    }
    this.#splitEdit = null;
    const i = sp.rules.findIndex((r) => r.match === match);
    if (i >= 0) {
      this.#splitSel = i + 1;
      this.#splitNote = yellow(`${match} is already in the list.`);
      return this.#render();
    }
    this.#splitSel = sp.rules.length + 1; // the new row
    this.#saveSplit({ ...sp, rules: [...sp.rules, { match, via: flip(sp.default) }] });
  }

  /** Tab while typing: the next site seen lately that has what was typed, and isn't listed yet. */
  #nextRecent(): void {
    const tab = (this.#splitTab ??= { query: this.#splitEdit ?? "", i: -1 });
    const listed = new Set(this.#settings.split.rules.map((r) => r.match));
    const found = recentSites.filter((site) => site.includes(tab.query) && !listed.has(site));
    if (!found.length) {
      this.#splitNote = dim(tab.query ? `No site seen lately has “${fit(tab.query, 24)}”.` : "No sites seen yet: browse through foxhole first.");
      return;
    }
    tab.i = (tab.i + 1) % found.length;
    this.#splitEdit = found[tab.i];
    this.#splitNote = dim(`${tab.i + 1} of ${found.length} seen lately · tab next`);
  }

  /** Saves the rules: the proxy reads them live, so the next connection follows them. */
  #saveSplit(split: Split): void {
    const next = { ...this.#settings, split };
    try {
      saveSettings(next);
    } catch (err) {
      this.#splitNote = red(`Couldn't save: ${(err as Error).message}`);
      return this.#render();
    }
    this.#settings = next;
    this.#global?.splitChanged();
    this.#splitNote = "";
    this.#splitSel = Math.min(this.#splitSel, split.rules.length + 1);
    this.#render();
  }

  /** Looks up, in the background, whether a firewall would keep other devices off the proxy's port. */
  #checkFirewall(): void {
    void firewallHint(this.#settings.port).then((hint) => ((this.#fwHint = hint), this.#render()));
  }

  /** Saves a change and applies it: a new address or port restarts a running proxy. */
  async #changeSetting(patch: Partial<Settings>): Promise<void> {
    const next = { ...this.#settings, ...patch };
    try {
      saveSettings(next);
    } catch (err) {
      this.#settingsNote = red(`Couldn't save: ${(err as Error).message}`);
      return this.#render();
    }
    this.#settings = next;
    this.#settingsNote = "";
    if ("relay" in patch) useRelay(loadRelay(next)); // takes effect at once, no restart
    if ("share" in patch || "port" in patch) {
      this.#host = proxyHost(next);
      this.#port = next.port;
      this.#checkFirewall();
      await this.#restartProxy();
    }
    this.#render();
  }

  /** Moves a running proxy to the current address and port. Not in global mode: tun2socks is tied to the old one. */
  /** Starts the proxy on the current address, and remembers which that is. */
  #startProxy(): Promise<ProxyHandle> {
    this.#proxyAt = `${this.#host}:${this.#port}`;
    return startProxy(this.#conn, this.#host, this.#port, this.#login);
  }

  async #restartProxy(): Promise<void> {
    if (!this.#proxy) return;
    if (this.#global) {
      // only a real change waits for global off (sharing switched on and back off isn't one)
      this.#proxyStale = `${this.#host}:${this.#port}` !== this.#proxyAt;
      this.#settingsNote = this.#proxyStale ? yellow("Applies when global mode is turned off.") : "";
      return;
    }
    this.#proxyStale = false;
    this.#busy = true;
    this.#render();
    try {
      await this.#proxy.close();
      this.#proxy = null;
      this.#proxy = await this.#startProxy();
      this.#message = green(`proxy now on ${this.#proxyAddr()}`);
    } catch (err) {
      // e.g. the port is taken: nothing listens now, so say disconnected
      this.#active = null;
      this.#message = red(`proxy couldn't start on ${this.#host}:${this.#port}: ${(err as Error).message} — disconnected`);
    } finally {
      this.#busy = false;
      this.#refreshNet();
    }
  }

  #settingsPopup(): string[] {
    const s = this.#settings;
    const e = this.#edit;
    const cursor = cyan("▏");
    // long values (the 57-char deployment id, the key) would widen the box: scroll the tail while typing, middle-truncate at rest
    const relayVal = (full: string, editing: boolean, masked: boolean) =>
      editing
        ? (full.length > 23 ? "…" + full.slice(-22) : full) + cursor
        : !full
          ? dim("off")
          : masked
            ? "••••••••"
            : full.length > 22 ? full.slice(0, 11) + "…" + full.slice(-6) : full;
    const values = [
      onOff(s.share),
      e?.key === "port" ? e.text + cursor : String(s.port),
      e?.key === "username" ? e.text + cursor : s.username || dim("optional"),
      e?.key === "password" ? "•".repeat(e.text.length) + cursor : s.password ? "••••••••" : dim("optional"),
      (s.relay ? green("on") : dim("off")) + dim("  ⏎ step by step"),
      relayVal(e?.key === "relayId" ? e.text : s.relay?.deploymentId ?? "", e?.key === "relayId", false),
      relayVal(e?.key === "relayKey" ? e.text : s.relay?.authKey ?? "", e?.key === "relayKey", true),
    ];
    const w = Math.max(...SETTINGS.map((it) => it.label.length));
    const rows = SETTINGS.map((it, i) => {
      const here = i === this.#setSel;
      const label = it.label.padEnd(w);
      return `${here ? cyan("❯") : " "} ${here ? bold(label) : label}   ${values[i]}`;
    });
    const loginHelp = (what: string) =>
      e?.key === what
        ? [dim(`Type the ${what} · enter save (empty: none) · esc cancel`)]
        : [dim("Asked from other devices when sharing is on; apps on"), dim("this computer don't need it. Optional: empty means no login.")];
    const relayGuide = [
      dim("Blocked vpn.mozilla.org (Iran)? Make your own free relay on"),
      dim("Google Apps Script: “VPN relay · set up” walks you through it."),
    ];
    const relayOn = [green("Relay on — used only when vpn.mozilla.org can't be reached."), dim("Clear both fields to turn it off.")];
    const help = {
      share: s.share
        ? [
            `Set your phone's Wi-Fi proxy to ${bold(cyan(`${lanIp() ?? "this computer's IP"}:${s.port}`))}.`,
            s.username || s.password
              ? dim("Devices sign in with the username and password below.")
              : yellow("No password: anyone on this network can use it. Set one below."),
            ...(this.#fwHint ? [dim("If they can't connect, open the port in the firewall:"), ...this.#fwHint.map((c) => cyan(c))] : []),
          ]
        : [dim("Only this computer can use the proxy."), dim("Turn on to use the VPN from your phone, on the same Wi-Fi.")],
      port: e?.key === "port"
        ? [dim("Type the new port · enter save · esc cancel")]
        : [dim("One port serves SOCKS5 and HTTP. Default 1080.")],
      username: loginHelp("username"),
      password: loginHelp("password"),
      relaySetup: s.relay ? relayOn : relayGuide,
      relayId: e?.key === "relayId"
        ? [dim("Paste your Apps Script deployment id · enter save · esc cancel")]
        : s.relay ? relayOn : relayGuide,
      relayKey: e?.key === "relayKey"
        ? [dim("Type or paste the auth key · tab: generate a strong one"), dim("enter save · esc cancel")]
        : s.relay ? relayOn : relayGuide,
    }[SETTINGS[this.#setSel].key];
    return box(
      ["", ...rows, "", ...help, this.#settingsNote, "", dim("↑↓ select · enter change · esc close")],
      { title: bold(cyan("⚙ Settings")), width: 66 },
    );
  }

  /** Redraws at most every 100 ms: tun2socks can log many lines a second while the Logs popup is open. */
  #renderSoon(): void {
    this.#renderTimer ??= setTimeout(() => {
      this.#renderTimer = null;
      this.#render();
    }, 100);
  }

  /** The fox's mood: what the connection is doing. */
  #mood(): Mood {
    return this.#busy || this.#loading ? "waiting" : this.#global ? "global" : this.#active ? "proxy" : "off";
  }

  /** The fox's next frame, over the last where the last render put it: only its lines that changed are drawn. */
  #animate(): void {
    const at = this.#foxAt;
    // resized: a render is coming, which places it anew
    if (!at || !screenOn || at.cols !== (process.stdout.columns || 80) || at.rows !== (process.stdout.rows || 24)) return;
    const lines = fox(this.#mood(), Date.now());
    const out = lines.map((l, i) => (l === this.#foxDrawn[i] ? "" : `\x1b[${at.y + i + 1};${at.x + 1}H${l}`)).join("");
    this.#foxDrawn = lines;
    if (out) process.stdout.write("\x1b[0m" + out);
  }

  #render(): void {
    if (!screenOn) return; // a late redraw (timer, log line) must not paint over the normal screen
    const u = this.#conn.usage;
    const data = !u
      ? dim("unknown")
      : u.unlimited
        ? green("unlimited")
        : `${bold(gb(u.remaining).replace(" GB", ""))} of ${gb(u.max)} left` + (u.reset ? dim(` · resets ${shortDate(u.reset)}`) : ""); // as Firefox shows it
    const gc = this.#globalCountry;
    const state = this.#global
      ? `${lit(" GLOBAL TUN ON ")} ${green(flagged(gc!.code, countryName(gc!.code, gc!.name)))}`
      : this.#active
        ? green(`● connected ${flagged(this.#active.code, countryName(this.#active.code, this.#active.name))}`)
        : dim("○ disconnected");
    const sp = this.#settings.split;
    const split = splitSummary(sp);
    const route = this.#global
      ? green(sp.default === "vpn" ? "all system traffic → VPN" : "system traffic → direct") + (split ? dim(` · ${split}`) : "")
      : this.#active
        ? `${cyan(this.#proxyAddr())}  ${dim([split ? "" : "SOCKS5 or HTTP", this.#host === "0.0.0.0" ? "shared on this network" : "", split ?? ""].filter(Boolean).join(" · "))}`
        : dim("—");
    const status = this.#message;
    const net = this.#net === undefined ? dim("checking…") : this.#net ?? yellow("offline");
    const ip = this.#ip === undefined ? dim("checking…") : this.#ip === null ? yellow("unreachable") : `${bold(this.#ip)}  ${dim(this.#ipNote)}`;
    const account = `${this.#email ?? dim("unknown")}  ${dim("O to log out")}`;
    const cols = process.stdout.columns || 80, rows = process.stdout.rows || 24;
    const wide = cols >= SIDE_W;
    // A long value (e.g. a --verbose proxy error) would widen the box past the terminal, or its panel, and wrap.
    const room4value = (wide ? LEFT_W : cols - 6) - 9; // border 4, slack 2; label and gap 9
    const headLines = [
      ["account", account],
      ["data", data],
      ["network", net],
      ["ip", ip],
      ["route", route],
      ["status", status],
    ].map(([label, value]) => `${dim(label.padEnd(8))} ${fit(value, room4value)}`);

    const version = versionLines(true);
    // A short window drops the tips, then the fox, before the buttons (they name the keys) get cut off.
    const foot = 4 + version.length; // a blank line, the buttons, a blank line, the version, the link
    const foxOn = wide ? rows - foot >= FOX_H + 9 : rows - 18 - version.length - (FOX_H + 1) >= 5;
    const tips = wide
      ? rows - foot - 3 >= (foxOn ? FOX_H + 9 : 9)
      : foxOn ? rows - 21 - version.length - (FOX_H + 1) >= 5 : rows >= 22;
    const room = Math.max(3, wide
      ? rows - foot - (tips ? 3 : 0) - 6 // beside the details: the window's height
      : rows - (tips ? 21 : 18) - version.length - (foxOn ? FOX_H + 1 : 0));
    const { start, slice } = window(this.#sel, this.#countries.length, room);
    const label = (c: Country) => flagged(c.code, countryName(c.code, c.name));
    const body = slice.map((i) => {
      const c = this.#countries[i];
      const here = i === this.#sel;
      const mark = !c.available ? red("×") : this.#active?.code === c.code ? green("●") : dim("○");
      return [
        `${here ? cyan("❯") : " "} ${mark}`,
        here ? bold(c.code) : dim(c.code),
        c.locked ? `${dim(strike("paid"))} ${green("free")}` : green("free"),
        here ? bold(cyan(label(c))) : label(c),
      ];
    });
    if (!body.length) body.push(["   ", "", "", dim("loading…")]);
    const range = this.#countries.length > room
      ? `${start + 1}–${start + slice.length} of ${this.#countries.length}`
      : this.#countries.length ? `${this.#countries.length} countries` : ""; // none yet: the list says loading…

    const title = bold(cyan(emoji("🦊 ") + "foxhole-vpn"));
    const key = (k: string, rest: string) => `[${under(k)}${rest}]`;
    // Lit while on, each part on its own: the underline's reset would end an outer style
    const globalBtn = this.#global ? ["[", under("G"), "lobal TUN]"].map(lit).join("") : dim(key("G", "lobal TUN"));
    // On the connected country, D disconnects (lit like a switch that's on); elsewhere Enter connects
    const connectBtn = this.#active && this.#countries[this.#sel]?.code === this.#active.code
      ? ["[", under("D"), "isconnect]"].map(lit).join("")
      : bold(cyan("[⏎ Connect]"));
    // Lit while any site is split off, like a switch that's on
    const splitBtn = splitOn(sp) ? ["[Split ", under("T"), "unnel]"].map(lit).join("") : dim(`[Split ${under("T")}unnel]`);
    const buttons = [connectBtn, globalBtn, splitBtn, dim(key("S", "ettings")), dim(key("L", "ogs")), dim(key("Q", "uit"))].join("  ");
    const table = (minWidth: number) => grid(["", "Code", "Tier", "Country"], body, { caption: bold("Locations"), captionRight: dim(range), minWidth });
    // Under a popup, its shape alone: the backdrop's colors go, which would leave half of each two-color cell
    const covered = this.#restoring || this.#pwMode || this.#settingsOpen || this.#splitOpen || this.#logsOpen;
    const foxLines = foxOn ? fox(this.#mood(), Date.now(), covered) : [];
    let panels: string[];
    let foxX: number, foxY: number; // where the fox is in the frame
    let tableX = 0, tableY: number, tableW: number; // and the table's first country
    if (wide) {
      // the panel and the table as tall as each other: the window's height, or the fox's
      const height = Math.max(foxOn ? FOX_H + 9 : 8, 6 + body.length);
      while (body.length < height - 6) body.push(["", "", "", ""]);
      // the fox above the details, the two in the middle of the panel
      const group = [...foxLines.map((l) => centerIn(l, LEFT_W)), ...(foxOn ? [""] : []), ...headLines];
      const gap = Math.floor((height - 2 - group.length) / 2);
      const side = box([...Array<string>(gap).fill(""), ...group, ...Array<string>(height - 2 - gap - group.length).fill("")], {
        title, right: state, width: LEFT_W,
      });
      const t = table(TABLE_W);
      panels = side.map((l, i) => `${l} ${t[i]}`);
      [foxX, foxY] = [2 + Math.floor((LEFT_W - FOX_W) / 2), 1 + gap];
      [tableX, tableY, tableW] = [vw(side[0]) + 1, 5, vw(t[0])]; // after its caption and headings
    } else {
      const head = [...foxLines, ...(foxOn ? [""] : []), ...headLines];
      const t = table(Math.max(vw(box(head, { title, right: state })[0]), vw(buttons), 78)); // a steady 78, whichever buttons show: fits an 80-column terminal
      const inner = vw(t[0]) - 4;
      panels = [...box(head.map((l, i) => (i < foxLines.length ? centerIn(l, inner) : l)), { title, right: state, width: inner }), ...t];
      [foxX, foxY] = [2 + Math.floor((inner - FOX_W) / 2), 1];
      [tableY, tableW] = [head.length + 2 + 5, vw(t[0])]; // the head box, then the table's caption and headings
    }
    const width = vw(panels[0]);
    const frame = [
      ...panels,
      // The free locations' IPs are shared widely, so picky sites flag them.
      ...(tips ? [
        centerIn(dim(emoji("💡 ") + "Claude, ChatGPT, Gemini, Netflix, YouTube Music, Spotify and banks"), width),
        // Each part dimmed on its own: an inner style's reset would end an outer dim.
        centerIn(["often block shared VPN IPs: pick a ", under("paid location"), " for them."].map(dim).join(""), width),
        centerIn(["Foxhole made the paid servers ", green("free")].map(dim).join("") + " for you" + emoji(" 🦊"), width),
      ] : []),
      "",
      centerIn(buttons, width),
      "",
      ...version.map((l) => centerIn(l, width)),
      centerIn(dim(repoLink), width),
    ];
    const popup = this.#restoring
      ? this.#restoringPopup()
      : this.#pwMode
        ? this.#passwordPopup()
        : this.#wizard
          ? this.#wizard.render(cols, frame.length - 2)
          : this.#blocked
          ? this.#blockedPopup()
          : this.#settingsOpen
          ? this.#settingsPopup()
          : this.#splitOpen
            ? this.#splitPopup(frame.length)
            : this.#logsOpen
            ? this.#logsPopup(width, frame.length)
            : null;
    const { top, left } = draw(popup ? overlay(frame, popup, width) : frame);
    // the wizard's screenshot as a real picture, over the room it left (as overlay() places the popup: centered, a 1-cell margin)
    if (GRAPHICS) {
      const at = popup && this.#wizard?.picture ? this.#wizard.picture : null;
      const y = top + Math.floor((frame.length - (popup?.length ?? 0) - 2) / 2) + 1, x = left + Math.floor((width - (popup ? vw(popup[0]) : 0) - 2) / 2) + 1;
      process.stdout.write(pictureAt(at, y, x));
    }
    // the fox's next frames go over this one (#animate); under a popup it waits
    this.#foxAt = foxOn && !popup ? { x: left + foxX, y: top + foxY, cols, rows } : null;
    this.#foxDrawn = foxLines;
    const buttonsY = frame.length - version.length - 3;
    // as overlay() places it: centered, with a 1-cell margin; the rows follow the border and a blank line
    const setW = popup ? vw(popup[0]) : 0;
    this.#hit = {
      top, left, buttonsY, setW,
      rowsTop: tableY, rowsLeft: tableX, width: tableW,
      start,
      rows: slice.length,
      buttons: frame[buttonsY].replace(/\x1b\[[0-9;]*m/g, ""),
      setTop: Math.floor((frame.length - (popup?.length ?? 0) - 2) / 2) + 3,
      setX: Math.floor((width - setW - 2) / 2) + 1,
    };
  }

  /** The Split tunneling popup: everything else's way, then each rule's, with how many connections each took. */
  #splitPopup(frameHeight: number): string[] {
    const sp = this.#settings.split;
    const e = this.#splitEdit;
    const way = (v: Via) => (v === "vpn" ? green("VPN") : yellow("direct"));
    const took = (k: string) => (hits.get(k) ? dim(`${hits.get(k)} matched`) : "");
    const all = [
      { label: "Everything else", way: way(sp.default), took: took("") },
      ...sp.rules.map((r) => ({ label: r.match, way: way(r.via), took: took(r.match) })),
      { label: e !== null ? (e.length > 33 ? `…${e.slice(-32)}` : e) + cyan("▏") : dim("+ add a site"), way: "", took: "" }, // typing: its end shows
    ];
    const room = Math.max(3, frameHeight - 13); // what fits beside the popup's other lines
    const { start, slice } = window(this.#splitSel, all.length, room);
    this.#splitStart = start;
    this.#splitShown = slice.length;
    const pad = (str: string, w: number) => str + " ".repeat(Math.max(1, w - vw(str)));
    const rows = slice.map((i) => {
      const here = i === this.#splitSel;
      const label = fit(all[i].label, 34);
      return `${here ? cyan("❯") : " "} ${pad(here && i <= sp.rules.length ? bold(label) : label, 36)}${pad(all[i].way, 8)}${all[i].took}`;
    });
    const sel = this.#splitSel;
    const help =
      e !== null
        ? [dim("Type a site: bbc.co.uk (and its subdomains), *.co.uk, ir,"), dim("1.2.3.4 or 10.0.0.0/8 · tab: seen lately · enter add · esc cancel")]
        : sel === 0
          ? [sp.default === "vpn" ? "Sites not listed use the VPN: list the ones to bypass it." : "Sites not listed go direct: list the ones that need the VPN.", dim("enter switches it")]
          : sel <= sp.rules.length
            ? [dim("A site covers its subdomains; the most specific rule wins."), dim("Direct sites see your real IP. Applies to new connections.")]
            : [dim(`A new site goes ${sp.default === "vpn" ? "direct" : "through the VPN"}: the other way from the rest.`), ""];
    const tip = !sp.rules.length && sp.default === "vpn" && e === null ? [`Tip: press ${under("i")} to send Iranian sites (*.ir) direct.`] : [];
    return box(
      ["", ...rows, "", ...help, ...tip, this.#splitNote, "", dim("↑↓ select · enter VPN/direct · a add · x delete · esc close")],
      { title: bold(cyan("⇄ Split tunneling")), width: 66 },
    );
  }

  /** The Logs popup: the newest lines that fit, updated live while open. */
  #logsPopup(width: number, frameHeight: number): string[] {
    const inner = width - 6; // box border + padding (4) and the overlay's margin (2)
    const rows = Math.max(3, frameHeight - 6); // box top/bottom, margin, footer
    const shown = logLines.slice(-rows);
    const body = shown.length
      ? shown.map((l) => fit(dim(l.slice(0, 8)) + l.slice(8), inner)) // dim the HH:MM:SS
      : [dim("Nothing logged yet. Proxy failures (e.g. ports the VPN refuses)"), dim("and tun2socks output in global mode appear here.")];
    const padded = [...body, ...Array<string>(Math.max(0, rows - body.length)).fill("")];
    const count = logLines.length > rows ? `newest ${rows} of ${logLines.length}` : `${logLines.length} lines`;
    const footer = `${dim(`c copy · esc close · ${count}`)}${this.#logsNote && `  ${this.#logsNote}`}`;
    return box([...padded, footer], { title: bold(cyan("Logs")), width: inner });
  }

  /** Copies every log line to the clipboard, not just the newest shown, and says how it went. */
  async #copyLogs(): Promise<void> {
    if (!logLines.length) this.#logsNote = dim("nothing to copy yet");
    else if (await copyText(logLines.join("\n") + "\n")) this.#logsNote = green(`✓ copied all ${logLines.length} lines to the clipboard`);
    else this.#logsNote = yellow(process.platform === "linux" ? "couldn't copy: install wl-clipboard or xclip" : "couldn't copy to the clipboard");
    this.#render();
  }

  /** The popup shown while quitting restores global mode's routes and DNS. */
  /** Shows the blocked popup when err says vpn.mozilla.org is blocked here (with no relay set); whether it did. */
  #saysBlocked(err: unknown): boolean {
    if (!(err instanceof GuardianBlocked)) return false;
    this.#blocked = this.#blockedTold = true;
    return true;
  }

  #blockedPopup(): string[] {
    return box(
      [
        "",
        bold(yellow("Mozilla's VPN service is blocked here")),
        "",
        "It seems your government or internet provider blocks",
        "Firefox's VPN service (vpn.mozilla.org) in your country.",
        "",
        "Set up a relay to get around it: a free script on your",
        "own Google account that reaches it for foxhole. It takes",
        "a few minutes, and foxhole shows you each click.",
        "",
        `${bold(cyan("[⏎ Set up a relay]"))}   ${dim("[esc Not now]")}`,
        "",
      ],
      { title: bold(yellow("vpn.mozilla.org blocked")) },
    );
  }

  #restoringPopup(): string[] {
    return box(
      [
        "",
        "Restoring networking…",
        "",
        emoji("🦊 ") + "The fox is putting your routes and DNS",
        emoji("   ") + "back exactly where it found them.",
        "",
        yellow("Please don't force quit: a half-tidied"),
        yellow("den means no internet until you reboot."),
        "",
        dim("Just a moment, then foxhole closes by itself."),
        "",
      ],
      { title: bold(yellow("Quitting")), width: 48 },
    );
  }

  /** The popup asking for the sudo password (sudo wants the user's own login password). */
  #passwordPopup(): string[] {
    const field = "•".repeat(this.#pw.length) + (this.#pwChecking ? "" : cyan("▏"));
    const note = this.#pwChecking ? dim("checking…") : this.#pwError ? red(this.#pwError) : "";
    return box(
      [
        "",
        "Global mode routes all of this computer's",
        "traffic through the VPN, which needs",
        "administrator rights.",
        "",
        `Enter your ${bold("login password")} (used by sudo):`,
        "",
        `  ${field}`,
        `  ${note}`,
        "",
        dim("enter OK · esc cancel"),
      ],
      { title: bold(yellow(emoji("🔒 ") + "Administrator password")), width: 44 },
    );
  }
}

/** Returns the visible slice of indices centred on the selection. */
function window(sel: number, total: number, room: number): { start: number; slice: number[] } {
  if (total <= room) return { start: 0, slice: Array.from({ length: total }, (_, i) => i) };
  let start = Math.min(Math.max(0, sel - Math.floor(room / 2)), total - room);
  return { start, slice: Array.from({ length: room }, (_, i) => start + i) };
}
