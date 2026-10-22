import readline from "node:readline";
import { PassThrough } from "node:stream";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { userHome, findAccount } from "./profile.js";
import { fetchServerList, type Country } from "./serverlist.js";
import { Connection } from "./connection.js";
import { NotImplementedError } from "./auth.js";
import { GuardianError } from "./guardian.js";
import { network, publicIp, lanIp } from "./netinfo.js";
import { loadSettings, saveSettings, proxyHost, validPort, type Settings } from "./settings.js";
import { forgetToken } from "./tokenserver.js";
import { startProxy, onProxyWarning, type ProxyHandle } from "./proxy.js";
import { logLines, onLog } from "./log.js";
import { GlobalSession, sudoPriv, directPriv, isPrivileged, validateSudo, sudoUsesTouchId, touchIdSudo, ensureTun2socks, dialHost } from "./global.js";
import { checkUpdate, canUpdate, runUpdate, versionLines } from "./update.js";
import { bold, dim, under, strike, green, red, yellow, cyan, flag, countryName, gb, shortDate, vw, fit, box, grid, centerIn, draw, overlay, repoLink, REPO_URL, linkAt, openUrl } from "./ui.js";

const ESC = "\x1b[";
// alternate screen + hidden cursor + mouse reports (SGR): clicks and the wheel, see #mouse()
const ALT_ON = `${ESC}?1049h${ESC}?25l${ESC}?1000h${ESC}?1006h`;
const ALT_OFF = `${ESC}?1000l${ESC}?1006l${ESC}?25h${ESC}?1049l`;
let screenOn = false;
/** Back to the normal screen with mouse reports off; also runs on exit, so a crash doesn't leave them on. */
function leaveScreen(): void {
  if (!screenOn) return;
  screenOn = false;
  process.stdout.write(ALT_OFF);
}
process.on("exit", leaveScreen);

const REFRESHING = dim("refreshing…");
const LOGOUT_ASK = yellow("press O again to log out and switch accounts");
const onOff = (v: boolean) => (v ? green("on") : dim("off"));

/** The Settings popup's rows, in order. */
const SETTINGS = [
  { key: "share", label: "Share with devices on this network" },
  { key: "port", label: "Proxy port" },
  { key: "autoConnect", label: "Auto connect" },
] as const;

/** The last country connected to; the next start puts the cursor on it. */
const lastCountryFile = () => join(userHome(), ".config", "foxhole-vpn", "country");

function loadLastCountry(): string | null {
  try {
    return readFileSync(lastCountryFile(), "utf8").trim() || null;
  } catch {
    return null;
  }
}

function saveLastCountry(code: string): void {
  try {
    mkdirSync(dirname(lastCountryFile()), { recursive: true, mode: 0o700 });
    writeFileSync(lastCountryFile(), code);
  } catch {
    // only a convenience; never fail a connect over it
  }
}

/** Sort order: free & usable first, then paid, each alphabetical. */
function order(list: Country[]): Country[] {
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
  #setSel = 0;
  #portEdit: string | null = null; // the port being typed, while editing it
  #settingsNote = "";
  #proxyStale = false; // the running proxy still has the old address (changed during global mode)
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
  #logsOpen = false; // the Logs popup is open
  #restoring = false; // quitting: global mode's routes are being put back
  #renderTimer: NodeJS.Timeout | null = null;
  #net: string | null | undefined; // undefined: not read yet
  #ip: string | null | undefined; // undefined: checking
  #ipNote = "";
  #netSeq = 0; // drops answers from an older check
  // where the last render put the clickable parts; rows are frame lines, x columns in the frame
  #hit = { top: 0, left: 0, rowsTop: 0, start: 0, rows: 0, width: 0, buttonsY: -1, buttons: "", setTop: -1, setX: 0, setW: 0 };
  readonly #email = findAccount()?.email ?? null; // the Firefox account the token came from

  constructor(conn: Connection, host: string, port: number) {
    this.#conn = conn;
    this.#host = host;
    this.#port = port;
  }

  /** Resolves "logout" when the user logged out, so the caller can forget the token. */
  async run(): Promise<"logout" | undefined> {
    onLog(() => this.#logsOpen && this.#renderSoon());
    onProxyWarning((msg) => {
      this.#message = red(`proxy: ${msg}`);
      this.#render();
    });
    screenOn = true;
    process.stdout.write(ALT_ON);
    this.#message = dim("loading…");
    this.#render();
    try {
      this.#countries = order(await fetchServerList());
      this.#sel = Math.max(0, this.#countries.findIndex((c) => c.code === loadLastCountry()));
      this.#message = "";
    } catch (err) {
      this.#message = red(`server list failed: ${(err as Error).message}`);
    }
    // Only to a country actually remembered, never to whatever sorts first.
    if (this.#settings.autoConnect && this.#countries[this.#sel]?.code === loadLastCountry()) void this.#connect();
    this.#refreshUsage();
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
      this.#ipNote = country ? `VPN · ${flag(country.code)} ${countryName(country.code, country.name)}` : "your real IP";
      this.#render();
    });
  }

  #refreshUsage(): void {
    this.#conn
      .refreshUsage()
      .then((usage) => {
        // only replace our own "refreshing…"; the startup call must not wipe other messages
        if (this.#message === REFRESHING) this.#message = usage ? dim("usage updated") : yellow("usage unavailable");
        this.#render();
      })
      .catch((err) => {
        if (err instanceof NotImplementedError) {
          this.#message = yellow("token step not implemented — see AUTH.md (data unknown)");
        } else {
          this.#message = dim(`usage unavailable: ${(err as Error).message}`);
        }
        this.#render();
      });
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
        });
        if (rest) input.write(rest);
      };
      process.stdin.on("data", onData);
      if (process.stdin.isTTY) process.stdin.setRawMode(true);
      process.stdin.resume();
      const onResize = () => this.#render();
      process.stdout.on("resize", onResize);

      // Ctrl+C outside raw mode, a closed terminal or a kill: quit properly, so the
      // screen and mouse mode are restored and global mode puts the routes back.
      // SIGBREAK: Ctrl+Break on Windows.
      const signals = ["SIGINT", "SIGTERM", "SIGHUP", ...(process.platform === "win32" ? ["SIGBREAK"] as const : [])];
      const onSignal = () => void quit();
      for (const sig of signals) process.on(sig, onSignal);

      const quit = async (action?: "update" | "logout") => {
        for (const sig of signals) process.removeListener(sig, onSignal);
        input.removeListener("keypress", onKey); // keys now do nothing (and a second quit can't start)
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
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.stdin.pause();
        leaveScreen();
        if (action === "update") {
          runUpdate(); // runs npm in this terminal (asks for sudo if needed)
          console.log(green("\nUpdated. Start foxhole-vpn again to use the new version."));
        }
        resolve(action);
      };

      const onKey = (s: string, key: readline.Key) => {
        if (!key) return;
        if (key.ctrl && key.name === "c") return void quit();
        if (this.#pwMode) return this.#pwKey(s, key);
        if (this.#logsOpen) {
          // the popup only closes; other keys stay with it, so nothing happens behind it
          if (key.name === "escape" || key.name === "l") (this.#logsOpen = false), this.#render();
          return;
        }
        if (this.#settingsOpen) return this.#settingsKey(s, key);
        if (key.name === "q") return void quit();
        if (key.name === "l") return void ((this.#logsOpen = true), this.#render());
        if (this.#busy) return;
        if (key.name === "s") {
          this.#settingsOpen = true;
          this.#settingsNote = "";
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
          case "r":
            this.#message = REFRESHING;
            this.#refreshUsage();
            this.#refreshNet();
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
    if (b !== 0 || this.#pwMode || this.#logsOpen || this.#restoring) return;
    const h = this.#hit;
    const fx = x - h.left, fy = y - h.top;
    if (this.#settingsOpen) {
      const i = fy - h.setTop;
      if (this.#portEdit !== null || i < 0 || i >= SETTINGS.length || fx < h.setX || fx >= h.setX + h.setW) return;
      this.#setSel = i;
      return press("return");
    }
    if (linkAt(x, y)) return openUrl(REPO_URL);
    const k = fy - h.rowsTop;
    if (k >= 0 && k < h.rows && fx >= 0 && fx < h.width) {
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
      press(label.startsWith("⏎") ? "return" : label[0].toLowerCase());
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
      if (!this.#proxy) this.#proxy = await startProxy(this.#conn, this.#host, this.#port);
      await this.#conn.currentPass(); // warm the pass; surfaces auth/quota errors now
      this.#active = country;
      if (this.#global) this.#globalCountry = country;
      saveLastCountry(country.code);
      this.#message = green("connected");
    } catch (err) {
      if (err instanceof NotImplementedError) {
        this.#message = yellow("can't connect: token step not implemented (see AUTH.md)");
      } else if (err instanceof GuardianError && err.status === 401) {
        forgetToken(); // so the next start shows the token window
        this.#message = red("token rejected (expired) — quit and run foxhole again to get a new one");
      } else {
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
    if (process.platform === "win32") {
      // Windows has no sudo to ask: the whole app must already run as Administrator.
      if (await isPrivileged()) return void this.#enableGlobal(null);
      this.#message = yellow("global needs Administrator rights — quit, then run foxhole in Terminal (Admin)");
      return void this.#render();
    }
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

  /** password: for sudo; null when already privileged (Windows, elevated). */
  async #enableGlobal(password: string | null): Promise<void> {
    const server = this.#conn.server;
    if (!server || !this.#proxy) return;
    this.#busy = true;
    this.#message = dim("preparing tun2socks…");
    this.#render();
    let session: GlobalSession | null = null;
    try {
      this.#tun2socksPath ??= await ensureTun2socks();
      this.#message = dim("going global…");
      this.#render();
      session = new GlobalSession({
        priv: password === null ? directPriv(true) : sudoPriv(password),
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
    if (this.#portEdit !== null) {
      if (key.name === "escape") this.#portEdit = null;
      else if (key.name === "backspace") this.#portEdit = this.#portEdit.slice(0, -1);
      else if (key.name === "return") {
        const port = Number(this.#portEdit);
        if (!validPort(port)) this.#settingsNote = red("A port is a number from 1 to 65535.");
        else {
          this.#portEdit = null;
          return void this.#changeSetting({ port });
        }
      } else if (/^\d$/.test(s) && this.#portEdit.length < 5) this.#portEdit += s;
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
        if (item === "port") {
          this.#portEdit = "";
          this.#settingsNote = "";
        } else return void this.#changeSetting({ [item]: !this.#settings[item] });
      }
    }
    this.#render();
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
    if ("share" in patch || "port" in patch) {
      this.#host = proxyHost(next);
      this.#port = next.port;
      await this.#restartProxy();
    }
    this.#render();
  }

  /** Moves a running proxy to the current address and port. Not in global mode: tun2socks is tied to the old one. */
  async #restartProxy(): Promise<void> {
    if (!this.#proxy) return;
    if (this.#global) {
      this.#proxyStale = true;
      this.#settingsNote = yellow("Applies when global mode is turned off.");
      return;
    }
    this.#proxyStale = false;
    this.#busy = true;
    this.#render();
    try {
      await this.#proxy.close();
      this.#proxy = null;
      this.#proxy = await startProxy(this.#conn, this.#host, this.#port);
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
    const values = [
      onOff(s.share),
      this.#portEdit !== null ? `${this.#portEdit}${cyan("▏")}` : String(s.port),
      onOff(s.autoConnect),
    ];
    const w = Math.max(...SETTINGS.map((it) => it.label.length));
    const rows = SETTINGS.map((it, i) => {
      const here = i === this.#setSel;
      const label = it.label.padEnd(w);
      return `${here ? cyan("❯") : " "} ${here ? bold(label) : label}   ${values[i]}`;
    });
    const last = this.#countries.find((c) => c.code === loadLastCountry());
    const help = {
      share: s.share
        ? [
            `Set your phone's Wi-Fi proxy to ${bold(cyan(`${lanIp() ?? "this computer's IP"}:${s.port}`))}.`,
            yellow("No password: anyone on this network can use it, and your data."),
          ]
        : [dim("Only this computer can use the proxy."), dim("Turn on to use the VPN from your phone, on the same Wi-Fi.")],
      port: this.#portEdit !== null
        ? [dim("Type the new port · enter save · esc cancel")]
        : [dim("One port serves SOCKS5 and HTTP. Default 1080.")],
      autoConnect: [dim(last ? `Connects to ${flag(last.code)} ${countryName(last.code, last.name)} when foxhole opens.` : "Connects to the last country you used when foxhole opens.")],
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
      ? green(`● GLOBAL ${flag(gc!.code)} ${countryName(gc!.code, gc!.name)}`)
      : this.#active
        ? green(`● connected ${flag(this.#active.code)} ${countryName(this.#active.code, this.#active.name)}`)
        : dim("○ disconnected");
    const route = this.#global
      ? green("all system traffic → VPN")
      : this.#active
        ? `${cyan(this.#proxyAddr())}  ${dim(this.#host === "0.0.0.0" ? "SOCKS5 or HTTP · shared on this network" : "SOCKS5 or HTTP")}`
        : dim("—");
    const status = this.#message;
    // A long status (e.g. a --verbose proxy error) would widen the box past the terminal and wrap.
    const room4status = (process.stdout.columns || 80) - 20; // label 12, gap 2, border 4, slack 2
    const net = this.#net === undefined ? dim("checking…") : this.#net ?? yellow("offline");
    const ip = this.#ip === undefined ? dim("checking…") : this.#ip === null ? yellow("unreachable") : `${bold(this.#ip)}  ${dim(this.#ipNote)}`;
    const last = this.#settings.autoConnect && this.#countries.find((c) => c.code === loadLastCountry());
    const auto = !this.#settings.autoConnect
      ? `${onOff(false)}  ${dim("S to change")}`
      : `${onOff(true)}  ${dim(last ? `to ${flag(last.code)} ${countryName(last.code, last.name)}` : "to the last country used")}`;
    const account = `${this.#email ?? dim("unknown")}  ${dim("O to log out")}`;
    const headLines = [
      ["account", account],
      ["data", data],
      ["network", net],
      ["ip", ip],
      ["route", route],
      ["auto connect", auto],
      ["status", fit(status, room4status)],
    ].map(([label, value]) => `${dim(label.padEnd(12))}  ${value}`);

    const version = versionLines(true);
    const room = Math.max(3, (process.stdout.rows || 24) - 22 - version.length);
    const { start, slice } = window(this.#sel, this.#countries.length, room);
    const label = (c: Country) => `${flag(c.code)} ${countryName(c.code, c.name)}`;
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
      : `${this.#countries.length} countries`;

    const title = bold(cyan("🦊 foxhole-vpn"));
    const key = (k: string, rest: string) => `[${under(k)}${rest}]`;
    const buttons = [bold(cyan("[⏎ Connect]")), dim(key("G", "lobal TUN")), dim(key("D", "isconnect")), dim(key("R", "efresh")), dim(key("S", "ettings")), dim(key("L", "ogs")), dim(key("Q", "uit"))].join("  ");
    const headW = vw(box(headLines, { title, right: state })[0]);
    const table = grid(["", "Code", "Tier", "Country"], body, {
      caption: bold("Locations"),
      captionRight: dim(range),
      minWidth: Math.max(headW, vw(buttons)), // the button row is 78 wide: fits an 80-column terminal
    });
    const width = vw(table[0]);
    const frame = [
      ...box(headLines, { title, right: state, width: width - 4 }),
      ...table,
      // The free locations' IPs are shared widely, so picky sites flag them.
      centerIn(dim("💡 Claude, ChatGPT, Gemini, Netflix, YouTube Music, Spotify and banks"), width),
      // Each part dimmed on its own: an inner style's reset would end an outer dim.
      centerIn(["often block shared VPN IPs: pick a ", under("paid location"), " for them."].map(dim).join(""), width),
      centerIn(["Foxhole made the paid servers ", green("free")].map(dim).join("") + " for you 🦊", width),
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
        : this.#settingsOpen
          ? this.#settingsPopup()
          : this.#logsOpen
            ? this.#logsPopup(width, frame.length)
            : null;
    const { top, left } = draw(popup ? overlay(frame, popup, width) : frame);
    const buttonsY = frame.length - version.length - 3;
    // as overlay() places it: centered, with a 1-cell margin; the rows follow the border and a blank line
    const setW = popup ? vw(popup[0]) : 0;
    this.#hit = {
      top, left, width, buttonsY, setW,
      rowsTop: headLines.length + 2 + 5, // the head box, then the table's caption and headings
      start,
      rows: slice.length,
      buttons: frame[buttonsY].replace(/\x1b\[[0-9;]*m/g, ""),
      setTop: Math.floor((frame.length - (popup?.length ?? 0) - 2) / 2) + 3,
      setX: Math.floor((width - setW - 2) / 2) + 1,
    };
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
    return box([...padded, dim(`esc close · ${count}`)], { title: bold(cyan("Logs")), width: inner });
  }

  /** The popup shown while quitting restores global mode's routes and DNS. */
  #restoringPopup(): string[] {
    return box(
      [
        "",
        "Restoring networking…",
        "",
        "🦊 The fox is putting your routes and DNS",
        "   back exactly where it found them.",
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
      { title: bold(yellow("🔒 Administrator password")), width: 44 },
    );
  }
}

/** Returns the visible slice of indices centred on the selection. */
function window(sel: number, total: number, room: number): { start: number; slice: number[] } {
  if (total <= room) return { start: 0, slice: Array.from({ length: total }, (_, i) => i) };
  let start = Math.min(Math.max(0, sel - Math.floor(room / 2)), total - room);
  return { start, slice: Array.from({ length: room }, (_, i) => start + i) };
}
