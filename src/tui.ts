import readline from "node:readline";
import { PassThrough } from "node:stream";
import { fetchServerList, type Country } from "./serverlist.js";
import { Connection } from "./connection.js";
import { NotImplementedError } from "./auth.js";
import { GuardianError } from "./guardian.js";
import { forgetToken } from "./tokenserver.js";
import { startProxy, onProxyWarning, type ProxyHandle } from "./proxy.js";
import { GlobalSession, sudoPriv, validateSudo, ensureTun2socks } from "./global.js";
import { checkUpdate, canUpdate, runUpdate, versionLines } from "./update.js";
import { bold, dim, under, strike, green, red, yellow, cyan, flag, countryName, gb, shortDate, vw, fit, box, grid, centerIn, draw, repoLink, REPO_URL, linkAt, openUrl } from "./ui.js";

const ESC = "\x1b[";
// alternate screen + hidden cursor + mouse reports (SGR), so the repo link can be clicked
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

/** Sort order: free & usable first, then paid, each alphabetical. */
function order(list: Country[]): Country[] {
  return [...list].sort((a, b) => {
    const rank = (c: Country) => (!c.locked && c.available ? 0 : c.locked ? 2 : 1);
    return rank(a) - rank(b) || countryName(a.code, a.name).localeCompare(countryName(b.code, b.name));
  });
}

export class Tui {
  readonly #conn: Connection;
  readonly #host: string;
  readonly #port: number;
  #countries: Country[] = [];
  #sel = 0;
  #proxy: ProxyHandle | null = null;
  #active: Country | null = null;
  #message = "";
  #busy = false;
  #global: GlobalSession | null = null;
  #globalCountry: Country | null = null;
  #tun2socksPath: string | null = null;
  #pwMode = false;
  #pw = "";

  constructor(conn: Connection, host: string, port: number) {
    this.#conn = conn;
    this.#host = host;
    this.#port = port;
  }

  async run(): Promise<void> {
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
      this.#message = "";
    } catch (err) {
      this.#message = red(`server list failed: ${(err as Error).message}`);
    }
    this.#refreshUsage();
    void checkUpdate().then(() => this.#render()); // show the update notice once npm answers
    this.#render();
    await this.#loop();
  }

  #refreshUsage(): void {
    this.#conn
      .refreshUsage()
      .then(() => this.#render())
      .catch((err) => {
        if (err instanceof NotImplementedError) {
          this.#message = yellow("token step not implemented — see AUTH.md (data unknown)");
        } else {
          this.#message = dim(`usage unavailable: ${(err as Error).message}`);
        }
        this.#render();
      });
  }

  #loop(): Promise<void> {
    return new Promise((resolve) => {
      // stdin minus mouse reports: readline would split those into stray keypresses ("0", ";", "M"…).
      // SGR mouse report: ESC [ < button ; col ; row (M = press, m = release)
      // ponytail: assumes a report never straddles two reads, true for terminals in practice
      const input = new PassThrough();
      readline.emitKeypressEvents(input);
      const onData = (buf: Buffer) => {
        const rest = buf.toString().replace(/\x1b\[<(\d+);(\d+);(\d+)([Mm])/g, (_, b: string, x: string, y: string, kind: string) => {
          if (kind === "M" && b === "0" && linkAt(Number(x) - 1, Number(y) - 1)) openUrl(REPO_URL);
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
      const signals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
      const onSignal = () => void quit();
      for (const sig of signals) process.on(sig, onSignal);

      const quit = async (action?: "update") => {
        for (const sig of signals) process.removeListener(sig, onSignal);
        input.removeListener("keypress", onKey);
        process.stdin.removeListener("data", onData);
        process.stdout.removeListener("resize", onResize);
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.stdin.pause();
        // Give the terminal back first (mouse reports off): if cleanup is slow, clicks
        // and keys must not be echoed as ^[[<0;… junk, and text selection must work.
        leaveScreen();
        if (this.#global) {
          console.log("restoring networking…");
          await this.#global.stop().catch(() => {});
        }
        await this.#proxy?.close();
        if (action === "update") {
          runUpdate(); // runs npm in this terminal (asks for sudo if needed)
          console.log(green("\nUpdated. Start foxhole-vpn again to use the new version."));
        }
        resolve();
      };

      const onKey = (s: string, key: readline.Key) => {
        if (!key) return;
        if (key.ctrl && key.name === "c") return void quit();
        if (this.#pwMode) return this.#pwKey(s, key);
        if (key.name === "q") return void quit();
        if (this.#busy) return;
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
          case "r":
            this.#message = dim("refreshing…");
            this.#refreshUsage();
            break;
        }
        this.#render();
      };
      input.on("keypress", onKey);
    });
  }

  async #connect(): Promise<void> {
    const country = this.#countries[this.#sel];
    if (!country) return;
    this.#busy = true;
    this.#message = dim(`connecting to ${countryName(country.code, country.name)}…`);
    this.#render();
    try {
      await this.#conn.selectServer(country.locked ? country : country.available ? country : null);
      if (!this.#proxy) this.#proxy = await startProxy(this.#conn, this.#host, this.#port);
      await this.#conn.currentPass(); // warm the pass; surfaces auth/quota errors now
      this.#active = country;
      this.#message = green("connected");
    } catch (err) {
      if (err instanceof NotImplementedError) {
        this.#message = yellow("can't connect: token step not implemented (see AUTH.md)");
      } else if (err instanceof GuardianError && err.status === 401) {
        forgetToken(); // so the next start shows the token window
        this.#message = red("token rejected (expired) — quit and run foxhole again to get a new one");
      } else {
        this.#message = red(`connect failed: ${(err as Error).message}`);
      }
      if (this.#proxy && !this.#active) {
        await this.#proxy.close();
        this.#proxy = null;
      }
    } finally {
      this.#busy = false;
      this.#render();
    }
  }

  async #disconnect(): Promise<void> {
    if (this.#global) await this.#disableGlobal();
    if (!this.#proxy) return;
    await this.#proxy.close();
    this.#proxy = null;
    this.#active = null;
    this.#message = dim("disconnected");
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
    this.#pwMode = true;
    this.#pw = "";
    this.#render();
  }

  /** Keystrokes while the sudo-password prompt is open. */
  #pwKey(s: string, key: readline.Key): void {
    if (key.name === "escape") {
      this.#pwMode = false;
      this.#pw = "";
      this.#message = dim("cancelled");
    } else if (key.name === "return") {
      const pw = this.#pw;
      this.#pwMode = false;
      this.#pw = "";
      void this.#enableGlobal(pw);
      return;
    } else if (key.name === "backspace") {
      this.#pw = this.#pw.slice(0, -1);
    } else if (s && s.length === 1 && s >= " " && !key.ctrl && !key.meta) {
      this.#pw += s;
    }
    this.#render();
  }

  async #enableGlobal(password: string): Promise<void> {
    const server = this.#conn.server;
    if (!server || !this.#proxy) return;
    this.#busy = true;
    this.#message = dim("preparing tun2socks…");
    this.#render();
    let session: GlobalSession | null = null;
    try {
      this.#tun2socksPath ??= await ensureTun2socks();
      this.#message = dim("checking password…");
      this.#render();
      if (!(await validateSudo(password))) {
        this.#message = red("incorrect sudo password");
        return;
      }
      this.#message = dim("going global…");
      this.#render();
      session = new GlobalSession({
        priv: sudoPriv(password),
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
          this.#render();
        });
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
      this.#render();
    }
  }

  /** The proxy address; one port serves both SOCKS5 and HTTP. */
  #proxyAddr(): string {
    return `${this.#host}:${this.#proxy?.port ?? this.#port}`;
  }

  #render(): void {
    const u = this.#conn.usage;
    const data = !u
      ? dim("unknown")
      : u.unlimited
        ? green("unlimited")
        : `${bold(gb(u.remaining))} / ${gb(u.max)}` + (u.reset ? dim(` · resets ${shortDate(u.reset)}`) : "");
    const gc = this.#globalCountry;
    const state = this.#global
      ? green(`● GLOBAL ${flag(gc!.code)} ${countryName(gc!.code, gc!.name)}`)
      : this.#active
        ? green(`● connected ${flag(this.#active.code)} ${countryName(this.#active.code, this.#active.name)}`)
        : dim("○ disconnected");
    const route = this.#global
      ? green("all system traffic → VPN")
      : this.#active
        ? `${cyan(this.#proxyAddr())}  ${dim("SOCKS5 or HTTP")}`
        : dim("—");
    // The sudo prompt takes the status row, so nothing else on screen moves.
    const status = this.#pwMode
      ? `${yellow("sudo password:")} ${"•".repeat(this.#pw.length)}${cyan("▏")}  ${dim("enter submit · esc cancel")}`
      : this.#message;
    // A long status (e.g. a --verbose proxy error) would widen the box past the terminal and wrap.
    const room4status = (process.stdout.columns || 80) - 14;
    const headLines = [`${dim("data  ")}  ${data}`, `${dim("route ")}  ${route}`, `${dim("status")}  ${fit(status, room4status)}`];

    const version = versionLines(true);
    const room = Math.max(3, (process.stdout.rows || 24) - 15 - version.length);
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
    const key = (k: string, rest: string) => `[ ${under(k)}${rest} ]`;
    const buttons = [bold(cyan("[ ⏎ Connect ]")), dim(key("G", "lobal")), dim(key("D", "isconnect")), dim(key("R", "efresh Usage")), dim(key("Q", "uit"))].join("  ");
    const headW = vw(box(headLines, { title, right: state })[0]);
    const table = grid(["", "Code", "Tier", "Country"], body, {
      caption: bold("Locations"),
      captionRight: dim(range),
      minWidth: Math.max(headW, vw(buttons) + 4),
    });
    const width = vw(table[0]);
    draw([
      ...box(headLines, { title, right: state, width: width - 4 }),
      ...table,
      "",
      centerIn(buttons, width),
      "",
      ...version.map((l) => centerIn(l, width)),
      centerIn(dim(repoLink), width),
    ]);
  }
}

/** Returns the visible slice of indices centred on the selection. */
function window(sel: number, total: number, room: number): { start: number; slice: number[] } {
  if (total <= room) return { start: 0, slice: Array.from({ length: total }, (_, i) => i) };
  let start = Math.min(Math.max(0, sel - Math.floor(room / 2)), total - room);
  return { start, slice: Array.from({ length: room }, (_, i) => start + i) };
}
