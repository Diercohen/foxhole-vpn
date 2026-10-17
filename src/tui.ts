import readline from "node:readline";
import { fetchServerList, type Country } from "./serverlist.js";
import { Connection } from "./connection.js";
import { NotImplementedError } from "./auth.js";
import { startProxy, type ProxyHandle } from "./proxy.js";
import { GlobalSession, sudoPriv, validateSudo, ensureTun2socks } from "./global.js";
import { VERSION, checkUpdate, canUpdate, runUpdate, updateNotice } from "./update.js";
import { bold, dim, green, red, yellow, cyan, flag, countryName, gb, shortDate } from "./ui.js";

const ESC = "\x1b[";
const ALT_ON = `${ESC}?1049h${ESC}?25l`;
const ALT_OFF = `${ESC}?25h${ESC}?1049l`;
const HOME_CLEAR = `${ESC}H${ESC}2J`;

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
    process.stdout.write(ALT_ON);
    this.#message = dim("loading…");
    this.#render();
    try {
      this.#countries = order(await fetchServerList());
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
      readline.emitKeypressEvents(process.stdin);
      if (process.stdin.isTTY) process.stdin.setRawMode(true);
      process.stdin.resume();
      const onResize = () => this.#render();
      process.stdout.on("resize", onResize);

      const quit = async (action?: "update") => {
        process.stdin.removeListener("keypress", onKey);
        process.stdout.removeListener("resize", onResize);
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.stdin.pause();
        if (this.#global) {
          process.stdout.write(HOME_CLEAR + " restoring networking…\n");
          await this.#global.stop().catch(() => {});
        }
        await this.#proxy?.close();
        process.stdout.write(ALT_OFF);
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
      process.stdin.on("keypress", onKey);
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
      this.#message = green(`connected · ${this.#proxyAddr()}`);
    } catch (err) {
      if (err instanceof NotImplementedError) {
        this.#message = yellow("can't connect: token step not implemented (see AUTH.md)");
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

  #proxyAddr(): string {
    return `socks5://${this.#host}:${this.#proxy?.port ?? this.#port}`;
  }

  #render(): void {
    const u = this.#conn.usage;
    const data = !u
      ? dim("data: unknown")
      : u.unlimited
        ? green("data: unlimited")
        : `data: ${bold(gb(u.remaining))} / ${gb(u.max)}` +
          (u.reset ? dim(` · resets ${shortDate(u.reset)}`) : "");

    const gc = this.#globalCountry;
    const state = this.#global
      ? green(`● GLOBAL  ${flag(gc!.code)} ${countryName(gc!.code, gc!.name)} · system-wide`)
      : this.#active
        ? green(`● connected  ${flag(this.#active.code)} ${countryName(this.#active.code, this.#active.name)}`)
        : dim("○ disconnected");

    const lines: string[] = [];
    lines.push(` ${bold("🦊 foxhole-vpn")} ${dim(VERSION)}    ${state}`);
    lines.push("");
    lines.push(` ${data}`);
    if (this.#global) lines.push(` ${green("▸ all system traffic routed through the VPN")}`);
    else if (this.#active) lines.push(` ${cyan(this.#proxyAddr())}`);
    const note = updateNotice(true);
    if (note) note.forEach((l) => lines.push(` ${yellow(l)}`));
    lines.push("");
    lines.push(` ${bold("Location:")}`);

    const rows = process.stdout.rows || 24;
    const room = Math.max(5, rows - 11);
    const { start, slice } = window(this.#sel, this.#countries.length, room);
    slice.forEach((i) => {
      const c = this.#countries[i];
      const marker = i === this.#sel ? cyan("▸") : " ";
      const name = countryName(c.code, c.name).padEnd(20);
      const tier = c.locked ? dim("paid") : green("free");
      const tag = !c.available ? red(" ×") : this.#active?.code === c.code ? green(" ✓") : "";
      const row = ` ${marker} ${flag(c.code)}  ${name} ${tier}${tag}`;
      lines.push(i === this.#sel ? bold(row) : row);
    });
    if (start + room < this.#countries.length || start > 0) {
      lines.push(dim(`   … ${this.#countries.length} total`));
    }
    lines.push("");
    const rule = dim(" " + "─".repeat(Math.min(60, (process.stdout.columns || 60) - 2)));
    if (this.#pwMode) {
      lines.push(dim(" sudo password needed to route the whole system   ⏎ submit · esc cancel"));
      lines.push(rule);
      lines.push(` sudo password: ${"•".repeat(this.#pw.length)}`);
    } else {
      const g = this.#global ? "g global off" : "g go global";
      const upd = canUpdate() ? " · u update" : "";
      lines.push(dim(` ↑/↓ move · ⏎ connect · ${g} · d disconnect · r refresh${upd} · q quit`));
      lines.push(rule);
      lines.push(` ${this.#message}`);
    }

    process.stdout.write(HOME_CLEAR + lines.join("\n"));
  }
}

/** Returns the visible slice of indices centred on the selection. */
function window(sel: number, total: number, room: number): { start: number; slice: number[] } {
  if (total <= room) return { start: 0, slice: Array.from({ length: total }, (_, i) => i) };
  let start = Math.min(Math.max(0, sel - Math.floor(room / 2)), total - room);
  return { start, slice: Array.from({ length: room }, (_, i) => start + i) };
}
