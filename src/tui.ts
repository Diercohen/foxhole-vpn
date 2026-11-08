import readline from "node:readline";
import { PassThrough } from "node:stream";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { hostname } from "node:os";
import { userHome, findAccount } from "./profile.js";
import { fetchServerList, type Country } from "./serverlist.js";
import { Connection, RELAY_CODE } from "./connection.js";
import { GuardianError, GuardianBlocked, useRelay } from "./guardian.js";
import { network, publicIp, lanIp, firewallHint } from "./netinfo.js";
import { loadSettings, saveSettings, proxyHost, validPort, loginFor, telegramLink, onJoin, type Settings } from "./settings.js";
import { qrLines } from "./qr.js";
import { SHARE_PORT, serveShare, shareData, shareLink, parseShared, sharedWhat, importPlan, type ShareServer } from "./share.js";
import { traffic, runsOut, sizeOf } from "./traffic.js";
import { knownBlocked, sanctioned, verdictOf, verdictText, tryText, wantOf } from "./smart.js";
import { forgetToken } from "./tokenserver.js";
import { FIREFOX, LOW_DATA, authFor, loadAccounts, peekFirefox, saveAccounts, signOut, withFirefox, without, type Accounts } from "./accounts.js";
import { fetchUsage, type Usage } from "./guardian.js";
import { startProxy, onProxyWarning, checkSite, netState, onNetState, type ProxyHandle } from "./proxy.js";
import { startSmartDns, smartDnsHost, smartDnsProblem, type SmartDns } from "./smartdns.js";
import { logLines, onLog } from "./log.js";
import { useSplit, splitOn, splitSummary, parseRule, parseSite, appOf, wayOf, hits, recentSites, SMART, type Split, type Via } from "./split.js";
import { listApps } from "./apps.js";
import { helperFor, helperInstalled, helperReady } from "./helper.js";
import { GlobalSession, sudoPriv, adminPriv, isPrivileged, validateSudo, sudoUsesTouchId, touchIdSudo, ensureTun2socks, dialHost, type Priv } from "./global.js";
import { hot, onHot } from "./hot.js";
import { checkUpdate, canUpdate, runUpdate, restart, versionLines, latestVersion, fetchNotes, UPDATE_COMMAND, VERSION, type Notes, type Block, type Span } from "./update.js";
import { bold, dim, under, italic, strike, green, red, yellow, cyan, lit, unlit, purple, litPurple, flag, EMOJI, emoji, countryName, gb, shortDate, vw, fit, box, grid, centerIn, draw, overlay, repoLink, REPO_URL, linkAt, openUrl, copyText } from "./ui.js";
import { fox, FOX_W, FOX_H, type Mood } from "./fox.js";
import { loadRelay } from "./httprelay.js";
import { newAuthKey } from "./relaysetup.js";
import { RelayWizard, GRAPHICS, CELL_QUERY, cellSize, pictureAt, wrap } from "./relaywizard.js";
import { relayCheck, relayVerdict, relayStats, onRelayNotice, onRelaySplit } from "./relaymode.js";
import { caTrusted, setCaTrust } from "./catrust.js";

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

const onOff = (v: boolean) => (v ? green("on") : dim("off"));
const flip = (v: Via): Via => (v === "vpn" ? "direct" : "vpn");

// Side by side, the fox and the details are in a panel this wide inside its border (its title fits
// " GLOBAL TUN ON  🇬🇧 United Kingdom"), beside the table of countries; the window needs SIDE_W columns
// for it (one spare: Terminal.app draws a flag's line a cell longer). Narrower, the table goes below.
const LEFT_W = 53;
const TABLE_W = 44;
const SIDE_W = LEFT_W + 4 + 1 + TABLE_W + 1;

/** The Settings popup's rows, in order, each with its entry in `values`. "On this network" (key netRule) is hidden for now. */
const SETTINGS = [
  { key: "share", label: "Share with devices on this network" },
  { key: "port", label: "Proxy port" },
  { key: "username", label: "Username" },
  { key: "password", label: "Password" },
  { key: "telegram", label: "Use in Telegram" },
  { key: "smartDns", label: "Smart DNS for a TV or console" },
  { key: "give", label: "Share settings" },
  { key: "take", label: "Import settings" },
  { key: "relaySetup", label: "Set up" }, // these last ones in the VPN relay box
  { key: "relayId", label: "Deployment ID" },
  { key: "relayKey", label: "Auth key" },
  { key: "relayCheck", label: "Check" },
  { key: "relayCert", label: "Certificate" },
] as const;
/** Where the relay's rows start: the last ones, in a purple box of their own. */
const RELAY_AT = SETTINGS.findIndex((it) => it.key.startsWith("relay"));

/** The Relay "location", first in the list once a relay is set up: the web through the user's own Apps Script (relaymode.ts). */
const RELAY_ROW: Country = { code: RELAY_CODE, name: "Relay", locked: false, available: true, servers: [] };
/** Its row before one is set up, dimmed: Enter says what it is (#relayIntro), with the setup a key away. */
const RELAY_SETUP: Country = { code: "RELAY-SETUP", name: "Relay", locked: false, available: false, servers: [] };

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

/** The hot config's notice (hot.ts) in yellow, wrapped to `width`: 3 lines at most. */
const newsLines = (width: number): string[] => {
  const n = hot()?.notice;
  return n ? wrap(n, width).slice(0, 3).map(yellow) : [];
};

/** A block of the update's notes (update.ts Block) as lines, set as GitHub set it (bold, italic, code, links), wrapped to `width`. */
function noteLines(b: Block, width: number): string[] {
  const set = (s: Span, w: string) => {
    if (s.s) w = strike(w); // before the colors: its marks go on letters, not on their codes
    if (s.code || b.kind === "pre") w = cyan(w);
    if (s.b || b.kind === "h") w = bold(w);
    if (s.i) w = italic(w);
    return s.href ? under(w) : w;
  };
  const pad = " ".repeat(b.kind === "li" ? (b.depth - 1) * 2 : b.depth * 2);
  if (b.kind === "pre") return b.spans.map((s) => s.text).join("").split("\n").map((l) => `${pad}  ${set(b.spans[0], fit(l, width - pad.length - 2))}`);
  // words, each set on its own (a style can't run across the line break); runs without a space between are one word
  const words: string[] = [];
  let glued = false;
  for (const s of b.spans) {
    s.text.split(" ").forEach((part, i) => {
      const w = part && set(s, part);
      if (i === 0 && glued && words.length) words[words.length - 1] += w;
      else words.push(w);
    });
    glued = !s.text.endsWith(" ");
  }
  const lead = pad + (b.mark ? `${b.mark} ` : "");
  const lines: string[] = [];
  let line = lead;
  for (const w of words.filter(Boolean)) {
    if (line.length > lead.length && vw(line) + 1 + vw(w) > width) (lines.push(line), (line = " ".repeat(vw(lead)) + w));
    else line += (line.length > lead.length ? " " : "") + w;
  }
  return [...(b.kind === "h" ? [""] : []), ...lines, line];
}

export class Tui {
  readonly #conn: Connection;
  #host: string;
  #port: number;
  #settings: Settings = loadSettings();
  #settingsOpen = false; // the Settings popup is open
  #tgOpen = false; // over it, Telegram's: the proxy's QR code for a phone, and Telegram on this computer
  // over it, Share settings' (share.ts): its page on the local network while it's open, and whether the relay's in it
  #give: { server: Promise<ShareServer | null>; relay: boolean; error: string; note: string } | null = null;
  #take: { text: string; what: string[] } | null = null; // a settings link pasted in Import settings, checked: enter imports it
  #dataOpen = false; // the Data popup: this month's data by site (traffic.ts), to send the big ones direct
  #dataSel = 0;
  #dataNote = "";
  #wizard: RelayWizard | null = null; // the relay's setup, over Settings
  #blocked = false; // the popup saying vpn.mozilla.org is blocked here, with the relay's setup a key away
  #blockedTold = false; // said once already: a background check doesn't say it again, a connect does
  #relayIntro = false; // the popup saying what Relay is (its row, before one is set up), with the setup a key away
  #setSel = 0;
  #edit: { key: "port" | "username" | "password" | "relayId" | "relayKey" | "take"; text: string } | null = null; // the setting being typed
  readonly #login = (address: string | undefined) => loginFor(this.#settings, address); // live: a change applies to the next client
  #settingsNote = "";
  #fwHint: string[] | null = null; // commands that open the proxy's port in an active firewall (Linux)
  #proxyStale = false; // the running proxy still has the old address (changed during global mode)
  #proxyAt = ""; // the address the running proxy was started on
  #list: Country[] = []; // the server list's countries
  #countries: Country[] = []; // the Locations shown: the relay first (RELAY_SETUP until one is set up), then #list
  #sel = 0;
  #proxy: ProxyHandle | null = null;
  #active: Country | null = null;
  #message = "";
  #busy = false;
  #netPaused: Country | null = null; // the location a network's rule paused (Settings → On this network), connected again on leaving it
  #global: GlobalSession | null = null;
  #globalCountry: Country | null = null;
  #tun2socksPath: string | null = null;
  #pwMode = false; // the password popup is open
  #pw = "";
  #pwError = "";
  #pwChecking = false;
  #pwFor: "global" | "trust" | "untrust" = "global"; // what the password is for
  #trustAsk = false; // the popup asking to trust foxhole's certificate (relay mode)
  #caOk: boolean | undefined; // whether this computer trusts it; undefined: not checked yet
  #relayCheck: { tone: "ok" | "warn" | "error" | "busy"; text: string } | null = null; // Settings' last check of the relay
  #splitOpen = false; // the Split tunneling popup is open
  #splitSel = 0; // 0: "Everything else", then the rules, then "+ add a site"
  #splitStart = 0; // the first row shown, when the list scrolls
  #splitShown = 0; // how many rows are shown
  #splitEdit: string | null = null; // the site being typed
  #splitTab: { query: string; i: number } | null = null; // Tab going through recent sites
  #smartDns: SmartDns | null = null; // the home's DNS server, while Settings has it on (smartdns.ts)
  #smartDnsAt: string | null = null; // the address it listens on
  #smartDnsError = "";
  #smartDnsYields = false; // a Mac's whole-system mode has port 53 for its own DNS relay
  #smartDnsTurn = Promise.resolve(); // one start or stop at a time
  #checkLines: string[] | null = null; // the typed site's check (? while typing), shown for the help
  #checked: { site: string; via: Via } | null = null; // its offer: enter adds the site that way
  #splitNote = "";
  #apps: string[] = []; // apps to Tab through while typing, and to pick from (apps.ts)
  #pick: { query: string; sel: number } | null = null; // the app picker (p in the Split popup): what's searched for, the row
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
  #hit = { top: 0, left: 0, rowsTop: 0, rowsLeft: 0, start: 0, rows: 0, sep: -1, width: 0, buttonsY: -1, buttons: "", setTop: -1, setX: 0, setW: 0 };
  #accounts = loadAccounts(); // accounts.ts: the list, and the one in use (cli.ts signed in with it)
  #acctOpen = false; // the Accounts popup is open
  #acctSel = 0; // a row: the accounts, then "+ Add account"
  #acctNote = "";
  #removeAsk: string | null = null; // the account x was pressed on once: again signs it out
  #others = new Map<string, { usage: Usage | null; error: string | null }>(); // data left of those not in use
  #lowOpen = false; // the popup saying the account in use is low on data
  #notesOpen = false; // the popup with what's new in the update ('u'), whose Enter updates
  #notes: Notes | null | undefined; // what's new, from GitHub: undefined while it's asked, null when it didn't answer
  #notesTop = 0; // the first line shown: ↑↓ scroll a long one
  #lowSeen = ""; // the account and month it was shown for
  #quit: (action?: "update" | "logout") => Promise<void> = async () => {};
  readonly #firefoxEmail = this.#accounts.firefox ? findAccount()?.email ?? null : peekFirefox(); // read at the start: cli.ts may just have

  constructor(conn: Connection, host: string, port: number) {
    this.#conn = conn;
    this.#host = host;
    this.#port = port;
  }

  /** Resolves "logout" when the user logged out, so the caller can forget the token. */
  async run(): Promise<"logout" | undefined> {
    useSplit(() => this.#settings.split); // live: a change applies to the next connection
    this.#followSmartDns();
    // the Split popup's counts climb as sites load, and relay mode's on the data row
    let seen = -1;
    setInterval(() => {
      const n = relayStats.relayed + relayStats.fronted;
      if (this.#splitOpen || (this.#relayOn() && n !== seen && !this.#wizard)) (seen = n), this.#render();
    }, 1000).unref();
    onRelayNotice((msg) => ((this.#message = yellow(msg)), this.#render()));
    onRelaySplit((split) => this.#saveSplit(split)); // a bot-check page's "Open it directly"
    onHot(() => this.#render()); // a new notice, under the buttons
    setInterval(() => this.#animate(), 100).unref();
    onLog(() => this.#logsOpen && this.#renderSoon());
    onProxyWarning((msg) => {
      this.#message = red(`proxy: ${msg}`);
      this.#render();
    });
    onNetState((said) => ((this.#message = said ? red(said) : green("the internet is back")), this.#render())); // cut off or offline while connected
    // A closed terminal fails every write and read (EIO): that must not crash the quit that
    // puts global mode's routes back (it comes as SIGHUP, with nothing left to draw on).
    process.stdout.on("error", () => {});
    process.stdin.on("error", () => {});
    screenOn = true;
    process.stdout.write(ALT_ON);
    this.#message = dim("loading…");
    this.#render();
    try {
      this.#setList(order(await fetchServerList()));
      this.#message = "";
    } catch (err) {
      this.#setList([]);
      this.#message = existsSync("/sys/class/net/foxhole0")
        ? red("offline: a killed global session's routes are still on — quit and run  foxhole restore")
        : red(`server list failed: ${(err as Error).message}`) + this.#relayHint();
    }
    this.#loading = false;
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
    if (this.#settings.smartDns) void this.#followSmartDns(); // to the network's new address
    const seq = ++this.#netSeq;
    const country = this.#global ? this.#globalCountry : this.#active;
    // Proxy mode: ask through the proxy. Global mode tunnels the direct check already.
    const proxy = this.#proxy && this.#active && !this.#global
      ? { host: dialHost(this.#host), port: this.#proxy.port }
      : undefined;
    this.#ip = undefined;
    void network().then((n) => {
      if (seq !== this.#netSeq) return;
      const joined = this.#net !== undefined && n !== this.#net; // not the first look, at the start
      this.#net = n;
      this.#render();
      if (joined) this.#joined(n);
    });
    // relay mode: HTTP, as HTTPS in global mode would meet foxhole's own certificate, which Node doesn't trust
    void publicIp(proxy, 3, country === RELAY_ROW).then((ip) => {
      if (seq !== this.#netSeq) return;
      this.#ip = ip;
      this.#ipNote = country === RELAY_ROW ? "Google's · sites can still see yours" : country ? `VPN · ${flagged(country.code, countryName(country.code, country.name))}` : "not via Foxhole";
      this.#render();
    });
  }

  /** Re-reads the data used, quietly: a failed check keeps what's shown. */
  #refreshUsage(): void {
    this.#conn.refreshUsage().then(() => (this.#checkLow(), this.#render()), (err) => !this.#blockedTold && this.#saysBlocked(err) && this.#render());
  }

  // ── Accounts (accounts.ts) ───────────────────────────────────────────────────────────────

  get #email(): string | null {
    const a = this.#accounts;
    return a.current === FIREFOX ? this.#firefoxEmail : (a.own.find((x) => x.uid === a.current)?.email ?? null);
  }

  #ids(): string[] {
    return [...(this.#accounts.firefox ? [FIREFOX] : []), ...this.#accounts.own.map((x) => x.uid)];
  }

  #emailOf(id: string): string {
    return id === FIREFOX ? (this.#firefoxEmail ?? "Firefox's account") : (this.#accounts.own.find((x) => x.uid === id)?.email ?? "");
  }

  #saveAccounts(next: Accounts): void {
    this.#accounts = next;
    try {
      saveAccounts(next);
    } catch (err) {
      this.#acctNote = red(`couldn't save the accounts: ${(err as Error).message}`);
    }
  }

  /** Uses another account from now on (the next start too); connected, it disconnects first. */
  async #use(id: string): Promise<void> {
    const auth = authFor(this.#accounts, id);
    if (!auth) {
      this.#acctNote = red(id === FIREFOX ? "Firefox isn't signed in (or can't be read): sign in to Firefox, then try again." : "That account isn't there anymore.");
      return;
    }
    if (this.#busy) return void (this.#acctNote = yellow("wait for it to connect (or disconnect), then switch"));
    await this.#disconnect();
    this.#saveAccounts({ ...this.#accounts, current: id });
    this.#conn.setAuth(auth);
    this.#lowOpen = false;
    this.#acctNote = "";
    this.#message = green(`using ${this.#emailOf(id)}`);
    this.#refreshUsage();
    this.#render();
  }

  /** Signs an account out of foxhole (Firefox's: foxhole stops reading it); the last one gone, cli.ts asks how to sign in. */
  #remove(id: string): void {
    const own = this.#accounts.own.find((x) => x.uid === id);
    if (own) void signOut(own);
    if (id === FIREFOX) forgetToken();
    const was = this.#accounts.current;
    this.#saveAccounts(without(this.#accounts, id));
    this.#others.delete(id);
    this.#acctSel = Math.min(this.#acctSel, this.#ids().length);
    if (id !== was) return;
    const next = this.#accounts.current;
    if (!next || !authFor(this.#accounts, next)) return void this.#quit("logout");
    void this.#use(next);
  }

  /** The data left of the accounts not in use, as the popup opens. */
  #refreshOthers(): void {
    for (const id of this.#ids()) {
      if (id === this.#accounts.current) continue;
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
          (err) => this.#others.set(id, { usage: this.#others.get(id)?.usage ?? null, error: (err as { errno?: number }).errno === 110 ? "signed out" : "couldn't check" }),
        )
        .then(() => this.#render());
    }
  }

  #openAccounts(): void {
    this.#acctOpen = true;
    this.#accounts = { ...loadAccounts(), current: this.#accounts.current }; // those added in the desktop app meanwhile, too
    this.#acctNote = "";
    this.#removeAsk = null;
    this.#acctSel = Math.max(0, this.#ids().indexOf(this.#accounts.current ?? ""));
    this.#refreshOthers();
    this.#render();
  }

  /** The account in use has less than LOW_DATA left: a popup offers another (once a month per account, unless put away). */
  #checkLow(): void {
    const u = this.#conn.usage;
    const id = this.#accounts.current;
    if (!id || !u || u.unlimited || u.remaining >= LOW_DATA) return;
    const month = u.reset?.toISOString() ?? "";
    if (this.#accounts.lowSeen[id] === month || this.#lowSeen === `${id} ${month}`) return;
    this.#lowSeen = `${id} ${month}`;
    this.#lowOpen = true;
  }

  /** Keystrokes while the low-data popup is open: Enter, the accounts; Esc, later (not again this month). */
  #lowKey(key: readline.Key): void {
    if (key.name === "return") return void ((this.#lowOpen = false), this.#openAccounts());
    if (key.name !== "escape") return;
    this.#lowOpen = false;
    const id = this.#accounts.current, u = this.#conn.usage;
    if (id && u) this.#saveAccounts({ ...this.#accounts, lowSeen: { ...this.#accounts.lowSeen, [id]: u.reset?.toISOString() ?? "" } });
    this.#render();
  }

  /** What's new in the update, newest first, with Enter to update; ↑↓ scroll it when it's taller than the window. */
  #notesPopup(width: number, frameHeight: number): string[] {
    const inner = Math.min(70, width - 6); // box border + padding (4) and the overlay's margin (2)
    const notes = this.#notes;
    const body = notes === undefined ? [dim("Getting what's new…")]
      : !notes?.some((n) => n.blocks.length) ? [dim("What's new is on the releases page:"), dim(`${REPO_URL}/releases`)]
      : notes.flatMap((n, i) => [
        ...(notes.length > 1 ? [...(i ? [""] : []), bold(n.version)] : []),
        ...n.blocks.flatMap((b) => noteLines(b, inner)),
      ]);
    const room = Math.max(3, frameHeight - 10); // the box's border, the blank lines, the buttons, the command, the margin
    this.#notesTop = Math.min(this.#notesTop, Math.max(0, body.length - room));
    const shown = body.slice(this.#notesTop, this.#notesTop + room);
    const more = body.length > room ? dim(`  ↑↓ ${this.#notesTop + shown.length} of ${body.length} lines`) : "";
    return box(
      [
        "",
        ...shown,
        "",
        `${bold(green("[⏎ Update and restart]"))}   ${dim("[esc Not now]")}${more}`,
        dim(`runs ${UPDATE_COMMAND}`),
      ],
      { title: bold(green(`Foxhole ${latestVersion()} is out`)), width: inner },
    );
  }

  #lowPopup(): string[] {
    const u = this.#conn.usage;
    return box(
      ["", `${bold(this.#email ?? "This account")} has ${yellow(u ? gb(u.remaining) : "little")} left this month.`, "Switch to another account, or add one, to carry on.", "", dim("enter accounts · esc later")],
      { title: bold(yellow("Data is running low")), width: 62 },
    );
  }

  /** Keystrokes while the Accounts popup is open. */
  #acctKey(_s: string, key: readline.Key): void {
    const ids = this.#ids();
    if (key.name !== "x" && key.name !== "delete" && key.name !== "backspace") {
      this.#removeAsk = null; // a sign-out asked for goes with any other key
      this.#acctNote = "";
    }
    switch (key.name) {
      case "escape":
      case "a":
      case "o":
        this.#acctOpen = false;
        break;
      case "up":
      case "k":
        this.#acctSel = (this.#acctSel - 1 + ids.length + 1) % (ids.length + 1);
        this.#removeAsk = null;
        break;
      case "down":
      case "j":
        this.#acctSel = (this.#acctSel + 1) % (ids.length + 1);
        this.#removeAsk = null;
        break;
      case "return":
        // the last row: Firefox's sign-in, the terminal's own way in; others are added in the desktop app
        if (this.#acctSel === ids.length && !this.#accounts.firefox) {
          if (!authFor(withFirefox(this.#accounts), FIREFOX)) return void ((this.#acctNote = red("Firefox isn't signed in (or can't be read): sign in to Firefox, then try again.")), this.#render());
          const ff = findAccount()?.email?.toLowerCase();
          const twin = this.#accounts.own.find((x) => !!ff && x.email.toLowerCase() === ff);
          if (twin) return void ((this.#acctNote = yellow(`You're already signed in with ${twin.email}, so it isn't added again.`)), this.#render());
          this.#saveAccounts(withFirefox(this.#accounts));
          void this.#use(FIREFOX);
          this.#acctSel = 0;
        } else if (this.#acctSel === ids.length) {
          const url = `${REPO_URL}/releases/latest`;
          this.#acctNote = [
            ...wrap("Another account can't be added in the terminal: add it in Foxhole's desktop app, and it shows up here.", 60).map(yellow),
            `\x1b]8;;${url}\x1b\\${cyan(url)}\x1b]8;;\x1b\\`,
          ].join("\n");
          return this.#render();
        }
        else if (ids[this.#acctSel] !== this.#accounts.current) void this.#use(ids[this.#acctSel]);
        break;
      case "x":
      case "delete":
      case "backspace": {
        const id = ids[this.#acctSel];
        if (!id) break;
        if (this.#removeAsk === id) {
          this.#removeAsk = null;
          this.#remove(id);
        } else {
          this.#removeAsk = id;
          this.#acctNote = yellow(id === FIREFOX ? "press x again to stop using Firefox's sign-in (Firefox stays signed in)" : `press x again to sign out of ${this.#emailOf(id)}`);
          return this.#render();
        }
      }
    }
    this.#render();
  }

  #accountsPopup(): string[] {
    const ids = this.#ids();
    const rows = ids.map((id, i) => {
      const here = i === this.#acctSel;
      const current = id === this.#accounts.current;
      const o = this.#others.get(id);
      const u = current ? this.#conn.usage : o?.usage;
      const left = (current ? null : o?.error) ?? (!u ? "" : u.unlimited ? "unlimited" : `${gb(u.remaining)} left`);
      const email = this.#emailOf(id);
      const name = email.length > 30 ? email.slice(0, 29) + "…" : email;
      return `${here ? cyan("❯") : " "} ${current ? green("●") : dim("○")} ${here ? bold(name.padEnd(30)) : name.padEnd(30)} ${dim([left, id === FIREFOX ? "Firefox" : ""].filter(Boolean).join(" · "))}`;
    });
    const ff = this.#firefoxEmail;
    const add = `${this.#acctSel === ids.length ? cyan("❯") : " "} ${cyan("+")} ${this.#accounts.firefox ? "Add account" : `Use Firefox's sign-in${ff ? `, ${ff}` : ""}${process.platform === "darwin" ? dim(" (Full Disk Access)") : ""}`}`;
    return box(
      ["", dim("The VPN uses the one in use (●), from now on too."), "", ...rows, add, "", ...this.#acctNote.split("\n"), "", dim("↑↓ select · enter use / add · x sign out · esc close")],
      { title: bold(cyan("Accounts")), width: 62 },
    );
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
      const quit = (this.#quit = async (action?: "update" | "logout") => {
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
        this.#smartDns?.close();
        void this.#give?.server.then((server) => server?.close());
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
      });

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
        if (this.#blocked || this.#relayIntro) {
          if (key.name === "return") this.#wizard = new RelayWizard(() => this.#render());
          if (key.name === "return" || key.name === "escape") (this.#blocked = this.#relayIntro = false), this.#render();
          return;
        }
        if (this.#trustAsk) {
          if (key.name === "return") void this.#trust(true);
          if (key.name === "return" || key.name === "escape") (this.#trustAsk = false), this.#render();
          return;
        }
        if (this.#lowOpen) return this.#lowKey(key);
        if (this.#notesOpen) {
          if (key.name === "return") return void quit("update");
          if (key.name === "escape" || key.name === "u") this.#notesOpen = false;
          else if (key.name === "up" || key.name === "k") this.#notesTop = Math.max(0, this.#notesTop - 1);
          else if (key.name === "down" || key.name === "j") this.#notesTop++; // #notesPopup keeps it in range
          return this.#render();
        }
        if (this.#acctOpen) return this.#acctKey(s, key);
        if (this.#settingsOpen) return this.#settingsKey(s, key);
        if (this.#splitOpen) return this.#splitKey(s, key);
        if (this.#dataOpen) return this.#dataKey(key);
        if (key.name === "q") return void quit();
        if (key.name === "l") return void ((this.#logsOpen = true), (this.#logsNote = ""), this.#render());
        if (this.#busy) return;
        if (key.name === "s") {
          this.#settingsOpen = true;
          this.#settingsNote = "";
          this.#checkFirewall();
          void caTrusted().then((ok) => ((this.#caOk = ok), this.#render()));
          return this.#render();
        }
        if (key.name === "m") return void ((this.#dataOpen = true), (this.#dataSel = 0), (this.#dataNote = ""), this.#render());
        if (key.name === "t") {
          this.#splitOpen = true;
          this.#splitNote = "";
          void listApps().then((a) => (this.#apps = a.map((x) => x.name)), () => {});
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
            void this.#connectInMode();
            return;
          case "g":
            void this.#setMode();
            return;
          case "d":
            void this.#disconnect();
            return;
          case "r":
            // the relay, from anywhere in the list
            if (this.#countries[0] !== RELAY_ROW) break;
            this.#sel = 0;
            void this.#connectInMode();
            return;
          case "u":
            // what's new first: its Enter updates
            if (!canUpdate()) break;
            [this.#notesOpen, this.#notesTop] = [true, 0];
            if (this.#notes === undefined) void fetchNotes(latestVersion()!).then((n) => ((this.#notes = n), this.#render()));
            break;
          case "a":
          case "o": // where logging out was
            return this.#openAccounts();
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
    if (b !== 0 || this.#pwMode || this.#logsOpen || this.#dataOpen || this.#restoring || this.#wizard || this.#blocked || this.#relayIntro || this.#trustAsk || this.#acctOpen || this.#lowOpen || this.#notesOpen) return;
    const h = this.#hit;
    const fx = x - h.left, fy = y - h.top;
    if (this.#settingsOpen && !this.#tgOpen && !this.#give) {
      const k = fy - h.setTop, i = k > RELAY_AT ? k - 1 : k; // the relay's box takes a line above its rows
      if (this.#edit || k === RELAY_AT || i < 0 || i >= SETTINGS.length || fx < h.setX || fx >= h.setX + h.setW) return;
      this.#setSel = i;
      return press("return");
    }
    if (this.#splitOpen) {
      const i = fy - h.setTop;
      if (this.#splitEdit !== null || this.#pick || i < 0 || i >= this.#splitShown || fx < h.setX || fx >= h.setX + h.setW) return;
      this.#splitSel = this.#splitStart + i;
      return press("return");
    }
    if (linkAt(x, y)) return openUrl(REPO_URL);
    const k = fy - h.rowsTop;
    if (k >= 0 && k < h.rows && k !== h.sep && fx >= h.rowsLeft && fx < h.rowsLeft + h.width) {
      if (this.#busy) return;
      const i = h.start + k - (h.sep >= 0 && k > h.sep ? 1 : 0); // the line under the relay takes a row
      if (i === this.#sel) return press("return");
      this.#sel = i;
      return this.#render();
    }
    if (fy === h.buttonsY) {
      // the [...] around the click, if any
      const a = h.buttons.lastIndexOf("[", fx), z = h.buttons.indexOf("]", fx);
      if (a < 0 || z < 0 || h.buttons.lastIndexOf("]", fx - 1) > a) return;
      const label = h.buttons.slice(a + 1, z);
      press(label.startsWith("⏎") ? "return" : label.startsWith("Split") ? "t" : label.startsWith("Data") ? "m" : label[0].toLowerCase());
    }
  }

  async #connect(country = this.#countries[this.#sel]): Promise<void> {
    if (!country) return;
    if (country === RELAY_SETUP) return void ((this.#relayIntro = true), this.#render());
    const relay = country === RELAY_ROW ? loadRelay(this.#settings) : null;
    if (country === RELAY_ROW && !relay) return;
    this.#busy = true;
    this.#message = dim(relay ? "connecting through your relay…" : `connecting to ${countryName(country.code, country.name)}…`);
    this.#render();
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
      this.#message = relay ? purple("connected through your relay") : green("connected");
      if (relay) void this.#askTrust();
      else this.#refreshUsage();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EADDRINUSE") this.#message = red(`port ${this.#port} is in use by another app (a VPN or proxy?) — quit it, or pick another port in Settings`);
      else if (relay) this.#message = red((err as Error).message);
      else if (err instanceof GuardianError && err.status === 401) {
        forgetToken(); // so the next start shows the token window
        this.#message = red("token rejected (expired) — quit and run foxhole again to get a new one");
      } else {
        const blocked = this.#saysBlocked(err);
        // fetch's own message is just "fetch failed"; the network reason is in its cause
        const cause = (err as Error).cause as { code?: string; message?: string } | undefined;
        this.#message = red(`connect failed: ${(err as Error).message}${cause ? ` (${cause.code ?? cause.message})` : ""}`) + this.#relayHint();
        const failed = this.#message;
        if (!blocked) void netState().then((said) => said && this.#message === failed && ((this.#message = red(said)), this.#render())); // why, when it's the network (nothing said since)
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
    this.#netPaused = null;
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

  /** The computer joined network `n`: its rule pauses or connects, or leaving the one that paused connects again (onJoin). */
  #joined(n: string | null): void {
    const what = onJoin(this.#settings.networks, n, { active: !!this.#active, paused: !!this.#netPaused });
    if (!what || this.#busy) return;
    this.#message = dim(`${n}: ${what === "pause" ? "paused here, on again when you leave it" : what === "resume" ? "left the network that paused it" : "connecting"} (Settings → On this network)`);
    if (what === "pause") {
      const was = this.#active;
      return void this.#disconnect().then(() => (this.#netPaused = was));
    }
    const back = this.#netPaused;
    if (back && this.#countries.includes(back)) this.#sel = this.#countries.indexOf(back);
    void this.#connectInMode();
  }

  /** Enter: while off, connects in the mode last picked; while on, moves to the selected country as it is. */
  async #connectInMode(): Promise<void> {
    this.#netPaused = null; // the user's choice from now on
    const off = !this.#active;
    await this.#connect();
    if (!off || !this.#active || this.#settings.proxyOnly || this.#global) return;
    // relay mode's certificate first: its question and the password's would come up together
    if (this.#relayOn() && !(await caTrusted())) return;
    await this.#toggleGlobal();
  }

  /** The Global TUN checkbox: while off, only remembered for the next connect; while on, switches too. */
  async #setMode(): Promise<void> {
    if (this.#busy) return;
    const whole = !(this.#active ? this.#global : !this.#settings.proxyOnly);
    await this.#changeSetting({ proxyOnly: whole ? undefined : true });
    if (this.#active && whole !== !!this.#global) await this.#toggleGlobal();
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
    if (await helperReady()) return void this.#enableGlobal(""); // the network helper needs no password (helper.ts)
    let note = "";
    if (sudoUsesTouchId()) {
      // sudo takes the fingerprint here, so a password typed in the popup would go unused
      this.#busy = true;
      this.#message = yellow("Touch ID once: sets up the network helper"); // what fits the status line
      this.#render();
      const ok = await touchIdSudo();
      this.#busy = false;
      if (ok) return void this.#enableGlobal("");
      this.#message = "";
      note = "No Touch ID: type your password instead."; // cancelled, or no sensor (lid closed)
    }
    this.#askPassword("global", note);
  }

  /** Opens the password popup, for `what`. */
  #askPassword(what: "global" | "trust" | "untrust", note = ""): void {
    this.#pwFor = what;
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
    if (this.#pwFor === "global") void this.#enableGlobal(pw);
    else void this.#trust(this.#pwFor === "trust", sudoPriv(pw));
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
      const tun2socks = async () => (this.#tun2socksPath ??= await ensureTun2socks({ proxy: via, say: (msg) => ((this.#message = dim(msg)), this.#render()) }));
      if (process.platform === "win32") {
        this.#message = dim(helperInstalled() ? "going global… if Windows asks, allow PowerShell" : "Allow PowerShell once: sets up a helper"); // what fits the status line
        this.#render();
      }
      const helper = await helperFor(password, tun2socks);
      if (!helper) await tun2socks();
      this.#message = dim(process.platform === "win32" ? "going global… if Windows asks, allow PowerShell" : "going global…");
      this.#render();
      session = new GlobalSession({
        priv: helper?.priv ?? (password === null ? await adminPriv(true) : sudoPriv(password)),
        server,
        proxyHost: this.#host,
        proxyPort: this.#proxy.port,
        tun2socksPath: helper?.tun2socksPath ?? this.#tun2socksPath!,
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
          this.#smartDnsBack();
          this.#refreshNet();
          this.#render();
        });
      });
      session.onNetworkChange((event, detail) => {
        this.#message = event === "lost" ? yellow(`global: ${detail}`) : green(`global ON · rerouted ${detail}`);
        if (event === "restored") this.#refreshNet();
        this.#render();
      });
      if (process.platform === "darwin") {
        this.#smartDnsYields = true; // its DNS relay is about to have port 53
        await this.#followSmartDns();
      }
      await session.start();
      this.#global = session;
      this.#globalCountry = this.#active;
      this.#message = dim("verifying…");
      this.#render();
      const ip = await session.verifyExitIp(this.#relayOn());
      this.#message = ip
        ? (this.#relayOn() ? purple : green)(`global ON · exit IP ${ip}`)
        : yellow(`global on, but internet check failed — DNS or ${this.#relayOn() ? "relay" : "VPN"} issue`);
    } catch (err) {
      this.#message = red(`global failed: ${(err as Error).message}`);
      await session?.stop().catch(() => {});
      this.#global = null;
      this.#smartDnsBack();
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
      this.#smartDnsBack();
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
    if (this.#give) return this.#giveKey(s, key);
    if (this.#take) {
      if (key.name === "return") void this.#import(this.#take.text);
      else if (key.name === "escape") this.#take = null;
      return this.#render();
    }
    if (this.#tgOpen) {
      // Telegram on this computer takes the proxy from its own link, and asks first
      if (key.name === "return") openUrl(telegramLink("127.0.0.1", this.#settings.port, null, true));
      else if (key.name === "escape") this.#tgOpen = false;
      return this.#render();
    }
    const e = this.#edit;
    if (e) {
      if (key.name === "escape") this.#edit = null;
      else if (key.name === "backspace") e.text = e.text.slice(0, -1);
      else if (key.name === "return") {
        if (e.key === "port" && !validPort(Number(e.text))) this.#settingsNote = red("A port is a number from 1 to 65535.");
        else if (e.key === "take") {
          const shared = parseShared(e.text);
          if (!shared) this.#settingsNote = red("That isn't a Foxhole settings link: copy all of it again.");
          else (this.#take = { text: e.text, what: importPlan(this.#settings, shared).what }), (this.#edit = null);
        } else {
          this.#edit = null;
          if (e.key === "relayId" || e.key === "relayKey") this.#relayCheck = null; // it was of the old ones
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
      } else if (e.key === "take") {
        if (s && /^[\x21-\x7e]+$/.test(s) && e.text.length + s.length <= 8192) e.text += s; // a link: no spaces, nothing else
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
        if (item === "smartDns") return void this.#changeSetting({ smartDns: !this.#settings.smartDns || undefined });
        if (item === "relaySetup") return void ((this.#wizard = new RelayWizard(() => this.#render())), this.#render());
        if (item === "relayCert") return void this.#trust(!this.#caOk);
        if (item === "relayCheck") return void this.#checkRelay();
        if (item === "telegram") return void ((this.#tgOpen = true), this.#render());
        if (item === "give") return this.#giveOpen();
        // typed in place: the username and relay id start from the current value, the rest from scratch
        this.#edit = { key: item, text: item === "username" ? this.#settings.username : item === "relayId" ? (this.#settings.relay?.deploymentId ?? "") : "" };
        this.#settingsNote = "";
      }
    }
    this.#render();
  }

  /** Share settings opened: its page on the local network, for a phone's camera (share.ts), till it's closed. */
  #giveOpen(): void {
    const give = { server: Promise.resolve<ShareServer | null>(null), relay: false, error: "", note: "" };
    give.server = serveShare({ name: hostname().replace(/\.local$/, ""), version: VERSION, apk: null }).catch((err) => {
      give.error = err.code === "EADDRINUSE" ? `Another app here is using Foxhole's sharing port (${SHARE_PORT}).` : (err as Error).message;
      this.#render();
      return null;
    });
    this.#give = give;
    this.#render();
  }

  /** Keystrokes in Share settings: r the relay in it or not, c copies the link, esc closes it (and its page). */
  #giveKey(s: string, key: readline.Key): void {
    const g = this.#give!;
    const data = shareData(this.#settings, g.relay);
    if (key.name === "escape") {
      void g.server.then((server) => server?.close());
      this.#give = null;
    } else if (s === "r" && this.#settings.relay) (g.relay = !g.relay), (g.note = "");
    else if (s === "c" && data) {
      void copyText(shareLink(data)).then((ok) => {
        g.note = ok ? green("✓ copied the link") : yellow(process.platform === "linux" ? "couldn't copy: install wl-clipboard or xclip" : "couldn't copy to the clipboard");
        this.#render();
      });
    }
    this.#render();
  }

  /** Share settings: the QR code of its page (the settings in it) if it fits, what it shares, and the link. */
  #givePopup(frameHeight: number): string[] {
    const g = this.#give!;
    const data = shareData(this.#settings, g.relay);
    const lan = lanIp();
    let qr: string[] = [];
    try {
      if (data && lan) qr = qrLines(`http://${lan}:${SHARE_PORT}/#${data}`);
    } catch {
      /* too much for a QR code: the link alone */
    }
    const link = data ? shareLink(data) : "";
    const linkLines = link.match(/.{1,62}/g) ?? [];
    const center = (l: string) => " ".repeat(Math.max(0, Math.floor((62 - vw(l)) / 2))) + l;
    const wide = qr.length > 0 && vw(qr[0]) <= 62;
    const fits = wide && qr.length + linkLines.length + 14 <= frameHeight;
    const body = g.error
      ? wrap(g.error, 62).map(red)
      : !data
        ? [yellow("Nothing to share yet: no relay, and split tunneling as it comes.")]
        : [
            ...(fits
              ? ["", ...qr.map(center), "", "Scan it with the phone's camera, on this Wi-Fi: it opens these", "settings in Foxhole."]
              : [dim(!lan ? "Not on a network: no QR code to scan." : wide ? "A taller terminal shows its QR code." : "Its QR code is too big for a terminal: send the link instead.")]),
            "",
            ...sharedWhat(parseShared(data)!).map((w) => `${green("✓")} ${w}`),
            ...(g.relay ? [yellow("Anyone with this code or link can use your relay.")] : []),
            "",
            dim("Elsewhere? Send this link, to paste in Foxhole's Import settings:"),
            ...linkLines.map((l) => cyan(l)),
          ];
    const keys = [this.#settings.relay && (g.relay ? "r without your relay" : "r with your relay too"), data && "c copy the link", "esc back"].filter(Boolean).join(" · ");
    return box([...body, "", ...(g.note ? [g.note] : []), dim(keys)], { title: bold(cyan("⇪ Share settings")), width: 66 });
  }

  /** Imports a settings link pasted (share.ts): its relay in place of this one, its sites with these rules, its switches on. */
  async #import(text: string): Promise<void> {
    const shared = parseShared(text);
    this.#take = null;
    if (!shared) return;
    const plan = importPlan(this.#settings, shared);
    if (plan.split) this.#saveSplit(plan.split);
    if (plan.relay) await this.#changeSetting({ relay: plan.relay });
    const saved = (!plan.split || this.#settings.split === plan.split) && (!plan.relay || this.#settings.relay === plan.relay);
    this.#settingsNote = saved ? green("✓ Imported: foxhole uses them from now on.") : this.#settingsNote || red("Couldn't save the settings file.");
    this.#render();
  }

  /** Settings' check of the relay (relayVerdict): its deployment ID and auth key, and its script's code. */
  async #checkRelay(): Promise<void> {
    if (this.#relayCheck?.tone === "busy") return;
    const relay = loadRelay(this.#settings); // the environment's ID and key, when set, before Settings'
    const env = ["FOXHOLE_RELAY_ID", "FOXHOLE_RELAY_KEY"].filter((k) => process.env[k]?.trim());
    if (!relay) {
      const has = this.#settings.relay;
      const text = !has ? "No relay yet: “Set up” walks you through it." : !has.deploymentId ? "No deployment ID: type it in “Deployment ID”." : "No auth key: type it in “Auth key”.";
      return void ((this.#relayCheck = { tone: "error", text }), this.#render());
    }
    this.#relayCheck = { tone: "busy", text: "" };
    this.#render();
    const v = (this.#relayCheck = await relayVerdict({ relay, server: null }));
    if (env.length) v.text += ` Checked with ${env.join(" and ")} from your environment, which foxhole uses over Settings.`;
    this.#message = v.tone === "ok" ? purple("✓ Relay works") : v.tone === "warn" ? yellow("Relay works, but its script is old") : red(v.text); // in full in Settings
    this.#render();
  }

  /** Keystrokes while the relay's setup is open; it finishes by saving the relay, back in Settings. */
  #wizardKey(s: string, key: readline.Key): void {
    const done = this.#wizard!.key(s, key);
    if (done) this.#wizard = null;
    if (done && done !== "close") {
      return void this.#changeSetting({ relay: done }).then(() => {
        if (!this.#settings.relay) return this.#render();
        // whether it works, at once: Settings, on the check's row (from the blocked popup too)
        this.#message = purple("✓ Relay set up");
        this.#settingsOpen = true;
        this.#setSel = SETTINGS.findIndex((it) => it.key === "relayCheck");
        void this.#checkRelay();
      });
    }
    this.#render();
  }

  /** Keystrokes while the Split tunneling popup is open. */
  #splitKey(s: string, key: readline.Key): void {
    const sp = this.#settings.split;
    const n = sp.rules.length;
    const e = this.#splitEdit;
    if (this.#pick) return this.#pickKey(s, key);
    if (e !== null) {
      if (key.name === "tab") return void (this.#nextRecent(), this.#render());
      if (s === "?") return void this.#check(e);
      this.#splitTab = null;
      if (key.name !== "return" && this.#checkLines) (this.#checkLines = this.#checked = null), (this.#splitNote = ""); // a check of what was typed before
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
      case "i": {
        // smart: Iranian sites direct (smart.ts); its save data stays as it was for the next time
        if (sp.default !== "vpn") break;
        const { smart, ...rest } = sp;
        return this.#saveSplit(smart ? rest : { ...rest, smart: true });
      }
      case "s": {
        if (sp.default !== "vpn" || !sp.smart) break;
        const { probe, ...rest } = sp;
        this.#saveSplit(probe ? rest : { ...rest, probe: true });
        if (!probe) this.#splitNote = dim("Other sites are tried directly first: your provider sees which.");
        break;
      }
      case "p":
        this.#pick = { query: "", sel: 0 };
        this.#splitNote = "";
        void listApps().then((a) => ((this.#apps = a.map((x) => x.name)), this.#render()), () => {});
    }
    this.#render();
  }

  /** The app picker's rows: the apps not listed yet that have what's searched for, those starting with it first; none found, the typed name itself. */
  #pickRows(): { name: string; typed?: boolean }[] {
    const q = this.#pick?.query.trim().toLowerCase() ?? "";
    const listed = new Set(this.#settings.split.rules.map((r) => r.match.toLowerCase()));
    const has = this.#apps.filter((a) => !listed.has(`app:${a.toLowerCase()}`) && a.toLowerCase().includes(q));
    const rows = [...has.filter((a) => a.toLowerCase().startsWith(q)), ...has.filter((a) => !a.toLowerCase().startsWith(q))].map((name) => ({ name }));
    return rows.length || !q ? rows : [{ name: this.#pick!.query.trim(), typed: true }];
  }

  /** Keystrokes in the app picker: typing searches, ↑↓ pick, enter adds, esc goes back to the rules. */
  #pickKey(s: string, key: readline.Key): void {
    const pick = this.#pick!;
    const rows = this.#pickRows();
    if (key.name === "escape") this.#pick = null;
    else if (key.name === "up") pick.sel = Math.max(0, pick.sel - 1);
    else if (key.name === "down") pick.sel = Math.min(rows.length - 1, pick.sel + 1);
    else if (key.name === "pageup") pick.sel = Math.max(0, pick.sel - 10);
    else if (key.name === "pagedown") pick.sel = Math.min(rows.length - 1, pick.sel + 10);
    else if (key.name === "return") {
      const row = rows[pick.sel];
      if (!row) return;
      this.#pick = null;
      return this.#addRule(`app:${row.name}`);
    } else if (key.name === "backspace") (pick.query = pick.query.slice(0, -1)), (pick.sel = 0);
    else if (s && s.length === 1 && s >= " " && !key.ctrl && !key.meta && pick.query.length < 60) (pick.query += s), (pick.sel = 0);
    this.#render();
  }

  /** Adds a typed site or app, going the other way than everything else. */
  #addRule(text: string): void {
    const sp = this.#settings.split;
    const match = parseRule(text);
    if (!match) {
      this.#splitNote = red(text.trim() ? `Not a site or an app: “${fit(text.trim(), 20)}”. Try *.ir or Telegram.` : "Type a site or an app first.");
      return this.#render();
    }
    this.#splitEdit = null;
    const via = this.#checked?.site === match ? this.#checked.via : null; // the check's offer
    this.#checkLines = this.#checked = null;
    const i = sp.rules.findIndex((r) => r.match.toLowerCase() === match.toLowerCase());
    if (i >= 0 && via && sp.rules[i].via !== via) {
      this.#splitSel = i + 1;
      return this.#saveSplit({ ...sp, rules: sp.rules.map((r, j) => (j === i ? { ...r, via } : r)) });
    }
    if (i >= 0) {
      this.#splitSel = i + 1;
      this.#splitNote = yellow(`${match} is already in the list.`);
      return this.#render();
    }
    this.#splitSel = sp.rules.length + 1; // the new row
    this.#saveSplit({ ...sp, rules: [...sp.rules, { match, via: via ?? flip(sp.default) }] });
  }

  /** Blocked or sanctioned? The typed site tried directly and, connected, through the VPN (proxy.ts checkSite). */
  async #check(text: string): Promise<void> {
    const site = parseSite(text);
    if (!site || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(site)) {
      this.#splitNote = red("Type a site's name to check it, like x.com.");
      return this.#render();
    }
    const vpn = this.#active && this.#active !== RELAY_ROW;
    this.#checkLines = [cyan(`Checking ${fit(site, 40)}…`), dim(vpn ? "Directly and through the VPN: a few seconds." : "Directly: a few seconds.")];
    this.#splitNote = "";
    this.#render();
    const got = await checkSite(vpn ? this.#conn : null, site);
    if (this.#splitEdit === null || parseSite(this.#splitEdit) !== site) return; // typed over meanwhile
    const verdict = verdictOf(site, got.direct, got.vpn);
    const [title, more] = verdictText(verdict, got.direct, got.vpn);
    const want = wantOf(verdict);
    const now = wayOf(site);
    this.#checked = want && now !== "probe" && now !== want ? { site, via: want } : null;
    const tone = verdict === "blocked" ? red : verdict === "sanctioned" || verdict === "partly" ? yellow : verdict === "open" ? green : bold;
    const way = now === "probe" ? "Save data sends it the way it opens." : `It ${now === "vpn" ? "uses the VPN" : "goes direct"} now.`;
    // three lines where typing's help has two: the smart line isn't there while typing
    this.#checkLines = [tone(bold(title)), `directly: ${tryText(got.direct)} · VPN: ${tryText(got.vpn)}`, dim(more)];
    this.#splitNote = this.#checked ? `${way} ${cyan(`enter: ${want === "vpn" ? "use the VPN for it" : "send it direct"}`)}` : dim(way);
    this.#render();
  }

  /** Tab while typing: the next site seen lately, or app on this computer, that has what was typed, and isn't listed yet. */
  #nextRecent(): void {
    const tab = (this.#splitTab ??= { query: this.#splitEdit ?? "", i: -1 });
    const listed = new Set(this.#settings.split.rules.map((r) => r.match.toLowerCase()));
    const q = tab.query.toLowerCase();
    const found = [...recentSites, ...this.#apps.map((a) => `app:${a}`)].filter((x) => x.toLowerCase().includes(q) && !listed.has(x.toLowerCase()));
    if (!found.length) {
      this.#splitNote = dim(tab.query ? `No site seen lately nor app has “${fit(tab.query, 24)}”.` : "No sites seen yet: browse through foxhole first.");
      return;
    }
    tab.i = (tab.i + 1) % found.length;
    this.#splitEdit = found[tab.i];
    this.#splitNote = dim(`${tab.i + 1} of ${found.length} seen lately or apps · tab next`);
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
    if ("relay" in patch) {
      useRelay(loadRelay(next)); // takes effect at once, no restart
      this.#setList(this.#list);
      // relay mode follows: through the new relay, or off without one
      if (this.#active === RELAY_ROW) void (loadRelay(next) ? this.#connect(RELAY_ROW) : this.#disconnect());
    }
    if ("smartDns" in patch) this.#followSmartDns();
    if ("share" in patch || "port" in patch) {
      this.#host = proxyHost(next);
      this.#port = next.port;
      this.#checkFirewall();
      await this.#restartProxy();
    }
    this.#render();
  }

  /** Whole-system mode is over: Smart DNS has port 53 again, if it stepped aside. */
  #smartDnsBack(): void {
    if (!this.#smartDnsYields) return;
    this.#smartDnsYields = false;
    void this.#followSmartDns();
  }

  /**
   * Starts or stops Smart DNS as Settings has it, out of a Mac's whole-system mode's way, and moves it to the network's
   * new address. Resolves once done. A port it can't have is said in Settings.
   */
  #followSmartDns(): Promise<void> {
    return (this.#smartDnsTurn = this.#smartDnsTurn.then(async () => {
      const want = !!this.#settings.smartDns && !this.#smartDnsYields;
      const host = smartDnsHost(lanIp());
      if (this.#smartDns && (!want || this.#smartDnsAt !== host)) {
        this.#smartDns.close();
        this.#smartDns = null;
      }
      if (!want) this.#smartDnsError = "";
      if (!want || this.#smartDns) return this.#render();
      try {
        if (!host) throw new Error("This computer isn't on a local network.");
        this.#smartDns = await startSmartDns(this.#conn, { host, self: () => lanIp(), vpn: () => !!this.#active && this.#active !== RELAY_ROW });
        this.#smartDnsAt = host;
        this.#smartDnsError = "";
      } catch (err) {
        this.#smartDnsError = smartDnsProblem(err as NodeJS.ErrnoException);
      }
      this.#render();
    }));
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
    const rc = this.#relayCheck;
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
      dim("⏎ QR code for your phone"),
      onOff(!!s.smartDns) + (s.smartDns && this.#smartDnsYields ? yellow("  paused") : s.smartDns && this.#smartDnsError ? red("  ✗ can't start") : ""),
      dim("⏎ QR code and link"),
      e?.key === "take" ? (e.text.length > 23 ? "…" + e.text.slice(-22) : e.text) + cursor : this.#take ? yellow("⏎ import") : dim("⏎ paste a link"),
      (s.relay ? green("on") : dim("off")) + dim("  ⏎ step by step"),
      relayVal(e?.key === "relayId" ? e.text : s.relay?.deploymentId ?? "", e?.key === "relayId", false),
      relayVal(e?.key === "relayKey" ? e.text : s.relay?.authKey ?? "", e?.key === "relayKey", true),
      !rc ? dim("⏎ check") : rc.tone === "busy" ? dim("checking…") : { ok: purple("✓ works"), warn: yellow("old script"), error: red("✗ not working") }[rc.tone] + dim("  ⏎ again"),
      this.#caOk === undefined ? dim("…") : this.#caOk ? green("trusted") + dim("  ⏎ remove") : yellow("not trusted") + dim("  ⏎ trust"),
    ];
    const w = Math.max(...SETTINGS.map((it) => it.label.length));
    const rows = SETTINGS.map((it, i) => {
      const here = i === this.#setSel;
      const label = it.label.padEnd(i < RELAY_AT ? w : w - 2); // in the relay's box too, the values line up
      return `${here ? cyan("❯") : " "} ${here ? bold(label) : label}   ${values[i]}`;
    });
    const loginHelp = (what: string) =>
      e?.key === what
        ? [dim(`Type the ${what} · enter save (empty: none) · esc cancel`)]
        : [dim("Asked from other devices when sharing is on; apps on"), dim("this computer don't need it. Optional: empty means no login.")];
    const relayGuide = [
      dim("Blocked vpn.mozilla.org (Iran)? Make your own free relay on"),
      dim("Google Apps Script: “Set up” above walks you through it."),
    ];
    const relayOn = [green("Relay on: Firefox VPN uses it when vpn.mozilla.org is blocked,"), dim("and Relay, first in Locations, browses through it. Clear both to remove.")];
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
      telegram: [dim("Telegram through the VPN, other apps not: its proxy set by a"), dim("QR code on your phone, or in a click on this computer.")],
      smartDns: !s.smartDns
        ? [dim("YouTube and blocked or sanctioned sites on a TV, a console or an"), dim("iPhone, with no app: only its DNS is set to this computer.")]
        : this.#smartDnsYields
          ? [yellow("On a Mac it works in Proxy only mode: Whole system mode needs"), yellow("port 53 for its own DNS.")]
          : this.#smartDnsError
          ? wrap(this.#smartDnsError, 62).map(red)
          : [
              `Set the TV's or console's DNS to ${bold(cyan(lanIp() ?? "this computer's IP"))}.`,
              this.#active ? dim("Only the web and WhatsApp's messages: not games or calls.") : yellow("Connect first: till then it gets the network's own answers."),
              dim("An iPhone's apps need Local Network on, in Privacy & Security."),
              dim("Telegram doesn't use DNS: its QR code is in the row above."),
            ],
      give: [dim("Your relay and split tunneling, for the family's other devices:"), dim("a QR code for a phone to scan, or a link to send.")],
      take: e?.key === "take"
        ? [dim("Paste a Foxhole settings link · enter check · esc cancel")]
        : this.#take
          ? [
              ...this.#take.what.map((w) => `${green("✓")} ${w}`),
              ...(this.#take.what.some((w) => w.startsWith("VPN relay")) ? wrap("A relay sees what goes through it: take one only from someone you trust.", 62).map(yellow) : []),
              dim("enter import · esc cancel"),
            ]
          : [dim("Settings someone shared with you: paste their link"), dim("(foxhole://settings…), see what it changes, then import it.")],
      relaySetup: s.relay ? relayOn : relayGuide,
      relayId: e?.key === "relayId"
        ? [dim("Paste your Apps Script deployment id · enter save · esc cancel")]
        : s.relay ? relayOn : relayGuide,
      relayKey: e?.key === "relayKey"
        ? [dim("Type or paste the auth key · tab: generate a strong one"), dim("enter save · esc cancel")]
        : s.relay ? relayOn : relayGuide,
      relayCheck:
        rc && rc.tone !== "busy"
          ? wrap(rc.tone === "ok" ? `✓ ${rc.text}` : rc.text, 62).map(rc.tone === "ok" ? purple : rc.tone === "warn" ? yellow : red)
          : [dim("Asks your Apps Script to fetch, as relay mode does: checks the"), dim("deployment ID, the auth key, and that the script is up to date.")],
      relayCert: [
        dim("Relay mode opens sites' encryption on this computer, with"),
        dim("certificates from foxhole's own authority, made here alone."),
        `Terminal tools: ${cyan(process.platform === "win32" ? "foxhole env | iex" : 'eval "$(foxhole env)"')}`,
      ],
    }[SETTINGS[this.#setSel].key];
    return box(
      // the relay's rows in purple, its own part of foxhole (as in the desktop app), with whether it's on; 62: the popup's 66 less this box's sides
      ["", ...rows.slice(0, RELAY_AT), ...box(rows.slice(RELAY_AT), { width: 62, color: purple, title: `${bold(purple("VPN relay"))} ${s.relay ? lit(" ENABLED ") : unlit(" DISABLED ")}` }), "", ...help, this.#settingsNote, dim("↑↓ select · enter change · esc close")],
      { title: bold(cyan("⚙ Settings")), width: 66 },
    );
  }

  /** Telegram's popup: the QR code that sets this proxy in a phone's Telegram (sharing on), and this computer's. */
  #telegramPopup(frameHeight: number): string[] {
    const s = this.#settings;
    const lan = lanIp();
    const link = s.share && lan ? telegramLink(lan, s.port, loginFor(s, lan)) : null;
    const qr = link ? qrLines(link) : [];
    const center = (l: string) => " ".repeat(Math.max(0, Math.floor((62 - vw(l)) / 2))) + l;
    const phone = !link
      ? [yellow("Turn on “Share with devices on this network” to use this"), yellow("proxy from your phone's Telegram.")]
      : qr.length + 9 <= frameHeight
        ? ["", ...qr.map(center), "", "Scan it with your phone's camera: Telegram asks to use this proxy."]
        : [dim("A taller terminal shows its QR code. Or open this on the phone:"), ...wrap(link, 62).map((l) => cyan(l))];
    return box([...phone, "", dim("enter Telegram on this computer · esc back")], { title: bold(cyan("✈ Telegram")), width: 66 });
  }

  /** The sites the Data popup lists: those that used the VPN this month, the biggest first. */
  #dataRows() {
    return traffic().sites.filter((x) => x.vpn > 0).slice(0, 12);
  }

  /** Keystrokes in the Data popup: ↑↓ pick a site, enter sends it direct (a rule), esc or m closes. */
  #dataKey(key: readline.Key): void {
    const rows = this.#dataRows();
    const sp = this.#settings.split;
    if (key.name === "escape" || key.name === "m") this.#dataOpen = false;
    else if (key.name === "up" || key.name === "k") this.#dataSel = Math.max(0, this.#dataSel - 1);
    else if (key.name === "down" || key.name === "j") this.#dataSel = Math.min(rows.length - 1, this.#dataSel + 1);
    else if (key.name === "return" && rows[this.#dataSel]) {
      const site = rows[this.#dataSel].site;
      if (sp.default !== "vpn") this.#dataNote = yellow("Everything not listed goes direct already: see Split tunneling.");
      else if (sp.rules.some((r) => r.match === site)) this.#dataNote = yellow(`${site} has a rule already: see Split tunneling.`);
      // blocked here (save data found it so), or refusing Iran: direct, it would stop working
      else if (knownBlocked(site) || sanctioned(site)) this.#dataNote = yellow(`${site} doesn't open direct here: it stays on the VPN.`);
      else {
        this.#saveSplit({ ...sp, rules: [...sp.rules, { match: site, via: "direct" }] });
        this.#dataNote = green(`✓ ${site} goes direct now`) + dim(": new connections skip the VPN.");
      }
    }
    this.#render();
  }

  /** The Data popup: the month's data left and when it runs out at its rate, then the sites that spent it. */
  #dataPopup(frameHeight: number): string[] {
    const u = this.#conn.usage;
    const { since, sites } = traffic();
    const rows = this.#dataRows();
    const top = rows[0]?.vpn || 1;
    const direct = sites.reduce((n, x) => n + x.direct, 0);
    const out = u && !u.unlimited ? runsOut(u.max, u.remaining, u.reset) : null;
    const left = !u ? dim("Data left: unknown till connected.") : u.unlimited ? green("Unlimited data.") : `${bold(gb(u.remaining))} of ${gb(u.max)} left${u.reset ? dim(` · resets ${shortDate(u.reset)}`) : ""}`;
    const pace = out ? yellow(`At this rate it runs out around ${shortDate(out)}.`) : u && !u.unlimited && u.reset ? dim("At this rate it lasts till it resets.") : "";
    const listed = new Set(this.#settings.split.rules.filter((r) => r.via === "direct").map((r) => r.match));
    const room = Math.max(3, frameHeight - 16);
    const lines = rows.slice(0, room).map((x, i) => {
      const here = i === this.#dataSel;
      const bar = "█".repeat(Math.max(1, Math.round((x.vpn / top) * 16)));
      return `${here ? cyan("❯") : " "} ${(here ? bold : (t: string) => t)(fit(x.site, 28).padEnd(28))} ${cyan(bar.padEnd(16))} ${sizeOf(x.vpn).padStart(7)}${listed.has(x.site) ? green("  direct now") : ""}`;
    });
    return box(
      [
        "",
        left,
        pace,
        "",
        rows.length ? `Through the VPN since ${shortDate(new Date(since))}, on this computer:` : dim("Nothing through the VPN yet this month on this computer."),
        ...lines,
        "",
        direct ? dim(`Direct: ${sizeOf(direct)}, none of it the VPN's data.`) : "",
        this.#dataNote,
        "",
        dim("↑↓ select · enter send it direct · esc close"),
      ],
      { title: bold(cyan("◔ Data this month")), width: 66 },
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
    const lines = fox(this.#mood(), Date.now(), false, this.#relayOn());
    const out = lines.map((l, i) => (l === this.#foxDrawn[i] ? "" : `\x1b[${at.y + i + 1};${at.x + 1}H${l}`)).join("");
    this.#foxDrawn = lines;
    if (out) process.stdout.write("\x1b[0m" + out);
  }

  #render(): void {
    if (!screenOn) return; // a late redraw (timer, log line) must not paint over the normal screen
    const u = this.#conn.usage;
    // relay mode in purple where Firefox VPN is green
    const relayOn = this.#relayOn();
    const ok = relayOn ? purple : green, on = relayOn ? litPurple : lit;
    const data = relayOn
      ? `${bold(String(relayStats.relayed))} relayed ${dim(`· ${relayStats.fronted} straight to Google · ~20k a day`)}`
      : !u
      ? dim("unknown")
      : u.unlimited
        ? green("unlimited")
        : `${bold(gb(u.remaining).replace(" GB", ""))} of ${gb(u.max)} left` + // as Firefox shows it; then when it runs out at this rate, if before it resets
          (runsOut(u.max, u.remaining, u.reset) ? yellow(` · runs out ~${shortDate(runsOut(u.max, u.remaining, u.reset)!)}`) : u.reset ? dim(` · resets ${shortDate(u.reset)}`) : "");
    const gc = this.#globalCountry;
    const place = (c: Country) => (c === RELAY_ROW ? "Relay" : flagged(c.code, countryName(c.code, c.name)));
    const state = this.#global
      ? `${on(" GLOBAL TUN ON ")} ${ok(place(gc!))}`
      : this.#active
        ? ok(`● connected ${place(this.#active)}`)
        : dim("○ disconnected");
    const sp = this.#settings.split;
    const split = splitSummary(sp);
    const route = this.#global
      // the relay carries the web; what isn't goes direct
      ? ok(sp.default === "direct" ? "system traffic → direct" : relayOn ? "web → relay · the rest direct" : "all system traffic → VPN") + (split ? dim(` · ${split}`) : "")
      : this.#active
        ? `${cyan(this.#proxyAddr())}  ${dim([split ? "" : "SOCKS5 or HTTP", this.#host === "0.0.0.0" ? "shared on this network" : "", split ?? ""].filter(Boolean).join(" · "))}`
        : dim("—");
    const status = this.#message;
    const net = this.#net === undefined ? dim("checking…") : this.#net ?? yellow("offline");
    const ip = this.#ip === undefined ? dim("checking…") : this.#ip === null ? yellow("unreachable") : `${bold(this.#ip)}  ${dim(this.#ipNote)}`;
    const account = `${this.#email ?? dim("unknown")}  ${dim("A accounts")}`;
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

    const version = [...newsLines(Math.min(cols - 4, 76)), ...versionLines(true)];
    // A short window drops the tips, then the fox, before the buttons (they name the keys) get cut off.
    const foot = 4 + version.length; // a blank line, the buttons, a blank line, the version, the link
    const foxOn = wide ? rows - foot >= FOX_H + 9 : rows - 18 - version.length - (FOX_H + 1) >= 5;
    const tips = wide
      ? rows - foot - 3 >= (foxOn ? FOX_H + 9 : 9)
      : rows - 21 - version.length - (foxOn ? FOX_H + 1 : 0) >= 6; // not at the cost of the list (6: its header, 5 countries)
    // the repo's link goes too before the list gets shorter than that
    const link = wide || rows - (tips ? 21 : 18) - version.length - (foxOn ? FOX_H + 1 : 0) >= 6;
    const room = Math.max(3, wide
      ? rows - foot - (tips ? 3 : 0) - 6 // beside the details: the window's height
      : rows - (tips ? 21 : 18) - version.length - (foxOn ? FOX_H + 1 : 0) + (link ? 0 : 1));
    const { start, slice } = window(this.#sel, this.#countries.length, room - 1); // a line goes under the relay
    const label = (c: Country) => flagged(c.code, countryName(c.code, c.name));
    const body: (string[] | null)[] = slice.map((i) => {
      const c = this.#countries[i];
      const here = i === this.#sel;
      if (c === RELAY_SETUP) {
        const name = emoji("🟣 ") + "Relay · not set up yet";
        return [`${here ? cyan("❯") : " "} ${dim("○")}`, "", dim("relay"), here ? purple(name) : dim(name)];
      }
      if (c === RELAY_ROW) {
        const name = emoji("🟣 ") + "Relay · via Google";
        return [`${here ? cyan("❯") : " "} ${this.#active === c ? purple("●") : dim("○")}`, "", purple("relay"), here ? bold(purple(name)) : purple(name)];
      }
      const mark = !c.available ? red("×") : this.#active?.code === c.code ? green("●") : dim("○");
      return [
        `${here ? cyan("❯") : " "} ${mark}`,
        here ? bold(c.code) : dim(c.code),
        c.locked ? `${dim(strike("paid"))} ${green("free")}` : green("free"),
        here ? bold(cyan(label(c))) : label(c),
      ];
    });
    if (!this.#list.length) body.push(["   ", "", "", dim("loading…")]);
    const sep = start === 0 && body.length > 1 ? 1 : -1; // a line between the relay and the countries (grid's null)
    if (sep > 0) body.splice(sep, 0, null);
    const range = this.#countries.length > room
      ? `${start + 1}–${start + slice.length} of ${this.#countries.length}`
      : this.#list.length ? `${this.#list.length} countries` : ""; // none yet: the list says loading…

    const title = bold(cyan(emoji("🦊 ") + "foxhole-vpn"));
    const key = (k: string, rest: string) => `[${under(k)}${rest}]`;
    // Lit while on, each part on its own: the underline's reset would end an outer style
    // The checkbox: what's on while connected, what connecting will do while off
    const globalBtn = (this.#active ? this.#global : !this.#settings.proxyOnly) ? ["[x] ", under("G"), "lobal TUN"].map(on).join("") : dim(`[ ] ${under("G")}lobal TUN`);
    // On the connected country, D disconnects (lit like a switch that's on); elsewhere Enter connects
    const sel = this.#countries[this.#sel];
    const connectBtn = this.#active && sel?.code === this.#active.code
      ? ["[", under("D"), "isconnect]"].map(on).join("")
      : sel === RELAY_SETUP ? bold(purple("[⏎ What's Relay?]")) : bold((sel === RELAY_ROW ? purple : cyan)("[⏎ Connect]"));
    // Lit while any site is split off, like a switch that's on
    const splitBtn = splitOn(sp) ? ["[Split ", under("T"), "unnel]"].map(lit).join("") : dim(`[Split ${under("T")}unnel]`);
    const buttons = [connectBtn, globalBtn, splitBtn, dim(key("S", "ettings")), dim("[Data]"), dim(key("L", "ogs")), dim(key("Q", "uit"))].join("  ");
    const table = (minWidth: number) => grid(["", "Code", "Tier", "Country"], body, { caption: bold("Locations"), captionRight: dim(range), minWidth });
    // Under a popup, its shape alone: the backdrop's colors go, which would leave half of each two-color cell
    const covered = this.#restoring || this.#pwMode || this.#settingsOpen || this.#splitOpen || this.#logsOpen || this.#dataOpen;
    const foxLines = foxOn ? fox(this.#mood(), Date.now(), covered, relayOn) : [];
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
      ...(link ? [centerIn(dim(repoLink), width)] : []),
    ];
    const popup = this.#restoring
      ? this.#restoringPopup()
      : this.#pwMode
        ? this.#passwordPopup()
        : this.#wizard
          ? this.#wizard.render(cols, frame.length - 2)
          : this.#blocked
          ? this.#blockedPopup()
          : this.#relayIntro
          ? this.#relayPopup()
          : this.#trustAsk
          ? this.#trustPopup()
          : this.#lowOpen
          ? this.#lowPopup()
          : this.#notesOpen
          ? this.#notesPopup(width, frame.length)
          : this.#acctOpen
          ? this.#accountsPopup()
          : this.#settingsOpen
          ? this.#tgOpen ? this.#telegramPopup(frame.length) : this.#give ? this.#givePopup(frame.length) : this.#settingsPopup()
          : this.#splitOpen
            ? this.#splitPopup(frame.length)
            : this.#dataOpen
            ? this.#dataPopup(frame.length)
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
    const buttonsY = frame.length - version.length - (link ? 3 : 2);
    // as overlay() places it: centered, with a 1-cell margin; the rows follow the border and a blank line
    const setW = popup ? vw(popup[0]) : 0;
    this.#hit = {
      top, left, buttonsY, setW,
      rowsTop: tableY, rowsLeft: tableX, width: tableW,
      start, sep,
      rows: slice.length + (sep > 0 ? 1 : 0),
      buttons: frame[buttonsY].replace(/\x1b\[[0-9;]*m/g, "").replace(/\[[x ]\] Global TUN/, "[Global TUN  ]"), // one button for #mouse, box and label
      setTop: Math.floor((frame.length - (popup?.length ?? 0) - 2) / 2) + 3,
      setX: Math.floor((width - setW - 2) / 2) + 1,
    };
  }

  /** The app picker, in the Split popup's place: a search, and the apps that have it. */
  #pickPopup(frameHeight: number): string[] {
    const pick = this.#pick!;
    const sp = this.#settings.split;
    const rows = this.#pickRows();
    const q = pick.query.trim().toLowerCase();
    const room = Math.max(3, frameHeight - 12);
    const { slice } = window(pick.sel, rows.length, room);
    const mark = (name: string) => {
      const i = q ? name.toLowerCase().indexOf(q) : -1;
      return i < 0 ? name : name.slice(0, i) + yellow(name.slice(i, i + q.length)) + name.slice(i + q.length);
    };
    const lines = slice.map((i) => {
      const r = rows[i];
      const label = r.typed ? `+ add “${fit(r.name, 30)}” as an app` : mark(fit(r.name, 54));
      return `${i === pick.sel ? cyan("❯") : " "} ${i === pick.sel ? bold(label) : label}`;
    });
    const count = !this.#apps.length ? "Looking for apps…" : `${rows.filter((r) => !r.typed).length} of ${this.#apps.length} apps`;
    return box(
      [
        "",
        `${dim("search:")} ${pick.query}${cyan("▏")}`,
        dim(count + (rows[0]?.typed ? " · none has it: not running now? add it by name" : "")),
        "",
        ...(lines.length ? lines : [dim("  No apps found.")]),
        "",
        dim(`The app you pick goes ${sp.default === "vpn" ? "direct" : "through the VPN"}: unlike the rest.`),
        this.#splitNote,
        "",
        dim("type to search · ↑↓ select · enter add · esc back"),
      ],
      { title: bold(cyan("⇄ Split tunneling · pick an app")), width: 66 },
    );
  }

  /** The Split tunneling popup: everything else's way, then each rule's, with how many connections each took. */
  #splitPopup(frameHeight: number): string[] {
    if (this.#pick) return this.#pickPopup(frameHeight);
    const sp = this.#settings.split;
    const e = this.#splitEdit;
    const way = (v: Via) => (v === "vpn" ? green("VPN") : yellow("direct"));
    const took = (k: string) => (hits.get(k) ? dim(`${hits.get(k)} matched`) : "");
    const all = [
      { label: "Everything else", way: way(sp.default), took: took("") },
      ...sp.rules.map((r) => ({ label: r.match, way: way(r.via), took: took(r.match) })),
      { label: e !== null ? (e.length > 33 ? `…${e.slice(-32)}` : e) + cyan("▏") : dim("+ add a site or app"), way: "", took: "" }, // typing: its end shows
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
        ? (this.#checkLines ?? [dim("A site: bbc.co.uk (and subdomains), *.co.uk, ir · ? checks it"), dim("or an app: Telegram · tab: seen lately · enter add · esc cancel")])
        : sel === 0
          ? [sp.default === "vpn" ? "Sites and apps not listed use the VPN: list the ones to bypass it." : "Sites and apps not listed go direct: list those needing the VPN.", dim("enter switches it")]
          : sel <= sp.rules.length && appOf(sp.rules[sel - 1].match) !== null
            ? [dim("An app's rule covers all its connections, whatever the site."), dim("Direct apps see your real IP. Applies to new connections.")]
            : sel <= sp.rules.length
              ? [dim("A site covers its subdomains; the most specific rule wins."), dim("Direct sites see your real IP. Applies to new connections.")]
              : [dim(`A new site or app goes ${sp.default === "vpn" ? "direct" : "through the VPN"}: unlike the rest.`), ""];
    const tick = (on: boolean | undefined, what: string, key: string) => `${on ? green("✓") : dim("○")} ${what} ${dim(`(${under(key)})`)}`;
    // smart (smart.ts) only decides with everything else through the VPN
    const smart =
      sp.default === "vpn" && e === null
        ? [`${tick(sp.smart, "Iranian sites direct", "i")}${sp.smart ? `   ${tick(sp.probe, "Save data", "s")}   ${took(SMART)}` : ""}`]
        : [];
    return box(
      ["", ...rows, "", ...smart, ...help, this.#splitNote, "", dim("↑↓ select · enter VPN/direct · a add · p apps · x del · esc close")],
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

  /** The Locations: the relay first (dimmed until one is set up), then the countries. The selection stays on its row. */
  #setList(list: Country[]): void {
    const at = this.#countries[this.#sel]?.code ?? loadLastCountry();
    this.#list = list;
    this.#countries = [loadRelay(this.#settings) ? RELAY_ROW : RELAY_SETUP, ...list];
    const i = this.#countries.findIndex((c) => c.code === at);
    this.#sel = i >= 0 ? i : this.#countries[0] === RELAY_SETUP && list.length ? 1 : 0; // else the first to connect to
  }

  /** Connected through the relay (relaymode.ts), not Firefox VPN. */
  #relayOn(): boolean {
    return this.#active === RELAY_ROW && !!this.#conn.relay;
  }

  /** After a failure Firefox VPN can't get past: where a relay is set up, how to browse through it instead. */
  #relayHint(): string {
    return this.#countries[0] === RELAY_ROW && !this.#relayOn() ? dim(" · R: browse through your relay") : "";
  }

  /** After connecting to the relay: asks to trust foxhole's certificate, if this computer doesn't yet (sites won't open). */
  async #askTrust(): Promise<void> {
    this.#caOk = await caTrusted();
    this.#trustAsk = !this.#caOk && this.#relayOn();
    this.#render();
  }

  /** Trusts foxhole's certificate (`add`), or stops: macOS and Windows ask in a window of their own, Linux needs root. */
  async #trust(add: boolean, priv?: Priv): Promise<void> {
    if (this.#busy) return;
    if (process.platform === "linux" && !priv) {
      if (!(await isPrivileged())) return this.#askPassword(add ? "trust" : "untrust");
      priv = await adminPriv(true);
    }
    this.#busy = true;
    this.#message = dim(process.platform === "darwin" ? "macOS asks for your password…" : process.platform === "win32" ? "Windows asks you to confirm: choose Yes…" : add ? "trusting the certificate…" : "removing the certificate…");
    this.#render();
    try {
      await setCaTrust(add, priv);
      this.#caOk = await caTrusted();
      this.#message = !add ? dim("certificate removed") : this.#caOk ? purple("✓ Certificate trusted. Restart your browser, then sites open through the relay.") : yellow("certificate added, but not trusted yet");
    } catch (err) {
      this.#message = red(`certificate ${add ? "not trusted" : "not removed"}: ${(err as Error).message}`);
    } finally {
      this.#busy = false;
      if (this.#settingsOpen) this.#settingsNote = this.#message;
      this.#render();
    }
  }

  #trustPopup(): string[] {
    const how = process.platform === "darwin" ? "macOS asks for your password once," : process.platform === "win32" ? "Windows asks you to confirm once," : "It takes your sudo password once,";
    return box(
      [
        "",
        bold(purple("Trust foxhole's certificate to browse")),
        "",
        "The relay can only fetch pages, so foxhole opens",
        "each site's encryption on this computer to carry",
        "it, with certificates from its own authority: made",
        "on this computer, and never sent anywhere.",
        "",
        how,
        "then restart your browser.",
        "",
        `${bold(purple("[⏎ Trust it]"))}   ${dim("[esc Not now]")}`,
        "",
      ],
      { title: bold(purple(emoji("🔐 ") + "One more step")) },
    );
  }

  /** The popup shown while quitting restores global mode's routes and DNS. */
  /** Shows the blocked popup when err says vpn.mozilla.org is blocked here (with no relay set); whether it did. */
  #saysBlocked(err: unknown): boolean {
    if (!(err instanceof GuardianBlocked)) return false;
    this.#blocked = this.#blockedTold = true;
    return true;
  }

  /** What Relay is, from its row before one is set up, with the setup a key away. */
  #relayPopup(): string[] {
    return box(
      [
        "",
        bold(purple("Your own way through")),
        "",
        ...wrap("A free script on your own Google account fetches the web for you. Your internet provider sees only a visit to Google, so Relay gets through where Firefox VPN is blocked (e.g. Iran), and lets foxhole reach Firefox VPN there too.", 57),
        "",
        ...wrap("It carries web pages only, and sites can still see your IP. Setting it up takes a few minutes, and foxhole shows you each click.", 57),
        "",
        `${bold(purple("[⏎ Set up step by step]"))}   ${dim("[esc Not now]")}`,
        "",
      ],
      { title: bold(purple(emoji("🟣 ") + "Relay")) },
    );
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
        ...(this.#pwFor === "global"
          ? ["Global mode routes all of this computer's", "traffic through the VPN, which needs", "administrator rights.", "", "Once: foxhole sets up a small network", "helper with it, so it won't ask again."]
          : [`${this.#pwFor === "trust" ? "Trusting" : "Removing"} foxhole's certificate for`, "the system and its browsers needs", "administrator rights."]),
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
