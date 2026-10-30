#!/usr/bin/env node
import net from "node:net";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fetchServerList } from "./serverlist.js";
import { findAccount, openBrowser, FULL_DISK_ACCESS, type AccountState, type ProfileAccessError } from "./profile.js";
import { FirefoxAuth, StaticAuth, type Authenticator } from "./auth.js";
import { Connection, findCountry } from "./connection.js";
import { fetchEntitlement, useRelay } from "./guardian.js";
import { loadRelay } from "./httprelay.js";
import { startProxy } from "./proxy.js";
import { firewallHint, lanIp } from "./netinfo.js";
import { useSplit, splitSummary, type Split } from "./split.js";
import { runGlobal, directPriv, isPrivileged, dialHost, staleCleanupScript, parseDefaultRoute } from "./global.js";
import { loadSettings, proxyHost, loginFor } from "./settings.js";
import { restoreWindows, serveElevated, HELPER_CMD } from "./global-win32.js";
import { Tui } from "./tui.js";
import { envLines } from "./catrust.js";
import { loadCa } from "./mitm.js";
import { checkUpdate, updateNotice, versionLines } from "./update.js";
import { startTokenReceiver, loadSavedToken, saveToken, forgetToken, tokenFile, tokenTtl, tokenProblem } from "./tokenserver.js";
import { bold, dim, green, red, yellow, cyan, under, code, flag, countryName, gb, shortDate, box, vw, centerIn, copyText, openUrl } from "./ui.js";

// Node gives each server address only 250 ms before moving on; far VPN servers
// take 600-900 ms to answer, so every attempt failed with a blank AggregateError.
net.setDefaultAutoSelectFamilyAttemptTimeout(3000);

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

const ENV_TOKEN = "FOXHOLE_ACCESS_TOKEN";

/** The access token to use: the env var if set, else the one saved from Firefox. */
function tokenEnv(): { name: string; value: string } | null {
  const value = process.env[ENV_TOKEN];
  if (value) return { name: ENV_TOKEN, value };
  const saved = loadSavedToken();
  return saved ? { name: "saved token", value: saved } : null;
}

/** Warns about a pasted access token that is expired or short-lived. */
function noteTokenTtl(): void {
  const env = tokenEnv();
  if (!env) return;
  const ttl = tokenTtl(env.value);
  if (ttl === null) return;
  if (ttl <= 0) {
    console.log(red(`${env.name} has expired — fetch a fresh one (it can't be refreshed).`));
  } else {
    console.log(dim(`token valid for ${Math.floor(ttl / 60)}m ${ttl % 60}s (static tokens aren't refreshed)`));
  }
}

/** Picks an authenticator: the env token if set, else the Firefox session, else the saved token. */
function makeAuth(): Authenticator | null {
  const env = tokenEnv();
  if (env?.name === ENV_TOKEN) return new StaticAuth(env.value);
  const account = findAccount();
  if (account?.signedIn) return new FirefoxAuth(account);
  return env ? new StaticAuth(env.value) : null;
}

/** The system won't let us read Firefox's profile: how to allow it (macOS: opens the Full Disk Access pane), then exit. */
function blockedExit(err: ProfileAccessError): never {
  const [first, ...rest] = err.message.split("\n");
  console.error("\n" + red(first) + "\n" + rest.map((l) => (/^\d\./.test(l) ? "  " + l.replace(/(Full Disk Access|Allow)/g, (m) => bold(m)) : dim(l))).join("\n"));
  if (process.platform === "darwin") {
    openUrl(FULL_DISK_ACCESS);
    console.error(dim("\n(System Settings is opening on that page.)"));
  }
  process.exit(1);
}

function requireAuth(): Authenticator {
  const auth = makeAuth();
  if (!auth) {
    const blocked = findAccount()?.blocked;
    if (blocked) blockedExit(blocked);
    console.error(red("Not signed in to Firefox") + ` and no ${bold("FOXHOLE_ACCESS_TOKEN")} set.`);
    console.error(dim(`Run ${bold("foxhole login")}, or set FOXHOLE_ACCESS_TOKEN=<vpn access token>.`));
    process.exit(1);
  }
  return auth;
}

/**
 * Like requireAuth, but checks the token first, and when none works and we have a
 * terminal, waits for one instead of exiting: signed out, for the Firefox sign-in;
 * signed in, from the Browser Console window.
 */
async function ensureAuth(): Promise<Authenticator> {
  const env = tokenEnv();
  const errors: string[] = [];
  if (env?.name === ENV_TOKEN) {
    const problem = await tokenProblem(env.value);
    if (!problem) return new StaticAuth(env.value);
    errors.push(`${ENV_TOKEN} ${problem}.`, "Unset it so the new token below is used next time.");
  }
  // Signed in to Firefox: tokens come from its session and are renewed as they expire.
  const account = findAccount();
  if (account?.signedIn) {
    const auth = new FirefoxAuth(account);
    try {
      await auth.getAccessToken(AbortSignal.timeout(15_000)); // fail here, not on the first connect
      return auth;
    } catch (err) {
      errors.push("Couldn't get a token from your Firefox login:", (err as Error).message);
    }
  }
  // A token saved from the window below, e.g. when the Firefox account server can't be reached.
  if (env && env.name !== ENV_TOKEN) {
    const problem = await tokenProblem(env.value);
    if (!problem) return new StaticAuth(env.value);
    forgetToken();
    errors.push(`Your saved token ${problem}.`, "Get a new one below.");
  }
  // Firefox's profile can't be read (macOS privacy protection): signing in again wouldn't help, allowing it does
  if (account?.blocked) blockedExit(account.blocked);
  const error = errors.join("\n");
  if (!process.stdin.isTTY) {
    if (error) {
      console.error(red(error));
      process.exit(1);
    }
    return requireAuth(); // non-interactive: keep the plain error
  }
  if (!account?.signedIn) {
    // Signed out: the sign-in is all it takes, as the token then comes from that login.
    if (error) console.log(red(error));
    if (!(await cmdLogin())) process.exit(130); // cancelled: the app can't connect without a token
    return ensureAuth(); // signed in now
  }
  const token = await captureToken(error);
  if (!token) process.exit(130); // cancelled or timed out: the app can't connect without a token
  saveToken(token);
  return new StaticAuth(token);
}

/**
 * Minimal JS syntax colors for the snippet. Each token sets only the foreground
 * and returns to the block's near-white, so the code block's background stays
 * unbroken. Strings are matched first, so words inside them aren't colored.
 */
function highlight(line: string): string {
  const fg = (n: number, t: string) => `\x1b[38;5;${n}m${t}\x1b[38;5;255m`;
  return line.replace(
    /("(?:[^"\\]|\\.)*")|\b(async|await|const)\b|\b(ChromeUtils|console|fetch|JSON)\b|(=>|\?\?|\?\.)/g,
    (_, str, kw, builtin, op) =>
      str ? fg(150, str) : kw ? fg(176, kw) : builtin ? fg(81, builtin) : fg(215, op),
  );
}

/** Resolves to null when the user presses q or Ctrl+C; stop() releases the keyboard. */
function cancelKeys(): { cancelled: Promise<null>; stop: () => void } {
  // Raw mode so q works without Enter; it also turns Ctrl+C into a 0x03 byte instead of SIGINT.
  let cancel = () => {};
  const cancelled = new Promise<null>((resolve) => (cancel = () => resolve(null)));
  const onKey = (b: Buffer) => [3, 0x71, 0x51].includes(b[0]) && cancel(); // Ctrl+C, q, Q
  process.once("SIGINT", cancel);
  process.stdin.on("data", onKey).setRawMode(true).resume();
  const stop = () => {
    process.removeListener("SIGINT", cancel);
    process.stdin.removeListener("data", onKey).setRawMode(false).pause();
  };
  return { cancelled, stop };
}

/**
 * Runs a loopback receiver and shows the steps to copy a snippet into Firefox's
 * Browser Console, which posts the VPN token straight back. Returns the token,
 * or null if the user cancels (Ctrl+C) or the wait times out.
 */
async function captureToken(error: string): Promise<string | null> {
  // Mouse reports off, in case an earlier run was killed with them on: the user
  // must be able to select and copy the snippet.
  process.stdout.write("\x1b[?1000l\x1b[?1006l");
  const rec = await startTokenReceiver();
  const copied = await copyText(rec.snippet);
  // only shown when signed in (signed out, ensureAuth asks for the sign-in instead)
  const email = findAccount()?.email ?? null;
  const status = bold(green("✓ You are signed in to Firefox"));
  const steps = [
    // one box line per sentence, so the window stays narrow enough for an 80-column terminal
    status,
    ...(email ? [email] : []),
    "",
    ...error.split("\n").map((l, i) => red(`${i ? " " : "✗"} ${l}`)),
    "",
    bold("Let's grab a new token from Firefox."),
    "",
    `${bold("1.")} In Firefox open ${cyan("about:config")} and set`,
    `   ${cyan("devtools.chrome.enabled")} to ${bold("true")}. ${dim("(first time only)")}`,
    "",
    `${bold("2.")} Open the ${bold("Browser Console")}: ${cyan(process.platform === "darwin" ? "⌘ ⇧ J" : "Ctrl+Shift+J")}.`,
    `   ${dim("(the Browser Console, not the page's web console)")}`,
    "",
    copied
      ? `${bold("3.")} Paste it (${green("it's already in your clipboard")}) and press ${bold("Enter")}.`
      : `${bold("3.")} Paste the snippet printed below and press ${bold("Enter")}.`,
    "",
    dim("The token comes back over localhost only and is saved to"),
    dim(`${tokenFile()} (readable only by you) for next time.`),
  ];
  const title = cyan("🦊 foxhole-vpn");
  // centered in the box's inner width (row width minus "│ " and " │")
  const inner = vw(box(steps, { title })[0]) - 4;
  steps[0] = centerIn(status, inner);
  if (email) steps[1] = centerIn(green(`(${email})`), inner);
  const boxed = box(steps, { title });
  // No border around the code: box characters would end up in what the user copies.
  const lines = rec.snippet.split("\n");
  const w = Math.max(...lines.map((l) => l.length));
  const out = [
    ...boxed,
    "",
    copied
      ? `${bold(green("✓ Copied to your clipboard"))} ${dim("— just paste it into the Browser Console:")}`
      : bold("Paste this into the Browser Console:"),
    ...(!copied && process.platform === "linux" ? [dim("(with wl-clipboard or xclip installed, foxhole copies it for you)")] : []),
    "",
    ...lines.map((l) => code(`  ${highlight(l)}${" ".repeat(w - l.length)}  `)),
    "",
    dim(`Waiting for the token from Firefox (up to 2 minutes) · press ${under("q")} or ${under("Ctrl+C")} to cancel`),
  ];
  process.stdout.write("\n" + out.join("\n") + "\n");

  const keys = cancelKeys();
  const timedOut = Symbol();
  const token = await Promise.race([rec.token.catch(() => timedOut), keys.cancelled]);
  keys.stop();
  rec.close();
  if (typeof token === "string") {
    console.log(green("✓ token received — saved for next time."));
    return token;
  }
  const why = token === timedOut ? "No token arrived within 2 minutes, so foxhole closed." : "Cancelled.";
  console.log(yellow(`${why} foxhole needs a token to connect — run it again when you're ready.`));
  return null;
}

function handleAuthError(err: unknown): never {
  console.error(red(`\nError: ${(err as Error).message}`));
  offlineHint();
  process.exit(1);
}

/** Offline because a killed global session's tun still takes all traffic? Then say how to fix it. */
function offlineHint(): void {
  if (existsSync("/sys/class/net/foxhole0")) console.error(yellow(`A killed global session's routes are still on, which keeps this computer offline: run  ${bold("foxhole restore")}`));
}

async function cmdCountries() {
  const list = await fetchServerList();
  const free = list.filter((c) => !c.locked);
  console.log(bold(`\n${list.length} countries (${free.length} on the free tier):\n`));
  for (const c of list) {
    const name = countryName(c.code, c.name);
    const tier = c.locked ? dim("paid") : green("free");
    const status = c.available ? "" : red(" (no servers)");
    console.log(`  ${flag(c.code)}  ${c.code}  ${name.padEnd(22)} ${tier}${status}`);
  }
  console.log();
}

async function cmdUsage() {
  const conn = new Connection(requireAuth());
  try {
    const usage = await conn.refreshUsage();
    if (!usage) {
      console.log(dim("No usage information available."));
      return;
    }
    if (usage.unlimited) {
      console.log(green("Unlimited data."));
      return;
    }
    const used = usage.max - usage.remaining;
    const pct = Number((used * 100n) / usage.max);
    const resetStr = usage.reset ? `, resets ${shortDate(usage.reset)}` : "";
    console.log(
      `${bold(gb(usage.remaining))} of ${gb(usage.max)} left ` +
        dim(`(${pct}% used${resetStr})`),
    );
  } catch (err) {
    handleAuthError(err);
  }
}

async function cmdDoctor() {
  const account = findAccount();
  console.log(bold("\nfoxhole-vpn doctor\n"));
  console.log(`  Firefox profile : ${account?.blocked ? red(`can't be read (${account.blocked.code})`) : account ? green("found") : red("not found")}`);
  if (account?.blocked) console.log(dim(account.blocked.message.replace(/^/gm, "    ")));
  else if (account) {
    console.log(`  Signed in       : ${account.signedIn ? green("yes") : red("no")}`);
    console.log(`  Account         : ${account.email ?? dim("unknown")}`);
  }
  const env = tokenEnv();
  const auth = makeAuth();
  if (auth instanceof FirefoxAuth) {
    console.log(`  Token source    : ${green("Firefox login")}`);
  } else if (env) {
    console.log(`  Token source    : ${green(env.name)}`);
  }
  try {
    const list = await fetchServerList();
    console.log(`  Server list     : ${green(`ok (${list.length} countries)`)}`);
  } catch (err) {
    console.log(`  Server list     : ${red((err as Error).message)}`);
  }
  if (!auth) {
    console.log(`  VPN token       : ${dim("no auth — sign in or set FOXHOLE_ACCESS_TOKEN")}`);
  } else {
    const conn = new Connection(auth);
    try {
      const ent = await fetchEntitlement(await auth.getAccessToken());
      console.log(`  Entitlement     : ${ent ? green("active") : yellow("none")}`);
      const usage = await conn.refreshUsage();
      if (usage?.unlimited) {
        console.log(`  Data remaining  : ${green("unlimited")}`);
      } else if (usage) {
        console.log(`  Data remaining  : ${green(`${gb(usage.remaining)} of ${gb(usage.max)}`)}`);
      }
    } catch (err) {
      console.log(`  VPN token       : ${red((err as Error).message)}`);
    }
  }
  console.log();
}

/** Opens the browser's own sign-in and waits for it. The signed-in account, or undefined if not. */
async function cmdLogin(): Promise<AccountState | undefined> {
  const account = findAccount();
  if (account?.blocked) blockedExit(account.blocked);
  if (account?.signedIn) {
    console.log(green(`Already signed in to Firefox as ${account.email ?? "your account"}.`));
    return account;
  }
  // The browser itself must be signed in (that's what its VPN uses); signing in on
  // accounts.firefox.com only signs in the website, so open the browser's own sign-in page.
  openBrowser("about:preferences#sync");
  console.log(
    "\n" +
      box(
        [
          bold("Sign in inside the Firefox browser, not on a website."),
          "",
          `Firefox is opening its ${bold("Sync")} settings: click ${bold("Sign in")} there.`,
          dim(`(didn't open? In Firefox: menu ${bold("☰")} → ${bold("Sign in")})`),
          "",
          `${bold("Sync is optional")}: foxhole only needs the sign-in, so you can`,
          `turn off everything on the ${bold("Choose what to sync")} screen.`,
        ],
        { title: cyan("🦊 foxhole login") },
      ).join("\n") +
      "\n",
  );
  if (!process.stdin.isTTY) return void console.log(dim("After signing in, re-run your command."));

  console.log(dim(`Waiting for Firefox to sign in (up to 5 minutes) · press ${under("q")} or ${under("Ctrl+C")} to cancel`));
  const keys = cancelKeys();
  let timer: NodeJS.Timeout | undefined;
  let ticks = 0;
  const found = new Promise<AccountState | "timeout">((resolve) => {
    timer = setInterval(() => {
      const a = findAccount();
      if (a?.signedIn) resolve(a);
      else if (++ticks >= 300) resolve("timeout");
    }, 1000);
  });
  const result = await Promise.race([found, keys.cancelled]);
  clearInterval(timer);
  keys.stop();
  if (result === null) return void console.log(yellow("Cancelled."));
  if (result === "timeout") {
    console.log(yellow("Firefox still isn't signed in. Signed in on a website instead? Sign in inside the browser, then run foxhole login again."));
    process.exit(1);
  }
  console.log(green(`✓ Firefox is signed in as ${result.email ?? "your account"}.`));
  return result;
}

async function cmdProxy() {
  const auth = await ensureAuth();
  const conn = new Connection(auth);
  const code = arg("country");
  const country = code ? await findCountry(code) : null;
  if (code && !country) {
    console.error(red(`Unknown country code: ${code}`));
    process.exit(1);
  }
  const server = await conn.selectServer(country);
  if (auth instanceof StaticAuth) noteTokenTtl();
  const where = country ? `${flag(country.code)} ${countryName(country.code, country.name)}` : "recommended";
  const settings = loadSettings();
  useSplit(() => settings.split); // the rules set in the TUI's Split tunneling popup
  const host = arg("host") ?? proxyHost(settings);
  const port = Number(arg("port") ?? settings.port);
  const handle = await startProxy(conn, host, port, (address) => loginFor(settings, address));
  console.log(green(`\nProxy on ${bold(`${host}:${handle.port}`)} (SOCKS5 and HTTP)  →  ${where}`));
  splitNote(settings.split);
  console.log(dim(`upstream ${server.hostname}:${server.port}`));
  if (host === "0.0.0.0") {
    // listening on all addresses: other devices use this computer's LAN address
    console.log(`Other devices on this network: ${bold(cyan(`${lanIp() ?? "this computer's IP"}:${handle.port}`))}`);
    const firewall = await firewallHint(handle.port);
    if (firewall) console.log(yellow(`A firewall is on: if other devices can't connect, run  ${firewall.join(" && ")}`));
  }
  const here = `${dialHost(host)}:${handle.port}`; // 0.0.0.0 is where it listens, not an address to dial
  console.log(dim(`e.g.  export ALL_PROXY=socks5://${here}`));
  console.log(dim(`  or  export HTTPS_PROXY=http://${here} HTTP_PROXY=http://${here}\n`));
  // Warm the pass so auth errors surface immediately, not on first request.
  try {
    await conn.currentPass();
    console.log(green("Connected. Press Ctrl+C to stop."));
  } catch (err) {
    await handle.close();
    handleAuthError(err);
  }
  await notice();
  const stop = async () => {
    await handle.close();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

async function cmdTui() {
  const host = arg("host") ?? proxyHost(loadSettings());
  const port = Number(arg("port") ?? loadSettings().port);
  // ponytail: a Firefox login first, even for relay mode; a relay-only start (no Guardian auth) if users without one need it
  if ((await new Tui(new Connection(await ensureAuth()), host, port).run()) !== "logout") return;
  forgetToken();
  openBrowser("about:preferences#sync");
  console.log(green("\n✓ Logged out: the saved VPN token is deleted."));
  console.log(`To switch accounts: in Firefox's ${bold("Sync")} settings click ${bold("Sign out")}, sign in with the other account,`);
  console.log(`then run ${bold("foxhole")} again to get a new token.`);
  if (tokenEnv()?.name === ENV_TOKEN) console.log(yellow(`Also unset ${ENV_TOKEN}: foxhole uses it before the saved token.`));
}

async function cmdGlobal() {
  if (WIN && !(await isPrivileged())) {
    // Say so before the token steps, not after them.
    console.error(red("Global mode needs Administrator rights.") + ` Open ${bold("Terminal (Admin)")} and run ${bold("foxhole global")} there.`);
    process.exit(1);
  }
  const conn = new Connection(await ensureAuth());
  const code = arg("country");
  const country = code ? await findCountry(code) : null;
  if (code && !country) {
    console.error(red(`Unknown country code: ${code}`));
    process.exit(1);
  }
  await conn.selectServer(country);
  await notice();
  const settings = loadSettings();
  useSplit(() => settings.split); // the rules set in the TUI's Split tunneling popup
  splitNote(settings.split);
  try {
    await runGlobal(conn, {
      host: arg("host") ?? proxyHost(settings),
      port: Number(arg("port") ?? settings.port),
      force: process.argv.includes("--force"),
      login: (address) => loginFor(settings, address),
    });
  } catch (err) {
    handleAuthError(err);
  }
}

/** Says when split tunneling sends some sites another way, so the CLI's routing isn't a surprise. */
function splitNote(split: Split): void {
  const summary = splitSummary(split);
  if (summary) console.log(yellow(`Split tunneling: ${summary} (change it with ${bold("t")} in ${bold("foxhole")})`));
}

/** Windows: undoes what a killed `global` session left behind (DNS rule, firewall rules, tun2socks). */
async function cmdRestore() {
  if (process.platform === "linux") {
    // What a killed global session leaves, removed in one shell so sudo asks for the password once,
    // here; elevating itself spares `sudo foxhole`, which nvm's PATH doesn't survive.
    const uplink = parseDefaultRoute(spawnSync("ip", ["route"]).stdout?.toString() ?? "", "foxhole0");
    const script = staleCleanupScript(uplink);
    const root = process.getuid?.() === 0;
    const r = spawnSync(root ? "sh" : "sudo", [...(root ? [] : ["sh"]), "-c", script], { stdio: "inherit" });
    console.log(r.status === 0 ? green("Networking restored (foxhole's tun, its routes and its IPv6 and UDP blocks removed).") : red("Not restored: sudo was refused."));
    return;
  }
  if (process.platform !== "win32") {
    console.log(dim("Nothing to do: on macOS a reboot restores networking."));
    return;
  }
  if (!(await isPrivileged())) {
    console.error(red("restore needs Administrator rights.") + ` Run it in ${bold("Terminal (Admin)")}.`);
    process.exit(1);
  }
  await restoreWindows(directPriv());
  console.log(green("Networking restored (DNS rule, firewall rules and tun2socks removed)."));
}

const WIN = process.platform === "win32";

const HELP = `${bold("foxhole-vpn")} — use Firefox's built-in VPN system-wide

${bold("Usage:")} foxhole [command] [options]

${bold("Commands:")}
  ${dim("(no command)")}         Launch the interactive TUI
  countries            List available countries (free vs paid)
  usage                Show remaining data this month
  status | doctor      Check Firefox login, server list, entitlement, data
  login                Sign in to the Firefox browser (its VPN needs it)
  proxy [--country XX] [--port N] [--host H]
                       Run a local SOCKS5 + HTTP proxy through the VPN
  global [--country XX] [--force]
                       Route ALL system traffic through the VPN (needs ${WIN ? "Administrator" : "sudo"})${WIN || process.platform === "linux" ? `
  restore              Undo a global session that was killed (${WIN ? "Administrator" : "asks for your password"})` : ""}
  env                  Print settings that make terminal tools trust relay mode's
                       certificate and use the proxy: ${WIN ? "foxhole env | iex" : 'eval "$(foxhole env)"'}
  -v, --version        Show the version and whether an update is available
  help                 Show this help

${bold("Options:")}
  --verbose            Also show per-connection errors (e.g. ports the VPN
                       refuses) and tun2socks logs

${dim(WIN ? "global: run  foxhole global  in Terminal (Admin)  · Ctrl+C restores networking." : 'global: run as  sudo env "PATH=$PATH" foxhole global  · Ctrl+C restores networking.')}
${dim("Stop any other active VPN first (or pass --force).")}

${bold("Environment:")}
  FOXHOLE_ACCESS_TOKEN   Use this VPN access token instead of the saved one (~/.config/foxhole-vpn/token)
`;

/** After a quick command, print the yellow update notice if a newer version is out. */
async function notice() {
  await checkUpdate();
  if (updateNotice()) console.error("\n" + versionLines().join("\n"));
}

async function main() {
  // Windows: global mode's helper, started as Administrator through Windows' admin prompt (global-win32.ts's uacPriv)
  if (process.argv[2] === HELPER_CMD) return serveElevated(process.argv[3]);
  if (process.argv[2] === "env") {
    // for a shell to read, at once: no update check
    loadCa(); // the files it names must be there: a missing SSL_CERT_FILE breaks every tool that reads it
    return void console.log(envLines(`127.0.0.1:${loadSettings().port}`).join("\n"));
  }
  checkUpdate(); // fire while the command runs; shown afterwards
  useRelay(loadRelay(loadSettings())); // where vpn.mozilla.org is blocked, relay Guardian's control calls (httprelay.ts)
  const cmd = process.argv.slice(2).find((a) => a !== "--verbose") ?? "tui"; // --verbose can go anywhere
  if (cmd === "-v" || cmd === "--version" || cmd === "version") {
    await checkUpdate();
    console.log(versionLines().join("\n"));
    return;
  }
  switch (cmd) {
    // Long-running commands show the update notice themselves.
    case "tui":
    case "up":
      await cmdTui();
      // All closed: a dial or IP check still in flight (one the tunnel's teardown cut
      // off waits for its timeout) must not keep the prompt from coming back.
      process.exit(0);
    case "proxy":
      return cmdProxy();
    case "global":
      return cmdGlobal();
    // Quick commands: run, then show the notice.
    case "countries":
      await cmdCountries();
      break;
    case "usage":
      await cmdUsage();
      break;
    case "status":
    case "doctor":
      await cmdDoctor();
      break;
    case "login":
      await cmdLogin();
      break;
    case "restore":
      await cmdRestore();
      break;
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      break;
    default:
      console.error(red(`Unknown command: ${cmd}\n`));
      console.log(HELP);
      process.exit(1);
  }
  await notice();
}

main().catch((err) => {
  console.error(red(`Error: ${(err as Error).message}`));
  offlineHint();
  process.exit(1);
});
