#!/usr/bin/env node
import net from "node:net";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fetchServerList } from "./serverlist.js";
import { findAccount } from "./profile.js";
import { FirefoxAuth, StaticAuth, NotImplementedError, type Authenticator } from "./auth.js";
import { Connection, findCountry } from "./connection.js";
import { fetchEntitlement, GuardianError } from "./guardian.js";
import { startProxy } from "./proxy.js";
import { runGlobal } from "./global.js";
import { Tui } from "./tui.js";
import { checkUpdate, updateNotice, versionLines } from "./update.js";
import { startTokenReceiver, loadSavedToken, saveToken, forgetToken, tokenFile } from "./tokenserver.js";
import { bold, dim, green, red, yellow, cyan, under, code, flag, countryName, gb, shortDate, box } from "./ui.js";

// Node gives each server address only 250 ms before moving on; far VPN servers
// take 600-900 ms to answer, so every attempt failed with a blank AggregateError.
net.setDefaultAutoSelectFamilyAttemptTimeout(3000);

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

/** Seconds until a JWT's `exp`, or null if it can't be read. */
function tokenTtl(jwt: string): number | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const body = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as { exp?: number };
    return typeof body.exp === "number" ? Math.round(body.exp - Date.now() / 1000) : null;
  } catch {
    return null;
  }
}

const ENV_TOKEN = "FOXHOLE_ACCESS_TOKEN";

/** The access token to use: the env var if set, else the one saved from Firefox. */
function tokenEnv(): { name: string; value: string } | null {
  const value = process.env[ENV_TOKEN];
  if (value) return { name: ENV_TOKEN, value };
  const saved = loadSavedToken();
  return saved ? { name: "saved token", value: saved } : null;
}

/** Why a token can't be used ("has expired", "was rejected…"), or null if it looks fine. */
async function tokenProblem(token: string): Promise<string | null> {
  const ttl = tokenTtl(token);
  if (ttl !== null && ttl <= 0) return "has expired";
  try {
    await fetchEntitlement(token, AbortSignal.timeout(8000));
  } catch (err) {
    // Only a 401 means the token is bad; offline or a slow server shouldn't block startup.
    if (err instanceof GuardianError && err.status === 401) return "was rejected by Mozilla (expired or revoked)";
  }
  return null;
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

/** Picks an authenticator: the env token if set, else the Firefox session. */
function makeAuth(): Authenticator | null {
  const env = tokenEnv();
  if (env) return new StaticAuth(env.value);
  const account = findAccount();
  return account?.signedIn ? new FirefoxAuth(account) : null;
}

function requireAuth(): Authenticator {
  const auth = makeAuth();
  if (!auth) {
    console.error(red("Not signed in to Firefox") + ` and no ${bold("FOXHOLE_ACCESS_TOKEN")} set.`);
    console.error(dim(`Run ${bold("foxhole login")}, or set FOXHOLE_ACCESS_TOKEN=<vpn access token>.`));
    process.exit(1);
  }
  return auth;
}

/**
 * Like requireAuth, but when nothing is configured and we have a terminal, show
 * the Firefox token-capture window and wait for the token instead of exiting.
 */
async function ensureAuth(): Promise<Authenticator> {
  // A Firefox login alone isn't enough: FirefoxAuth can't mint a token yet (AUTH.md).
  const env = tokenEnv();
  let error: string | null = null;
  if (env) {
    const problem = await tokenProblem(env.value);
    if (!problem) return new StaticAuth(env.value);
    if (env.name === ENV_TOKEN) {
      error = `${ENV_TOKEN} ${problem}.\nUnset it so the new token below is used next time.`;
    } else {
      forgetToken();
      error = `Your saved token ${problem}.\nGet a new one below.`;
    }
  }
  if (!process.stdin.isTTY) {
    if (error) console.error(red(error));
    return requireAuth(); // non-interactive: keep the plain error
  }
  const token = await captureToken(error);
  if (!token) return requireAuth();
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

/**
 * Runs a loopback receiver and shows the steps to copy a snippet into Firefox's
 * Browser Console, which posts the VPN token straight back. Returns the token,
 * or null if the user cancels (Ctrl+C) or the wait times out.
 */
async function captureToken(error: string | null = null): Promise<string | null> {
  // Mouse reports off, in case an earlier run was killed with them on: the user
  // must be able to select and copy the snippet.
  process.stdout.write("\x1b[?1000l\x1b[?1006l");
  const rec = await startTokenReceiver();
  const steps = [
    // one box line per sentence, so the window stays narrow enough for an 80-column terminal
    ...(error ? [...error.split("\n").map((l, i) => red(`${i ? " " : "✗"} ${l}`)), ""] : []),
    bold(error ? "Let's grab a new token from Firefox." : "No VPN token yet — let's grab one from Firefox."),
    "",
    `${bold("1.")} In Firefox open ${cyan("about:config")} and set`,
    `   ${cyan("devtools.chrome.enabled")} to ${bold("true")}.`,
    `${bold("2.")} Open the ${bold("Browser Console")}: ${cyan("⌘⇧J")} (mac) / ${cyan("Ctrl+Shift+J")}.`,
    `   ${dim("(the Browser Console, not the page's web console)")}`,
    `${bold("3.")} Paste the snippet printed below and press ${bold("Enter")}.`,
    "",
    dim("The token comes back over localhost only and is saved to"),
    dim(`${tokenFile()} (readable only by you) for next time.`),
  ];
  process.stdout.write("\n" + box(steps, { title: cyan("🦊 foxhole-vpn") }).join("\n") + "\n\n");
  // No border around the code: box characters would end up in what the user copies.
  const lines = rec.snippet.split("\n");
  const w = Math.max(...lines.map((l) => l.length));
  process.stdout.write(bold("Paste this into the Browser Console:") + "\n\n");
  process.stdout.write(lines.map((l) => code(`  ${highlight(l)}${" ".repeat(w - l.length)}  `)).join("\n") + "\n\n");
  process.stdout.write(dim(`waiting for the token on ${rec.url.replace(/\/[0-9a-f]+$/, "/…")} · ${under("Ctrl+C")} to cancel\n`));

  const cancelled = new Promise<null>((resolve) => {
    const onInt = () => resolve(null);
    process.once("SIGINT", onInt);
    rec.token.finally(() => process.removeListener("SIGINT", onInt));
  });
  const token = await Promise.race([rec.token.catch(() => null), cancelled]);
  rec.close();
  if (token) console.log(green("✓ token received — saved for next time."));
  else console.log(yellow("cancelled — no token."));
  return token;
}

function handleAuthError(err: unknown): never {
  if (err instanceof NotImplementedError) {
    console.error(yellow("\nThe VPN token step is not implemented yet."));
    console.error(dim("foxhole-vpn can read your Firefox login but cannot mint a token."));
    console.error(dim("See AUTH.md for the one function that needs filling in.\n"));
    process.exit(2);
  }
  console.error(red(`\nError: ${(err as Error).message}`));
  process.exit(1);
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
  console.log(`  Firefox profile : ${account ? green("found") : red("not found")}`);
  if (account) {
    console.log(`  Signed in       : ${account.signedIn ? green("yes") : red("no")}`);
    console.log(`  Account         : ${account.email ?? dim("unknown")}`);
  }
  const env = tokenEnv();
  if (env) {
    console.log(`  Token source    : ${green(env.name)}`);
  }
  try {
    const list = await fetchServerList();
    console.log(`  Server list     : ${green(`ok (${list.length} countries)`)}`);
  } catch (err) {
    console.log(`  Server list     : ${red((err as Error).message)}`);
  }
  const auth = makeAuth();
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
      if (err instanceof NotImplementedError) {
        console.log(`  VPN token       : ${yellow("not implemented (see AUTH.md)")}`);
      } else {
        console.log(`  VPN token       : ${red((err as Error).message)}`);
      }
    }
  }
  console.log();
}

function openBrowser(url: string) {
  if (process.platform === "darwin") {
    spawn("open", ["-a", "Firefox", url], { detached: true, stdio: "ignore" }).unref();
    return;
  }
  const candidates = [
    "/opt/firefox-official/firefox",
    "firefox",
    "xdg-open",
  ].filter((c) => c === "firefox" || c === "xdg-open" || existsSync(c));
  const cmd = candidates[0] ?? "xdg-open";
  spawn(cmd, [url], { detached: true, stdio: "ignore" }).unref();
}

async function cmdLogin() {
  const account = findAccount();
  if (account?.signedIn) {
    console.log(green(`Already signed in to Firefox as ${account.email ?? "your account"}.`));
    return;
  }
  console.log("Opening Firefox so you can sign in to your Firefox Account…");
  openBrowser("https://accounts.firefox.com/");
  console.log(dim("After signing in, re-run your command."));
}

async function cmdProxy() {
  const conn = new Connection(await ensureAuth());
  const code = arg("country");
  const country = code ? await findCountry(code) : null;
  if (code && !country) {
    console.error(red(`Unknown country code: ${code}`));
    process.exit(1);
  }
  const server = await conn.selectServer(country);
  noteTokenTtl();
  const where = country ? `${flag(country.code)} ${countryName(country.code, country.name)}` : "recommended";
  const host = arg("host") ?? "127.0.0.1";
  const port = Number(arg("port") ?? 1080);
  const handle = await startProxy(conn, host, port);
  console.log(green(`\nProxy on ${bold(`${host}:${handle.port}`)} (SOCKS5 and HTTP)  →  ${where}`));
  console.log(dim(`upstream ${server.hostname}:${server.port}`));
  console.log(dim(`e.g.  export ALL_PROXY=socks5://${host}:${handle.port}`));
  console.log(dim(`  or  export HTTPS_PROXY=http://${host}:${handle.port} HTTP_PROXY=http://${host}:${handle.port}\n`));
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
  const host = arg("host") ?? "127.0.0.1";
  const port = Number(arg("port") ?? 1080);
  await new Tui(new Connection(await ensureAuth()), host, port).run();
}

async function cmdGlobal() {
  const conn = new Connection(await ensureAuth());
  const code = arg("country");
  const country = code ? await findCountry(code) : null;
  if (code && !country) {
    console.error(red(`Unknown country code: ${code}`));
    process.exit(1);
  }
  await conn.selectServer(country);
  await notice();
  try {
    await runGlobal(conn, {
      host: arg("host") ?? "127.0.0.1",
      port: Number(arg("port") ?? 1080),
      force: process.argv.includes("--force"),
    });
  } catch (err) {
    handleAuthError(err);
  }
}

const HELP = `${bold("foxhole-vpn")} — use Firefox's built-in VPN system-wide

${bold("Usage:")} foxhole [command] [options]

${bold("Commands:")}
  ${dim("(no command)")}         Launch the interactive TUI
  countries            List available countries (free vs paid)
  usage                Show remaining data this month
  status | doctor      Check Firefox login, server list, entitlement, data
  login                Open Firefox to sign in to your Firefox Account
  proxy [--country XX] [--port N] [--host H]
                       Run a local SOCKS5 + HTTP proxy through the VPN
  global [--country XX] [--force]
                       Route ALL system traffic through the VPN (needs sudo)
  -v, --version        Show the version and whether an update is available
  help                 Show this help

${bold("Options:")}
  --verbose            Also show per-connection errors (e.g. ports the VPN
                       refuses) and tun2socks logs

${dim("global: run as  sudo -E foxhole global  · Ctrl+C restores networking.")}
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
  checkUpdate(); // fire while the command runs; shown afterwards
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
      return cmdTui();
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
  process.exit(1);
});
