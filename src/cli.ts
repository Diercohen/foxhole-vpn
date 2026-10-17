#!/usr/bin/env node
import net from "node:net";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fetchServerList } from "./serverlist.js";
import { findAccount } from "./profile.js";
import { FirefoxAuth, StaticAuth, NotImplementedError, type Authenticator } from "./auth.js";
import { Connection, findCountry } from "./connection.js";
import { fetchEntitlement } from "./guardian.js";
import { startProxy } from "./proxy.js";
import { runGlobal } from "./global.js";
import { Tui } from "./tui.js";
import { bold, dim, green, red, yellow, flag, countryName, gb, shortDate } from "./ui.js";

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

/** The manual access-token env var, if set; overrides the Firefox session. */
function tokenEnv(): { name: string; value: string } | null {
  const value = process.env.FOXHOLE_ACCESS_TOKEN;
  return value ? { name: "FOXHOLE_ACCESS_TOKEN", value } : null;
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
    console.error(dim(`Run ${bold("foxhole-vpn login")}, or set FOXHOLE_ACCESS_TOKEN=<vpn access token>.`));
    process.exit(1);
  }
  return auth;
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
  const conn = new Connection(requireAuth());
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
  console.log(green(`\nSOCKS5 proxy on ${bold(`${host}:${handle.port}`)}  →  ${where}`));
  console.log(dim(`upstream ${server.hostname}:${server.port}`));
  console.log(dim(`e.g.  export ALL_PROXY=socks5://${host}:${handle.port}\n`));
  // Warm the pass so auth errors surface immediately, not on first request.
  try {
    await conn.currentPass();
    console.log(green("Connected. Press Ctrl+C to stop."));
  } catch (err) {
    await handle.close();
    handleAuthError(err);
  }
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
  await new Tui(new Connection(requireAuth()), host, port).run();
}

async function cmdGlobal() {
  const conn = new Connection(requireAuth());
  const code = arg("country");
  const country = code ? await findCountry(code) : null;
  if (code && !country) {
    console.error(red(`Unknown country code: ${code}`));
    process.exit(1);
  }
  await conn.selectServer(country);
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

${bold("Usage:")} foxhole-vpn [command] [options]

${bold("Commands:")}
  ${dim("(no command)")}         Launch the interactive TUI
  countries            List available countries (free vs paid)
  usage                Show remaining data this month
  status | doctor      Check Firefox login, server list, entitlement, data
  login                Open Firefox to sign in to your Firefox Account
  proxy [--country XX] [--port N] [--host H]
                       Run a local SOCKS5 proxy through the VPN
  global [--country XX] [--force]
                       Route ALL system traffic through the VPN (needs sudo)
  help                 Show this help

${dim("global: run as  sudo -E foxhole-vpn global  · Ctrl+C restores networking.")}
${dim("Stop any other active VPN first (or pass --force).")}

${bold("Environment:")}
  FOXHOLE_ACCESS_TOKEN   Use this VPN access token instead of the Firefox login
`;

async function main() {
  const cmd = process.argv[2] ?? "tui";
  switch (cmd) {
    case "tui":
    case "up":
      return cmdTui();
    case "countries":
      return cmdCountries();
    case "usage":
      return cmdUsage();
    case "status":
    case "doctor":
      return cmdDoctor();
    case "login":
      return cmdLogin();
    case "proxy":
      return cmdProxy();
    case "global":
      return cmdGlobal();
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return;
    default:
      console.error(red(`Unknown command: ${cmd}\n`));
      console.log(HELP);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(red(`Error: ${(err as Error).message}`));
  process.exit(1);
});
