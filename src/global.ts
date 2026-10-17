import { execFile } from "node:child_process";
import { spawn } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import {
  readFileSync, writeFileSync, existsSync, lstatSync, readlinkSync, symlinkSync, rmSync,
  mkdtempSync, mkdirSync, copyFileSync, chmodSync, readdirSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import type { Connection } from "./connection.js";
import { startProxy } from "./proxy.js";
import { dim, green, red, bold } from "./ui.js";

const exec = promisify(execFile);

const TUN = "foxhole0";
const TUN_ADDR = "198.18.0.1"; // RFC 2544 benchmark range, unlikely to clash
const RESOLV = "/etc/resolv.conf";

export interface DefaultRoute {
  gw: string | null;
  dev: string;
}

/** Parses `ip route` output for the IPv4 default route. Pure. */
export function parseDefaultRoute(ipRoute: string): DefaultRoute | null {
  for (const line of ipRoute.split("\n")) {
    const m = line.match(/^default(?:\s+via\s+(\S+))?\s+dev\s+(\S+)/);
    if (m) return { gw: m[1] ?? null, dev: m[2] };
  }
  return null;
}

/** True for virtual/VPN interfaces we must not treat as the real uplink. Pure. */
export function isVpnDev(dev: string): boolean {
  return /^(tun|tap|wg|ppp|utun|gpd|nordlynx|proton)/i.test(dev);
}

/** Builds the `ip` command sequence to route everything through the tun. Pure. */
export function planSetup(serverIp: string, orig: DefaultRoute): string[][] {
  const pin = orig.gw
    ? ["ip", "route", "add", serverIp, "via", orig.gw, "dev", orig.dev]
    : ["ip", "route", "add", serverIp, "dev", orig.dev];
  return [
    ["ip", "tuntap", "add", "mode", "tun", "dev", TUN],
    ["ip", "addr", "add", `${TUN_ADDR}/15`, "dev", TUN],
    ["ip", "link", "set", "dev", TUN, "up"],
    pin, // keep the tunnel's own packets off the tunnel
    ["ip", "route", "add", "default", "dev", TUN, "metric", "1"],
  ];
}

/** Reverse of planSetup, best-effort. Pure. */
export function planTeardown(serverIp: string): string[][] {
  return [
    ["ip", "route", "del", "default", "dev", TUN, "metric", "1"],
    ["ip", "route", "del", serverIp],
    ["ip", "link", "set", "dev", TUN, "down"],
    ["ip", "tuntap", "del", "mode", "tun", "dev", TUN],
  ];
}

async function run(argv: string[], quiet = false): Promise<void> {
  try {
    await exec(argv[0], argv.slice(1));
  } catch (err) {
    if (!quiet) throw new Error(`${argv.join(" ")} → ${(err as Error).message}`);
  }
}

const GO_ARCH: Record<string, string> = { x64: "amd64", arm64: "arm64" };

/** Downloads the prebuilt tun2socks from GitHub releases to `dest`. */
async function downloadTun2socks(dest: string): Promise<void> {
  const arch = GO_ARCH[process.arch];
  if (process.platform !== "linux" || !arch) {
    throw new Error(`no prebuilt tun2socks for ${process.platform}/${process.arch}`);
  }
  const asset = `tun2socks-linux-${arch}.zip`;
  const url = `https://github.com/xjasonlyu/tun2socks/releases/latest/download/${asset}`;
  console.log(dim(`downloading ${asset} from GitHub…`));
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const tmp = mkdtempSync(join(tmpdir(), "foxhole-t2s-"));
  try {
    const zip = join(tmp, asset);
    writeFileSync(zip, Buffer.from(await res.arrayBuffer()));
    await exec("unzip", ["-oq", zip, "-d", tmp]);
    const bin = readdirSync(tmp).find((f) => /^tun2socks/.test(f) && !/\.(zip|md|txt)$/i.test(f));
    if (!bin) throw new Error("tun2socks binary not found in archive");
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(join(tmp, bin), dest); // copy, not rename: /tmp may be a different fs
    chmodSync(dest, 0o755);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Finds tun2socks, or obtains it. Prefers the prebuilt GitHub binary (works
 * where Go's module proxy is blocked); falls back to `go install` via a mirror
 * that bypasses the often-blocked proxy.golang.org.
 */
async function ensureTun2socks(): Promise<string> {
  const home = process.env.HOME ?? "/root";
  const cache = join(home, ".cache", "foxhole", "tun2socks");
  for (const probe of ["tun2socks", join(home, "go/bin/tun2socks"), cache]) {
    try {
      await exec(probe, ["--version"]);
      return probe;
    } catch {
      /* keep looking */
    }
  }
  try {
    await downloadTun2socks(cache);
    return cache;
  } catch (err) {
    console.log(dim(`prebuilt download failed (${(err as Error).message}); trying go…`));
  }
  try {
    await exec("go", ["install", "github.com/xjasonlyu/tun2socks/v2@latest"], {
      env: { ...process.env, GOPROXY: "https://goproxy.cn,direct", GOSUMDB: "off" },
    });
    return join(home, "go/bin/tun2socks");
  } catch (err) {
    throw new Error(
      "Could not obtain tun2socks. Download it from " +
        "https://github.com/xjasonlyu/tun2socks/releases and put it on your PATH " +
        `or at ${cache}  (${(err as Error).message})`,
    );
  }
}

/** DNS over the tunnel: upstream is TCP-only, so force glibc to resolve via TCP. */
function setDns(): () => void {
  const wasSymlink = existsSync(RESOLV) && lstatSync(RESOLV).isSymbolicLink();
  const target = wasSymlink ? readlinkSync(RESOLV) : null;
  const backup = !wasSymlink && existsSync(RESOLV) ? readFileSync(RESOLV, "utf8") : null;
  if (wasSymlink) rmSync(RESOLV);
  writeFileSync(RESOLV, "# foxhole\nnameserver 1.1.1.1\nnameserver 9.9.9.9\noptions use-vc\n");
  return () => {
    try {
      rmSync(RESOLV, { force: true });
      if (wasSymlink && target) symlinkSync(target, RESOLV);
      else if (backup !== null) writeFileSync(RESOLV, backup);
    } catch {
      /* best effort */
    }
  };
}

export interface GlobalOptions {
  host: string;
  port: number;
  force: boolean;
}

/**
 * Routes the whole system through the VPN: local proxy + tun2socks + routes.
 * Requires root. Tears everything down on exit.
 *
 * shortcut: IPv6 is not tunnelled or blocked here — if the box has working
 * IPv6, traffic can leak around the tunnel. Upgrade: add an IPv6 null route or
 * a matching IPv6 tun when IPv6 support is needed.
 */
export async function runGlobal(conn: Connection, opts: GlobalOptions): Promise<void> {
  if (process.getuid?.() !== 0) {
    console.error(red("Global mode needs root.") + ` Run: ${bold("sudo -E foxhole global")}`);
    process.exit(1);
  }
  if (!conn.server) throw new Error("No server selected");

  // Refuse if another VPN already owns the default route (would conflict).
  const { stdout: routeOut } = await exec("ip", ["route"]);
  const orig = parseDefaultRoute(routeOut);
  if (!orig) throw new Error("No default route found; are you online?");
  if (isVpnDev(orig.dev) && !opts.force) {
    throw new Error(
      `Another VPN is active on ${orig.dev}. Stop it first, or pass --force.`,
    );
  }

  const serverIp = (await lookup(conn.server.hostname)).address;
  const tun2socks = await ensureTun2socks();

  // Start the local proxy and prove auth works BEFORE touching the system.
  const proxy = await startProxy(conn, opts.host, opts.port);
  try {
    await conn.currentPass();
  } catch (err) {
    await proxy.close();
    throw err;
  }

  const teardown: Array<() => void | Promise<void>> = [() => proxy.close()];
  let t2s: ReturnType<typeof spawn> | null = null;
  const cleanup = async () => {
    for (const step of planTeardown(serverIp)) await run(step, true);
    t2s?.kill("SIGTERM");
    for (const fn of teardown.reverse()) {
      try {
        await fn();
      } catch {
        /* best effort */
      }
    }
  };
  process.on("SIGINT", () => void cleanup().then(() => process.exit(0)));
  process.on("SIGTERM", () => void cleanup().then(() => process.exit(0)));

  try {
    for (const step of planSetup(serverIp, orig)) await run(step);
    teardown.push(setDns());
    t2s = spawn(tun2socks, ["--device", TUN, "--proxy", `socks5://${opts.host}:${opts.port}`], {
      stdio: "ignore",
    });
    t2s.on("exit", (code) => {
      if (code) console.error(red(`tun2socks exited (${code})`));
    });
    console.log(green(`\n● all system traffic now routes through the VPN (${serverIp}).`));
    console.log(dim(`   DNS forced over TCP · IPv6 not tunnelled`));
    console.log(dim("   Press Ctrl+C to disconnect and restore networking.\n"));
    await new Promise(() => {}); // run until signalled
  } catch (err) {
    await cleanup();
    throw err;
  }
}
