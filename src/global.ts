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
import { dim, green, red, yellow, bold } from "./ui.js";

const exec = promisify(execFile);

const TUN = "escapedfox0";
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

/**
 * Builds the `ip` command sequence to route everything through the tun. Pure.
 * `bypassIps` (the VPN server and the DNS resolvers) are pinned to the real
 * uplink so they don't loop through — or get refused by — the tunnel.
 */
export function planSetup(bypassIps: string[], orig: DefaultRoute): string[][] {
  const pin = (ip: string) =>
    orig.gw
      ? ["ip", "route", "add", ip, "via", orig.gw, "dev", orig.dev]
      : ["ip", "route", "add", ip, "dev", orig.dev];
  return [
    ["ip", "tuntap", "add", "mode", "tun", "dev", TUN],
    ["ip", "addr", "add", `${TUN_ADDR}/15`, "dev", TUN],
    ["ip", "link", "set", "dev", TUN, "up"],
    ...bypassIps.map(pin),
    ["ip", "route", "add", "default", "dev", TUN, "metric", "1"],
    // The upstream is IPv4-only; blackhole IPv6 so apps can't leak around it
    // over native IPv6 (they fall back to IPv4, which goes through the tun).
    ["ip", "-6", "route", "add", "blackhole", "default", "metric", "1"],
  ];
}

/** Reverse of planSetup, best-effort. Pure. */
export function planTeardown(bypassIps: string[]): string[][] {
  return [
    ["ip", "-6", "route", "del", "blackhole", "default", "metric", "1"],
    ["ip", "route", "del", "default", "dev", TUN, "metric", "1"],
    ...bypassIps.map((ip) => ["ip", "route", "del", ip]),
    ["ip", "link", "set", "dev", TUN, "down"],
    ["ip", "tuntap", "del", "mode", "tun", "dev", TUN],
  ];
}

/**
 * Detects another full-tunnel VPN that would beat escapedfox's default route.
 * Besides a VPN device on the default, many VPNs install 0.0.0.0/1 + 128.0.0.0/1
 * (more specific than 0.0.0.0/0), which win regardless of metric. Pure.
 */
export function conflictingVpn(ipRoute: string, orig: DefaultRoute): boolean {
  if (isVpnDev(orig.dev)) return true;
  return /^(0\.0\.0\.0|128\.0\.0\.0)\/1\s/m.test(ipRoute);
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
  const tmp = mkdtempSync(join(tmpdir(), "escapedfox-t2s-"));
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
  const cache = join(home, ".cache", "escapedfox", "tun2socks");
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

/**
 * The DNS resolvers in use, to be pinned to the real uplink. The VPN refuses
 * port-53 traffic ("Destination IP Prohibited") and can't carry UDP, so DNS
 * must bypass the tunnel. Reads systemd-resolved's upstreams (which ignore
 * /etc/resolv.conf) and any real nameserver in resolv.conf.
 */
// Skip resolvers reached via their own interface, not the real uplink: loopback
// (127/8) and Tailscale's CGNAT range (100.64/10, e.g. MagicDNS 100.100.100.100).
function pinnableResolver(ip: string): boolean {
  if (ip.startsWith("127.")) return false;
  const [a, b] = ip.split(".").map(Number);
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

async function dnsUpstreams(): Promise<string[]> {
  const ips = new Set<string>();
  try {
    const { stdout } = await exec("resolvectl", ["dns"]);
    for (const m of stdout.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)) ips.add(m[1]);
  } catch {
    /* resolvectl absent */
  }
  try {
    for (const line of readFileSync(RESOLV, "utf8").split("\n")) {
      const m = line.match(/^\s*nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})/);
      if (m) ips.add(m[1]);
    }
  } catch {
    /* no resolv.conf */
  }
  return [...ips].filter(pinnableResolver);
}

/** Writes resolv.conf (used only when no resolver is configured); returns a restore fn. */
function writeResolv(contents: string): () => void {
  const wasSymlink = existsSync(RESOLV) && lstatSync(RESOLV).isSymbolicLink();
  const target = wasSymlink ? readlinkSync(RESOLV) : null;
  const backup = !wasSymlink && existsSync(RESOLV) ? readFileSync(RESOLV, "utf8") : null;
  if (wasSymlink) rmSync(RESOLV);
  writeFileSync(RESOLV, contents);
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
 * IPv6 is blackholed (not tunnelled) so apps fall back to IPv4 through the tun
 * rather than leaking over native IPv6.
 */
export async function runGlobal(conn: Connection, opts: GlobalOptions): Promise<void> {
  if (process.getuid?.() !== 0) {
    console.error(red("Global mode needs root.") + ` Run: ${bold("sudo -E escapedfox global")}`);
    process.exit(1);
  }
  if (!conn.server) throw new Error("No server selected");

  // Refuse if another VPN already owns the default route (would conflict).
  const { stdout: routeOut } = await exec("ip", ["route"]);
  const orig = parseDefaultRoute(routeOut);
  if (!orig) throw new Error("No default route found; are you online?");
  if (conflictingVpn(routeOut, orig) && !opts.force) {
    throw new Error(
      `Another VPN looks active (default on ${orig.dev}, or 0/1 split routes). ` +
        `Its routes beat escapedfox's — stop it first, or pass --force.`,
    );
  }

  // Resolve to one IPv4 address and make the proxy dial exactly that: the pin
  // below must cover the same IP the proxy connects to, or its upstream loops
  // back through the tun. (Fastly is anycast/multi-IP, so a second DNS lookup in
  // the proxy could otherwise pick a different, unpinned address.)
  const serverIp = (await lookup(conn.server.hostname, { family: 4 })).address;
  conn.server.ip = serverIp;
  const tun2socks = await ensureTun2socks();

  // DNS must bypass the tunnel (the VPN forbids port 53). Pin the resolvers in
  // use; if none are configured, fall back to a public one and point at it.
  const dnsIps = await dnsUpstreams();
  let restoreDns: () => void = () => {};
  if (dnsIps.length === 0) {
    dnsIps.push("1.1.1.1");
    restoreDns = writeResolv("# escapedfox\nnameserver 1.1.1.1\n");
  }
  const bypassIps = [...new Set([serverIp, ...dnsIps])];

  // Start the local proxy and prove auth works BEFORE touching the system.
  const proxy = await startProxy(conn, opts.host, opts.port);
  try {
    await conn.currentPass();
  } catch (err) {
    await proxy.close();
    throw err;
  }

  const teardown: Array<() => void | Promise<void>> = [() => proxy.close(), restoreDns];
  let t2s: ReturnType<typeof spawn> | null = null;
  const cleanup = async () => {
    for (const step of planTeardown(bypassIps)) await run(step, true);
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
    for (const step of planSetup(bypassIps, orig)) await run(step);
    // Inherit stderr so tun2socks's own errors (bad device, etc.) are visible.
    t2s = spawn(tun2socks, ["--device", TUN, "--proxy", `socks5://${opts.host}:${opts.port}`], {
      stdio: ["ignore", "ignore", "inherit"],
    });
    let t2sDead = false;
    t2s.on("exit", (code) => {
      t2sDead = true;
      console.error(red(`tun2socks exited (${code}) — traffic is not being tunnelled.`));
    });
    console.log(green(`\n● routing all system traffic through the VPN (${serverIp})…`));

    // Verify: this fetch now goes through the tun; report the public exit IP so
    // the user sees immediately whether global mode actually took effect.
    await new Promise((r) => setTimeout(r, 2500));
    if (!t2sDead) {
      try {
        const res = await fetch("https://api.ipify.org", { signal: AbortSignal.timeout(8000) });
        console.log(green(`  exit IP is now ${bold((await res.text()).trim())}`));
      } catch {
        console.log(
          yellow("  couldn't reach the internet through the tunnel — check the tun2socks output above."),
        );
      }
    }
    console.log(
      dim(`  DNS via ${dnsIps.join(", ")} (direct, outside tunnel) · IPv6 blackholed · Ctrl+C restores.\n`),
    );
    await new Promise(() => {}); // run until signalled
  } catch (err) {
    await cleanup();
    throw err;
  }
}
