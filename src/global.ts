import { execFile } from "node:child_process";
import { spawn } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import {
  readFileSync, writeFileSync, rmSync,
  mkdtempSync, mkdirSync, copyFileSync, chmodSync, readdirSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import type { Connection } from "./connection.js";
import { startProxy } from "./proxy.js";
import { startDnsForwarder, type DnsForwarder } from "./dns.js";
import { dim, green, red, yellow, bold } from "./ui.js";

const exec = promisify(execFile);

const TUN = "escapedfox0";
const TUN_ADDR = "198.18.0.1"; // RFC 2544 benchmark range, unlikely to clash
const RESOLV = "/etc/resolv.conf";

// Private / special ranges must skip the tunnel: the VPN refuses them
// ("Destination IP Prohibited") and tunnelling them would break LAN access.
const PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];

// DNS is resolved through the tunnel via DoH (the VPN forbids port 53). The
// forwarder listens here; systemd-resolved is pointed at it.
const DOH_HOST = "cloudflare-dns.com";
const DOH_PORT = 5353;

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
export async function ensureTun2socks(): Promise<string> {
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

// ── Privilege: run the networking commands either directly (already root) or
// via `sudo -S` (password fed on stdin, collected in the app). ────────────────

export interface Priv {
  run(argv: string[], quiet?: boolean): Promise<void>;
  spawn(argv: string[]): ReturnType<typeof spawn>;
}

/** Already running as root. tun2socks stderr is shown (CLI use). */
export function directPriv(): Priv {
  return {
    run,
    spawn: (argv) => spawn(argv[0], argv.slice(1), { stdio: ["ignore", "ignore", "inherit"] }),
  };
}

/** Checks a sudo password without running anything. */
export function validateSudo(password: string): Promise<boolean> {
  return new Promise((resolve) => {
    const p = spawn("sudo", ["-S", "-k", "-p", "", "-v"], { stdio: ["pipe", "ignore", "ignore"] });
    p.on("error", () => resolve(false));
    p.on("exit", (code) => resolve(code === 0));
    p.stdin.end(password + "\n");
  });
}

/** Elevates each command with `sudo -S`, feeding the password on stdin. */
export function sudoPriv(password: string): Priv {
  const feed = (p: ReturnType<typeof spawn>) => p.stdin!.end(password + "\n");
  return {
    run: (argv, quiet = false) =>
      new Promise<void>((resolve, reject) => {
        const p = spawn("sudo", ["-S", "-p", "", ...argv], { stdio: ["pipe", "ignore", "pipe"] });
        let err = "";
        p.stderr!.on("data", (d) => (err += d));
        p.on("error", reject);
        p.on("exit", (code) =>
          code === 0 || quiet ? resolve() : reject(new Error(`${argv.join(" ")} → ${err.trim() || `exit ${code}`}`)),
        );
        feed(p);
      }),
    spawn: (argv) => {
      // stderr ignored: tun2socks' JSON logs would corrupt the TUI's screen.
      const p = spawn("sudo", ["-S", "-p", "", ...argv], { stdio: ["pipe", "ignore", "ignore"] });
      feed(p);
      return p;
    },
  };
}

// ── Shared global session: the privileged half, usable by the CLI and the TUI.
// The caller runs the SOCKS proxy (as the user) and selects conn.server first.

export interface GlobalSessionOptions {
  priv: Priv;
  server: { hostname: string; ip?: string };
  proxyHost: string;
  proxyPort: number;
  tun2socksPath: string;
  force: boolean;
}

export class GlobalSession {
  readonly #o: GlobalSessionOptions;
  #bypassIps: string[] = [];
  #addedPrivate: string[] = [];
  #dns: DnsForwarder | null = null;
  #dnsDev: string | null = null;
  #t2s: ReturnType<typeof spawn> | null = null;
  #exitCb: ((code: number | null) => void) | null = null;
  #stopped = false;

  constructor(o: GlobalSessionOptions) {
    this.#o = o;
  }

  /** Called if tun2socks dies unexpectedly. */
  onExit(cb: (code: number | null) => void): void {
    this.#exitCb = cb;
  }

  /** Sets up routing + tun2socks. Returns the pinned server IP and DNS mode. */
  async start(): Promise<{ serverIp: string; dns: string }> {
    const { priv, server, force } = this.#o;
    const { stdout: routeOut } = await exec("ip", ["route"]); // reading needs no root
    const orig = parseDefaultRoute(routeOut);
    if (!orig) throw new Error("No default route found; are you online?");
    if (conflictingVpn(routeOut, orig) && !force) {
      throw new Error(
        `Another VPN looks active (default on ${orig.dev}, or 0/1 split routes). Stop it, or force.`,
      );
    }
    // Pin the exact IPv4 the proxy will dial, so its upstream can't loop back
    // through the tun (Fastly is anycast; a second lookup could pick another IP).
    const serverIp = (await lookup(server.hostname, { family: 4 })).address;
    server.ip = serverIp;

    // DNS: resolve through the tunnel via DoH so lookups aren't done on (and
    // can't be blocked by) the local network. Point systemd-resolved at a local
    // forwarder that speaks DoH over the proxy. If there's no resolved, fall
    // back to pinning the resolvers to the real uplink.
    let dns: string;
    try {
      this.#dns = await startDnsForwarder({
        socksHost: this.#o.proxyHost,
        socksPort: this.#o.proxyPort,
        dohHost: DOH_HOST,
        host: "127.0.0.1",
        port: DOH_PORT,
      });
      await priv.run(["resolvectl", "dns", orig.dev, `127.0.0.1:${DOH_PORT}`]);
      await priv.run(["resolvectl", "domain", orig.dev, "~."]);
      this.#dnsDev = orig.dev;
      this.#bypassIps = [serverIp];
      dns = `tunnelled (DoH via ${DOH_HOST})`;
    } catch {
      await this.#dns?.close();
      this.#dns = null;
      const dnsIps = await dnsUpstreams();
      if (dnsIps.length === 0) dnsIps.push("1.1.1.1");
      this.#bypassIps = [...new Set([serverIp, ...dnsIps])];
      dns = `direct: ${dnsIps.join(", ")} (no systemd-resolved — DNS may be visible locally)`;
    }

    for (const step of planSetup(this.#bypassIps, orig)) await priv.run(step);

    // Keep private/LAN ranges off the tunnel. Best-effort: a range that already
    // has a route (e.g. Docker) fails to add — skip it, and only remove on
    // teardown the ones we actually added.
    const pin = (dest: string) =>
      orig.gw
        ? ["ip", "route", "add", dest, "via", orig.gw, "dev", orig.dev]
        : ["ip", "route", "add", dest, "dev", orig.dev];
    for (const cidr of PRIVATE_CIDRS) {
      try {
        await priv.run(pin(cidr));
        this.#addedPrivate.push(cidr);
      } catch {
        /* route already present */
      }
    }
    this.#t2s = priv.spawn([
      this.#o.tun2socksPath,
      "--device",
      TUN,
      "--proxy",
      `socks5://${this.#o.proxyHost}:${this.#o.proxyPort}`,
    ]);
    this.#t2s.on("exit", (code) => this.#exitCb?.(code));
    return { serverIp, dns };
  }

  /** The public exit IP (confirms the tunnel works), or null if unreachable. */
  async verifyExitIp(): Promise<string | null> {
    try {
      const res = await fetch("https://api.ipify.org", { signal: AbortSignal.timeout(8000) });
      return (await res.text()).trim();
    } catch {
      return null;
    }
  }

  /** Restores routing and stops tun2socks. Best-effort, idempotent. */
  async stop(): Promise<void> {
    if (this.#stopped) return;
    this.#stopped = true;
    if (this.#dnsDev) await this.#o.priv.run(["resolvectl", "revert", this.#dnsDev], true);
    await this.#dns?.close();
    for (const cidr of this.#addedPrivate) await this.#o.priv.run(["ip", "route", "del", cidr], true);
    for (const step of planTeardown(this.#bypassIps)) await this.#o.priv.run(step, true);
    this.#t2s?.kill("SIGTERM");
    await this.#o.priv.run(["pkill", "-f", TUN], true); // sudo child may outlive the signal
    this.#t2s = null;
  }
}

export interface GlobalOptions {
  host: string;
  port: number;
  force: boolean;
}

/**
 * CLI global mode: routes everything through the VPN and runs until Ctrl+C.
 * Requires root (so the whole process is elevated via `sudo -E`).
 */
export async function runGlobal(conn: Connection, opts: GlobalOptions): Promise<void> {
  if (process.getuid?.() !== 0) {
    console.error(red("Global mode needs root.") + ` Run: ${bold("sudo -E escapedfox global")}`);
    process.exit(1);
  }
  if (!conn.server) throw new Error("No server selected");

  const tun2socksPath = await ensureTun2socks();
  // Start the local proxy and prove auth works BEFORE touching the system.
  const proxy = await startProxy(conn, opts.host, opts.port);
  try {
    await conn.currentPass();
  } catch (err) {
    await proxy.close();
    throw err;
  }

  const session = new GlobalSession({
    priv: directPriv(),
    server: conn.server,
    proxyHost: opts.host,
    proxyPort: opts.port,
    tun2socksPath,
    force: opts.force,
  });
  let dead = false;
  session.onExit((code) => {
    dead = true;
    console.error(red(`tun2socks exited (${code}) — traffic is not being tunnelled.`));
  });

  const cleanup = async () => {
    await session.stop();
    await proxy.close();
  };
  process.on("SIGINT", () => void cleanup().then(() => process.exit(0)));
  process.on("SIGTERM", () => void cleanup().then(() => process.exit(0)));

  try {
    const { serverIp, dns } = await session.start();
    console.log(green(`\n● routing all system traffic through the VPN (${serverIp})…`));
    await new Promise((r) => setTimeout(r, 2500));
    if (!dead) {
      const ip = await session.verifyExitIp();
      console.log(
        ip
          ? green(`  exit IP is now ${bold(ip)}`)
          : yellow("  couldn't reach the internet through the tunnel — check the tun2socks output above."),
      );
    }
    console.log(dim(`  DNS ${dns} · IPv6 blackholed · Ctrl+C restores.\n`));
    await new Promise(() => {}); // run until signalled
  } catch (err) {
    await cleanup();
    throw err;
  }
}
