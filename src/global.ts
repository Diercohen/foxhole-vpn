import { execFile } from "node:child_process";
import { spawn } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import {
  readFileSync, writeFileSync, rmSync,
  mkdtempSync, mkdirSync, copyFileSync, chmodSync, readdirSync, existsSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import type { Connection } from "./connection.js";
import { startProxy, type ProxyLogin } from "./proxy.js";
import { startDnsForwarder, type DnsForwarder } from "./dns.js";
import { GUARDIAN_HOST, pinGuardian } from "./guardian.js";
import { publicIp } from "./netinfo.js";
import { dim, green, red, yellow, bold, verbose } from "./ui.js";
import { DarwinRouting } from "./global-darwin.js";
import { WindowsRouting, isWindowsAdmin } from "./global-win32.js";
import { logStream } from "./log.js";
import { userHome } from "./profile.js";

const exec = promisify(execFile);

const TUN = "foxhole0";
const TUN_ADDR = "198.18.0.1"; // RFC 2544 benchmark range, unlikely to clash
const RESOLV = "/etc/resolv.conf";

// Private / special ranges must skip the tunnel: the VPN refuses them
// ("Destination IP Prohibited") and tunnelling them would break LAN access.
export const PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];

// DNS is resolved through the tunnel via DoH (the VPN forbids port 53). On Linux the
// forwarder listens on a free port it picks; systemd-resolved is pointed at it.
export const DOH_HOST = "cloudflare-dns.com";
const WATCH_MS = 3000; // how often global mode checks for a network change (Wi-Fi switch)

export interface DefaultRoute {
  gw: string | null;
  dev: string;
}

/** Parses `ip route` output for the IPv4 default route, ignoring any on `skipDev`. Pure. */
export function parseDefaultRoute(ipRoute: string, skipDev?: string): DefaultRoute | null {
  for (const line of ipRoute.split("\n")) {
    const m = line.match(/^default(?:\s+via\s+(\S+))?\s+dev\s+(\S+)/);
    if (m && m[2] !== skipDev) return { gw: m[1] ?? null, dev: m[2] };
  }
  return null;
}

/** `ip route add` argv sending `dest` out the real uplink, around the tun. Pure. */
export function pinCmd(dest: string, orig: DefaultRoute): string[] {
  return orig.gw
    ? ["ip", "route", "add", dest, "via", orig.gw, "dev", orig.dev]
    : ["ip", "route", "add", dest, "dev", orig.dev];
}

/**
 * True when a network change (Wi-Fi switch, reconnect) broke global mode's pins: the
 * uplink moved, the VPN server now routes into the tun (`serverRoute`: `ip route get`),
 * or something reset our tun's DNS (`linkDns`: `resolvectl dns foxhole0`, null when
 * DNS isn't tunnelled; `dohPort`: where the DoH forwarder listens). Pure.
 */
export function needsRepin(pinnedTo: DefaultRoute, uplink: DefaultRoute, serverRoute: string, linkDns: string | null, dohPort: number): boolean {
  if (uplink.dev !== pinnedTo.dev || uplink.gw !== pinnedTo.gw) return true;
  if (new RegExp(`\\bdev ${TUN}\\b`).test(serverRoute)) return true;
  return linkDns !== null && !new RegExp(`\\b127\\.0\\.0\\.1:${dohPort}\\b`).test(linkDns);
}

/** An address to dial the local proxy on: a listen-on-all address (sharing on the network) isn't one on Windows. */
export const dialHost = (host: string): string => (["0.0.0.0", "::", ""].includes(host) ? "127.0.0.1" : host);

/** True for virtual/VPN interfaces we must not treat as the real uplink. Pure. */
export function isVpnDev(dev: string): boolean {
  return /^(tun|tap|wg|ppp|utun|gpd|nordlynx|proton)/i.test(dev);
}

/**
 * Builds the `ip` command sequence to route everything through the tun. Pure.
 * `bypassIps` (the VPN server, Guardian and the DNS resolvers) are pinned to the real
 * uplink so they don't loop through — or get refused by — the tunnel.
 */
export function planSetup(bypassIps: string[], orig: DefaultRoute): string[][] {
  return [
    ["ip", "tuntap", "add", "mode", "tun", "dev", TUN],
    ["ip", "addr", "add", `${TUN_ADDR}/15`, "dev", TUN],
    ["ip", "link", "set", "dev", TUN, "up"],
    ...bypassIps.map((ip) => pinCmd(ip, orig)),
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
 * Detects another full-tunnel VPN that would beat foxhole-vpn's default route.
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
const IS_WIN = process.platform === "win32";
const EXE = IS_WIN ? ".exe" : "";

/** Downloads `url` and unpacks the zip into a fresh temp folder; returns that folder. */
async function fetchZip(url: string, sha256?: string): Promise<string> {
  const name = basename(new URL(url).pathname);
  console.log(dim(`downloading ${name}…`));
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  if (sha256 && createHash("sha256").update(body).digest("hex") !== sha256) {
    throw new Error(`${name}: checksum mismatch`);
  }
  const tmp = mkdtempSync(join(tmpdir(), "foxhole-vpn-t2s-"));
  const zip = join(tmp, name);
  writeFileSync(zip, body);
  // Windows 10+ ships bsdtar, which unpacks zips; it has no unzip.
  if (IS_WIN) await exec("tar", ["-xf", zip, "-C", tmp]);
  else await exec("unzip", ["-oq", zip, "-d", tmp]);
  return tmp;
}

/** Downloads the prebuilt tun2socks from GitHub releases to `dest`. */
async function downloadTun2socks(dest: string): Promise<void> {
  const arch = GO_ARCH[process.arch];
  if (!["linux", "darwin", "win32"].includes(process.platform) || !arch) {
    throw new Error(`no prebuilt tun2socks for ${process.platform}/${process.arch}`);
  }
  const os = IS_WIN ? "windows" : process.platform;
  const tmp = await fetchZip(`https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-${os}-${arch}.zip`);
  try {
    const bin = readdirSync(tmp).find((f) => /^tun2socks/.test(f) && !/\.(zip|md|txt)$/i.test(f));
    if (!bin) throw new Error("tun2socks binary not found in archive");
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(join(tmp, bin), dest); // copy, not rename: /tmp may be a different fs
    chmodSync(dest, 0o755);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// tun2socks on Windows needs the Wintun driver DLL beside it; pinned to the
// release's published SHA-256 (https://www.wintun.net).
const WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

/** Puts wintun.dll next to the tun2socks binary at `exe`, if it isn't there yet. */
async function ensureWintun(exe: string): Promise<void> {
  const dll = join(dirname(exe), "wintun.dll");
  if (existsSync(dll)) return;
  const arch = GO_ARCH[process.arch];
  const tmp = await fetchZip(WINTUN_URL, WINTUN_SHA256);
  try {
    copyFileSync(join(tmp, "wintun", "bin", arch, "wintun.dll"), dll);
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
  const home = userHome();
  const cache = join(home, ".cache", "foxhole-vpn", `tun2socks${EXE}`);
  if (IS_WIN) {
    // Only our own copy: it must sit next to wintun.dll, which we can put there.
    try {
      await exec(cache, ["--version"]);
    } catch {
      await downloadTun2socks(cache);
    }
    await ensureWintun(cache);
    return cache;
  }
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

/**
 * Already running as root (or as Administrator on Windows). tun2socks stderr is
 * shown (CLI use), or with `toLog` sent to the in-app log (the TUI's screen).
 */
export function directPriv(toLog = false): Priv {
  return {
    run,
    spawn: (argv) => {
      if (!toLog) return spawn(argv[0], argv.slice(1), { stdio: ["ignore", "ignore", verbose ? "inherit" : "ignore"] });
      const p = spawn(argv[0], argv.slice(1), { stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
      logStream(basename(argv[0]), p.stderr!);
      return p;
    },
  };
}

/** True if this process may change routing: root, or an elevated process on Windows. */
export async function isPrivileged(): Promise<boolean> {
  return IS_WIN ? isWindowsAdmin() : process.getuid?.() === 0;
}

/** Runs `sudo -S <args>` with `input` on stdin; true if it succeeds. */
function sudoOk(args: string[], input: string): Promise<boolean> {
  return new Promise((resolve) => {
    const p = spawn("sudo", ["-S", "-p", "", ...args], { stdio: ["pipe", "ignore", "ignore"] });
    p.on("error", () => resolve(false));
    p.on("exit", (code) => resolve(code === 0));
    p.stdin.end(input);
  });
}

/** Checks a sudo password without running anything. */
export const validateSudo = (password: string): Promise<boolean> => sudoOk(["-k", "-v"], password + "\n");

/** True when a PAM config has an active pam_tid line: sudo takes a fingerprint (Touch ID). Pure. */
export const pamTouchId = (pam: string): boolean => /^\s*auth\s+\S+\s+pam_tid\.so\b/m.test(pam);

/** macOS set up to authorize sudo by Touch ID, where a typed password would go unused. */
export function sudoUsesTouchId(): boolean {
  if (process.platform !== "darwin") return false;
  return ["/etc/pam.d/sudo_local", "/etc/pam.d/sudo"].some((f) => {
    try {
      return pamTouchId(readFileSync(f, "utf8"));
    } catch {
      return false; // missing or unreadable: ask for the password, as without Touch ID
    }
  });
}

/**
 * Authorizes sudo by Touch ID (macOS shows its fingerprint prompt) and, unlike validateSudo,
 * keeps it cached for the commands that follow. No password goes in, so a cancelled prompt
 * (or no sensor: lid closed) fails instead of waiting for one.
 */
export const touchIdSudo = (): Promise<boolean> => sudoOk(["-v"], "");

/** Elevates each command with `sudo -S`, feeding the password on stdin ("" after Touch ID: sudo uses what it cached). */
export function sudoPriv(password: string): Priv {
  // Nothing at all without a password: an empty line would count as a wrong attempt.
  const feed = (p: ReturnType<typeof spawn>) => p.stdin!.end(password && password + "\n");
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
      // stderr goes to the in-app log (the TUI's Logs popup), not the terminal: it would
      // corrupt the screen. Always read, so a chatty child never blocks on a full pipe.
      const p = spawn("sudo", ["-S", "-p", "", ...argv], { stdio: ["pipe", "ignore", "pipe"] });
      logStream(argv[0].endsWith("node") ? "dns relay" : basename(argv[0]), p.stderr!);
      feed(p);
      return p;
    },
  };
}

// ── Shared global session: the privileged half, usable by the CLI and the TUI.
// The caller runs the SOCKS proxy (as the user) and selects conn.server first.

/** How a platform follows the real uplink across network changes (Wi-Fi switch, reconnect). */
export interface Rerouter<U> {
  /** The real uplink (not our tunnel), or null while offline. */
  uplink(): Promise<U | null>;
  /** True when the bypass routes (or DNS) no longer lead out through `uplink`. */
  broken(uplink: U): Promise<boolean>;
  /** Moves the bypass routes (and DNS where it's per-network) to `uplink`. The tunnel stays up, so nothing leaks. */
  repin(uplink: U): Promise<void>;
  /** "en0 (192.168.1.1)", for messages. */
  label(uplink: U): string;
}

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
  #udpBlocked = false;
  #dns: DnsForwarder | null = null;
  #t2s: ReturnType<typeof spawn> | null = null;
  #exitCb: ((code: number | null) => void) | null = null;
  #netCb: ((event: "lost" | "restored", detail: string) => void) | null = null;
  #stopped = false;
  #orig: DefaultRoute | null = null; // the uplink the pins currently go through
  #pinnedIps: string[] = []; // VPN server + Guardian, kept across re-pins
  #watchTimer: NodeJS.Timeout | null = null;
  #tick: Promise<void> | null = null;
  readonly #mac: DarwinRouting | WindowsRouting | null;

  constructor(o: GlobalSessionOptions) {
    // tun2socks and the DNS forwarder dial the proxy, even when it listens on all addresses
    this.#o = { ...o, proxyHost: dialHost(o.proxyHost) };
    this.#mac = process.platform === "darwin" ? new DarwinRouting(this.#o) : IS_WIN ? new WindowsRouting(this.#o) : null;
  }

  /** Called if tun2socks dies unexpectedly. */
  onExit(cb: (code: number | null) => void): void {
    this.#exitCb = cb;
  }

  /** Called when a network change breaks the routing ("lost", repeated if the reason changes) and once it's fixed ("restored"). */
  onNetworkChange(cb: (event: "lost" | "restored", detail: string) => void): void {
    this.#netCb = cb;
  }

  /** Sets up routing + tun2socks. Returns the pinned server IP and DNS mode. */
  async start(): Promise<{ serverIp: string; dns: string }> {
    if (this.#mac) {
      const res = await this.#mac.start((code) => this.#exitCb?.(code));
      this.#arm(this.#mac as Rerouter<unknown>);
      return res;
    }
    if (process.platform !== "linux") throw new Error("global mode needs Linux, macOS or Windows; use `proxy` instead");
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
    // Guardian too, while DNS still works: renewing the pass must not need the tunnel.
    const guardianIp = (await lookup(GUARDIAN_HOST, { family: 4 })).address;
    pinGuardian(guardianIp);
    const pinned = [...new Set([serverIp, guardianIp])];
    this.#pinnedIps = pinned;
    this.#bypassIps = pinned;
    this.#orig = orig;
    for (const step of planSetup(pinned, orig)) await priv.run(step);
    await this.#pinPrivate(orig);

    // DNS: resolve through the tunnel via DoH so lookups aren't done on (and
    // can't be blocked by) the local network. Point systemd-resolved at a local
    // forwarder that speaks DoH over the proxy, set on our own tun: the uplink's
    // DNS belongs to the network manager (reverting it there left no DNS at all
    // until a reconnect), and ours goes away with the tun. If there's no resolved,
    // fall back to pinning the resolvers to the real uplink.
    let dns: string;
    try {
      this.#dns = await startDnsForwarder({
        socksHost: this.#o.proxyHost,
        socksPort: this.#o.proxyPort,
        dohHost: DOH_HOST,
        host: "127.0.0.1",
        port: 0, // a fixed port can be taken: 5353 is mDNS's (avahi)
        connections: 8, // as on macOS and Windows: one slow lookup mustn't hold up the rest
      });
      await this.#pointDns();
      dns = `tunnelled (DoH via ${DOH_HOST})`;
    } catch (err) {
      await priv.run(["resolvectl", "revert", TUN], true);
      await this.#dns?.close();
      this.#dns = null;
      const dnsIps = await dnsUpstreams();
      if (dnsIps.length === 0) dnsIps.push("1.1.1.1");
      this.#bypassIps = [...new Set([...pinned, ...dnsIps])]; // first: stop() removes what got added if a pin fails
      for (const ip of dnsIps) await priv.run(pinCmd(ip, orig));
      dns = `direct: ${dnsIps.join(", ")} (${(err as Error).message} — DNS may be visible locally)`;
    }

    // Reject UDP into the tunnel: it's TCP-only, so QUIC (Chrome's HTTP/3 over
    // UDP 443) would otherwise hang instead of falling back to TCP. The REJECT
    // makes that fallback immediate. Best-effort (needs iptables). Loopback DNS
    // and LAN UDP go out other interfaces, so they're unaffected.
    try {
      await priv.run(["iptables", "-I", "OUTPUT", "-o", TUN, "-p", "udp", "-j", "REJECT"]);
      this.#udpBlocked = true;
    } catch {
      /* no iptables — users can disable QUIC in the browser instead */
    }

    this.#t2s = priv.spawn([
      this.#o.tun2socksPath,
      "--device",
      TUN,
      "--proxy",
      `socks5://${this.#o.proxyHost}:${this.#o.proxyPort}`,
    ]);
    this.#t2s.on("exit", (code) => this.#exitCb?.(code));
    this.#arm({
      uplink: async () => parseDefaultRoute((await exec("ip", ["route"])).stdout, TUN),
      broken: (up) => this.#broken(up),
      repin: (up) => this.#repin(up),
      label: (up) => `${up.dev}${up.gw ? ` (${up.gw})` : ""}`,
    });
    return { serverIp, dns };
  }

  /**
   * Keep private/LAN ranges off the tunnel. Best-effort: a range that already
   * has a route (e.g. Docker) fails to add — skip it, and only remove on
   * teardown the ones we actually added.
   */
  async #pinPrivate(orig: DefaultRoute): Promise<void> {
    for (const cidr of PRIVATE_CIDRS) {
      try {
        await this.#o.priv.run(pinCmd(cidr, orig));
        this.#addedPrivate.push(cidr);
      } catch {
        /* route already present */
      }
    }
  }

  /** Checks for a network change every WATCH_MS and re-pins after one, until stop(). */
  #arm<U>(r: Rerouter<U>): void {
    let told = ""; // the last problem reported, so each is told once
    const tell = (msg: string) => void (msg !== told && this.#netCb?.("lost", (told = msg)));
    const fixed = (up: U) => {
      told = "";
      this.#netCb?.("restored", `via ${r.label(up)}`);
    };
    const tick = async () => {
      try {
        const up = await r.uplink();
        // No network yet: the tunnel's routes stay, so traffic fails instead of leaking.
        if (!up) return tell("network down — waiting for it to come back");
        if (!(await r.broken(up))) return void (told && fixed(up)); // a blip that left the pins intact
        if (!told.startsWith("rerouting failed")) tell(`network changed (${r.label(up)}) — rerouting…`);
        await r.repin(up);
        fixed(up);
      } catch (err) {
        tell(`rerouting failed: ${(err as Error).message} — retrying`);
      }
    };
    // Chained, not an interval: a slow re-pin must not overlap the next check.
    const loop = () => {
      if (this.#stopped) return;
      this.#tick = tick().finally(() => {
        this.#tick = null;
        if (!this.#stopped) this.#watchTimer = setTimeout(loop, WATCH_MS);
      });
    };
    this.#watchTimer = setTimeout(loop, WATCH_MS);
  }

  async #broken(uplink: DefaultRoute): Promise<boolean> {
    const serverRoute = (await exec("ip", ["route", "get", this.#pinnedIps[0]])).stdout;
    const linkDns = this.#dns ? await exec("resolvectl", ["dns", TUN]).then((r) => r.stdout, () => "") : null;
    return needsRepin(this.#orig!, uplink, serverRoute, linkDns, this.#dns?.port ?? 0);
  }

  /** Sends every lookup to the DoH forwarder: "~." on our tun makes systemd-resolved prefer it to the uplink's DNS. */
  async #pointDns(): Promise<void> {
    await this.#o.priv.run(["resolvectl", "dns", TUN, `127.0.0.1:${this.#dns!.port}`]);
    await this.#o.priv.run(["resolvectl", "domain", TUN, "~."]);
  }

  /**
   * Switching country with global on: pins the new server's IP to the uplink before the proxy
   * dials it, or that dial would loop back through the tun. Earlier pins stay until stop().
   */
  async addServer(server: { hostname: string; ip?: string }): Promise<void> {
    const ip = (await lookup(server.hostname, { family: 4 })).address; // the current server still carries this lookup
    if (this.#mac) await this.#mac.pin(ip);
    else if (!this.#pinnedIps.includes(ip)) {
      await this.#o.priv.run(pinCmd(ip, this.#orig!));
      this.#pinnedIps.push(ip);
      this.#bypassIps = [...new Set([...this.#bypassIps, ip])];
    }
    server.ip = ip;
  }

  /** Moves the pins to a new uplink. The tun and its default route stay up meanwhile, so nothing leaks. */
  async #repin(orig: DefaultRoute): Promise<void> {
    const { priv } = this.#o;
    // Stale pins may survive (same device, old gateway); clear them so the adds below can't collide.
    for (const ip of this.#bypassIps) await priv.run(["ip", "route", "del", ip], true);
    for (const cidr of this.#addedPrivate) await priv.run(["ip", "route", "del", cidr], true);
    this.#addedPrivate = [];
    if (this.#dns) {
      await this.#pointDns(); // in case the network manager reset our tun's DNS
    } else {
      // Direct DNS: the new network brings its own resolvers.
      const dnsIps = await dnsUpstreams();
      if (dnsIps.length === 0) dnsIps.push("1.1.1.1");
      this.#bypassIps = [...new Set([...this.#pinnedIps, ...dnsIps])];
    }
    for (const ip of this.#bypassIps) await priv.run(pinCmd(ip, orig));
    await this.#pinPrivate(orig);
    this.#orig = orig;
  }

  /** The public exit IP (confirms the tunnel works), or null if unreachable. */
  async verifyExitIp(): Promise<string | null> {
    return publicIp(); // retries: right after start, tun2socks may not be reading the tun yet
  }

  /** Restores routing and stops tun2socks. Best-effort, idempotent. */
  async stop(): Promise<void> {
    if (this.#stopped) return;
    this.#stopped = true;
    if (this.#watchTimer) clearTimeout(this.#watchTimer);
    await this.#tick; // a re-pin in flight would add routes after the teardown below
    if (this.#mac) return this.#mac.stop();
    if (this.#udpBlocked)
      await this.#o.priv.run(["iptables", "-D", "OUTPUT", "-o", TUN, "-p", "udp", "-j", "REJECT"], true);
    for (const cidr of this.#addedPrivate) await this.#o.priv.run(["ip", "route", "del", cidr], true);
    // Stop tun2socks before deleting the device: a tun still held open can't be
    // deleted, and the leftover makes the next `ip tuntap add` fail (busy).
    await stopProcess(this.#t2s, () => this.#o.priv.run(["pkill", "-f", TUN], true)); // sudo child may outlive the signal
    this.#t2s = null;
    for (const step of planTeardown(this.#bypassIps)) await this.#o.priv.run(step, true);
    await this.#dns?.close(); // last: until the tun (and the DNS setting on it) is gone, lookups still come here
  }
}

/**
 * Stops a child on purpose: detaches its exit listeners first (so the "died
 * unexpectedly" callback doesn't fire), signals it, runs `extra` (e.g. pkill),
 * and waits up to 3s for it to exit.
 */
export async function stopProcess(p: ReturnType<typeof spawn> | null, extra: () => Promise<void>): Promise<void> {
  if (!p || p.exitCode !== null || p.signalCode !== null) return void (await extra());
  p.removeAllListeners("exit");
  const exited = new Promise((r) => p.once("exit", r));
  p.kill("SIGTERM");
  await extra();
  await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
}

export interface GlobalOptions {
  host: string;
  port: number;
  force: boolean;
  login?: (address: string | undefined) => ProxyLogin | null; // what a proxy client must sign in with
}

/**
 * CLI global mode: routes everything through the VPN and runs until Ctrl+C.
 * Requires root (so the whole process is elevated via `sudo -E`).
 */
export async function runGlobal(conn: Connection, opts: GlobalOptions): Promise<void> {
  if (!(await isPrivileged())) {
    console.error(
      IS_WIN
        ? red("Global mode needs Administrator rights.") + ` Open ${bold("Terminal (Admin)")} and run ${bold("foxhole global")} there.`
        : red("Global mode needs root.") + ` Run: ${bold("sudo -E foxhole global")}`,
    );
    process.exit(1);
  }
  if (!conn.server) throw new Error("No server selected");

  const tun2socksPath = await ensureTun2socks();
  // Start the local proxy and prove auth works BEFORE touching the system.
  const proxy = await startProxy(conn, opts.host, opts.port, opts.login);
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
  session.onNetworkChange((event, detail) => console.log(event === "lost" ? yellow(`  ${detail}`) : green(`  rerouted ${detail}`)));

  const cleanup = async () => {
    await session.stop();
    await proxy.close();
  };
  const onSignal = () => void cleanup().then(() => process.exit(0));
  // SIGBREAK is Ctrl+Break, SIGHUP a closed console window (Windows gives ~10s to clean up).
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP", ...(IS_WIN ? ["SIGBREAK"] : [])]) process.on(sig, onSignal);

  try {
    const { serverIp, dns } = await session.start();
    console.log(green(`\n● routing all system traffic through the VPN (${serverIp})…`));
    await new Promise((r) => setTimeout(r, 2500));
    if (!dead) {
      const ip = await session.verifyExitIp();
      console.log(
        ip
          ? green(`  exit IP is now ${bold(ip)}`)
          : yellow(`  couldn't reach the internet through the tunnel — ${verbose ? "check the tun2socks output above" : "run with --verbose for details"}.`),
      );
    }
    console.log(dim(`  DNS ${dns} · IPv6 ${IS_WIN ? "blocked" : "blackholed"} · Ctrl+C restores.\n`));
    await new Promise(() => {}); // run until signalled
  } catch (err) {
    await cleanup();
    throw err;
  }
}
