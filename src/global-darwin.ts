// macOS global routing. Same plan as the Linux path in global.ts, with BSD tools:
// tun2socks creates the utun, `route` steers traffic (0/1 + 128/1 beat the
// default without replacing it), and networksetup points DNS at a root-run copy
// of the DoH forwarder on 127.0.0.1:53 (the system resolver can't use a port).
import { execFile, type spawn } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import { connect } from "node:net";
import { PRIVATE_CIDRS, DOH_HOST, isVpnDev, stopProcess, type GlobalSessionOptions, type Rerouter } from "./global.js";
import { GUARDIAN_HOST, pinGuardian } from "./guardian.js";
import { currentSplit } from "./split.js";

const exec = promisify(execFile);

const UTUN = "utun123";
const TUN_ADDR = "198.18.0.1";
const DNS_MARK = "foxhole-dns"; // tags the root DNS relay's command line for pkill

export interface MacRoute {
  gw: string | null;
  dev: string;
}

/** Parses `route -n get default`. Pure. */
export function parseRouteGet(out: string): MacRoute | null {
  const dev = out.match(/^\s*interface:\s*(\S+)/m)?.[1];
  if (!dev) return null;
  return { gw: out.match(/^\s*gateway:\s*(\S+)/m)?.[1] ?? null, dev };
}

/** Network service name ("Wi-Fi") for a device ("en0"), from `networksetup -listnetworkserviceorder`. Pure. */
export function serviceForDevice(out: string, dev: string): string | null {
  for (const m of out.matchAll(/^\(\d+\)\s+(.+)\n\(Hardware Port: .*, Device: ([^)]+)\)/gm)) {
    if (m[2] === dev) return m[1].trim();
  }
  return null;
}

/** `networksetup -getdnsservers` output → the args that restore it. Pure. */
export function dnsRestoreArgs(out: string): string[] {
  const ips = out.split("\n").map((s) => s.trim()).filter((s) => /^[0-9a-f.:]+$/i.test(s));
  return ips.length ? ips : ["Empty"];
}

/**
 * The primary IPv4 default in `netstat -rn -f inet`, skipping `skipDev` (our utun).
 * `route get default` can't be trusted once our 0/1 routes exist. Pure.
 */
export function parseNetstatDefault(netstat: string, skipDev: string): MacRoute | null {
  let scoped: MacRoute | null = null;
  for (const line of netstat.split("\n")) {
    const [dest, gw, flags, ...rest] = line.trim().split(/\s+/);
    const dev = rest.find((t) => /^[a-z]+\d+$/i.test(t)); // Netif; older macOS adds Refs/Use columns first
    if (dest !== "default" || !dev || dev === skipDev) continue;
    const route = { gw: /^\d{1,3}(\.\d{1,3}){3}$/.test(gw) ? gw : null, dev }; // "link#4": on-link
    if (!flags.includes("I")) return route; // I: scoped to a non-primary interface
    scoped ??= route;
  }
  return scoped;
}

/** True when the pins no longer lead out through `uplink`: it moved, or the server routes into our utun (`route -n get <server>`). Pure. */
export function macNeedsRepin(pinnedTo: MacRoute, uplink: MacRoute, serverRouteGet: string): boolean {
  if (uplink.dev !== pinnedTo.dev || uplink.gw !== pinnedTo.gw) return true;
  return parseRouteGet(serverRouteGet)?.dev === UTUN;
}

/** Another full-tunnel VPN: default on a utun, or 0/1 + 128.0/1 split routes in `netstat -rn -f inet`. Pure. */
export function macConflictingVpn(netstat: string, orig: MacRoute): boolean {
  return isVpnDev(orig.dev) || /^(0|128\.0)\/1\s/m.test(netstat);
}

async function waitFor(what: string, probe: () => Promise<unknown>, ms = 5000): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    try {
      await probe();
      return;
    } catch {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

const tcpProbe = (port: number) =>
  new Promise<void>((resolve, reject) => {
    const s = connect(port, "127.0.0.1", () => (s.destroy(), resolve()));
    s.on("error", reject);
  });

/** `route` arguments sending a route out the uplink: by its gateway, else its device. Pure. */
const via = (up: MacRoute): string[] => (up.gw ? [up.gw] : ["-interface", up.dev]);

export class DarwinRouting implements Rerouter<MacRoute> {
  readonly #o: GlobalSessionOptions;
  #undo: string[][] = []; // privileged commands reversing what start() did
  #pinUndo: string[][] = []; // the same for the routes tied to the uplink, redone on a network change
  #procs: ReturnType<typeof spawn>[] = [];
  #relay: ReturnType<typeof spawn> | null = null; // the root DNS relay, which also routes direct sites (relay.ts)
  #dnsService: string | null = null;
  #dnsRestore: string[] = [];
  #directDns = false; // DNS not tunnelled: the resolvers are pinned too
  #orig: MacRoute | null = null;
  #pinnedIps: string[] = []; // VPN server + Guardian, kept across re-pins

  constructor(o: GlobalSessionOptions) {
    this.#o = o;
  }

  async start(onExit: (code: number | null, signal: NodeJS.Signals | null) => void): Promise<{ serverIp: string; dns: string }> {
    const { priv, server, force, proxyHost, proxyPort } = this.#o;
    const orig = parseRouteGet((await exec("route", ["-n", "get", "default"])).stdout);
    if (!orig) throw new Error("No default route found; are you online?");
    const { stdout: netstat } = await exec("netstat", ["-rn", "-f", "inet"]);
    if (macConflictingVpn(netstat, orig) && !force) {
      throw new Error(`Another VPN looks active (default on ${orig.dev}, or 0/1 split routes). Stop it, or force.`);
    }
    const serverIp = (await lookup(server.hostname, { family: 4 })).address;
    server.ip = serverIp;
    // Guardian too, while DNS still works: renewing the pass must not need the tunnel.
    const guardianIp = (await lookup(GUARDIAN_HOST, { family: 4 })).address;
    pinGuardian(guardianIp);
    this.#pinnedIps = [...new Set([serverIp, guardianIp])];
    this.#orig = orig;

    const step = async (add: string[], del: string[]) => {
      await priv.run(add);
      this.#undo.push(del);
    };
    await this.#pin(orig);

    const t2s = priv.spawn([this.#o.tun2socksPath, "--device", UTUN, "--proxy", `socks5://${proxyHost}:${proxyPort}`]);
    t2s.on("exit", onExit);
    this.#procs.push(t2s);
    await waitFor(`${UTUN} to appear`, () => exec("ifconfig", [UTUN]));
    await priv.run(["ifconfig", UTUN, TUN_ADDR, TUN_ADDR, "up"]);

    let dns: string;
    try {
      await this.#tunnelDns(orig.dev);
      dns = `tunnelled (DoH via ${DOH_HOST})`;
    } catch (err) {
      // Fall back to pinning the current resolvers to the real uplink (a DNS leak).
      this.#directDns = true;
      const ips = await this.#pinResolvers(orig);
      dns = `direct: ${ips.join(", ")} (${(err as Error).message} — DNS may be visible locally)`;
    }

    for (const half of ["0.0.0.0/1", "128.0.0.0/1"]) {
      await step(["route", "-n", "add", "-net", half, TUN_ADDR], ["route", "-n", "delete", "-net", half]);
    }
    // The upstream is IPv4-only; reject IPv6 so apps fall back to IPv4 (the tunnel).
    for (const half of ["::/1", "8000::/1"]) {
      await step(
        ["route", "-n", "add", "-inet6", "-net", half, "::1", "-reject"],
        ["route", "-n", "delete", "-inet6", "-net", half],
      ).catch(() => (dns += " · IPv6 NOT blocked, may bypass the VPN"));
    }
    // ponytail: UDP isn't rejected (no pf rules), so QUIC waits for its TCP
    // fallback instead of failing fast; add a pf anchor if that's noticeable.
    return { serverIp, dns };
  }

  /** Routes `dest` out the real uplink, recording how to undo it in #pinUndo. */
  async #pinRoute(kind: "-host" | "-net", dest: string, up: MacRoute): Promise<void> {
    await this.#o.priv.run(["route", "-n", "add", kind, dest, ...via(up)]);
    this.#pinUndo.push(["route", "-n", "delete", kind, dest]);
  }

  /** Pins the VPN server, Guardian and the private ranges to the uplink. */
  async #pin(up: MacRoute): Promise<void> {
    for (const ip of this.#pinnedIps) await this.#pinRoute("-host", ip, up);
    for (const cidr of PRIVATE_CIDRS) {
      await this.#pinRoute("-net", cidr, up).catch(() => {
        /* route already present */
      });
    }
  }

  /** Pins one more VPN server (a country switch), kept across re-pins. */
  async pin(ip: string): Promise<void> {
    if (this.#pinnedIps.includes(ip)) return;
    await this.#pinRoute("-host", ip, this.#orig!);
    this.#pinnedIps.push(ip);
  }

  /** Pins the resolvers the system uses now (direct DNS); returns them. */
  async #pinResolvers(up: MacRoute): Promise<string[]> {
    const { stdout } = await exec("scutil", ["--dns"]);
    const ips = [...new Set([...stdout.matchAll(/nameserver\[\d+\]\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})/g)].map((m) => m[1]))];
    for (const ip of ips) {
      if (ip.startsWith("127.")) continue;
      await this.#pinRoute("-host", ip, up).catch(() => {});
    }
    return ips;
  }

  async uplink(): Promise<MacRoute | null> {
    return parseNetstatDefault((await exec("netstat", ["-rn", "-f", "inet"])).stdout, UTUN);
  }

  async broken(up: MacRoute): Promise<boolean> {
    const { stdout } = await exec("route", ["-n", "get", this.#pinnedIps[0]]);
    return macNeedsRepin(this.#orig!, up, stdout);
  }

  async repin(up: MacRoute): Promise<void> {
    const { priv } = this.#o;
    // Stale pins may survive (same device, old gateway); clear them so the adds below can't collide.
    for (const argv of this.#pinUndo.reverse()) await priv.run(argv, true);
    this.#pinUndo = [];
    await this.#pin(up);
    if (this.#directDns) await this.#pinResolvers(up);
    // The DNS setting belongs to the network service ("Wi-Fi"), so it survives a Wi-Fi
    // switch; only a move to another service (Ethernet) has to carry it over.
    if (this.#dnsService) {
      const service = serviceForDevice((await exec("networksetup", ["-listnetworkserviceorder"])).stdout, up.dev);
      if (!service) throw new Error(`no network service for ${up.dev}`);
      if (service !== this.#dnsService) {
        await priv.run(["networksetup", "-setdnsservers", this.#dnsService, ...this.#dnsRestore], true);
        await this.#pointDns(service);
      }
    }
    this.#orig = up;
    this.#relay?.stdin?.write(`via ${JSON.stringify(via(up))}\n`);
    await priv.run(["killall", "-HUP", "mDNSResponder"], true); // drop answers cached while offline
  }

  label(up: MacRoute): string {
    return `${up.dev}${up.gw ? ` (${up.gw})` : ""}`;
  }

  /**
   * Runs the DoH forwarder as root on :53 and points the uplink's service at it. The relay also
   * routes split tunneling's direct sites around the tunnel as it looks them up (relay.ts); its
   * stdin stays open for new rules and a moved uplink, and its end has it remove those routes.
   */
  async #tunnelDns(dev: string): Promise<void> {
    const { priv, proxyHost, proxyPort } = this.#o;
    const service = serviceForDevice((await exec("networksetup", ["-listnetworkserviceorder"])).stdout, dev);
    if (!service) throw new Error(`no network service for ${dev}`);
    const relayJs = JSON.stringify(new URL("./relay.js", import.meta.url).href);
    const dns = { socksHost: proxyHost, socksPort: proxyPort, dohHost: DOH_HOST, host: "127.0.0.1", port: 53, connections: 8 };
    const opts = JSON.stringify({ dns, split: currentSplit(), via: via(this.#orig!) });
    // In the desktop app execPath is Electron's, run as plain Node (env: sudo clears the environment)
    const node = process.versions.electron ? ["env", "ELECTRON_RUN_AS_NODE=1", process.execPath] : [process.execPath];
    this.#relay = priv.spawn(
      [...node, "--input-type=module", "-e", `import { relayMain } from ${relayJs}; await relayMain(${opts}); // ${DNS_MARK}`],
      true,
    );
    this.#procs.push(this.#relay);
    await waitFor("the DNS relay", () => tcpProbe(53));
    await this.#pointDns(service);
  }

  /** Points a network service's DNS at the relay, remembering what to restore. */
  async #pointDns(service: string): Promise<void> {
    const { priv } = this.#o;
    this.#dnsRestore = dnsRestoreArgs((await exec("networksetup", ["-getdnsservers", service])).stdout);
    await priv.run(["networksetup", "-setdnsservers", service, "127.0.0.1"]);
    this.#dnsService = service;
    await priv.run(["killall", "-HUP", "mDNSResponder"], true); // flush cached answers
  }

  /** Split tunneling's rules changed: the relay routes by the new ones. */
  splitChanged(): void {
    this.#relay?.stdin?.write(`rules ${JSON.stringify(currentSplit())}\n`);
  }

  /** Restores DNS and routing, stops tun2socks and the relay. Best-effort. */
  async stop(): Promise<void> {
    const { priv } = this.#o;
    if (this.#dnsService) await priv.run(["networksetup", "-setdnsservers", this.#dnsService, ...this.#dnsRestore], true);
    // The relay removes its direct routes as its stdin ends: give it the time to.
    const relay = this.#relay;
    this.#relay = null;
    if (relay && relay.exitCode === null && relay.signalCode === null) {
      await new Promise((r) => (relay.once("exit", r), relay.stdin?.end(), setTimeout(r, 10_000)));
    }
    for (const argv of [...this.#undo.reverse(), ...this.#pinUndo.reverse()]) await priv.run(argv, true);
    this.#undo = [];
    this.#pinUndo = [];
    // sudo children may outlive the signal. The [x] keeps pkill from matching its own sudo.
    const pkill = async () => {
      await priv.run(["pkill", "-f", `${UTUN.slice(0, -1)}[${UTUN.slice(-1)}]`], true);
      await priv.run(["pkill", "-f", `${DNS_MARK.slice(0, -1)}[${DNS_MARK.slice(-1)}]`], true);
    };
    await Promise.all(this.#procs.map((p) => stopProcess(p, pkill)));
    if (!this.#procs.length) await pkill();
    this.#procs = [];
    await priv.run(["killall", "-HUP", "mDNSResponder"], true);
  }
}
