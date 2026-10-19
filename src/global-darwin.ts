// macOS global routing. Same plan as the Linux path in global.ts, with BSD tools:
// tun2socks creates the utun, `route` steers traffic (0/1 + 128/1 beat the
// default without replacing it), and networksetup points DNS at a root-run copy
// of the DoH forwarder on 127.0.0.1:53 (the system resolver can't use a port).
import { execFile, type spawn } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import { connect } from "node:net";
import { PRIVATE_CIDRS, DOH_HOST, isVpnDev, type GlobalSessionOptions } from "./global.js";

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

export class DarwinRouting {
  readonly #o: GlobalSessionOptions;
  #undo: string[][] = []; // privileged commands reversing what start() did
  #procs: ReturnType<typeof spawn>[] = [];
  #dnsService: string | null = null;
  #dnsRestore: string[] = [];

  constructor(o: GlobalSessionOptions) {
    this.#o = o;
  }

  async start(onExit: (code: number | null) => void): Promise<{ serverIp: string; dns: string }> {
    const { priv, server, force, proxyHost, proxyPort } = this.#o;
    const orig = parseRouteGet((await exec("route", ["-n", "get", "default"])).stdout);
    if (!orig) throw new Error("No default route found; are you online?");
    const { stdout: netstat } = await exec("netstat", ["-rn", "-f", "inet"]);
    if (macConflictingVpn(netstat, orig) && !force) {
      throw new Error(`Another VPN looks active (default on ${orig.dev}, or 0/1 split routes). Stop it, or force.`);
    }
    const serverIp = (await lookup(server.hostname, { family: 4 })).address;
    server.ip = serverIp;

    const step = async (add: string[], del: string[]) => {
      await priv.run(add);
      this.#undo.push(del);
    };
    const viaUplink = (kind: "-host" | "-net", dest: string) =>
      ["route", "-n", "add", kind, dest, ...(orig.gw ? [orig.gw] : ["-interface", orig.dev])];

    await step(viaUplink("-host", serverIp), ["route", "-n", "delete", "-host", serverIp]);
    for (const cidr of PRIVATE_CIDRS) {
      await step(viaUplink("-net", cidr), ["route", "-n", "delete", "-net", cidr]).catch(() => {
        /* route already present */
      });
    }

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
      const { stdout } = await exec("scutil", ["--dns"]);
      const ips = new Set([...stdout.matchAll(/nameserver\[\d+\]\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})/g)].map((m) => m[1]));
      for (const ip of ips) {
        if (ip.startsWith("127.")) continue;
        await step(viaUplink("-host", ip), ["route", "-n", "delete", "-host", ip]).catch(() => {});
      }
      dns = `direct: ${[...ips].join(", ")} (${(err as Error).message} — DNS may be visible locally)`;
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

  /** Runs the DoH forwarder as root on :53 and points the uplink's service at it. */
  async #tunnelDns(dev: string): Promise<void> {
    const { priv, proxyHost, proxyPort } = this.#o;
    const service = serviceForDevice((await exec("networksetup", ["-listnetworkserviceorder"])).stdout, dev);
    if (!service) throw new Error(`no network service for ${dev}`);
    const dnsJs = JSON.stringify(new URL("./dns.js", import.meta.url).href);
    const opts = JSON.stringify({ socksHost: proxyHost, socksPort: proxyPort, dohHost: DOH_HOST, host: "127.0.0.1", port: 53, connections: 8 });
    this.#procs.push(
      priv.spawn([
        process.execPath, "--input-type=module", "-e",
        `import { startDnsForwarder } from ${dnsJs}; await startDnsForwarder(${opts}); // ${DNS_MARK}`,
      ]),
    );
    await waitFor("the DNS relay", () => tcpProbe(53));
    this.#dnsRestore = dnsRestoreArgs((await exec("networksetup", ["-getdnsservers", service])).stdout);
    await priv.run(["networksetup", "-setdnsservers", service, "127.0.0.1"]);
    this.#dnsService = service;
    await priv.run(["killall", "-HUP", "mDNSResponder"], true); // flush cached answers
  }

  /** Restores DNS and routing, stops tun2socks and the relay. Best-effort. */
  async stop(): Promise<void> {
    const { priv } = this.#o;
    if (this.#dnsService) await priv.run(["networksetup", "-setdnsservers", this.#dnsService, ...this.#dnsRestore], true);
    for (const argv of this.#undo.reverse()) await priv.run(argv, true);
    this.#undo = [];
    for (const p of this.#procs) p.kill("SIGTERM");
    // sudo children may outlive the signal. The [x] keeps pkill from matching its own sudo.
    await priv.run(["pkill", "-f", `${UTUN.slice(0, -1)}[${UTUN.slice(-1)}]`], true);
    await priv.run(["pkill", "-f", `${DNS_MARK.slice(0, -1)}[${DNS_MARK.slice(-1)}]`], true);
    await priv.run(["killall", "-HUP", "mDNSResponder"], true);
  }
}
