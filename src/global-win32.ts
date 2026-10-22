// Windows global routing. Same plan as the Linux/macOS paths, with Windows tools:
// tun2socks creates a Wintun adapter, `netsh` gives it an address and steers
// traffic (0/1 + 128/1 beat the default route without replacing it), an NRPT
// rule sends every DNS lookup to the DoH forwarder on 127.0.0.1:53, and firewall
// rules block IPv6 and QUIC so apps fall back to IPv4 TCP (what the tunnel carries).
// Needs an elevated (Administrator) process; nothing here survives a reboot except
// the NRPT and firewall rules, which `restoreWindows()` removes.
import { execFile, type spawn } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import { startDnsForwarder, type DnsForwarder } from "./dns.js";
import { PRIVATE_CIDRS, DOH_HOST, stopProcess, type GlobalSessionOptions, type Priv, type Rerouter } from "./global.js";
import { GUARDIAN_HOST, pinGuardian } from "./guardian.js";

const exec = promisify(execFile);

const TUN = "foxhole0";
const TUN_ADDR = "198.18.0.1";
const TUN_MASK = "255.254.0.0"; // /15, as on Linux
const TAG = "foxhole-vpn"; // names our firewall rules and NRPT rule, for cleanup

/** argv running a PowerShell script (single quotes only: no argv escaping surprises). */
export const ps = (script: string): string[] => [
  "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script,
];

async function psOut(script: string): Promise<string> {
  const [cmd, ...args] = ps(script);
  return (await exec(cmd, args, { windowsHide: true })).stdout.trim();
}

/** True if this process runs elevated (as Administrator). */
export async function isWindowsAdmin(): Promise<boolean> {
  try {
    const out = await psOut(
      "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    );
    return out === "True";
  } catch {
    return false;
  }
}

export interface WinRoute {
  ifIndex: number;
  alias: string;
  desc: string;
  gw: string | null; // null when the route is on-link
  split: number; // existing 0.0.0.0/1 + 128.0.0.0/1 routes (another VPN)
}

// The uplink Windows would use for the internet, plus any split routes already present.
export const UPLINK_PS = [
  "$r = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction Stop | Where-Object { $_.NextHop } | Select-Object -First 1",
  "$a = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue",
  "$s = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1' }).Count",
  "[pscustomobject]@{ ifIndex = $r.ifIndex; alias = $r.InterfaceAlias; gw = $r.NextHop; desc = [string]$a.InterfaceDescription; split = $s } | ConvertTo-Json -Compress",
].join("; ");

/** Parses UPLINK_PS's JSON. Pure. */
export function parseWinUplink(json: string): WinRoute | null {
  try {
    const o = JSON.parse(json) as { ifIndex?: number; alias?: string; gw?: string; desc?: string; split?: number };
    if (typeof o.ifIndex !== "number" || !o.alias) return null;
    const gw = o.gw && o.gw !== "0.0.0.0" ? o.gw : null;
    return { ifIndex: o.ifIndex, alias: o.alias, desc: o.desc ?? "", gw, split: o.split ?? 0 };
  } catch {
    return null;
  }
}

/**
 * For the network-change check, in one PowerShell run: the uplink past our own adapter
 * (its 0/1 routes would win Find-NetRoute), and the adapter the VPN server routes via.
 */
export const watchPs = (serverIp: string): string =>
  [
    "$i = { param($n) Get-NetIPInterface -InterfaceIndex $n -AddressFamily IPv4 -ErrorAction SilentlyContinue }",
    `$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne '${TUN}' -and (& $i $_.ifIndex).ConnectionState -eq 'Connected' } | Sort-Object { $_.RouteMetric + (& $i $_.ifIndex).InterfaceMetric } | Select-Object -First 1`,
    `$v = (Find-NetRoute -RemoteIPAddress '${serverIp}' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop } | Select-Object -First 1).InterfaceAlias`,
    "if ($r) { [pscustomobject]@{ ifIndex = $r.ifIndex; alias = $r.InterfaceAlias; gw = $r.NextHop; via = [string]$v } | ConvertTo-Json -Compress }",
  ].join("; ");

export interface WinWatch {
  up: WinRoute;
  via: string; // the adapter the VPN server routes through now
}

/** Parses watchPs's JSON; null when offline. Pure. */
export function parseWinWatch(json: string): WinWatch | null {
  const up = parseWinUplink(json);
  return up ? { up, via: (JSON.parse(json) as { via?: string }).via ?? "" } : null;
}

/** True when the pins no longer lead out through the uplink: it moved, or the server routes into our adapter. Pure. */
export function winNeedsRepin(pinnedTo: WinRoute, now: WinWatch): boolean {
  return now.up.ifIndex !== pinnedTo.ifIndex || now.up.gw !== pinnedTo.gw || now.via === TUN;
}

/** Adapter name/description of a VPN (we must not treat it as the real uplink). Pure. */
export function isWinVpnAdapter(alias: string, desc: string): boolean {
  return /wintun|wireguard|tap-windows|openvpn|tunnel|vpn|nordlynx|proton|fortinet|cisco anyconnect|globalprotect|pangp|juniper|zerotier|tailscale/i
    .test(`${alias} ${desc}`);
}

/** Another full-tunnel VPN: the uplink is a VPN adapter, or 0/1 split routes exist. Pure. */
export const winConflictingVpn = (r: WinRoute): boolean => r.split > 0 || isWinVpnAdapter(r.alias, r.desc);

/** netsh argv adding (or deleting) `prefix` via the uplink. Pure. */
export function pinRoute(op: "add" | "delete", prefix: string, up: { ifIndex: number; gw: string | null }): string[] {
  const p = prefix.includes("/") ? prefix : `${prefix}/32`;
  return [
    "netsh", "interface", "ipv4", op, "route", `prefix=${p}`, `interface=${up.ifIndex}`,
    ...(up.gw ? [`nexthop=${up.gw}`] : []), "store=active",
  ];
}

/** netsh/PowerShell argv that remove everything a crashed session may have left behind. Pure. */
export function planStaleCleanup(): string[][] {
  return [
    ps(`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '${TAG}' } | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache`),
    ["netsh", "advfirewall", "firewall", "delete", "rule", `name=${TAG}`],
  ];
}

async function waitFor(what: string, probe: () => Promise<unknown>, ms = 10000): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    try {
      await probe();
      return;
    } catch {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((r) => setTimeout(r, 300));
  }
}

/** Removes what an earlier, killed session left behind (DNS rule, firewall rules, adapter routes). */
export async function restoreWindows(priv: Priv): Promise<void> {
  for (const argv of planStaleCleanup()) await priv.run(argv, true);
  // A tun2socks left running keeps the adapter and its 0/1 routes alive.
  await priv.run(["taskkill", "/F", "/IM", "tun2socks.exe"], true);
}

export class WindowsRouting implements Rerouter<WinWatch> {
  readonly #o: GlobalSessionOptions;
  #undo: string[][] = []; // privileged commands reversing what start() did
  #pinUndo: string[][] = []; // the same for the routes tied to the uplink, redone on a network change
  #directDns = false; // DNS not tunnelled: the resolvers are pinned too
  #orig: WinRoute | null = null;
  #pinnedIps: string[] = []; // VPN server + Guardian, kept across re-pins
  #t2s: ReturnType<typeof spawn> | null = null;
  #dns: DnsForwarder | null = null;

  constructor(o: GlobalSessionOptions) {
    this.#o = o;
  }

  /** The uplink's interface, as networkInterfaces() names it: split tunneling's direct sites leave from its address. */
  device(): string | null {
    return this.#orig?.alias ?? null;
  }

  async start(onExit: (code: number | null, signal: NodeJS.Signals | null) => void): Promise<{ serverIp: string; dns: string }> {
    const { priv, server, force, proxyHost, proxyPort } = this.#o;
    const up = parseWinUplink(await psOut(UPLINK_PS).catch(() => ""));
    if (!up) throw new Error("No default route found; are you online?");
    if (winConflictingVpn(up) && !force) {
      throw new Error(`Another VPN looks active (uplink ${up.alias}, or 0/1 split routes). Stop it, or force.`);
    }
    await restoreWindows(priv); // a crashed earlier run must not stack on top of this one

    const serverIp = (await lookup(server.hostname, { family: 4 })).address;
    server.ip = serverIp;
    // Guardian too, while DNS still works: renewing the pass must not need the tunnel.
    const guardianIp = (await lookup(GUARDIAN_HOST, { family: 4 })).address;
    pinGuardian(guardianIp);
    this.#pinnedIps = [...new Set([serverIp, guardianIp])];
    this.#orig = up;

    const step = async (add: string[], del: string[]) => {
      await priv.run(add);
      this.#undo.push(del);
    };
    await this.#pin(up);

    this.#t2s = priv.spawn([this.#o.tun2socksPath, "--device", TUN, "--proxy", `socks5://${proxyHost}:${proxyPort}`]);
    this.#t2s.on("exit", onExit);
    await waitFor(`the ${TUN} adapter to appear`, () => psOut(`Get-NetAdapter -Name '${TUN}' -ErrorAction Stop`));
    await priv.run(["netsh", "interface", "ipv4", "set", "address", `name=${TUN}`, "source=static", `address=${TUN_ADDR}`, `mask=${TUN_MASK}`]);
    await priv.run(["netsh", "interface", "ipv4", "set", "interface", `interface=${TUN}`, "metric=1"], true);

    let dns: string;
    try {
      await this.#tunnelDns();
      dns = `tunnelled (DoH via ${DOH_HOST})`;
    } catch (err) {
      // Fall back to pinning the current resolvers to the real uplink (a DNS leak).
      this.#directDns = true;
      const ips = await this.#pinResolvers(up);
      dns = `direct: ${ips.join(", ") || "system"} (${(err as Error).message} — DNS may be visible locally)`;
    }

    for (const half of ["0.0.0.0/1", "128.0.0.0/1"]) {
      await step(
        ["netsh", "interface", "ipv4", "add", "route", `prefix=${half}`, `interface=${TUN}`, "metric=1", "store=active"],
        ["netsh", "interface", "ipv4", "delete", "route", `prefix=${half}`, `interface=${TUN}`, "store=active"],
      );
    }

    // The upstream is IPv4 TCP only. Block global IPv6 so apps fall back to IPv4
    // (through the tunnel), and QUIC (UDP 443) so browsers fall back to TCP at once.
    // The firewall answers immediately, so nothing hangs waiting for a timeout.
    const fw = (extra: string[]) => ["netsh", "advfirewall", "firewall", "add", "rule", `name=${TAG}`, "dir=out", "action=block", ...extra];
    const delFw = ["netsh", "advfirewall", "firewall", "delete", "rule", `name=${TAG}`];
    try {
      await step(fw(["protocol=any", "remoteip=2000::/3"]), delFw);
      await priv.run(fw(["protocol=UDP", "remoteport=443"]));
      const off = await psOut("@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count").catch(() => "0");
      if (off !== "0") dns += " · Windows Firewall is off: IPv6 NOT blocked, may bypass the VPN";
    } catch {
      dns += " · IPv6 NOT blocked, may bypass the VPN";
    }
    return { serverIp, dns };
  }

  /** Routes `prefix` out the uplink, recording how to undo it in #pinUndo. */
  async #pinRoute(prefix: string, up: WinRoute): Promise<void> {
    await this.#o.priv.run(pinRoute("add", prefix, up));
    this.#pinUndo.push(pinRoute("delete", prefix, up));
  }

  /** Pins the VPN server, Guardian and the private ranges to the uplink. */
  async #pin(up: WinRoute): Promise<void> {
    for (const ip of this.#pinnedIps) await this.#pinRoute(ip, up);
    for (const cidr of PRIVATE_CIDRS) {
      await this.#pinRoute(cidr, up).catch(() => {
        /* route already present */
      });
    }
  }

  /** Pins one more VPN server (a country switch), kept across re-pins. */
  async pin(ip: string): Promise<void> {
    if (this.#pinnedIps.includes(ip)) return;
    await this.#pinRoute(ip, this.#orig!);
    this.#pinnedIps.push(ip);
  }

  /** Pins the resolvers the system uses now (direct DNS); returns them. */
  async #pinResolvers(up: WinRoute): Promise<string[]> {
    const out = await psOut(
      "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique",
    ).catch(() => "");
    const ips = out.split(/\s+/).filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !ip.startsWith("127."));
    for (const ip of ips) await this.#pinRoute(ip, up).catch(() => {});
    return ips;
  }

  async uplink(): Promise<WinWatch | null> {
    return parseWinWatch(await psOut(watchPs(this.#pinnedIps[0])).catch(() => ""));
  }

  async broken(now: WinWatch): Promise<boolean> {
    return winNeedsRepin(this.#orig!, now);
  }

  // DNS needs nothing here: the NRPT rule and the firewall rules aren't tied to an adapter.
  async repin({ up }: WinWatch): Promise<void> {
    const { priv } = this.#o;
    // Stale pins may survive (same adapter, old gateway); clear them so the adds below can't collide.
    for (const argv of this.#pinUndo.reverse()) await priv.run(argv, true);
    this.#pinUndo = [];
    await this.#pin(up);
    if (this.#directDns) await this.#pinResolvers(up);
    this.#orig = up;
    await priv.run(ps("Clear-DnsClientCache"), true); // drop failures cached while offline
  }

  label({ up }: WinWatch): string {
    return `${up.alias}${up.gw ? ` (${up.gw})` : ""}`;
  }

  /** Runs the DoH forwarder on 127.0.0.1:53 and sends every lookup there with an NRPT rule. */
  async #tunnelDns(): Promise<void> {
    const { priv, proxyHost, proxyPort } = this.#o;
    this.#dns = await startDnsForwarder({ socksHost: proxyHost, socksPort: proxyPort, dohHost: DOH_HOST, host: "127.0.0.1", port: 53, connections: 8 });
    try {
      await priv.run(ps(`Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -Comment '${TAG}'; Clear-DnsClientCache`));
      this.#undo.push(planStaleCleanup()[0]);
      // Prove the system resolver now answers through the tunnel; else fall back.
      await Promise.race([
        lookup(DOH_HOST, { family: 4 }),
        new Promise((_, rej) => setTimeout(() => rej(new Error("DNS check timed out")), 8000)),
      ]);
    } catch (err) {
      await priv.run(planStaleCleanup()[0], true);
      await this.#dns.close();
      this.#dns = null;
      throw err;
    }
  }

  /** Restores DNS, firewall and routing, stops tun2socks. Best-effort. */
  async stop(): Promise<void> {
    const { priv } = this.#o;
    for (const argv of [...this.#undo.reverse(), ...this.#pinUndo.reverse()]) await priv.run(argv, true);
    this.#undo = [];
    this.#pinUndo = [];
    await this.#dns?.close();
    this.#dns = null;
    // Stopping tun2socks removes the adapter (and any route still on it).
    await stopProcess(this.#t2s, async () => {});
    this.#t2s = null;
  }
}
