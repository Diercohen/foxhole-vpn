// What the TUI shows about the user's network: Wi-Fi (and its name) or wired, and
// the public IP (the VPN exit's when connected). Read-only, no root.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import http from "node:http";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const exec = promisify(execFile);

/** Wireless interfaces in `iw dev`. Pure. */
export function parseIwDev(out: string): string[] {
  return [...out.matchAll(/^\s*Interface\s+(\S+)/gm)].map((m) => m[1]);
}

/** SSID from `iw dev <if> link`, `netsh wlan show interfaces`, or macOS's `ipconfig getsummary` / `networksetup -getairportnetwork`. Pure. */
export function parseSsid(out: string): string | null {
  const m = out.match(/^\s*(?:SSID\s*:|Current Wi-Fi Network:)\s*(.+?)\s*$/m);
  if (!m || m[1] === "<redacted>") return null; // newer macOS hides it without location access
  return m[1];
}

/** The in-use network's name in `nmcli -t -f IN-USE,SSID device wifi list` (terse mode escapes ":" and "\"). Pure. */
export function parseNmcliWifi(out: string): string | null {
  const m = out.match(/^\*:(.+)$/m);
  return m ? m[1].replace(/\\([:\\])/g, "$1") : null;
}

/** iw prints a name's non-ASCII bytes (and backslashes, edge spaces) as \xNN: back to UTF-8 text, e.g. a Persian name. Pure. */
export const unescapeIw = (s: string): string =>
  Buffer.from(s.replace(/\\x([0-9a-f]{2})/gi, (_, h: string) => String.fromCharCode(parseInt(h, 16))), "latin1").toString("utf8");

// a command's output, failed or not (netsh exits 1 where it won't tell the Wi-Fi's name)
const run = (cmd: string, args: string[], env?: Record<string, string>) =>
  exec(cmd, args, { timeout: 3000, windowsHide: true, ...(env && { env: { ...process.env, ...env } }) }).then(
    (r) => r.stdout,
    (e: { stdout?: string }) => e.stdout ?? "",
  );

/**
 * What stands for the Wi-Fi's name where the system shows it only to apps allowed Location (macOS 14.4+, Windows 11
 * 24H2+, Android: the name can tell where you are). The window offers to ask (wifiAccess), in so many words first.
 */
export const WIFI_HIDDEN = "name hidden";

/** Windows hides the name from apps without Location, and netsh says so, with its Settings page's address. Pure. */
export const windowsHidesWifi = (out: string): boolean => !parseSsid(out) && out.includes("ms-settings:privacy-location");

// JXA, argv[0] the Wi-Fi device: the scan record macOS 15 caches in its SystemConfiguration store, unredacted (empty
// in macOS 27)
const SCAN_RECORD_SSID = `function run(argv) {
  ObjC.import("SystemConfiguration");
  try {
    const st = ObjC.castRefToObject($.SCDynamicStoreCopyValue(null, $("State:/Network/Interface/" + argv[0] + "/AirPort")));
    return $.NSKeyedUnarchiver.unarchiveObjectWithData(st.objectForKey("CachedScanRecord")).objectForKey("SSID_STR").js;
  } catch {
    return "";
  }
}`;

// macOS: Foxhole.app's own little app (gui/build/wifi.m) that reads the name, asking for Location as "Foxhole". It's
// started by `open`: macOS asks about and allows what LaunchServices starts, not a program another one runs. The
// terminal app and `electron .` have none of their own, so they use the installed Foxhole's.
const OWN_MAC_HELPER = resolve(process.execPath, "../../Helpers/Foxhole Wi-Fi.app");
const MAC_HELPER = existsSync(OWN_MAC_HELPER) ? OWN_MAC_HELPER : "/Applications/Foxhole.app/Contents/Helpers/Foxhole Wi-Fi.app";

/** The helper's answer: allowed / denied / unasked, and the Wi-Fi's name. `ask`: asks first, if it's not been asked. */
async function macHelper(ask: boolean): Promise<[string, string]> {
  const out = join(tmpdir(), `foxhole-wifi-${process.pid}-${Date.now()}`);
  await exec("open", ["-g", "-j", "-n", "-W", "--stdout", out, MAC_HELPER, ...(ask ? ["--args", "ask"] : [])], { timeout: ask ? 130_000 : 5000 }).catch(() => {});
  try {
    const [how = "", name = ""] = readFileSync(out, "utf8").split("\n");
    return [how, name.trim()];
  } catch {
    return ["", ""];
  } finally {
    rmSync(out, { force: true });
  }
}

/**
 * Asks to be shown the Wi-Fi's name (the user chose to, having been told why): "allowed", "denied", or "settings"
 * where it's turned on in the system's Settings (Windows has no question per desktop app; macOS asks only once).
 */
export async function wifiAccess(): Promise<"allowed" | "denied" | "settings"> {
  if (process.platform !== "darwin" || !existsSync(MAC_HELPER)) return "settings";
  const [how] = await macHelper(true);
  return how === "allowed" ? "allowed" : how === "denied" ? "settings" : "denied";
}

/** The connected Wi-Fi's name, or null (wired, offline, or unknown). */
export async function wifiName(): Promise<string | null> {
  if (process.platform === "win32") {
    const out = await run("netsh", ["wlan", "show", "interfaces"]);
    return parseSsid(out) ?? (windowsHidesWifi(out) ? WIFI_HIDDEN : null);
  }
  if (process.platform === "darwin") {
    const ports = await run("networksetup", ["-listallhardwareports"]);
    const dev = ports.match(/Hardware Port: Wi-Fi\s*\nDevice:\s*(\S+)/)?.[1] ?? "en0";
    const summary = await run("ipconfig", ["getsummary", dev]);
    const ssid = parseSsid(summary) ?? parseSsid(await run("networksetup", ["-getairportnetwork", dev]));
    if (ssid || !/^\s*SSID\s*:\s*<redacted>/m.test(summary)) return ssid;
    // redacted for apps not allowed Location: the helper's, else (Foxhole.app isn't installed) macOS 15's scan record
    if (existsSync(MAC_HELPER)) return (await macHelper(false))[1] || WIFI_HIDDEN;
    return (await run("osascript", ["-l", "JavaScript", "-e", SCAN_RECORD_SSID, dev])).trim() || WIFI_HIDDEN;
  }
  // NetworkManager first (Ubuntu, Fedora, Mint…): always there, and it gives the name in UTF-8,
  // where iw isn't always installed. Cached results only: no Wi-Fi scan on each check.
  const nm = await run("nmcli", ["-t", "-f", "IN-USE,SSID", "device", "wifi", "list", "--rescan", "no"], { LC_ALL: "C.UTF-8" });
  const name = parseNmcliWifi(nm);
  if (name) return name;
  for (const dev of parseIwDev(await run("iw", ["dev"]))) {
    const ssid = parseSsid(await run("iw", ["dev", dev, "link"]));
    if (ssid) return unescapeIw(ssid);
  }
  return null;
}

/**
 * What lets other devices reach `port` through the firewall, given which one is on: firewalld
 * (on by default on Fedora; most spins and Server use zones that close the proxy's port) or
 * ufw (off by default on Ubuntu, `ufwConf` is /etc/ufw/ufw.conf). Pure.
 */
export function firewallCommands(firewalld: boolean, ufwConf: string | null, port: number): string[] | null {
  if (firewalld) return [`sudo firewall-cmd --permanent --add-port=${port}/tcp`, "sudo firewall-cmd --reload"];
  if (ufwConf && /^\s*ENABLED\s*=\s*yes/m.test(ufwConf)) return [`sudo ufw allow ${port}/tcp`];
  return null;
}

/** firewallCommands for this computer (Linux only; reading needs no root). */
export async function firewallHint(port: number): Promise<string[] | null> {
  if (process.platform !== "linux") return null;
  const firewalld = (await run("systemctl", ["is-active", "firewalld"])).trim() === "active";
  let ufw: string | null = null;
  try {
    ufw = readFileSync("/etc/ufw/ufw.conf", "utf8");
  } catch {
    /* no ufw */
  }
  return firewallCommands(firewalld, ufw, port);
}

/**
 * This computer's interface on the local network, skipping VPN, container and loopback interfaces, and a phone's mobile
 * data (Qualcomm's rmnet, MediaTek's ccmni, …): on a phone sharing its hotspot, the hotspot's is the one others reach.
 */
function lanInterface(ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): { name: string; address: string } | null {
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (/^(lo|docker|br-|veth|virbr|tun|tap|wg|utun|ppp|tailscale|zt|foxhole|vEthernet|Loopback|(r_)?rmnet|ccmni|seth_|pdp|wwan|v4-|clat)/i.test(name)) continue;
    const a = addrs?.find((x) => x.family === "IPv4" && !x.internal && !x.address.startsWith("169.254."));
    if (a) return { name, address: a.address };
  }
  return null;
}

/** The IPv4 address of the interface named `dev` (as the routing table names it), or null. */
export function ipv4Of(dev: string, ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): string | null {
  return ifaces[dev]?.find((a) => a.family === "IPv4" && !a.internal)?.address ?? null;
}

/** This computer's address on the local network (for other devices to reach the proxy). */
export function lanIp(ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): string | null {
  return lanInterface(ifaces)?.address ?? null;
}

/** What this computer is online through, for the TUI. */
export async function network(): Promise<string | null> {
  return describeNetwork(await wifiName(), lanInterface()?.name);
}

/** "Wi-Fi · <name>", "Wi-Fi", "Ethernet (wired)", or null when offline, from the Wi-Fi name and the LAN interface's. Pure. */
export function describeNetwork(wifi: string | null, iface: string | undefined): string | null {
  if (wifi) return `Wi-Fi · ${wifi}`;
  if (!iface) return null;
  // Not every Wi-Fi name is readable (Windows wants location access, Linux `iw`): go by the interface.
  return /^wl|wi-?fi|wireless/i.test(iface) ? "Wi-Fi" : "Ethernet (wired)";
}

export const IP_HOST = "api.ipify.org";
// Relay mode asks Cloudflare instead: Google's fetches pass the user's own IP on in X-Forwarded-For, which ipify
// reports; Cloudflare's trace reports the address that connected (Google's), which is what most sites go by.
export const TRACE_HOST = "www.cloudflare.com";
const isIp = (s: string) => /^[0-9a-f.:]+$/i.test(s) && s.length <= 45;
/** The IP in an answer from ipify (just the IP), or from Cloudflare's trace (`trace`: an ip= line). Pure. */
export const ipIn = (text: string, trace: boolean): string | null => {
  const ip = (trace ? (text.match(/^ip=(.+)$/m)?.[1] ?? "") : text).trim();
  return isIp(ip) ? ip : null;
};

/**
 * The public IP the internet sees. With `proxy`, asks through foxhole's own HTTP
 * proxy, so it's the VPN exit's; without, it's whatever the system routes (global
 * mode tunnels that too). Tries `tries` times, 1.5s apart: the first check often
 * races a tunnel that's still coming up. Null if unreachable. `plain`: relay mode (over plain HTTP, from TRACE_HOST).
 */
export async function publicIp(proxy?: { host: string; port: number }, tries = 3, plain = false): Promise<string | null> {
  for (let i = 1; ; i++) {
    const ip = await publicIpOnce(proxy, plain);
    if (ip || i >= tries) return ip;
    await new Promise((r) => setTimeout(r, 1500));
  }
}

async function publicIpOnce(proxy?: { host: string; port: number }, plain = false): Promise<string | null> {
  try {
    const [host, path] = plain ? [TRACE_HOST, "/cdn-cgi/trace"] : [IP_HOST, "/"];
    if (!proxy) {
      // plain: relay mode in global mode, where HTTPS would end at relay mode's certificate, which Node doesn't trust
      const text = await (await fetch(`${plain ? "http" : "https"}://${host}${path}`, { signal: AbortSignal.timeout(8000) })).text();
      return ipIn(text, plain);
    }
    // Plain-HTTP GET in absolute form: the proxy forwards it through the tunnel.
    const text = await new Promise<string>((resolve, reject) => {
      const req = http.get(
        { host: proxy.host, port: proxy.port, path: `http://${host}${path}`, headers: { Host: host }, timeout: 8000 },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (d: string) => (body += d));
          res.on("end", () => (res.statusCode === 200 ? resolve(body.trim()) : reject(new Error(`HTTP ${res.statusCode}`))));
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new Error("timed out"))).on("error", reject);
    });
    return ipIn(text, plain);
  } catch {
    return null;
  }
}
