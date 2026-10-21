// What the TUI shows about the user's network: Wi-Fi (and its name) or wired, and
// the public IP (the VPN exit's when connected). Read-only, no root.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import http from "node:http";
import { networkInterfaces } from "node:os";

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

const run = (cmd: string, args: string[]) =>
  exec(cmd, args, { timeout: 3000, windowsHide: true }).then((r) => r.stdout, () => "");

// JXA: the SSID in the scan record macOS caches in its SystemConfiguration store,
// which, unlike `ipconfig`, it doesn't redact. argv[0] is the Wi-Fi device.
const SCAN_RECORD_SSID = `function run(argv) {
  ObjC.import("SystemConfiguration");
  const st = ObjC.castRefToObject($.SCDynamicStoreCopyValue(null, $("State:/Network/Interface/" + argv[0] + "/AirPort")));
  return $.NSKeyedUnarchiver.unarchiveObjectWithData(st.objectForKey("CachedScanRecord")).objectForKey("SSID_STR").js;
}`;

/** The connected Wi-Fi's name, or null (wired, offline, or unknown). */
export async function wifiName(): Promise<string | null> {
  if (process.platform === "win32") return parseSsid(await run("netsh", ["wlan", "show", "interfaces"]));
  if (process.platform === "darwin") {
    const ports = await run("networksetup", ["-listallhardwareports"]);
    const dev = ports.match(/Hardware Port: Wi-Fi\s*\nDevice:\s*(\S+)/)?.[1] ?? "en0";
    const summary = await run("ipconfig", ["getsummary", dev]);
    const ssid = parseSsid(summary) ?? parseSsid(await run("networksetup", ["-getairportnetwork", dev]));
    if (ssid || !/^\s*SSID\s*:\s*<redacted>/m.test(summary)) return ssid;
    // macOS 15+ redacts the name for apps without location access; the scan record still has it.
    return (await run("osascript", ["-l", "JavaScript", "-e", SCAN_RECORD_SSID, dev])).trim() || "name hidden by macOS";
  }
  for (const dev of parseIwDev(await run("iw", ["dev"]))) {
    const ssid = parseSsid(await run("iw", ["dev", dev, "link"]));
    if (ssid) return ssid;
  }
  return null;
}

/** This computer's interface on the local network, skipping VPN, container and loopback interfaces. */
function lanInterface(ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): { name: string; address: string } | null {
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (/^(lo|docker|br-|veth|virbr|tun|tap|wg|utun|ppp|tailscale|zt|foxhole|vEthernet|Loopback)/i.test(name)) continue;
    const a = addrs?.find((x) => x.family === "IPv4" && !x.internal && !x.address.startsWith("169.254."));
    if (a) return { name, address: a.address };
  }
  return null;
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

const IP_HOST = "api.ipify.org";
const isIp = (s: string) => /^[0-9a-f.:]+$/i.test(s) && s.length <= 45;

/**
 * The public IP the internet sees. With `proxy`, asks through foxhole's own HTTP
 * proxy, so it's the VPN exit's; without, it's whatever the system routes (global
 * mode tunnels that too). Tries `tries` times, 1.5s apart: the first check often
 * races a tunnel that's still coming up. Null if unreachable.
 */
export async function publicIp(proxy?: { host: string; port: number }, tries = 3): Promise<string | null> {
  for (let i = 1; ; i++) {
    const ip = await publicIpOnce(proxy);
    if (ip || i >= tries) return ip;
    await new Promise((r) => setTimeout(r, 1500));
  }
}

async function publicIpOnce(proxy?: { host: string; port: number }): Promise<string | null> {
  try {
    if (!proxy) {
      const text = (await (await fetch(`https://${IP_HOST}`, { signal: AbortSignal.timeout(8000) })).text()).trim();
      return isIp(text) ? text : null;
    }
    // Plain-HTTP GET in absolute form: the proxy forwards it through the tunnel.
    const text = await new Promise<string>((resolve, reject) => {
      const req = http.get(
        { host: proxy.host, port: proxy.port, path: `http://${IP_HOST}/`, headers: { Host: IP_HOST }, timeout: 8000 },
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
    return isIp(text) ? text : null;
  } catch {
    return null;
  }
}
