// Telegram for a device on Smart DNS. Telegram's apps have its servers' addresses built in and ask DNS nothing, and Iran
// blocks those addresses, so no DNS answer can help. Instead the device has this computer as its router: what it sends to
// Telegram's addresses goes into a tun (tun2socks, this computer's proxy, the VPN), and the rest goes on to the real
// router, so its other traffic stays direct. Smart DNS stays its DNS. macOS's for now: it isn't proven on a phone yet.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { TELEGRAM_CIDRS, stopProcess, type Priv } from "./global.js";
import { TUN_ADDR, UTUN, waitFor } from "./global-darwin.js";

const exec = promisify(execFile);
const FORWARDING = "net.inet.ip.forwarding";
const tunUp = () => exec("ifconfig", [UTUN]);

/**
 * Starts the router: tun2socks to the proxy on `proxyPort`, Telegram's addresses into it, and IP forwarding on. Resolves
 * to what stops it again. `onExit`: tun2socks stopped by itself. Call only with this computer's port 53 held by Smart DNS:
 * then no whole-system session, which has the same tun, is running.
 * ponytail: a killed Foxhole leaves forwarding on till the next reboot (the tun and its routes are `foxhole restore`'s and
 * the next start's); clearing it could cut off Internet Sharing, which needs it too.
 */
export async function startGateway(o: { priv: Priv; tun2socksPath: string; proxyPort: number; onExit: (code: number | null) => void }): Promise<() => Promise<void>> {
  const { priv } = o;
  const pkill = () => priv.run(["pkill", "-f", `${UTUN.slice(0, -1)}[${UTUN.slice(-1)}]`], true); // the [3] keeps pkill off its own command line
  if (await tunUp().then(() => true, () => false)) {
    await pkill(); // a killed Foxhole's: its routes go with it
    await waitFor("the old tun to go", () => tunUp().then(() => Promise.reject(new Error("still there")), () => {}));
  }
  const wasOn = (await exec("sysctl", ["-n", FORWARDING])).stdout.trim() === "1"; // Internet Sharing has it on too: left as it was
  const t2s = priv.spawn([o.tun2socksPath, "--device", UTUN, "--proxy", `socks5://127.0.0.1:${o.proxyPort}`]);
  t2s.on("exit", o.onExit);
  const stop = async () => {
    for (const cidr of TELEGRAM_CIDRS) await priv.run(["route", "-n", "delete", "-net", cidr], true);
    if (!wasOn) await priv.run(["sysctl", "-w", `${FORWARDING}=0`], true);
    await stopProcess(t2s, pkill);
  };
  try {
    await waitFor(`${UTUN} to appear`, tunUp);
    await priv.run(["ifconfig", UTUN, TUN_ADDR, TUN_ADDR, "up"]);
    for (const cidr of TELEGRAM_CIDRS) await priv.run(["route", "-n", "add", "-net", cidr, TUN_ADDR]);
    if (!wasOn) await priv.run(["sysctl", "-w", `${FORWARDING}=1`]);
  } catch (err) {
    await stop();
    throw err;
  }
  return stop;
}
