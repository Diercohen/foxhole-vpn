// macOS global mode's DNS relay (it runs as root), and the routes that take split tunneling's direct
// sites around the tunnel. macOS refuses a connection out the uplink while our utun's routes cover
// its destination, so the relay routes a direct site's addresses out the uplink as it looks them up,
// before the app connects. An address a VPN site also uses stays in the tunnel: a shared CDN
// address must not carry VPN traffic around it.
import { execFile } from "node:child_process";
import net from "node:net";
import { startDnsForwarder, type DnsForwarderOptions } from "./dns.js";
import { useSplit, viaOf, type Split } from "./split.js";
import { OWN_HOSTS } from "./proxy.js";

// Private, loopback, link-local and CGNAT addresses: the LAN's routes already take them
const LOCAL = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;

export interface DirectRoutes {
  /** A lookup's answer, before it's returned: route its addresses as its site goes. */
  answer(name: string, ips: string[]): Promise<void>;
  /** The rules changed: take addresses back into the tunnel that no longer go direct. */
  recheck(): Promise<void>;
  /** The uplink moved: the routes go its new way (`via`: a gateway, or "-interface", a device). */
  move(via: string[]): Promise<void>;
  /** Removes every route added. */
  clear(): Promise<void>;
}

/** Host routes out the uplink for direct sites' addresses; `run` runs a `route` command, true if it worked. */
export function directRoutes(via: string[], run: (argv: string[]) => Promise<boolean>): DirectRoutes {
  const names = new Map<string, Set<string>>(); // every site an address was looked up for
  const routed = new Set<string>(); // addresses taken around the tunnel
  const direct = (name: string) => !OWN_HOSTS.has(name) && viaOf(name) === "direct";
  const allDirect = (ip: string) => [...names.get(ip)!].every(direct);
  const unroute = async (ip: string) => void (routed.delete(ip) && (await run(["route", "-n", "delete", "-host", ip])));
  return {
    async answer(name, ips) {
      for (const ip of ips) {
        if (!net.isIPv4(ip) || LOCAL.test(ip)) continue;
        if (!names.has(ip) && names.size >= 50_000) for (const old of names.keys()) if (!routed.has(old)) names.delete(old); // a long session's
        names.set(ip, (names.get(ip) ?? new Set()).add(name));
        if (!allDirect(ip)) await unroute(ip);
        else if (!routed.has(ip) && (await run(["route", "-n", "add", "-host", ip, ...via]))) routed.add(ip);
      }
    },
    async recheck() {
      for (const ip of [...routed]) if (!allDirect(ip)) await unroute(ip);
    },
    async move(next) {
      via = next;
      for (const ip of routed) await run(["route", "-n", "change", "-host", ip, ...via]);
    },
    async clear() {
      await Promise.all([...routed].map(unroute));
    },
  };
}

/**
 * The relay process: the DoH forwarder, plus direct routes as above. foxhole sends it new rules
 * ("rules <json>") and a moved uplink ("via <json>") on stdin; when stdin ends (foxhole stopped
 * global mode, or is gone) it removes its routes and exits.
 */
export async function relayMain(o: { dns: DnsForwarderOptions; split: Split; via: string[] }): Promise<void> {
  let split = o.split;
  useSplit(() => split);
  const run = (argv: string[]) => new Promise<boolean>((r) => execFile(argv[0], argv.slice(1), { timeout: 5000 }, (err) => r(!err)));
  const routes = directRoutes(o.via, run);
  const quit = () => void routes.clear().finally(() => process.exit(0));
  let rest = "";
  process.stdin.on("data", (d: Buffer) => {
    const lines = (rest + d.toString()).split("\n");
    rest = lines.pop() ?? "";
    for (const line of lines) {
      const [cmd, json] = [line.slice(0, line.indexOf(" ")), line.slice(line.indexOf(" ") + 1)];
      if (cmd === "rules") {
        split = JSON.parse(json) as Split;
        // then let lookups happen again, so newly direct sites get their routes
        void routes.recheck().then(() => run(["killall", "-HUP", "mDNSResponder"]));
      } else if (cmd === "via") void routes.move(JSON.parse(json) as string[]);
    }
  });
  process.stdin.on("end", quit);
  process.on("SIGTERM", quit);
  await startDnsForwarder({ ...o.dns, onAnswer: (name, ips) => routes.answer(name, ips) });
}
