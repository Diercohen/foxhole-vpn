// Split tunneling by app on a computer: which app opened a connection to the proxy, from the system's own table of
// TCP connections and the processes holding them (macOS lsof + ps, Linux ss, Windows netstat + tasklist). In global
// mode the proxy's client is tun2socks, so the app is the one whose connection goes to the same address and port.
// Android does apps natively (its VPN leaves an app out or takes only some: FoxholeService); iOS can't tell apps apart.
import { execFile } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { promisify } from "node:util";
import net from "node:net";

const exec = promisify(execFile);

export interface TcpConn {
  local: string; // "ip:port", as addr() writes it
  remote: string;
  pid: number;
  app: string; // as appName() writes it; "" when the system won't say (another user's process)
  exe?: string; // its executable, where the table tells (macOS)
}

/** "ip:port" with brackets, an IPv4-mapped prefix and a zone gone, so every source writes an address the same way. Pure. */
export const addr = (ip: string, port: string | number): string =>
  `${ip.replace(/^\[|\]$/g, "").replace(/%.*$/, "").replace(/^::ffff:(?=\d+\.)/i, "").toLowerCase()}:${Number(port)}`;

/** An app's name from its executable: the outermost .app bundle on macOS ("Google Chrome" for its helpers too), else the file's name without .exe. Pure. */
export function appName(exe: string): string {
  return exe.match(/\/([^/]+)\.app\//)?.[1] ?? basename(exe.replace(/\\/g, "/")).replace(/\.exe$/i, "");
}

/**
 * macOS `lsof +c0 -nP -w -iTCP -sTCP:ESTABLISHED -Fpcn` with `ps -axo pid=,comm=` (each process's executable). Not
 * netstat: inside Electron (macOS 27) it lists no TCP connections at all. Pure.
 */
export function parseLsof(lsof: string, ps: string): TcpConn[] {
  const exes = new Map<number, string>();
  for (const m of ps.matchAll(/^\s*(\d+) (.+)$/gm)) exes.set(Number(m[1]), m[2]);
  const at = (a: string) => addr(a.slice(0, a.lastIndexOf(":")), a.slice(a.lastIndexOf(":") + 1)); // "1.2.3.4:443", "[::1]:443"
  const out: TcpConn[] = [];
  let pid = 0;
  let cmd = "";
  for (const line of lsof.split("\n")) {
    if (line[0] === "p") (pid = Number(line.slice(1))), (cmd = "");
    else if (line[0] === "c") cmd = line.slice(1);
    else if (line[0] === "n" && line.includes("->")) {
      const [local, remote] = line.slice(1).split("->");
      const exe = exes.get(pid);
      out.push({ local: at(local), remote: at(remote), pid, app: appName(exe ?? cmd), ...(exe ? { exe } : {}) });
    }
  }
  return out;
}

/** Linux `ss -tnpH`: the processes it names are this user's (or all, as root). Pure. */
export function parseSs(ss: string): TcpConn[] {
  const at = (a: string) => addr(a.slice(0, a.lastIndexOf(":")), a.slice(a.lastIndexOf(":") + 1));
  const out: TcpConn[] = [];
  for (const line of ss.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 5 || f[0] === "LISTEN") continue;
    const p = line.match(/users:\(\("((?:[^"\\]|\\.)*)",pid=(\d+)/);
    out.push({ local: at(f[3]), remote: at(f[4]), pid: p ? Number(p[2]) : 0, app: p ? p[1] : "" });
  }
  return out;
}

/** Windows `netstat -ano -p TCP` (and TCPv6) with `tasklist /fo csv /nh`. Pure. */
export function parseWin(netstat: string, tasklist: string): TcpConn[] {
  const names = new Map<number, string>();
  for (const m of tasklist.matchAll(/^"([^"]+)","(\d+)"/gm)) names.set(Number(m[2]), appName(m[1]));
  const at = (a: string) => addr(a.slice(0, a.lastIndexOf(":")), a.slice(a.lastIndexOf(":") + 1));
  const out: TcpConn[] = [];
  for (const m of netstat.matchAll(/^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$/gm)) {
    if (m[3] === "LISTENING") continue;
    const pid = Number(m[4]);
    out.push({ local: at(m[1]), remote: at(m[2]), pid, app: names.get(pid) ?? "" });
  }
  return out;
}

const run = async (cmd: string, args: string[]) => (await exec(cmd, args, { windowsHide: true, maxBuffer: 32 << 20 })).stdout;

async function readTable(): Promise<TcpConn[]> {
  if (process.platform === "darwin") {
    // lsof exits 1 when it finds nothing: that's an empty table, not an error
    const lsof = run("lsof", ["+c0", "-nP", "-w", "-iTCP", "-sTCP:ESTABLISHED", "-Fpcn"]).catch((e) => (e.code === 1 ? (e.stdout ?? "") : Promise.reject(e)));
    return parseLsof(...(await Promise.all([lsof, run("ps", ["-axo", "pid=,comm="])])));
  }
  if (process.platform === "win32") {
    const [v4, v6, tasks] = await Promise.all([run("netstat", ["-ano", "-p", "TCP"]), run("netstat", ["-ano", "-p", "TCPv6"]), run("tasklist", ["/fo", "csv", "/nh"])]);
    return parseWin(v4 + v6, tasks);
  }
  return parseSs(await run("ss", ["-tnpH"]));
}

// One read at a time, shared: a page opens many connections at once
let last: { at: number; table: Promise<TcpConn[]> } | null = null;
/** The table as read no earlier than `since` (ms). */
function table(since: number): Promise<TcpConn[]> {
  if (!last || last.at < since) last = { at: Date.now(), table: readTable().catch(() => []) };
  return last.table;
}

/** foxhole's own connections, and tun2socks' (global mode's, handing apps' connections to the proxy): no app of the user's. */
const SELF = appName(process.execPath); // "Foxhole" in the desktop app: its macOS DNS relay too
const ours = (c: TcpConn) => !c.app || c.pid === process.pid || c.app === SELF || /^tun2socks/i.test(c.app);
const LOOPBACK = /^(127\.|::1$|::ffff:127\.)/;

/**
 * The app behind a proxy client `peer` (its socket) going to `target`, or undefined: another device's, or not found.
 * A client on this computer is the app itself, unless it's tun2socks: then the app connected to `target` (an address).
 */
export async function appFor(peer: Pick<net.Socket, "remoteAddress" | "remotePort" | "localAddress" | "localPort">, target: { host: string; port: number }): Promise<string | undefined> {
  if (!peer.remoteAddress || !LOOPBACK.test(peer.remoteAddress) || !peer.localAddress) return undefined;
  const me = addr(peer.remoteAddress, peer.remotePort ?? 0);
  const proxy = addr(peer.localAddress, peer.localPort ?? 0);
  const to = net.isIP(target.host) ? addr(target.host, target.port) : null;
  const t0 = Date.now();
  // a table read lately, then (not found: the connection is newer) one read since it came
  for (const since of [t0 - 500, t0]) {
    const conns = await table(since);
    const client = conns.find((c) => c.local === me && c.remote === proxy);
    if (client && !ours(client)) return client.app;
    // ponytail: two apps on the same address and port at once can't be told apart; the first one found wins
    const app = to && conns.find((c) => c.remote === to && !ours(c))?.app;
    if (app) return app;
  }
  return undefined;
}

export interface AppInfo {
  name: string;
  icon?: string; // where its icon is: an .app bundle (macOS) or .exe (Windows), for the desktop app to draw; an image (Linux)
}

const ls = (dir: string) => {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
};

/** Apps to pick from: those online now, and on macOS the installed ones. Sorted, without foxhole's own. */
export async function listApps(): Promise<AppInfo[]> {
  const conns = (await table(Date.now() - 2000)).filter((c) => !ours(c));
  const apps = new Map<string, AppInfo>();
  const add = (name: string, icon?: string) => void ((!apps.has(name) || (icon && !apps.get(name)!.icon)) && apps.set(name, icon ? { name, icon } : { name }));
  if (process.platform === "darwin") {
    for (const c of conns) add(c.app, c.exe?.match(/^(.+?\.app)\//)?.[1] ?? c.exe);
    for (const dir of ["/Applications", "/System/Applications", `${homedir()}/Applications`]) {
      for (const f of ls(dir)) if (f.endsWith(".app")) add(f.slice(0, -4), join(dir, f));
    }
  } else if (process.platform === "win32") {
    const exes = await winExes().catch(() => new Map<number, string>());
    for (const c of conns) add(c.app, exes.get(c.pid));
  } else {
    const icons = linuxIcons();
    for (const c of conns) add(c.app, icons.get(c.app));
  }
  return [...apps.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** Windows: each process's executable (tasklist doesn't say), for its icon. */
async function winExes(): Promise<Map<number, string>> {
  const out = await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", "Get-Process | Where-Object Path | ForEach-Object { \"$($_.Id)|$($_.Path)\" }"]);
  return new Map([...out.matchAll(/^(\d+)\|(.+?)\r?$/gm)].map((m) => [Number(m[1]), m[2]]));
}

/**
 * The icon an app's .desktop file names, by the name ss gives its process (the program's, cut to 15 characters), out
 * of `desktop` (a launcher file's text). Pure.
 */
export function desktopIcon(desktop: string): { proc: string; icon: string } | null {
  const exec = desktop.match(/^Exec=(?:env(?: \S+=\S+)+ )?"?([^\s"]+)/m)?.[1];
  const icon = desktop.match(/^Icon=(.+)$/m)?.[1].trim();
  const proc = exec && basename(exec).slice(0, 15);
  return proc && icon && proc !== "flatpak" ? { proc, icon } : null; // a Flatpak's process isn't named in its launcher
}

/** Linux: process name → icon file, from the launchers' .desktop files and the icon theme. */
function linuxIcons(): Map<string, string> {
  const shares = ["/usr/share", "/usr/local/share", `${homedir()}/.local/share`, "/var/lib/flatpak/exports/share", `${homedir()}/.local/share/flatpak/exports/share`];
  const find = (icon: string) => {
    if (icon.startsWith("/")) return /\.(png|svg)$/.test(icon) && existsSync(icon) ? icon : undefined;
    for (const share of shares) {
      for (const size of ["48x48", "64x64", "32x32", "128x128", "256x256", "scalable"]) {
        for (const ext of ["png", "svg"]) {
          const f = join(share, "icons/hicolor", size, "apps", `${icon}.${ext}`);
          if (existsSync(f)) return f;
        }
      }
      for (const ext of ["png", "svg"]) if (existsSync(join(share, "pixmaps", `${icon}.${ext}`))) return join(share, "pixmaps", `${icon}.${ext}`);
    }
    return undefined;
  };
  const icons = new Map<string, string>();
  for (const dir of [...shares.map((s) => join(s, "applications")), "/var/lib/snapd/desktop/applications"]) {
    for (const f of ls(dir)) {
      if (!f.endsWith(".desktop")) continue;
      let d: ReturnType<typeof desktopIcon> = null;
      try {
        d = desktopIcon(readFileSync(join(dir, f), "utf8"));
      } catch {
        /* unreadable */
      }
      const file = d && !icons.has(d.proc) ? find(d.icon) : undefined;
      if (d && file) icons.set(d.proc, file);
    }
  }
  return icons;
}
