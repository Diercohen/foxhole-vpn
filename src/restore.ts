// `foxhole restore`'s other half: the proxy's port, held by a Foxhole still running (stuck, or another copy), freed.
// The network half is each system's own: planStaleCleanup (Linux), planMacRestore (macOS), restoreWindows.
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import net from "node:net";
import { promisify } from "node:util";

const exec = promisify(execFile);
const out = (cmd: string, args: string[]) =>
  exec(cmd, args, { windowsHide: true, maxBuffer: 8 << 20 }).then((r) => r.stdout, (e) => (e.stdout as string | undefined) ?? "");

export interface Holder {
  pid: number; // 0: the system won't say whose (another user's, as root's)
  cmd: string; // its command line, "" when unknown
}

/** The pids listening on TCP `port` in Windows' `netstat -ano -p TCP` (and TCPv6). Pure. */
export function parseWinListen(netstat: string, port: number): number[] {
  const pids = [...netstat.matchAll(/^\s*TCP\s+\S*:(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$/gm)].filter((m) => Number(m[1]) === port).map((m) => Number(m[2]));
  return [...new Set(pids)];
}

/** The pids in Linux `ss -ltnpH` lines, 0 for a line that names none (another user's). Pure. */
export function parseSsPids(ss: string): number[] {
  const lines = ss.split("\n").filter((l) => l.trim());
  return [...new Set(lines.flatMap((l) => {
    const pids = [...l.matchAll(/pid=(\d+)/g)].map((m) => Number(m[1]));
    return pids.length ? pids : [0];
  }))];
}

/** Who listens on TCP `port` here. */
export async function portHolders(port: number): Promise<Holder[]> {
  if (process.platform === "win32") {
    const pids = parseWinListen((await out("netstat", ["-ano", "-p", "TCP"])) + (await out("netstat", ["-ano", "-p", "TCPv6"])), port);
    if (!pids.length) return [];
    const ps = await out("powershell", ["-NoProfile", "-NonInteractive", "-Command",
      `Get-CimInstance Win32_Process -Filter "${pids.map((p) => `ProcessId=${p}`).join(" OR ")}" | ForEach-Object { "$($_.ProcessId)|$($_.CommandLine)" }`]);
    const cmds = new Map([...ps.matchAll(/^(\d+)\|(.*?)\r?$/gm)].map((m) => [Number(m[1]), m[2]]));
    return pids.map((pid) => ({ pid, cmd: cmds.get(pid) ?? "" }));
  }
  if (process.platform === "darwin") {
    const pids = [...(await out("lsof", ["-nP", "-w", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fp"])).matchAll(/^p(\d+)$/gm)].map((m) => Number(m[1]));
    return Promise.all([...new Set(pids)].map(async (pid) => ({ pid, cmd: (await out("ps", ["-o", "command=", "-p", String(pid)])).trim() })));
  }
  return parseSsPids(await out("ss", ["-ltnpH", `sport = :${port}`])).map((pid) => {
    let cmd = "";
    try {
      cmd = pid ? readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").join(" ").trim() : "";
    } catch {
      /* gone, or not ours to read */
    }
    return { pid, cmd };
  });
}

/** One of Foxhole's: the desktop app, or the TUI or CLI (node …/foxhole-vpn/dist/cli.js, the `foxhole` command). Pure. */
export const isFoxhole = (cmd: string): boolean => /foxhole/i.test(cmd);

/** True when something accepts connections on 127.0.0.1:port. */
export function answers(port: number): Promise<boolean> {
  return new Promise((done) => {
    const s = net.connect({ host: "127.0.0.1", port });
    s.setTimeout(1000, () => (s.destroy(), done(false)));
    s.once("connect", () => (s.destroy(), done(true)));
    s.once("error", () => done(false));
  });
}

/**
 * Frees `port`: each Foxhole holding it is asked to quit (it puts its own whole-system mode back first), and made to
 * after 20 s. Anything else holding it is left running, and said. Lines for the terminal, in `say`.
 */
export async function freePort(port: number, say: (line: string) => void): Promise<boolean> {
  const holders = (await portHolders(port)).filter((h) => h.pid !== process.pid);
  if (!holders.length) return say(`Port ${port} is free.`), true;
  let free = true;
  for (const h of holders) {
    if (!h.pid) {
      say(`Port ${port} is held by another user's program: run foxhole restore as root (sudo) to see whose.`);
      free = false;
    } else if (!isFoxhole(h.cmd)) {
      say(`Port ${port} is held by ${h.cmd || "a program"} (pid ${h.pid}), not a Foxhole: left running. Quit it, or pick another port in Settings.`);
      free = false;
    } else if (!(await stop(h.pid, port))) {
      say(`Couldn't stop the Foxhole on port ${port} (pid ${h.pid}): another user's? Run foxhole restore as root (sudo).`);
      free = false;
    } else say(`Stopped the Foxhole that held port ${port} (pid ${h.pid}).`);
  }
  return free;
}

/** SIGTERM (Windows: ends it at once), then SIGKILL after 20 s; true once it's gone. */
async function stop(pid: number, port: number): Promise<boolean> {
  const alive = () => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (err) {
      return (err as NodeJS.ErrnoException).code === "EPERM";
    }
  };
  try {
    process.kill(pid, "SIGTERM");
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ESRCH";
  }
  for (const end = Date.now() + 20_000; Date.now() < end; await new Promise((r) => setTimeout(r, 250))) {
    if (!alive()) return true;
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    /* gone meanwhile */
  }
  await new Promise((r) => setTimeout(r, 500));
  return !alive() || !(await answers(port));
}
