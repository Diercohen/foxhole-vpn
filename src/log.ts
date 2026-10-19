// In-app log for the TUI's Logs popup: proxy failures and tun2socks output.
// Always collected (not only with --verbose), kept in memory, last MAX lines.

const MAX = 1000;
export const logLines: string[] = [];
const listeners = new Set<() => void>();

/** Adds a timestamped line and tells listeners (the open Logs popup). */
export function log(msg: string): void {
  logLines.push(`${new Date().toTimeString().slice(0, 8)}  ${msg}`);
  if (logLines.length > MAX) logLines.splice(0, logLines.length - MAX);
  for (const f of listeners) f();
}

export const onLog = (f: () => void) => void listeners.add(f);

/** Logs each line a child prints, e.g. tun2socks' JSON ({"level","msg"}) as "tun2socks: [info] msg". */
export function logStream(name: string, stream: NodeJS.ReadableStream): void {
  let rest = "";
  stream.on("data", (d: Buffer) => {
    const lines = (rest + d.toString()).split("\n");
    rest = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const j = JSON.parse(line) as { level?: string; msg?: string };
        log(`${name}: ${j.level ? `[${j.level}] ` : ""}${j.msg ?? line}`);
      } catch {
        log(`${name}: ${line}`);
      }
    }
  });
}
