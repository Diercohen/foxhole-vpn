// The installed version, whether npm has a newer one, and updating to it.
import { spawnSync } from "node:child_process";
import { accessSync, constants, readFileSync } from "node:fs";
import { cyan, dim, under, yellow } from "./ui.js";

export const VERSION: string = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;
let latest: string | null = null; // newer version on npm, once known
let upToDate = false; // npm answered, and has nothing newer
let check: Promise<void> | undefined;

// numeric x.y.z compare; parseInt drops a prerelease suffix ("0-beta" → 0)
export function newer(a: string, b: string): boolean {
  const x = a.split(".").map((n) => parseInt(n));
  const y = b.split(".").map((n) => parseInt(n));
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
  return false;
}

/** Asks npm once; later calls share that request. Best effort: offline or registry down just means no notice. */
export function checkUpdate(): Promise<void> {
  check ??= fetch("https://registry.npmjs.org/foxhole-vpn/latest", { signal: AbortSignal.timeout(3000) })
    .then((r) => r.json() as Promise<{ version?: string }>)
    .then(({ version }) => {
      if (version && newer(version, VERSION)) latest = version;
      else upToDate = Boolean(version);
    })
    .catch(() => {});
  return check;
}

// run through npx: nothing is installed to update, the next npx foxhole-vpn@latest fetches it
export const viaNpx = () => process.env.npm_command === "exec";
// npm replaces the folder this package sits in; a root-owned global folder (system Node) needs sudo for that
const sudo = (() => {
  if (process.platform === "win32") return false; // npm's global folder is per-user; there's no sudo
  try {
    accessSync(new URL("../..", import.meta.url), constants.W_OK);
    return false;
  } catch {
    return true;
  }
})();
const INSTALL = "npm install -g foxhole-vpn@latest";
export const UPDATE_COMMAND = (sudo ? "sudo " : "") + INSTALL;
// npm is Node too: through a slow tunnel its downloads time out like fetch would without these
const NODE_FIX = "--no-network-family-autoselection --dns-result-order=ipv4first";

/** A newer version is out, and npm can install it (under npx there's nothing installed to update). */
export const canUpdate = () => latest !== null && !viaNpx();

/** Runs the update in this terminal (sudo asks for the password here); returns npm's exit status. */
export function runUpdate(): number {
  console.log(cyan(UPDATE_COMMAND));
  const NODE_OPTIONS = `${process.env.NODE_OPTIONS ?? ""} ${NODE_FIX}`.trim();
  // sudo clears the environment, so env sets NODE_OPTIONS on its side
  return (
    spawnSync(sudo ? `sudo env NODE_OPTIONS="${NODE_FIX}" ${INSTALL}` : INSTALL, {
      shell: true,
      stdio: "inherit",
      env: { ...process.env, NODE_OPTIONS },
    }).status ?? 1
  );
}

/** "update available: …" and how to get it, once checkUpdate() found a newer version; onKey: a TUI screen that updates on 'u'. */
export function updateNotice(onKey = false): string[] | null {
  if (!latest) return null;
  return [
    `update available: ${VERSION} → ${latest}`,
    viaNpx()
      ? "quit, then run: npx foxhole-vpn@latest"
      : onKey
        ? `press ${under("u")} to update and restart · runs ${UPDATE_COMMAND}`
        : `run: ${UPDATE_COMMAND}, then restart`,
  ];
}

/** Version line(s): the update notice in yellow, or the installed version in grey. */
export const versionLines = (onKey = false): string[] =>
  updateNotice(onKey)?.map(yellow) ?? [dim(`foxhole-vpn ${VERSION}${upToDate ? " · latest" : ""}`)];
