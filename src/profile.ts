import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";

// When run under sudo, look in the invoking user's home, not root's.
export function userHome(): string {
  if (process.env.SUDO_USER && (process.env.HOME === "/root" || process.getuid?.() === 0)) {
    return join(process.platform === "darwin" ? "/Users" : "/home", process.env.SUDO_USER);
  }
  return homedir();
}

// Firefox stores its profiles under one of these roots depending on the build.
function profileRoots(): string[] {
  const home = userHome();
  return [
    join(home, ".mozilla", "firefox"),
    join(home, "snap", "firefox", "common", ".mozilla", "firefox"), // Ubuntu's own Firefox (a snap)
    join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"), // Flatpak
    join(home, ".config", "mozilla", "firefox"), // some Linux/Omarchy builds
    join(home, "Library", "Application Support", "Firefox"), // macOS
    join(process.env.APPDATA ?? join(home, "AppData", "Roaming"), "Mozilla", "Firefox"), // Windows
  ].filter(existsSync);
}

/** Reads a flat INI into { section: { key: value } }. */
function parseIni(text: string): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  let section = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1);
      out[section] = {};
    } else if (section) {
      const eq = line.indexOf("=");
      if (eq > 0) out[section][line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
    }
  }
  return out;
}

/** Candidate profile directories, the active install's default first. */
function candidateProfiles(root: string): string[] {
  const dirs: string[] = [];
  const iniPath = join(root, "profiles.ini");
  if (existsSync(iniPath)) {
    const ini = parseIni(readFileSync(iniPath, "utf8"));
    // Install sections point at the profile Firefox actually launches.
    for (const [name, sec] of Object.entries(ini)) {
      if (name.startsWith("Install") && sec.Default) dirs.push(join(root, sec.Default));
    }
    // Then any profile marked default, then all profiles.
    for (const [name, sec] of Object.entries(ini)) {
      if (name.startsWith("Profile") && sec.Path) {
        const p = sec.IsRelative === "0" ? sec.Path : join(root, sec.Path);
        if (sec.Default === "1") dirs.unshift(p);
        else dirs.push(p);
      }
    }
  }
  // Last resort: scan for *.default* directories.
  try {
    for (const entry of readdirSync(root)) {
      if (/\.default/i.test(entry)) dirs.push(join(root, entry));
    }
  } catch {
    /* ignore */
  }
  return [...new Set(dirs)];
}

export interface AccountState {
  profileDir: string;
  signedIn: boolean;
  verified: boolean;
  email: string | null;
}

/**
 * Finds the Firefox profile most likely in use and reports its Firefox Account
 * sign-in state. Does NOT return or log the session token.
 */
export function findAccount(): AccountState | null {
  // Every install's profiles, the most recently used first (Firefox writes prefs.js as it runs):
  // Ubuntu can have a stale ~/.mozilla beside the snap's live one, or the other way round.
  const used = (dir: string) => {
    try {
      return statSync(join(dir, "prefs.js")).mtimeMs;
    } catch {
      return 0;
    }
  };
  const dirs = profileRoots().flatMap(candidateProfiles).sort((a, b) => used(b) - used(a)); // stable: ties keep each install's order
  for (const dir of dirs) {
    const f = join(dir, "signedInUser.json");
    if (!existsSync(f)) continue;
    try {
      // Firefox writes `null` here on sign-out
      const data = JSON.parse(readFileSync(f, "utf8")) as {
        accountData?: { email?: string; verified?: boolean; sessionToken?: string };
      } | null;
      const acct = data?.accountData;
      const signedIn = !!acct?.sessionToken;
      return {
        profileDir: dir,
        signedIn,
        verified: !!acct?.verified,
        email: acct?.email ?? null,
      };
    } catch {
      /* unreadable/locked profile, try the next */
    }
  }
  // No profile has signedInUser.json at all → report the most recent as signed-out.
  return dirs[0] ? { profileDir: dirs[0], signedIn: false, verified: false, email: null } : null;
}

/** Opens `url` in Firefox itself: only it opens about: pages, such as its sign-in (about:preferences#sync). */
export function openBrowser(url: string) {
  // Under sudo it would start root's own Firefox, with root's profile, not the user's.
  if (process.getuid?.() === 0 && process.env.SUDO_USER) return;
  if (process.platform === "darwin") {
    // Firefox itself, as `open` hands it the # escaped (about:preferences%23sync); a running
    // Firefox takes the URL from it. Elsewhere than an Applications folder: just bring it up.
    const firefox = ["/Applications", join(userHome(), "Applications")]
      .map((dir) => join(dir, "Firefox.app/Contents/MacOS/firefox"))
      .find((p) => existsSync(p));
    const [cmd, ...args] = firefox ? [firefox, url] : ["open", "-a", "Firefox"];
    spawn(cmd, args, { detached: true, stdio: "ignore" }).on("error", () => {}).unref();
    return;
  }
  if (process.platform === "win32") {
    const firefox = [process.env.ProgramFiles, process.env["ProgramFiles(x86)"]]
      .map((dir) => dir && `${dir}\\Mozilla Firefox\\firefox.exe`)
      .find((p) => p && existsSync(p));
    // no default-browser fallback: only Firefox opens about: pages
    if (firefox) spawn(firefox, [url], { detached: true, stdio: "ignore" }).on("error", () => {}).unref();
    return;
  }
  // Firefox itself (only it opens about: pages): installed, on PATH (Ubuntu's snap too), or the
  // Flatpak (Fedora Silverblue and Kinoite have no `firefox` command); xdg-open as a last try
  const onPath = (cmd: string) => (process.env.PATH ?? "").split(":").some((dir) => dir && existsSync(join(dir, cmd)));
  const flatpak = ["/var/lib/flatpak", join(userHome(), ".local/share/flatpak")].some((d) => existsSync(join(d, "app/org.mozilla.firefox")));
  const [cmd, ...args] = existsSync("/opt/firefox-official/firefox")
    ? ["/opt/firefox-official/firefox"]
    : onPath("firefox")
      ? ["firefox"]
      : flatpak
        ? ["flatpak", "run", "org.mozilla.firefox"]
        : ["xdg-open"];
  spawn(cmd, [...args, url], { detached: true, stdio: "ignore" }).on("error", () => {}).unref();
}
