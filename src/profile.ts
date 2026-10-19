import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, readFileSync, readdirSync } from "node:fs";

// When run under sudo, look in the invoking user's home, not root's.
function userHome(): string {
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
    join(home, ".config", "mozilla", "firefox"), // some Linux/Omarchy builds
    join(home, "Library", "Application Support", "Firefox"), // macOS
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
  for (const root of profileRoots()) {
    for (const dir of candidateProfiles(root)) {
      const f = join(dir, "signedInUser.json");
      if (!existsSync(f)) continue;
      try {
        const data = JSON.parse(readFileSync(f, "utf8")) as {
          accountData?: { email?: string; verified?: boolean; sessionToken?: string };
        };
        const acct = data.accountData;
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
    // A profile with no signedInUser.json at all → report the first as signed-out.
    const first = candidateProfiles(root)[0];
    if (first) return { profileDir: first, signedIn: false, verified: false, email: null };
  }
  return null;
}
