// Foxhole's Mozilla accounts (accounts.json, readable only by the user): the ones it signed in to itself, their
// sessions kept here, and Firefox's own sign-in, read from Firefox's profile as each token is made (as before there
// was a list). One is in use, and stays so for the next start: the VPN's token comes from it.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { FirefoxAuth, SessionAuth, fxaPost, type Authenticator } from "./auth.js";
import { findAccount, userHome } from "./profile.js";

/** Firefox's sign-in, in the list. */
export const FIREFOX = "firefox";
/** Less data left than this (bytes): the window and the TUI offer another account. */
export const LOW_DATA = 500n * 1024n * 1024n;

export interface OwnAccount {
  uid: string;
  email: string;
  sessionToken: string; // hex: what Firefox keeps in signedInUser.json
}

export interface Accounts {
  current: string | null; // a uid, FIREFOX, or null: none yet (the first start asks how to sign in)
  firefox: boolean; // Firefox's sign-in is in the list
  own: OwnAccount[];
  lowSeen: Record<string, string>; // an account's id → the month (its quota's reset) the low-data warning was put away for
}

const PHONE = process.platform === "android" || (process.platform as string) === "ios"; // no Firefox there: own accounts only
const configDir = () => join(userHome(), ".config", "foxhole-vpn");
const accountsFile = () => join(configDir(), "accounts.json");
const isOwn = (a: unknown): a is OwnAccount => {
  const o = a as Partial<OwnAccount> | null;
  return typeof o?.uid === "string" && !!o.uid && typeof o.email === "string" && typeof o.sessionToken === "string" && /^[0-9a-f]{64}$/.test(o.sessionToken);
};

/** A file's accounts, the well-formed ones; null if it isn't one. Pure. */
export function parseAccounts(json: string): Accounts | null {
  let o: Partial<Record<keyof Accounts, unknown>>;
  try {
    o = JSON.parse(json);
  } catch {
    return null;
  }
  if (!o || typeof o !== "object") return null;
  const own = Array.isArray(o.own) ? o.own.filter(isOwn).map(({ uid, email, sessionToken }) => ({ uid, email, sessionToken })) : [];
  const firefox = o.firefox === true && !PHONE;
  const ids = [...(firefox ? [FIREFOX] : []), ...own.map((a) => a.uid)];
  const current = typeof o.current === "string" && ids.includes(o.current) ? o.current : (ids[0] ?? null);
  const lowSeen: Record<string, string> = {};
  for (const [k, v] of Object.entries(o.lowSeen && typeof o.lowSeen === "object" ? o.lowSeen : {})) if (typeof v === "string") lowSeen[k] = v;
  return { current, firefox, own, lowSeen };
}

/**
 * Before accounts.json, from an earlier version. A computer's used Firefox's sign-in (or a token got from it): it
 * carries on with it, without asking. A phone's kept its own sign-in where Firefox keeps one: it's the first account.
 * Otherwise, a first start: none yet.
 */
function migrate(): Accounts {
  const none: Accounts = { current: null, firefox: false, own: [], lowSeen: {} };
  if (PHONE) {
    try {
      const { accountData: a } = JSON.parse(readFileSync(join(userHome(), ".mozilla", "firefox", "foxhole.default", "signedInUser.json"), "utf8"));
      if (isOwn(a)) return { ...none, current: a.uid, own: [{ uid: a.uid, email: a.email, sessionToken: a.sessionToken }] };
    } catch {}
    return none;
  }
  const used = ["settings.json", "token", "country"].some((f) => existsSync(join(configDir(), f)));
  return used ? { ...none, current: FIREFOX, firefox: true } : none;
}

export function loadAccounts(): Accounts {
  if (existsSync(accountsFile())) {
    try {
      const a = parseAccounts(readFileSync(accountsFile(), "utf8"));
      if (a) return a;
    } catch {}
  }
  const a = migrate();
  if (a.current) saveAccounts(a); // once: from now on the file says
  return a;
}

/** Private (0600): it holds the sessions. Throws if it can't be written. */
export function saveAccounts(a: Accounts): void {
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  const tmp = `${accountsFile()}.tmp`;
  writeFileSync(tmp, JSON.stringify(a, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, accountsFile());
}

/** Adds (or renews) one Foxhole signed in to itself, and uses it. Pure. */
export function withOwn(a: Accounts, acct: OwnAccount): Accounts {
  const own = [...a.own.filter((x) => x.uid !== acct.uid), acct];
  return { ...a, own, current: acct.uid };
}

/** Takes one off the list (Firefox's: Foxhole stops reading it; Firefox stays signed in). Pure. */
export function without(a: Accounts, id: string): Accounts {
  const own = a.own.filter((x) => x.uid !== id);
  const firefox = a.firefox && id !== FIREFOX;
  const ids = [...(firefox ? [FIREFOX] : []), ...own.map((x) => x.uid)];
  return { ...a, own, firefox, current: a.current !== id ? a.current : (ids[0] ?? null) };
}

/** Puts Firefox's sign-in on the list, and uses it. Pure. */
export const withFirefox = (a: Accounts): Accounts => ({ ...a, firefox: !PHONE, current: PHONE ? a.current : FIREFOX });

/** The VPN token's source for an account; null for one not on the list (or Firefox's, signed out or unreadable). */
export function authFor(a: Accounts, id: string): Authenticator | null {
  if (id === FIREFOX) {
    const f = a.firefox ? findAccount() : null;
    return f?.signedIn ? new FirefoxAuth(f) : null;
  }
  const own = a.own.find((x) => x.uid === id);
  return own ? new SessionAuth(() => own.sessionToken) : null;
}

/**
 * Firefox's account, where it can be read without asking: not on macOS, whose privacy protection would ask the user
 * first (or want Full Disk Access). Null: not known.
 */
export function peekFirefox(): string | null {
  if (process.platform === "darwin" || PHONE) return null;
  const f = findAccount();
  return f?.signedIn && !f.blocked ? f.email : null;
}

/** Signs a session out at Mozilla (it leaves the account's devices list); quietly, as the account goes from here anyway. */
export async function signOut(sessionToken: string): Promise<void> {
  await fxaPost("/session/destroy", {}, sessionToken, AbortSignal.timeout(10_000)).catch(() => {});
}
