// Foxhole's Mozilla accounts (accounts.json, readable only by the user): the ones it signed in to itself, their
// sessions kept here, and Firefox's own sign-in, read from Firefox's profile as each token is made (as before there
// was a list). One is in use, and stays so for the next start: the VPN's token comes from it.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { FirefoxAuth, RefreshAuth, SessionAuth, destroyToken, fxaPost, type Authenticator } from "./auth.js";
import { findAccount, userHome } from "./profile.js";

/** Firefox's sign-in, in the list. */
export const FIREFOX = "firefox";
/** Less data left than this (bytes): the window and the TUI offer another account. */
export const LOW_DATA = 500n * 1024n * 1024n;

export interface OwnAccount {
  uid: string;
  email: string;
  sessionToken?: string; // hex: what Firefox keeps in signedInUser.json
  refreshToken?: string; // hex, VPN-only: what a TV's sent (tvpair.ts), instead of a session
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
  const hex = (t: unknown) => typeof t === "string" && /^[0-9a-f]{64}$/.test(t);
  return typeof o?.uid === "string" && !!o.uid && typeof o.email === "string" && (hex(o.sessionToken) || hex(o.refreshToken));
};
/** An account as it's kept: its uid, email, and its session or refresh token. */
const keep = ({ uid, email, sessionToken, refreshToken }: OwnAccount): OwnAccount => (sessionToken ? { uid, email, sessionToken } : { uid, email, refreshToken });

/** A file's accounts, the well-formed ones; null if it isn't one. Pure. */
export function parseAccounts(json: string): Accounts | null {
  let o: Partial<Record<keyof Accounts, unknown>>;
  try {
    o = JSON.parse(json);
  } catch {
    return null;
  }
  if (!o || typeof o !== "object") return null;
  const own = Array.isArray(o.own) ? o.own.filter(isOwn).map(keep) : [];
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
      if (isOwn(a)) return { ...none, current: a.uid, own: [keep(a)] };
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
  return !own ? null : own.sessionToken ? new SessionAuth(() => own.sessionToken as string) : new RefreshAuth(own.refreshToken as string);
}

/** takeSent's: the account's on the list already (`id`: its own, or FIREFOX), its sign-in still good. Said to the sender as it is. */
export class AlreadySignedIn extends Error {
  constructor(readonly id: string, readonly email: string) {
    super(`the other device is already signed in with ${email}`);
  }
}

/** What takeSent took: the sign-in, as the file keeps one; the one on the list it replaces (its sign-in had ended). */
export interface Taken {
  account: OwnAccount;
  replaced: OwnAccount | null;
}

/**
 * A sign-in another device sent this one (tvpair.ts), for the list `a`: checked with Mozilla first, whose refusal is
 * thrown (the sender's told, and ends the sign-in it made). The account's on the list already, its sign-in still
 * good: it stays as it is, a full sign-in not given up for a VPN-only one, and AlreadySignedIn is thrown. One that
 * has ended (or can't be checked), the new one takes its place. withSent puts what's taken on the list as it is by
 * then; the one it replaces is signed out once the list's saved (it leaves the account's devices list).
 */
export async function takeSent(a: Accounts, sent: Pick<OwnAccount, "uid" | "email" | "refreshToken">): Promise<Taken> {
  const acct = { uid: sent.uid, email: sent.email, refreshToken: sent.refreshToken };
  // as the file keeps one, and nothing a terminal would take for more than letters
  if (!isOwn(acct) || /[\x00-\x1f\x7f-\x9f]/.test(acct.uid + acct.email)) throw new Error("that isn't a sign-in Foxhole can keep");
  const same = (x: { uid?: string; email?: string | null }) => x.uid === acct.uid || (!!x.email && x.email.toLowerCase() === acct.email.toLowerCase());
  const twin = a.own.find(same);
  const good = (auth: Authenticator | null) => (auth ? auth.getAccessToken(AbortSignal.timeout(15_000)).then(() => true, () => false) : false);
  // the two asked at once: the sender waits half a minute for its answer
  const [, kept] = await Promise.all([new RefreshAuth(acct.refreshToken as string).getAccessToken(AbortSignal.timeout(15_000)), twin ? good(authFor(a, twin.uid)) : false]);
  if (twin && kept) throw new AlreadySignedIn(twin.uid, twin.email);
  const firefox = !twin && a.firefox ? findAccount() : null; // on the list: reading it was allowed
  if (firefox?.signedIn && same(firefox)) throw new AlreadySignedIn(FIREFOX, firefox.email ?? acct.email);
  return { account: acct, replaced: twin ?? null };
}

/** What takeSent took, on the list as it is when it's saved (it may have changed while Mozilla was asked): in the place of the one it replaces, and in use. Pure. */
export const withSent = (a: Accounts, { account, replaced }: Taken): Accounts => withOwn(replaced ? without(a, replaced.uid) : a, account);

/**
 * Firefox's account, where it can be read without asking: not on macOS, whose privacy protection would ask the user
 * first (or want Full Disk Access). Null: not known.
 */
export function peekFirefox(): string | null {
  if (process.platform === "darwin" || PHONE) return null;
  const f = findAccount();
  return f?.signedIn && !f.blocked ? f.email : null;
}

/** Signs an account out at Mozilla (it leaves the account's devices list); quietly, as the account goes from here anyway. */
export async function signOut(a: Pick<OwnAccount, "sessionToken" | "refreshToken">): Promise<void> {
  if (a.refreshToken) return destroyToken(a.refreshToken);
  if (a.sessionToken) await fxaPost("/session/destroy", {}, a.sessionToken, AbortSignal.timeout(10_000)).catch(() => {});
}
