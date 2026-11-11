// Foxhole's own Mozilla sign-in in a terminal, as Firefox's own clients sign in by Mozilla's API (FxA's onepw
// protocol): the password is stretched here and never sent, then a code (from the email, or the authenticator app)
// confirms the session. What it gives is the session the desktop app's sign-in window gets (accounts.ts OwnAccount).
import { hkdfSync, pbkdf2 } from "node:crypto";
import { FxaError, fxaPost, type FxaAnswer } from "./auth.js";

const NS = "identity.mozilla.com/picl/v1/";

/** What FxA checks in place of the password: PBKDF2 (1000 rounds, salted with the email), then HKDF. */
export async function authPW(email: string, password: string): Promise<string> {
  const quick = await new Promise<Buffer>((resolve, reject) =>
    pbkdf2(Buffer.from(password, "utf8"), Buffer.from(`${NS}quickStretch:${email}`, "utf8"), 1000, 32, "sha256", (err, k) => (err ? reject(err) : resolve(k))),
  );
  return Buffer.from(hkdfSync("sha256", quick, Buffer.alloc(0), `${NS}authPW`, 32)).toString("hex");
}

/** A session signed in, and what still confirms it: null (none), a code from the email, or the authenticator app's. */
export interface FxaLogin {
  uid: string;
  email: string;
  sessionToken: string;
  confirm: null | "email" | "totp";
}

/** FxA's refusal, said for the user. */
function refusal(d: FxaAnswer["data"], status: number): FxaError {
  const said: Record<number, string> = {
    102: "There's no Mozilla account with that email.",
    103: "That password isn't right.",
    114: "Too many tries: wait a while, then try again.",
    127: "That code isn't right (or it's expired): check the latest email.",
    183: "That code isn't right (or it's expired): check the latest email.",
  };
  return new FxaError(said[d.errno ?? 0] ?? `Mozilla refused the sign-in: ${d.message ?? `HTTP ${status}`}`, d.errno);
}

/**
 * Signs in with the email and password. Throws an FxaError: errno 125 when Mozilla wants to be sure first (send the
 * email's unblock code with sendUnblock, then sign in again with it), 103 a wrong password, 102 no such account.
 */
export async function login(email: string, password: string, unblockCode?: string, signal?: AbortSignal): Promise<FxaLogin> {
  let e = email.trim();
  for (let i = 0; ; i++) {
    const body = { email: e, authPW: await authPW(e, password), reason: "signin", verificationMethod: "email-otp", ...(unblockCode && { unblockCode }) };
    const { ok, status, data } = await fxaPost("/account/login?keys=false", body, undefined, signal);
    if (ok && typeof data.uid === "string" && typeof data.sessionToken === "string")
      return { uid: data.uid, email: e, sessionToken: data.sessionToken, confirm: data.verified ? null : data.verificationMethod === "totp-2fa" ? "totp" : "email" };
    // 120: the email's case isn't the account's, which the password is stretched with
    if (data.errno === 120 && typeof data.email === "string" && i === 0) {
      e = data.email;
      continue;
    }
    throw refusal(data, status);
  }
}

/** Emails the code that lets a blocked sign-in (errno 125) through. */
export async function sendUnblock(email: string, signal?: AbortSignal): Promise<void> {
  const { ok, status, data } = await fxaPost("/account/login/send_unblock_code", { email: email.trim() }, undefined, signal);
  if (!ok) throw refusal(data, status);
}

/** Confirms the session with the code from the email, or the authenticator app's (TOTP). */
export async function confirmLogin(s: FxaLogin, code: string, signal?: AbortSignal): Promise<void> {
  const c = code.replace(/\s/g, "");
  const { ok, status, data } = s.confirm === "totp"
    ? await fxaPost("/session/verify/totp", { code: c, service: "sync" }, s.sessionToken, signal)
    : await fxaPost("/session/verify_code", { code: c }, s.sessionToken, signal);
  if (!ok) throw refusal(data, status);
  if (s.confirm === "totp" && data.success !== true) throw new FxaError("That code isn't right: type the one your authenticator app shows now.");
}
