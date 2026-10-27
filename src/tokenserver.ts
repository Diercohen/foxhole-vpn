// A one-shot, loopback-only HTTP receiver that collects the VPN access token
// from Firefox. Firefox's Browser Console (a privileged context) runs a small
// snippet that mints the token and POSTs it here, so the user never has to copy
// the secret by hand.
//
// Safety: the server binds to 127.0.0.1 only and lives behind an unguessable
// 192-bit secret path. We send no CORS headers, so an ordinary web page can
// neither guess the URL nor read our replies — only code that was handed the
// snippet (i.e. the user's own console) can reach it. The token is validated
// (shape, expiry, scope), never logged, and the server closes the moment a
// valid token arrives or the wait times out. The caller saves it with
// saveToken(): a file only the user can read, so it's reused next time.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { chmodSync, chownSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { VPN_SCOPES } from "./auth.js";
import { fetchEntitlement, GuardianError } from "./guardian.js";
import { userHome } from "./profile.js";

const MAX_BODY = 8192; // a token is ~1 KB; anything larger isn't ours
export const TOKEN_PORT = 47380; // fixed so the URL is predictable; random if taken

/** Where the received token is kept between runs. */
export const tokenFile = () => join(userHome(), ".config", "foxhole-vpn", "token");

/** The saved token, or null if there is none. */
export function loadSavedToken(): string | null {
  try {
    return readFileSync(tokenFile(), "utf8").trim() || null;
  } catch {
    return null;
  }
}

/** Saves the token readable only by the user (0600, in a 0700 folder). */
export function saveToken(token: string): void {
  const file = tokenFile();
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, token, { mode: 0o600 });
  chmodSync(file, 0o600); // mode above only applies when the file is new
  // Under sudo, hand the file back to the real user so normal runs can read it.
  const uid = Number(process.env.SUDO_UID), gid = Number(process.env.SUDO_GID);
  if (process.getuid?.() === 0 && uid && gid) {
    chownSync(dirname(file), uid, gid);
    chownSync(file, uid, gid);
  }
}

/** Deletes the saved token (expired or rejected). */
export const forgetToken = () => rmSync(tokenFile(), { force: true });

/** True if s is a JWT that hasn't expired and carries the VPN scope. */
export function validToken(s: unknown): s is string {
  if (typeof s !== "string") return false;
  const parts = s.split(".");
  if (parts.length !== 3) return false;
  try {
    const body = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as { exp?: number; scope?: string };
    if (typeof body.exp === "number" && body.exp <= Date.now() / 1000) return false;
    const scopes = (body.scope ?? "").split(" ");
    return VPN_SCOPES.every((sc) => scopes.includes(sc));
  } catch {
    return false;
  }
}

/** Seconds until a JWT's `exp`, or null if it can't be read. */
export function tokenTtl(jwt: string): number | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const body = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as { exp?: number };
    return typeof body.exp === "number" ? Math.round(body.exp - Date.now() / 1000) : null;
  } catch {
    return null;
  }
}

/** Why a token can't be used ("has expired", "was rejected…"), or null if it looks fine. */
export async function tokenProblem(token: string): Promise<string | null> {
  const ttl = tokenTtl(token);
  if (ttl !== null && ttl <= 0) return "has expired";
  try {
    await fetchEntitlement(token, AbortSignal.timeout(8000));
  } catch (err) {
    // Only a 401 means the token is bad; offline or a slow server shouldn't block startup.
    if (err instanceof GuardianError && err.status === 401) return "was rejected by Mozilla (expired or revoked)";
  }
  return null;
}

/** The Browser Console snippet that mints the VPN token and posts it to `url`. */
export function tokenSnippet(url: string): string {
  return [
    "(async () => {",
    `  const m = ChromeUtils.importESModule("resource://gre/modules/FxAccounts.sys.mjs");`,
    `  const fxa = m.getFxAccountsSingleton?.() ?? m.fxAccounts;`,
    `  const token = await fxa.getOAuthToken({ scope: ["profile", "https://identity.mozilla.com/apps/vpn"] });`,
    `  const r = await fetch(${JSON.stringify(url)}, { method: "POST",`,
    `    headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });`,
    `  console.log(r.ok ? "foxhole: token sent — return to the terminal" : "foxhole: failed, HTTP " + r.status);`,
    "})();",
  ].join("\n");
}

export interface TokenReceiver {
  url: string; // where the snippet posts (loopback + secret path)
  snippet: string; // the Browser Console snippet to paste
  token: Promise<string>; // resolves with the token once a valid one arrives
  close(): void; // stop listening (idempotent)
}

/** Starts the receiver. `timeoutMs` rejects `token` if nothing valid arrives. */
export function startTokenReceiver(timeoutMs = 120_000, port = TOKEN_PORT): Promise<TokenReceiver> {
  const path = "/" + randomBytes(24).toString("hex");
  return new Promise((resolve, reject) => {
    let settle: (t: string) => void;
    let fail: (e: Error) => void;
    const token = new Promise<string>((res, rej) => ((settle = res), (fail = rej)));

    const server = createServer((req, res) => {
      if (req.method !== "POST" || req.url !== path) return void res.writeHead(404).end();
      let body = "";
      let aborted = false;
      req.on("data", (c: Buffer) => {
        body += c;
        if (body.length > MAX_BODY) (aborted = true), req.destroy();
      });
      req.on("end", () => {
        if (aborted) return;
        let tok: unknown;
        try {
          tok = (JSON.parse(body) as { token?: unknown }).token;
        } catch {
          /* not JSON */
        }
        if (validToken(tok)) {
          res.writeHead(200, { "content-type": "text/plain" }).end("ok");
          settle(tok);
        } else {
          res.writeHead(400, { "content-type": "text/plain" }).end("invalid");
        }
      });
    });

    // Port taken (another foxhole, or anything else): fall back to a random one.
    server.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code !== "EADDRINUSE" || port === 0) return reject(err);
      server.once("error", reject);
      server.listen(0, "127.0.0.1");
    });
    // Rejects `token` (not the startup promise, which has resolved by then).
    const timer = setTimeout(() => (server.close(), fail(new Error("timed out waiting for the token"))), timeoutMs);
    const close = () => (clearTimeout(timer), server.close());
    token.then(close, () => {}); // stop as soon as we have it (a timeout already closed it)

    server.once("listening", () => {
      const addr = server.address();
      const bound = typeof addr === "object" && addr ? addr.port : 0;
      const url = `http://127.0.0.1:${bound}${path}`;
      resolve({ url, snippet: tokenSnippet(url), token, close });
    });
    server.listen(port, "127.0.0.1");
  });
}
