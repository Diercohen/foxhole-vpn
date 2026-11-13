// Foxhole's own Mozilla sign-in (accounts.ts): Mozilla's page as Firefox opens it for its VPN, in a window of its own,
// as the phone app has it (mobile/App.tsx). signin.cjs answers its WebChannel as Firefox would, and the session it hands
// over goes to `done` once Mozilla has confirmed it (fxalogin.ts PageSignIn): the app adds it to the accounts (main.js),
// and its internal sign-in app hands it to the terminal's foxhole (start.js). The page talks to Firefox only: the window
// says it's Firefox. A fresh, in-memory session each time, nothing left behind.
import { BrowserWindow, ipcMain, shell } from "electron";
import { fileURLToPath } from "node:url";
import { PageSignIn } from "./dist/fxalogin.js";

/** Firefox on Windows, a version of now (a new one comes every 4 weeks; 144 came out 2025-10-14). */
const firefoxUa = () => {
  const v = 144 + Math.floor((Date.now() - Date.UTC(2025, 9, 14)) / (28 * 86_400_000));
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`;
};
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** 43 base64url characters, as a SHA-256 in base64url: what the page takes for the OAuth state and PKCE challenge. */
const random43 = () => Array.from({ length: 43 }, (_, i) => B64URL[Math.floor(Math.random() * 64) & (i === 42 ? 0x3c : 0x3f)]).join("");
/** The page Firefox opens to sign in for its VPN. Its OAuth code goes unused (no one has the challenge's verifier). */
const signInUrl = () =>
  `https://accounts.firefox.com/?${new URLSearchParams({
    context: "oauth_webchannel_v1", service: "vpn", client_id: "5882386c6d801776", state: random43(), code_challenge: random43(),
    code_challenge_method: "S256", access_type: "offline", response_type: "code", action: "email", entrypoint: "foxhole",
  })}`;

/** Mozilla's own sites (and the Google and Apple sign-ins it offers) open in the sign-in; any other link, in the browser. */
const SIGN_IN_HOSTS = /^https:\/\/([\w-]+\.)*(firefox\.com|mozilla\.org|mozilla\.com|google\.com|gstatic\.com|apple\.com)(\/|:|$)/;
let signInWin = null;
let page = null; // what the window's page handed over (PageSignIn), till it's given to `done` and the window's closed

/**
 * Opens the sign-in window (or brings it up): `done` gets the session once Mozilla has confirmed it, as by a code from
 * the email; `closed`, once the window's closed and what it handed over has been looked at a last time.
 */
export function openSignIn({ title, parent, done, closed = () => {} }) {
  if (signInWin) return signInWin.focus();
  const handed = (page = new PageSignIn(done));
  const win = (signInWin = new BrowserWindow({
    width: 520, height: 760, parent, title, backgroundColor: "#ffffff", autoHideMenuBar: true,
    webPreferences: { preload: fileURLToPath(new URL("signin.cjs", import.meta.url)), partition: `signin-${Date.now()}`, sandbox: true, contextIsolation: true },
  }));
  const wc = win.webContents;
  wc.setUserAgent(firefoxUa());
  wc.setWindowOpenHandler(({ url }) => {
    if (SIGN_IN_HOSTS.test(url)) void wc.loadURL(url);
    else void shell.openExternal(url);
    return { action: "deny" };
  });
  wc.on("will-navigate", (e, url) => {
    if (SIGN_IN_HOSTS.test(url)) return;
    e.preventDefault();
    void shell.openExternal(url);
  });
  win.on("closed", () => {
    if (signInWin === win) signInWin = null;
    // the code typed, but the page's last step failed (its red alert) or the window closed first: Mozilla says
    void handed.closed().finally(() => {
      if (page === handed) page = null;
      closed();
    });
  });
  void win.loadURL(signInUrl());
}

/** Closes the window once what it handed over was given to `done` (main.js: the app's signed in with it). */
export function closeSignIn() {
  if (page?.given) signInWin?.close();
}

ipcMain.on("signin", (e, json) => {
  if (!signInWin || e.sender !== signInWin.webContents || !/^https:\/\/accounts\.firefox\.com(\/|$)/.test(e.senderFrame?.url ?? "")) return;
  let m;
  try {
    m = JSON.parse(json);
  } catch {
    return;
  }
  if (m.t === "login") page.login(m.account);
  else if (m.t === "done") {
    // the page's last step, once the sign-in is confirmed (as by a code from the email)
    page.confirmed();
    signInWin.close();
  }
});
