// The sign-in window's page (Mozilla's, gui/signinwindow.js openSignIn): Firefox's side of its WebChannel, as the phone app's
// (mobile/App.tsx FXA_CHANNEL). The page asks the browser what it can do and hands it the signed-in session, which
// Firefox would keep in its profile and Foxhole keeps in its accounts (accounts.ts) to get the VPN's token with.
// The answers run in the page's own world (its events carry plain objects); what comes out goes to signinwindow.js.
const { contextBridge, ipcRenderer, webFrame } = require("electron");

contextBridge.exposeInMainWorld("foxholeSignIn", (json) => ipcRenderer.send("signin", String(json)));

const CHANNEL = `(() => {
  if (location.hostname !== "accounts.firefox.com" || window.foxholeChannel) return;
  window.foxholeChannel = true;
  const post = (m) => window.foxholeSignIn(JSON.stringify(m));
  const reply = (command, messageId, data) =>
    window.dispatchEvent(new CustomEvent("WebChannelMessageToContent", { detail: { id: "account_updates", message: { command, messageId, data } } }));
  window.addEventListener("WebChannelMessageToChrome", (e) => {
    let d;
    try { d = typeof e.detail === "string" ? JSON.parse(e.detail) : e.detail; } catch { return; }
    if (!d || d.id !== "account_updates" || !d.message) return;
    const { command, messageId, data } = d.message;
    if (command === "fxaccounts:fxa_status")
      reply(command, messageId, { clientId: "5882386c6d801776", capabilities: { engines: [], multiService: true, pairing: false, choose_what_to_sync: false, keys_optional: true, can_link_account_uid: true } });
    else if (command === "fxaccounts:can_link_account") reply(command, messageId, { ok: true });
    else if (command === "fxaccounts:oauth_flow_is_active") reply(command, messageId, { isActive: true });
    else if (command === "fxaccounts:login" && data && data.sessionToken)
      post({ t: "login", account: { email: data.email, sessionToken: data.sessionToken, uid: data.uid, verified: !!data.verified } });
    else if (command === "fxaccounts:oauth_login") post({ t: "done" });
  });
})();`;

void webFrame.executeJavaScript(CHANNEL); // in the page's world, before its own scripts: each page of the sign-in
