// Foxhole on a phone (Android, iOS): the desktop app's window (gui/renderer) in a WebView over its core (node/main.mjs,
// run by the native side in Node), and the Mozilla sign-in, which the desktop leaves to Firefox.
import React, { useEffect, useRef, useState } from "react";
import { ActivityIndicator, BackHandler, Keyboard, Linking, Modal, PermissionsAndroid, Platform, Pressable, StatusBar, StyleSheet, Text, View } from "react-native";
import { SafeAreaProvider, initialWindowMetrics, useSafeAreaInsets } from "react-native-safe-area-context";
import { WebView, type WebViewMessageEvent } from "react-native-webview";
import Core from "./specs/NativeFoxhole";

const REPO = "https://github.com/Diercohen/foxhole-vpn";
/** What the window may open, as gui/main.js. */
const LINKS: Record<string, string> = {
  repo: REPO,
  releases: `${REPO}/releases`,
  firefox: "https://www.mozilla.org/firefox/new/",
  relay: `${REPO}#where-vpnmozillaorg-is-blocked-eg-iran`,
  gas: "https://script.google.com/home",
};
const WINDOW = Core.page(); // scripts/prepare.mjs puts it there
const WWW = WINDOW.slice(0, WINDOW.lastIndexOf("/www/") + 5); // the window's files: what it may open and read
const BG = "#07060c";

// ── Signing in ───────────────────────────────────────────────────────────────────────────────────────────────
// Mozilla's sign-in as Firefox opens it for its VPN: the page talks to the browser in WebChannel messages, which
// FXA_CHANNEL answers as Firefox would, and hands it the signed-in session, which Firefox keeps in its profile and
// Foxhole gets the VPN's token with (AUTH.md). The page sends them only to Firefox: the WebView says it's Firefox.

/** Firefox on Windows, a version of now (a new one comes every 4 weeks; 144 came out 2025-10-14). */
const firefoxUa = () => {
  const v = 144 + Math.floor((Date.now() - Date.UTC(2025, 9, 14)) / (28 * 86_400_000));
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`;
};

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** 43 base64url characters, as a SHA-256 in base64url: what the page takes for the OAuth state and PKCE challenge. */
const random43 = () => Array.from({ length: 43 }, (_, i) => B64URL[Math.floor(Math.random() * 64) & (i === 42 ? 0x3c : 0x3f)]).join("");

/** The page Firefox opens to sign in for its VPN. Its OAuth code goes unused (no one has the challenge's verifier). */
function signInUrl() {
  const q: Record<string, string> = {
    context: "oauth_webchannel_v1", service: "vpn", client_id: "5882386c6d801776", state: random43(), code_challenge: random43(),
    code_challenge_method: "S256", access_type: "offline", response_type: "code", action: "email", entrypoint: "foxhole",
  };
  return `https://accounts.firefox.com/?${Object.entries(q).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&")}`;
}

/** Firefox's side of the page's WebChannel, enough for the sign-in: the session comes out to the app. */
const FXA_CHANNEL = `(() => {
  if (location.hostname !== "accounts.firefox.com" || window.foxholeChannel) return;
  window.foxholeChannel = true;
  const post = (m) => window.ReactNativeWebView.postMessage(JSON.stringify(m));
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
})();
true;`;

/** Mozilla's own sites (and the Google and Apple sign-ins it offers) open in the sign-in; any other link, in the browser. */
const SIGN_IN_HOSTS = /^https:\/\/([\w-]+\.)*(firefox\.com|mozilla\.org|mozilla\.com|google\.com|gstatic\.com|apple\.com)(\/|$)/;

function SignIn({ onClose, onMessage }: { onClose: () => void; onMessage: (e: WebViewMessageEvent) => void }) {
  const insets = useSafeAreaInsets();
  const [url] = useState(signInUrl);
  const [ua] = useState(firefoxUa);
  return (
    <Modal visible animationType="slide" onRequestClose={onClose} statusBarTranslucent navigationBarTranslucent>
      <View style={[styles.sheet, { paddingTop: insets.top, paddingBottom: insets.bottom }]}>
        <View style={styles.bar}>
          <Text style={styles.title}>Sign in to your Mozilla account</Text>
          <Pressable onPress={onClose} hitSlop={14} accessibilityRole="button" accessibilityLabel="Close">
            <Text style={styles.close}>✕</Text>
          </Pressable>
        </View>
        <WebView
          source={{ uri: url }}
          userAgent={ua}
          incognito // a fresh sign-in each time (to switch accounts too), nothing left behind
          domStorageEnabled
          setSupportMultipleWindows={false}
          // as early as it gets on Android (as a page starts loading, which can be too early: the page before), and
          // again once it's loaded: the page's sign-in steps don't load another
          injectedJavaScriptBeforeContentLoaded={FXA_CHANNEL}
          injectedJavaScript={FXA_CHANNEL}
          onMessage={onMessage}
          onShouldStartLoadWithRequest={(req) => SIGN_IN_HOSTS.test(req.url) || (void Linking.openURL(req.url), false)}
          startInLoadingState
          renderLoading={() => <ActivityIndicator style={StyleSheet.absoluteFill} color="#ff7a1a" size="large" />}
          style={styles.web}
        />
      </View>
    </Modal>
  );
}

// ── The window ───────────────────────────────────────────────────────────────────────────────────────────────

function Main() {
  const insets = useSafeAreaInsets();
  const web = useRef<React.ComponentRef<typeof WebView>>(null);
  const [signIn, setSignIn] = useState(false);
  const [keyboard, setKeyboard] = useState(0); // its height: the window ends above it
  const account = useRef<object | null>(null); // from the sign-in page, until the core is signed in with it
  const askedNotify = useRef(false);

  useEffect(() => {
    // the core's lines: its state, log and answers go to the window; it asks for the sign-in page
    const lines = Core.onLine((line) => {
      const m = JSON.parse(line);
      if (m.t === "signIn") return setSignIn(true);
      if (m.t === "state") {
        if (m.s.auth.stage === "ready" && account.current) {
          account.current = null; // signed in with it: the sign-in page is done
          setSignIn(false);
        }
        if (m.s.active && !askedNotify.current && Platform.OS === "android") {
          askedNotify.current = true; // the notification that keeps it running while connected
          void PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS);
        }
      }
      web.current?.injectJavaScript(`window.foxholeIn && window.foxholeIn(${line});true;`);
    });
    Core.start();
    const back = BackHandler.addEventListener("hardwareBackPress", () => {
      web.current?.injectJavaScript("window.foxholeBack && window.foxholeBack();true;");
      return true;
    });
    const shown = Keyboard.addListener("keyboardDidShow", (e) => setKeyboard(e.endCoordinates.height));
    const hidden = Keyboard.addListener("keyboardDidHide", () => setKeyboard(0));
    return () => [lines, back, shown, hidden].forEach((s) => s.remove());
  }, []);

  // the system bars' room, for the page's layout (style.css): the window runs under them
  const [page] = useState(() => `${WINDOW}#top=${insets.top}&bottom=${insets.bottom}&os=${Platform.OS}`); // from the first paint (phone.js)
  const insetsJs = `document.documentElement.style.setProperty("--safe-top", "${insets.top}px");
    document.documentElement.style.setProperty("--safe-bottom", "${keyboard ? 0 : insets.bottom}px");true;`;
  useEffect(() => web.current?.injectJavaScript(insetsJs), [insetsJs]);

  const fromWindow = (e: WebViewMessageEvent) => {
    const m = JSON.parse(e.nativeEvent.data);
    if (m.t === "act") Core.send(e.nativeEvent.data); // the core checks it's one the window may ask for
    else if (m.t === "open" && LINKS[m.which]) void Linking.openURL(LINKS[m.which]);
    else if (m.t === "back") Core.moveToBack();
  };

  const fromSignIn = (e: WebViewMessageEvent) => {
    // what sent it: Mozilla's sign-in, not another site in it (its origin, as Android's WebView says; or its URL)
    if (!/^https:\/\/accounts\.firefox\.com(\/|$)/.test(e.nativeEvent.url)) return;
    const m = JSON.parse(e.nativeEvent.data);
    if (m.t === "login") {
      account.current = m.account;
      if (m.account.verified) Core.send(JSON.stringify({ t: "signedIn", account: m.account }));
    } else if (m.t === "done") {
      // the page's last step, once the sign-in is confirmed (as by a code from the email)
      if (account.current) Core.send(JSON.stringify({ t: "signedIn", account: { ...account.current, verified: true } }));
      setSignIn(false);
    }
  };

  return (
    <View style={[styles.root, { paddingBottom: keyboard }]}>
      <StatusBar barStyle="light-content" />
      <WebView
        ref={web}
        source={{ uri: page }}
        originWhitelist={["file://*"]}
        allowFileAccess
        onShouldStartLoadWithRequest={(req) => req.url.startsWith(WWW)}
        allowingReadAccessToURL={WWW}
        onContentProcessDidTerminate={() => web.current?.reload()} // iOS ends it in the background when short of memory
        onMessage={fromWindow}
        onLoadEnd={() => web.current?.injectJavaScript(insetsJs)}
        textZoom={100}
        overScrollMode="never"
        bounces={false}
        setBuiltInZoomControls={false}
        webviewDebuggingEnabled={__DEV__}
        style={styles.web}
      />
      {signIn && <SignIn onClose={() => setSignIn(false)} onMessage={fromSignIn} />}
    </View>
  );
}

// ── A WebView too old for the window ────────────────────────────────────────────────────────────────────────

/** Chrome's version the window needs (its colors: color-mix, oklch). Android 9 came with 66; Chrome updates it to 138. */
const NEEDS_WEBVIEW = 111;
const WEBVIEW_APPS: Record<string, string> = { "com.android.chrome": "Chrome", "com.google.android.webview": "Android System WebView" };

/** What to update, and where, when the phone's WebView is older than the window needs. */
function OldWebView({ pkg, major }: { pkg: string; major: number }) {
  const app = WEBVIEW_APPS[pkg] ?? `the WebView (${pkg})`;
  return (
    <View style={styles.old}>
      <StatusBar barStyle="light-content" />
      <Text style={styles.oldTitle}>Update {app}</Text>
      <Text style={styles.oldText}>
        Foxhole's screens run in {app}, and this phone has version {major} of it: Foxhole needs {NEEDS_WEBVIEW} or later.
        Update it from Google Play or your app store, then open Foxhole again.
      </Text>
      <Pressable style={styles.oldButton} onPress={() => void Linking.openURL(`https://play.google.com/store/apps/details?id=${pkg}`)}>
        <Text style={styles.oldButtonText}>Open in Google Play</Text>
      </Pressable>
    </View>
  );
}

export default function App() {
  const [[pkg, version = ""]] = useState(() => Core.webView().split(" "));
  const major = parseInt(version, 10); // NaN when unknown: let it try
  return (
    <SafeAreaProvider initialMetrics={initialWindowMetrics}>
      {major < NEEDS_WEBVIEW ? <OldWebView pkg={pkg} major={major} /> : <Main />}
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: BG },
  web: { flex: 1, backgroundColor: BG },
  sheet: { flex: 1, backgroundColor: "#100c1a" },
  bar: { flexDirection: "row", alignItems: "center", paddingHorizontal: 20, paddingVertical: 14, gap: 12 },
  title: { flex: 1, color: "#f6f3fb", fontSize: 17, fontWeight: "700" },
  close: { color: "rgba(246, 243, 251, 0.7)", fontSize: 20, fontWeight: "600" },
  old: { flex: 1, backgroundColor: BG, justifyContent: "center", padding: 28, gap: 18 },
  oldTitle: { color: "#f6f3fb", fontSize: 24, fontWeight: "800" },
  oldText: { color: "rgba(246, 243, 251, 0.75)", fontSize: 16, lineHeight: 24 },
  oldButton: { alignSelf: "flex-start", backgroundColor: "#ff7a1a", borderRadius: 14, paddingHorizontal: 22, paddingVertical: 13 },
  oldButtonText: { color: "#fff", fontSize: 16, fontWeight: "700" },
});
