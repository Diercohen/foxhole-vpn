// The desktop window's bridge (gui/preload.cjs) on a phone: window.foxhole over React Native's WebView messages.
// Loaded before app.js (scripts/prepare.mjs puts it in index.html). App.tsx passes the core's lines in by foxholeIn().
(() => {
  // the room the system's bars take, from the first paint, and the phone's OS (App.tsx passes them in the URL; the room
  // later changes by script)
  const hash = new URLSearchParams(location.hash.slice(1));
  for (const k of ["top", "bottom"]) if (hash.has(k)) document.documentElement.style.setProperty(`--safe-${k}`, `${Number(hash.get(k))}px`);

  const post = (m) => window.ReactNativeWebView.postMessage(JSON.stringify(m));
  const waiting = new Map(); // act id → [resolve, reject]
  const states = [];
  const logs = [];
  let seq = 0;

  window.foxhole = {
    platform: hash.get("os") ?? "android", // "android" or "ios"
    act: (name, ...args) =>
      new Promise((resolve, reject) => {
        waiting.set(++seq, [resolve, reject]);
        post({ t: "act", id: seq, name, args });
      }),
    open: (which) => post({ t: "open", which }),
    onState: (cb) => states.push(cb),
    onLog: (cb) => logs.push(cb),
  };

  window.foxholeIn = (m) => {
    if (m.t === "state") for (const cb of states) cb(m.s);
    else if (m.t === "log") for (const cb of logs) cb(m.lines);
    else if (m.t === "reply") {
      const w = waiting.get(m.id);
      waiting.delete(m.id);
      if (w) m.error ? w[1](new Error(m.error)) : w[0](m.v);
    }
  };

  /** The back button: closes what's open (as Escape does), else the app goes to the background. */
  window.foxholeBack = () => {
    const open = document.querySelector(".sheet.on, .locations.on, .modal.on, .wz-shot.zoom");
    if (!open) return post({ t: "back" });
    if (open.classList.contains("wz-shot")) return open.classList.remove("zoom");
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
  };

  // The page is "in focus" while the app is on screen: the fox and the backdrop move only then (a WebView's own
  // focus comes and goes with taps and dialogs)
  document.hasFocus = () => document.visibilityState === "visible";
  for (const type of ["focus", "blur"]) window.addEventListener(type, (e) => e.target === window && e.isTrusted && e.stopImmediatePropagation(), true);
  document.addEventListener("visibilitychange", () => window.dispatchEvent(new Event(document.hidden ? "blur" : "focus")));
})();
