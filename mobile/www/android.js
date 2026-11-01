// The desktop window's bridge (gui/preload.cjs) on Android: window.foxhole over React Native's WebView messages.
// Loaded before app.js (scripts/prepare.mjs puts it in index.html). App.tsx passes the core's lines in by foxholeIn().
(() => {
  // the room the system's bars take, from the first paint (App.tsx passes it in the URL, and later changes by script)
  const bars = new URLSearchParams(location.hash.slice(1));
  for (const k of ["top", "bottom"]) if (bars.has(k)) document.documentElement.style.setProperty(`--safe-${k}`, `${Number(bars.get(k))}px`);

  const post = (m) => window.ReactNativeWebView.postMessage(JSON.stringify(m));
  const waiting = new Map(); // act id → [resolve, reject]
  const states = [];
  const logs = [];
  let seq = 0;

  window.foxhole = {
    platform: "android",
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
