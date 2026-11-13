// Foxhole's desktop app (main.js); or, started with --sign-in, only its Mozilla sign-in window (signinwindow.js): the
// internal app the terminal's foxhole signs in with (src/fxalogin.ts). That one says "open" once the window's up, then
// the session once signed in, on its stdout: a pipe only the foxhole that started it reads. Nothing is kept, and the
// app's own data (the app may be running) isn't touched.
import { app } from "electron";
import { join } from "node:path";
import { openSignIn } from "./signinwindow.js";
import { loadSettings } from "./dist/settings.js";
import { useFastlyFallback } from "./dist/dns.js";
import { useRelay } from "./dist/guardian.js";
import { loadRelay } from "./dist/httprelay.js";
import "./renderer/fa.js"; // foxholeWords, for the window's title
import "./renderer/ru.js";

if (!process.argv.includes("--sign-in")) await import("./main.js");
else {
  app.setPath("userData", join(app.getPath("temp"), "foxhole-sign-in"));
  const settings = loadSettings();
  // Mozilla's asked whether the session's confirmed (signinwindow.js) the way the terminal's foxhole reaches it: past
  // Fastly's dropped addresses (dns.ts), and through the relay where it's blocked
  useFastlyFallback();
  useRelay(loadRelay(settings));
  let said = false;
  app.on("window-all-closed", () => {}); // it quits once the window's closed and what it handed over looked at (closed, below)
  void app.whenReady().then(() => {
    openSignIn({
      title: foxholeWords(settings.lang)`Sign in to your Mozilla account`,
      done: (account) => ((said = true), process.stdout.write(`${JSON.stringify(account)}\n`, () => app.quit())),
      closed: () => said || app.quit(), // closed first: the foxhole sees it end with nothing said
    });
    app.focus({ steal: true }); // started from a terminal, it'd open behind it
    process.stdout.write("open\n");
  });
}
