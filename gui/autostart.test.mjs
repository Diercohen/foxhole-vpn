// The files the desktop starts Foxhole from at login, and Windows' calls to Electron. No network.
import assert from "node:assert";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "foxhole-autostart-"));
process.env.HOME = home;
delete process.env.XDG_CONFIG_HOME;
const { loginItem, AUTOSTART_FLAG } = await import("./autostart.js");

// macOS
const mac = loginItem("/Applications/Fox & <Hole>.app/Contents/MacOS/Foxhole", { platform: "darwin" });
assert.equal(mac.on(), false, "off until set");
mac.set(true);
assert.equal(mac.on(), true);
const plist = readFileSync(join(home, "Library/LaunchAgents/io.github.diercohen.foxhole.plist"), "utf8");
assert.ok(plist.includes(`<string>/Applications/Fox &amp; &lt;Hole>.app/Contents/MacOS/Foxhole</string><string>${AUTOSTART_FLAG}</string>`), "the path escaped for XML, then the flag");
mac.set(false);
assert.equal(mac.on(), false);
mac.set(false); // already off: no error

// Linux: spaces need the quotes; the rest is escaped for Exec and again for the file's strings
const linux = loginItem("/home/me/My $Apps/100% a\"b\\c.AppImage", { platform: "linux", args: ["--no-sandbox"] });
linux.set(true);
const entry = readFileSync(join(home, ".config/autostart/foxhole.desktop"), "utf8");
assert.ok(entry.split("\n").includes(`Exec="/home/me/My \\\\$Apps/100%% a\\\\"b\\\\\\\\c.AppImage" "${AUTOSTART_FLAG}" "--no-sandbox"`), entry);
assert.equal(linux.on(), true);
linux.set(false);

process.env.XDG_CONFIG_HOME = join(home, "xdg");
const xdg = loginItem("/opt/Foxhole/foxhole-desktop", { platform: "linux" });
xdg.set(true);
assert.ok(readFileSync(join(home, "xdg/autostart/foxhole.desktop"), "utf8").includes(`Exec="/opt/Foxhole/foxhole-desktop" "${AUTOSTART_FLAG}"`), "XDG_CONFIG_HOME's folder");

// Windows: Electron's Run key, asked with what it was set with
let set = null;
const win = loginItem("C:\\Foxhole\\Foxhole.exe", {
  platform: "win32",
  electron: { setLoginItemSettings: (s) => (set = s), getLoginItemSettings: (s) => ({ openAtLogin: s.path === set?.path && set.openAtLogin }) },
});
assert.equal(win.on(), false);
win.set(true);
assert.deepEqual(set, { path: "C:\\Foxhole\\Foxhole.exe", args: [AUTOSTART_FLAG], openAtLogin: true });
assert.equal(win.on(), true);
win.set(false);
assert.equal(win.on(), false);

rmSync(home, { recursive: true });
console.log("ok - autostart");
