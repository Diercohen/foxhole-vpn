// Settings' "Start when you log in": a file the desktop reads at login (macOS, Linux), Windows' Run key through Electron.
// macOS: a LaunchAgent, as Electron's own login item (SMAppService) needs a real signature and can't pass the flag below.
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const AUTOSTART_FLAG = "--autostart"; // started at login: no window, only the tray

const xml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

// AbandonProcessGroup: launchd would otherwise kill what outlives the app, like the updater's restart.
const plist = (label, command) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>${command.map((a) => `<string>${xml(a)}</string>`).join("")}</array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>AbandonProcessGroup</key><true/>
</dict>
</plist>
`;

/** One argument of a .desktop file's Exec: quoted for Exec, then escaped again as any of the file's strings. */
const execArg = (a) => `"${a.replace(/[\\"`$]/g, "\\$&")}"`.replace(/\\/g, "\\\\").replace(/%/g, "%%");
const desktopEntry = (command) => `[Desktop Entry]
Type=Application
Name=Foxhole
Exec=${command.map(execArg).join(" ")}
Terminal=false
`;

/** Whether this copy starts at login, and setting it. `electron` is Electron's app (Windows). */
export function loginItem(exe, { electron, args = [], platform = process.platform } = {}) {
  const command = [exe, AUTOSTART_FLAG, ...args];
  if (platform === "win32") {
    // Electron's own value name: openAtLogin reads no other, and executableWillLaunchAtLogin stayed false on Windows 11
    const item = { path: exe, args: [AUTOSTART_FLAG, ...args] };
    return {
      on: () => electron.getLoginItemSettings(item).openAtLogin,
      set: (on) => electron.setLoginItemSettings({ ...item, openAtLogin: on }),
    };
  }
  const label = "io.github.diercohen.foxhole";
  const [file, content] =
    platform === "darwin"
      ? [join(homedir(), "Library/LaunchAgents", `${label}.plist`), plist(label, command)]
      : [join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "autostart/foxhole.desktop"), desktopEntry(command)];
  return {
    // ponytail: the file alone; turned off in macOS's System Settings it still reads as on (as Windows' Task Manager does above). launchctl print-disabled if that matters.
    on: () => existsSync(file),
    set: (on) => {
      if (!on) return rmSync(file, { force: true });
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, content);
    },
  };
}
