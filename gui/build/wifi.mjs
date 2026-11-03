// Builds "Foxhole Wi-Fi.app" (wifi.m), the little app inside Foxhole.app that reads the Wi-Fi's name, which macOS
// shows only to apps allowed Location: it's named Foxhole, so that's who macOS asks about. macOS only; elsewhere a no-op.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

if (process.platform === "darwin") {
  const here = (p) => fileURLToPath(new URL(p, import.meta.url));
  const app = here("Foxhole Wi-Fi.app");
  const version = JSON.parse(readFileSync(here("../../package.json"), "utf8")).version;
  const why = "macOS shows Foxhole your Wi-Fi's name only with Location allowed. Foxhole reads just the name, never where you are.";
  rmSync(app, { recursive: true, force: true });
  mkdirSync(`${app}/Contents/MacOS`, { recursive: true });
  execFileSync("clang", ["-fobjc-arc", "-Os", "-arch", "arm64", "-arch", "x86_64", "-mmacosx-version-min=11", "-framework", "Foundation",
    "-framework", "CoreLocation", "-framework", "CoreWLAN", here("wifi.m"), "-o", `${app}/Contents/MacOS/foxhole-wifi`], { stdio: "inherit" });
  writeFileSync(`${app}/Contents/Info.plist`, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>io.github.diercohen.foxhole.wifi</string>
  <key>CFBundleName</key><string>Foxhole</string>
  <key>CFBundleDisplayName</key><string>Foxhole</string>
  <key>CFBundleExecutable</key><string>foxhole-wifi</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${version}</string>
  <key>CFBundleVersion</key><string>${version}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
  <key>NSLocationUsageDescription</key><string>${why}</string>
  <key>NSLocationWhenInUseUsageDescription</key><string>${why}</string>
</dict></plist>
`);
  execFileSync("codesign", ["--force", "-s", "-", app], { stdio: "inherit" });
}
