// Wi-Fi name parsing for each OS's tool output. No network.
import assert from "node:assert";
import { parseIwDev, parseSsid } from "../dist/netinfo.js";

assert.deepEqual(parseIwDev("phy#0\n\tInterface wlo1\n\t\tifindex 2\nphy#1\n\tInterface wlan1\n"), ["wlo1", "wlan1"], "iw dev");
assert.equal(parseSsid("Connected to 2c:97:b1:a9:06:60 (on wlo1)\n\tSSID: Home 5G\n\tfreq: 5745.0\n"), "Home 5G", "iw link");
assert.equal(parseSsid("Not connected.\n"), null, "iw: not connected");
assert.equal(
  parseSsid("    Name                   : Wi-Fi\n    State                  : connected\n    SSID                   : Cafe\n    BSSID                  : 2c:97:b1:a9:06:60\n"),
  "Cafe",
  "netsh: SSID, not BSSID",
);
assert.equal(parseSsid("    BSSID                  : 2c:97:b1:a9:06:60\n"), null, "netsh: BSSID alone isn't a name");
assert.equal(parseSsid("<dictionary> {\n  SSID : Office\n  Security : WPA2\n"), "Office", "macOS ipconfig getsummary");
assert.equal(parseSsid("  SSID : <redacted>\n"), null, "macOS without location access");
assert.equal(parseSsid("Current Wi-Fi Network: Office\n"), "Office", "macOS networksetup");

console.log("ok - Wi-Fi name parsers");
