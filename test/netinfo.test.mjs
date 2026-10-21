// Wi-Fi name parsing for each OS's tool output, and the network row. No network.
import assert from "node:assert";
import { parseIwDev, parseSsid, describeNetwork } from "../dist/netinfo.js";

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

assert.equal(describeNetwork("Home 5G", "en0"), "Wi-Fi · Home 5G", "on Wi-Fi");
assert.equal(describeNetwork(null, "en5"), "Ethernet (wired)", "macOS USB Ethernet");
assert.equal(describeNetwork(null, "enp3s0"), "Ethernet (wired)", "Linux Ethernet");
assert.equal(describeNetwork(null, "wlp2s0"), "Wi-Fi", "Linux Wi-Fi, no iw to name it");
assert.equal(describeNetwork(null, "Wi-Fi"), "Wi-Fi", "Windows Wi-Fi, name needs location access");
assert.equal(describeNetwork(null, undefined), null, "offline");

console.log("ok - Wi-Fi name parsers, network row");
