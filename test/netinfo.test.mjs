// Wi-Fi name parsing for each OS's tool output, and the network row. No network.
import assert from "node:assert";
import { parseIwDev, parseSsid, parseNmcliWifi, unescapeIw, describeNetwork, firewallCommands, ipIn } from "../dist/netinfo.js";

// Sharing the proxy: the command that opens its port in whichever firewall is on.
assert.deepEqual(firewallCommands(true, null, 1080), ["sudo firewall-cmd --permanent --add-port=1080/tcp", "sudo firewall-cmd --reload"], "firewalld (Fedora)");
assert.deepEqual(firewallCommands(false, "# comment\nENABLED=yes\nLOGLEVEL=low\n", 2080), ["sudo ufw allow 2080/tcp"], "ufw turned on");
assert.equal(firewallCommands(false, "ENABLED=no\n", 1080), null, "ufw installed but off (Ubuntu's default)");
assert.equal(firewallCommands(false, null, 1080), null, "no firewall");

// NetworkManager (Ubuntu): the in-use network is starred; terse mode escapes ":" and "\".
assert.equal(parseNmcliWifi(" :Neighbor\n*:Home 5G\n :\n"), "Home 5G", "nmcli: the starred one");
assert.equal(parseNmcliWifi("*:Cafe\\:Guest\\\\2\n"), "Cafe:Guest\\2", "nmcli: escapes undone");
assert.equal(parseNmcliWifi("*:خانه\n"), "خانه", "nmcli: a Persian name, as is");
assert.equal(parseNmcliWifi(" :Neighbor\n"), null, "nmcli: not connected");
assert.equal(parseNmcliWifi(""), null, "no nmcli");
// iw escapes every non-ASCII byte: a Persian name comes back readable.
assert.equal(unescapeIw("\\xd8\\xae\\xd8\\xa7\\xd9\\x86\\xd9\\x87"), "خانه", "iw: UTF-8 bytes");
assert.equal(unescapeIw("Home 5G"), "Home 5G", "iw: plain ASCII untouched");
assert.equal(unescapeIw("\\x20Lab\\x5c1"), " Lab\\1", "iw: edge space and backslash");

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

// The exit IP: ipify answers with it alone; relay mode reads it from Cloudflare's trace
assert.equal(ipIn("1.2.3.4\n", false), "1.2.3.4");
assert.equal(ipIn("fl=1\nh=www.cloudflare.com\nip=34.116.28.199\nts=1\nloc=US\n", true), "34.116.28.199");
assert.equal(ipIn("<html>blocked</html>", true), null, "not a trace");

console.log("ok - Wi-Fi name parsers, network row");
