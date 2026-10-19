// Pure-function checks for the Windows global-routing planner. No admin, no network.
import assert from "node:assert";
import { parseWinUplink, isWinVpnAdapter, winConflictingVpn, pinRoute, planStaleCleanup } from "../dist/global-win32.js";

// Find-NetRoute's uplink, as UPLINK_PS prints it.
const eth = parseWinUplink('{"ifIndex":7,"alias":"Ethernet","gw":"10.211.55.1","desc":"Parallels VirtIO Ethernet Adapter","split":0}');
assert.deepEqual(eth, { ifIndex: 7, alias: "Ethernet", desc: "Parallels VirtIO Ethernet Adapter", gw: "10.211.55.1", split: 0 }, "uplink with gateway");
assert.equal(parseWinUplink('{"ifIndex":12,"alias":"PPP","gw":"0.0.0.0","desc":"","split":0}').gw, null, "on-link route has no gateway");
assert.equal(parseWinUplink(""), null, "no route (offline)");
assert.equal(parseWinUplink("not json"), null, "garbage");

assert.ok(isWinVpnAdapter("foxhole0", "Wintun Userspace Tunnel"), "wintun flagged");
assert.ok(isWinVpnAdapter("Ethernet 3", "TAP-Windows Adapter V9"), "OpenVPN TAP flagged");
assert.ok(isWinVpnAdapter("wg0", "WireGuard Tunnel"), "WireGuard flagged");
assert.ok(!isWinVpnAdapter("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz"), "Wi-Fi not flagged");
assert.ok(!isWinVpnAdapter("Ethernet", "Realtek PCIe GbE Family Controller"), "Ethernet not flagged");

assert.ok(!winConflictingVpn(eth), "plain uplink is fine");
assert.ok(winConflictingVpn({ ...eth, split: 2 }), "0/1 split routes conflict");
assert.ok(winConflictingVpn({ ...eth, alias: "NordLynx", desc: "NordLynx Tunnel" }), "VPN uplink conflicts");

// Pins go via the real gateway on the uplink's interface, active-only (gone on reboot).
assert.deepEqual(
  pinRoute("add", "151.101.1.1", eth),
  ["netsh", "interface", "ipv4", "add", "route", "prefix=151.101.1.1/32", "interface=7", "nexthop=10.211.55.1", "store=active"],
  "server IP pinned via gateway",
);
assert.deepEqual(
  pinRoute("delete", "10.0.0.0/8", { ifIndex: 12, gw: null }),
  ["netsh", "interface", "ipv4", "delete", "route", "prefix=10.0.0.0/8", "interface=12", "store=active"],
  "on-link pin has no nexthop",
);

// Cleanup removes the tagged NRPT rule and firewall rules.
const cleanup = planStaleCleanup().map((a) => a.join(" "));
assert.ok(cleanup.some((c) => c.includes("Remove-DnsClientNrptRule") && c.includes("'foxhole-vpn'")), "NRPT rule removed");
assert.ok(cleanup.includes("netsh advfirewall firewall delete rule name=foxhole-vpn"), "firewall rules removed");

console.log("ok - Windows routing planner");
