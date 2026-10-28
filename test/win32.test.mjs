// Pure-function checks for the Windows global-routing planner, and the elevated helper's pipe. No admin, no network.
import assert from "node:assert";
import net from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseWinUplink, isWinVpnAdapter, winConflictingVpn, pinRoute, planStaleCleanup, watchPs, parseWinWatch, winNeedsRepin, pipePriv, serveElevated } from "../dist/global-win32.js";
import { logLines } from "../dist/log.js";

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

// After a Wi-Fi change: the uplink past our adapter, and where the VPN server routes now.
assert.ok(!watchPs("151.101.1.1").includes('"'), "watch script uses single quotes only");
assert.ok(watchPs("151.101.1.1").includes("-ne 'foxhole0'"), "watch skips our adapter");
const w = parseWinWatch('{"ifIndex":12,"alias":"Wi-Fi","gw":"192.168.1.1","via":"Wi-Fi"}');
assert.deepEqual(w, { up: { ifIndex: 12, alias: "Wi-Fi", desc: "", gw: "192.168.1.1", split: 0 }, via: "Wi-Fi" });
assert.equal(parseWinWatch(""), null, "offline");
assert.equal(winNeedsRepin(w.up, w), false, "nothing changed");
assert.equal(winNeedsRepin(w.up, { ...w, up: { ...w.up, gw: "10.0.0.1" } }), true, "new gateway, same adapter");
assert.equal(winNeedsRepin(w.up, { ...w, up: { ...w.up, ifIndex: 7 } }), true, "new adapter");
assert.equal(winNeedsRepin(w.up, { ...w, via: "foxhole0" }), true, "pin gone: server routes into our adapter");

console.log("ok - Windows routing planner");

// The helper's pipe, both ends in this process (a Unix socket off Windows), running node in place of netsh and tun2socks.
const pipe = process.platform === "win32" ? `\\\\.\\pipe\\foxhole-test-${process.pid}` : join(tmpdir(), `foxhole-test-${process.pid}.sock`);
const server = net.createServer();
await new Promise((r) => server.listen(pipe, r));
const node = (js) => [process.execPath, "-e", js];
const until = async (f, what) => {
  // a node start can take seconds on a cold Windows VM
  for (const end = Date.now() + 15_000; !f(); await new Promise((r) => setTimeout(r, 20))) if (Date.now() > end) throw new Error(`timed out: ${what}`);
};
const connect = async () => {
  const accepted = new Promise((r) => server.once("connection", r));
  const helper = serveElevated(pipe);
  const sock = await accepted;
  return { helper, sock, priv: pipePriv(sock) };
};

let { helper, sock, priv } = await connect();
await priv.run(node("process.exit(0)"));
await assert.rejects(priv.run(node("process.exit(3)")), /process\.exit\(3\) →/, "a failed command rejects, naming it");
await priv.run(node("process.exit(3)"), true); // quiet: a failure resolves
const kid = priv.spawn(node("console.error('hello from the helper'); setInterval(() => {}, 1000)"));
await until(() => logLines.some((l) => l.includes("hello from the helper")), "child's stderr in the log");
const exited = new Promise((r) => kid.once("exit", (...exit) => r(exit)));
assert.equal(kid.exitCode, null, "running");
kid.kill("SIGTERM");
assert.deepEqual(await exited, [null, "SIGTERM"], "killed through the helper");
assert.equal(kid.signalCode, "SIGTERM");
priv.close();
await helper; // a clean close ends the helper
assert.ok(sock.destroyed || !sock.writable, "pipe closed");

// The app killed with a child still running: the helper kills it, then cleans up (planStaleCleanup, quiet here).
({ helper, sock, priv } = await connect());
const orphan = priv.spawn(node("console.error('orphan ' + process.pid); setInterval(() => {}, 1000)"));
let pid = 0;
await until(() => (pid = Number(logLines.map((l) => l.match(/orphan (\d+)/)?.[1]).find(Boolean) ?? 0)), "orphan's pid");
sock.destroy();
await helper;
await until(() => { try { return !process.kill(pid, 0); } catch { return true; } }, "orphan killed");
assert.equal(orphan.signalCode, "SIGKILL", "the app counts the helper's children as gone with it");
await assert.rejects(priv.run(node("0")), /admin helper stopped/, "commands fail once the helper is gone");
await priv.run(node("0"), true); // quiet ones don't wait for it
server.close();

console.log("ok - elevated helper's pipe");
