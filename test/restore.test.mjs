// foxhole restore: what it removes on macOS, and who holds the proxy's port on each system
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { planMacRestore } from "../dist/global-darwin.js";
import { parseWinListen, parseSsPids, isFoxhole, portHolders, freePort } from "../dist/restore.js";

// macOS, a global session killed: its rows (as seen on 2026-11-03), a LAN's own, and another VPN's ::/1
const inet = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                198.18.0.1         UGScg             utun123
default            192.168.0.1        UGScg                 en0
10                 192.168.0.1        UGSc                  en0
10.211.55/24       link#30            UC              bridge100      !
100.64/10          192.168.0.1        UGSc                  en0
128.0/1            198.18.0.1         UGSc              utun123
172.16/12          192.168.0.1        UGSc                  en0
192.168.0          link#11            UCS                   en0      !
192.168.0/16       192.168.0.1        UGSc                  en0
192.168.0.146      a6:3d:ed:ef:6a:57  UHLWI                 en0      !
`;
const inet6 = `Internet6:
Destination                             Gateway                                 Flags               Netif Expire
::/1                                    ::1                                     UGRSc                 lo0
8000::/1                                fe80::1%utun4                           UGSc                utun4
`;
const plan = planMacRestore(inet, inet6, { gw: "192.168.0.1", dev: "en0" }, { "Wi-Fi": "127.0.0.1\n", Ethernet: "There aren't any DNS Servers set on Ethernet.\n", USB: "1.1.1.1\n" });
assert.deepEqual(plan, [
  ["pkill", "-f", "utun12[3]"],
  ["pkill", "-f", "foxhole-dn[s]"],
  ["route", "-n", "delete", "-net", "0.0.0.0/1"],
  ["route", "-n", "delete", "-net", "10.0.0.0/8", "192.168.0.1"],
  ["route", "-n", "delete", "-net", "100.64.0.0/10", "192.168.0.1"],
  ["route", "-n", "delete", "-net", "128.0.0.0/1"],
  ["route", "-n", "delete", "-net", "172.16.0.0/12", "192.168.0.1"],
  ["route", "-n", "delete", "-net", "192.168.0.0/16", "192.168.0.1"],
  ["route", "-n", "delete", "-inet6", "-net", "::/1"], // not 8000::/1: another VPN's, on its own utun
  ["networksetup", "-setdnsservers", "Wi-Fi", "Empty"], // only the service still pointed at the dead relay
  ["killall", "-HUP", "mDNSResponder"],
]);
// nothing left behind: only the processes and the DNS cache
assert.equal(planMacRestore("default 192.168.0.1 UGScg en0\n", "", { gw: "192.168.0.1", dev: "en0" }, { "Wi-Fi": "1.1.1.1" }).length, 3);

// Windows' netstat: the listener on 1080 (v4 and v6, one pid), not a connection from it nor port 10800
assert.deepEqual(parseWinListen(`
  TCP    0.0.0.0:1080           0.0.0.0:0              LISTENING       4242
  TCP    0.0.0.0:10800          0.0.0.0:0              LISTENING       7
  TCP    127.0.0.1:50000        127.0.0.1:1080         ESTABLISHED     99
  TCP    [::]:1080              [::]:0                 LISTENING       4242
`, 1080), [4242]);
// Linux ss: a named listener, and another user's (no pid shown)
assert.deepEqual(parseSsPids('LISTEN 0 511 0.0.0.0:1080 0.0.0.0:* users:(("node",pid=123,fd=21))\nLISTEN 0 511 [::]:1080 [::]:*\n'), [123, 0]);
assert.ok(isFoxhole("/Applications/Foxhole.app/Contents/MacOS/Foxhole"));
assert.ok(isFoxhole("node /home/u/.nvm/versions/node/v22/lib/node_modules/foxhole-vpn/dist/cli.js"));
assert.ok(!isFoxhole("/usr/bin/python3 -m http.server 1080"));

// live, on this system's own tables: a program that isn't Foxhole is left running; a Foxhole is stopped
const listener = (name) =>
  new Promise((resolve) => {
    const c = spawn(process.execPath, ["-e", "const s = require('net').createServer().listen(0, '0.0.0.0', () => console.log(s.address().port))", name]);
    c.stdout.once("data", (d) => resolve({ c, port: Number(String(d).trim()) }));
  });
const other = await listener("plain");
assert.deepEqual((await portHolders(other.port)).map((h) => h.pid), [other.c.pid], `${process.platform}: the listener on ${other.port}`);
assert.equal(await freePort(other.port, () => {}), false);
assert.equal(other.c.exitCode, null, "not Foxhole: left running");
other.c.kill();
const fox = await listener("foxhole-test");
const said = [];
assert.equal(await freePort(fox.port, (l) => said.push(l)), true, said.join("\n"));
const exited = fox.c.exitCode !== null || fox.c.signalCode !== null || (await Promise.race([new Promise((r) => fox.c.once("exit", () => r(true))), new Promise((r) => setTimeout(r, 3000, false))]));
assert.ok(exited, "a Foxhole: stopped"); // (its exit is told a moment after it's gone: Windows ends it at once)
console.log("ok - foxhole restore: macOS's leftovers, and who holds the proxy's port");
