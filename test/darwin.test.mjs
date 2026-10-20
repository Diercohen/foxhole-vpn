// Pure-function checks for the macOS global-routing parsers. No root, no network.
import assert from "node:assert";
import { parseRouteGet, serviceForDevice, dnsRestoreArgs, macConflictingVpn, parseNetstatDefault, macNeedsRepin } from "../dist/global-darwin.js";

const routeGet = `   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>`;
assert.deepEqual(parseRouteGet(routeGet), { gw: "192.168.0.1", dev: "en0" }, "route get with gateway");
assert.deepEqual(parseRouteGet("  interface: ppp0\n"), { gw: null, dev: "ppp0" }, "route get without gateway");
assert.equal(parseRouteGet("route: writing to routing socket: not in table"), null, "no default");

const services = `An asterisk (*) denotes that a network service is disabled.
(1) 10/100M LAN
(Hardware Port: 10/100M LAN, Device: en6)

(3) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
`;
assert.equal(serviceForDevice(services, "en0"), "Wi-Fi", "device → service");
assert.equal(serviceForDevice(services, "en6"), "10/100M LAN", "service name with spaces");
assert.equal(serviceForDevice(services, "en9"), null, "unknown device");

assert.deepEqual(dnsRestoreArgs("There aren't any DNS Servers set on Wi-Fi.\n"), ["Empty"], "no DNS → Empty");
assert.deepEqual(dnsRestoreArgs("1.1.1.1\n8.8.8.8\n"), ["1.1.1.1", "8.8.8.8"], "manual DNS kept");

const en0 = { gw: "192.168.0.1", dev: "en0" };
assert.ok(!macConflictingVpn("default  192.168.0.1  UGScg  en0\n", en0), "plain uplink ok");
assert.ok(macConflictingVpn("0/1  10.8.0.1  UGSc  utun4\n128.0/1  10.8.0.1  UGSc  utun4\n", en0), "split routes");
assert.ok(macConflictingVpn("", { gw: null, dev: "utun3" }), "default on utun");

// After a Wi-Fi change: the primary default from netstat, past our utun's 0/1 routes.
const netstat = [
  "Routing tables", "", "Internet:",
  "Destination        Gateway            Flags               Netif Expire",
  "0/1                198.18.0.1         UGSc              utun123",
  "default            10.0.0.1           UGScIg                en1",
  "default            192.168.1.1        UGScg                 en0",
  "128.0/1            198.18.0.1         UGSc              utun123",
].join("\n");
assert.deepEqual(parseNetstatDefault(netstat, "utun123"), { gw: "192.168.1.1", dev: "en0" }, "primary default, not the scoped one");
assert.deepEqual(
  parseNetstatDefault("default  192.168.1.1  UGSc  12  0  en0\n", "utun123"),
  { gw: "192.168.1.1", dev: "en0" },
  "older netstat with Refs/Use columns",
);
assert.deepEqual(parseNetstatDefault("default  link#4  UCS  en5\n", "utun123"), { gw: null, dev: "en5" }, "on-link default");
assert.equal(parseNetstatDefault("0/1  198.18.0.1  UGSc  utun123\n", "utun123"), null, "offline: only our routes");

const home = { gw: "192.168.1.1", dev: "en0" };
const viaEn0 = "   route to: 151.101.1.1\n    gateway: 192.168.1.1\n  interface: en0\n";
const viaTun = "   route to: 151.101.1.1\n    gateway: 198.18.0.1\n  interface: utun123\n";
assert.equal(macNeedsRepin(home, home, viaEn0), false, "nothing changed");
assert.equal(macNeedsRepin(home, { gw: "10.0.0.1", dev: "en0" }, viaEn0), true, "new gateway");
assert.equal(macNeedsRepin(home, home, viaTun), true, "pin gone: server routes into the utun");

console.log("ok - macOS routing parsers");
