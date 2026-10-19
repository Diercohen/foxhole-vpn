// Pure-function checks for the macOS global-routing parsers. No root, no network.
import assert from "node:assert";
import { parseRouteGet, serviceForDevice, dnsRestoreArgs, macConflictingVpn } from "../dist/global-darwin.js";

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

console.log("ok - macOS routing parsers");
