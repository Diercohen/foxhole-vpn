// Pure-function checks for the global-routing planner. No root, no network.
import assert from "node:assert";
import { parseDefaultRoute, isVpnDev, planSetup, planTeardown, conflictingVpn } from "../dist/global.js";

// Real-world `ip route` with a DHCP default plus extra routes.
const r1 = parseDefaultRoute(
  "default via 192.168.0.1 dev wlo1 proto dhcp src 192.168.0.103 metric 600\n" +
    "10.0.0.0/8 dev eth0 scope link",
);
assert.deepEqual(r1, { gw: "192.168.0.1", dev: "wlo1" }, "default via gw");

// Point-to-point default with no gateway.
assert.deepEqual(parseDefaultRoute("default dev ppp0\n"), { gw: null, dev: "ppp0" }, "default no gw");

// No default route at all.
assert.equal(parseDefaultRoute("10.0.0.0/8 dev eth0\n"), null, "no default");

assert.ok(isVpnDev("tun0") && isVpnDev("wg0") && isVpnDev("proton0"), "vpn devs flagged");
assert.ok(!isVpnDev("wlo1") && !isVpnDev("eth0"), "real devs not flagged");

// Setup pins the server IP via the original uplink, then defaults via the tun.
const setup = planSetup("151.101.1.1", { gw: "192.168.0.1", dev: "wlo1" });
assert.deepEqual(
  setup.find((c) => c[2] === "add" && c[3] === "151.101.1.1"),
  ["ip", "route", "add", "151.101.1.1", "via", "192.168.0.1", "dev", "wlo1"],
  "server IP pinned via real gateway",
);
assert.ok(
  setup.some((c) => c.join(" ") === "ip route add default dev foxhole0 metric 1"),
  "default routed through tun",
);

// Gateway-less uplink pins the server IP by device only.
const setupNoGw = planSetup("151.101.1.1", { gw: null, dev: "ppp0" });
assert.deepEqual(
  setupNoGw.find((c) => c[3] === "151.101.1.1"),
  ["ip", "route", "add", "151.101.1.1", "dev", "ppp0"],
  "server IP pinned by device",
);

// IPv6 is blackholed so apps can't leak around the v4-only tunnel.
assert.ok(
  setup.some((c) => c.join(" ") === "ip -6 route add blackhole default metric 1"),
  "IPv6 blackholed on setup",
);

// Teardown removes the default, the pin, and the IPv6 blackhole.
const teardown = planTeardown("151.101.1.1");
assert.ok(teardown.some((c) => c.join(" ") === "ip route del default dev foxhole0 metric 1"), "default removed");
assert.ok(teardown.some((c) => c.join(" ") === "ip route del 151.101.1.1"), "pin removed");
assert.ok(teardown.some((c) => c.join(" ") === "ip -6 route del blackhole default metric 1"), "IPv6 restored");

// A VPN on the default device, or 0/1 split routes, is detected as conflicting.
const wlo1 = { gw: "192.168.0.1", dev: "wlo1" };
assert.equal(conflictingVpn("default via 192.168.0.1 dev wlo1\n", wlo1), false, "plain uplink is fine");
assert.equal(conflictingVpn("default via 10.0.0.1 dev tun0\n", { gw: "10.0.0.1", dev: "tun0" }), true, "vpn dev conflicts");
assert.equal(
  conflictingVpn("0.0.0.0/1 via 10.136.12.1 dev tun0\ndefault via 192.168.0.1 dev wlo1\n", wlo1),
  true,
  "0/1 split route conflicts even when default looks normal",
);

console.log("ok - global routing planner builds correct ip command sequences");
