// Pure-function checks for the global-routing planner. No root, no network.
import assert from "node:assert";
import { parseDefaultRoute, isVpnDev, planSetup, planTeardown, conflictingVpn, needsRepin, pinCmd, dialHost } from "../dist/global.js";

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

// Setup pins every bypass IP (VPN server + DNS resolvers) via the real uplink,
// then routes the default through the tun.
const setup = planSetup(["151.101.1.1", "8.8.8.8"], { gw: "192.168.0.1", dev: "wlo1" });
assert.deepEqual(
  setup.find((c) => c[3] === "151.101.1.1"),
  ["ip", "route", "add", "151.101.1.1", "via", "192.168.0.1", "dev", "wlo1"],
  "server IP pinned via real gateway",
);
assert.deepEqual(
  setup.find((c) => c[3] === "8.8.8.8"),
  ["ip", "route", "add", "8.8.8.8", "via", "192.168.0.1", "dev", "wlo1"],
  "DNS resolver pinned via real gateway",
);
assert.ok(
  setup.some((c) => c.join(" ") === "ip route add default dev foxhole0 metric 1"),
  "default routed through tun",
);

// Gateway-less uplink pins bypass IPs by device only.
const setupNoGw = planSetup(["151.101.1.1"], { gw: null, dev: "ppp0" });
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

// Teardown removes the default, every pin, and the IPv6 blackhole.
const teardown = planTeardown(["151.101.1.1", "8.8.8.8"]);
assert.ok(teardown.some((c) => c.join(" ") === "ip route del default dev foxhole0 metric 1"), "default removed");
assert.ok(teardown.some((c) => c.join(" ") === "ip route del 151.101.1.1"), "server pin removed");
assert.ok(teardown.some((c) => c.join(" ") === "ip route del 8.8.8.8"), "DNS pin removed");
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

// After a Wi-Fi change: find the real uplink past our own tun default (metric 1, listed first).
assert.deepEqual(
  parseDefaultRoute("default dev foxhole0 metric 1\ndefault via 10.0.0.1 dev wlo1 proto dhcp metric 600\n", "foxhole0"),
  { gw: "10.0.0.1", dev: "wlo1" },
  "tun default skipped",
);
assert.equal(parseDefaultRoute("default dev foxhole0 metric 1\n", "foxhole0"), null, "only the tun: network down");

// Re-pin when the uplink moved, the server routes into the tun, or DNS was reset.
const okRoute = "151.101.1.1 via 192.168.0.1 dev wlo1 src 192.168.0.103 uid 1000\n    cache";
const tunRoute = "151.101.1.1 dev foxhole0 src 198.18.0.1 uid 1000\n    cache";
const ourDns = "Link 3 (wlo1): 127.0.0.1:41234";
assert.equal(needsRepin(wlo1, wlo1, okRoute, ourDns, 41234), false, "nothing changed");
assert.equal(needsRepin(wlo1, wlo1, okRoute, null, 0), false, "nothing changed, direct DNS");
assert.equal(needsRepin(wlo1, { gw: "10.0.0.1", dev: "wlo1" }, okRoute, ourDns, 41234), true, "new gateway, same device");
assert.equal(needsRepin(wlo1, { gw: "192.168.0.1", dev: "eth0" }, okRoute, ourDns, 41234), true, "new device");
assert.equal(needsRepin(wlo1, wlo1, tunRoute, ourDns, 41234), true, "pin deleted: server goes into the tun");
assert.equal(needsRepin(wlo1, wlo1, okRoute, "Link 3 (wlo1): 192.168.0.1", 41234), true, "network manager reset DNS");
assert.equal(needsRepin(wlo1, wlo1, okRoute, ourDns, 4123), true, "another port isn't ours, even as a prefix");
assert.equal(dialHost("0.0.0.0"), "127.0.0.1", "listen-on-all is dialed on loopback");
assert.equal(dialHost("127.0.0.1"), "127.0.0.1");
assert.deepEqual(pinCmd("10.0.0.0/8", wlo1), ["ip", "route", "add", "10.0.0.0/8", "via", "192.168.0.1", "dev", "wlo1"]);

console.log("ok - global routing planner builds correct ip command sequences");
