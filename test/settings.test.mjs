// Settings file parsing and the LAN address shown for sharing. No network.
import assert from "node:assert";
import { parseSettings, proxyHost, validPort, DEFAULTS } from "../dist/settings.js";
import { lanIp } from "../dist/netinfo.js";

assert.deepEqual(parseSettings('{"share":true,"port":8080,"autoConnect":true}'), { share: true, port: 8080, autoConnect: true });
assert.deepEqual(parseSettings("not json"), DEFAULTS, "corrupt file: defaults");
assert.deepEqual(parseSettings("null"), DEFAULTS, "null: defaults");
assert.deepEqual(parseSettings('{"share":"yes","port":70000}'), DEFAULTS, "bad values dropped");
assert.deepEqual(parseSettings('{"port":2080}'), { ...DEFAULTS, port: 2080 }, "missing keys default");
assert.ok(validPort(1) && validPort(65535) && !validPort(0) && !validPort(65536) && !validPort(80.5) && !validPort("80"));
assert.equal(proxyHost({ ...DEFAULTS, share: true }), "0.0.0.0");
assert.equal(proxyHost(DEFAULTS), "127.0.0.1");

const v4 = (address, internal = false) => ({ family: "IPv4", address, internal });
assert.equal(
  lanIp({ lo: [v4("127.0.0.1", true)], docker0: [v4("172.17.0.1")], tun0: [v4("10.8.0.2")], tailscale0: [v4("100.64.0.3")], wlo1: [v4("192.168.1.20")] }),
  "192.168.1.20",
  "skips loopback, containers and VPNs",
);
assert.equal(lanIp({ en0: [v4("169.254.3.4")], en1: [v4("10.0.0.7")] }), "10.0.0.7", "skips link-local");
assert.equal(lanIp({ lo: [v4("127.0.0.1", true)] }), null, "offline");

console.log("ok - settings parsing and LAN address");
