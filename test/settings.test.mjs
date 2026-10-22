// Settings file parsing and the LAN address shown for sharing. No network.
import assert from "node:assert";
import { parseSettings, proxyHost, validPort, loginFor, DEFAULTS } from "../dist/settings.js";
import { lanIp } from "../dist/netinfo.js";

assert.deepEqual(parseSettings('{"share":true,"port":8080,"username":"fox","password":"pw"}'), { ...DEFAULTS, share: true, port: 8080, username: "fox", password: "pw" });

// Split rules: each checked like a typed site; bad ones and repeats dropped
const split = (v) => parseSettings(JSON.stringify({ split: v })).split;
assert.deepEqual(
  split({ default: "direct", rules: [{ match: "*.CO.uk", via: "vpn" }, { match: "nope nope", via: "direct" }, { match: "x.ir", via: "maybe" }, { match: "*.co.uk", via: "direct" }, { match: "10.0.0.0/8", via: "direct" }] }),
  { default: "direct", rules: [{ match: "*.co.uk", via: "vpn" }, { match: "10.0.0.0/8", via: "direct" }] },
);
assert.deepEqual(split({ default: "sideways", rules: "all" }), { default: "vpn", rules: [] }, "nonsense: no split");
assert.deepEqual(DEFAULTS.split, { default: "vpn", rules: [] }, "default: everything through the VPN");
assert.deepEqual(parseSettings('{"share":true,"autoConnect":false}'), { ...DEFAULTS, share: true }, "the removed auto connect option is dropped");
assert.deepEqual(parseSettings("not json"), DEFAULTS, "corrupt file: defaults");
assert.deepEqual(parseSettings("null"), DEFAULTS, "null: defaults");
assert.deepEqual(parseSettings('{"share":"yes","port":70000}'), DEFAULTS, "bad values dropped");
assert.deepEqual(parseSettings('{"port":2080}'), { ...DEFAULTS, port: 2080 }, "missing keys default");
assert.ok(validPort(1) && validPort(65535) && !validPort(0) && !validPort(65536) && !validPort(80.5) && !validPort("80"));
assert.equal(proxyHost({ ...DEFAULTS, share: true }), "0.0.0.0");
assert.equal(proxyHost(DEFAULTS), "127.0.0.1");

// The proxy login is asked only from other devices, and only once one is set.
const withLogin = { ...DEFAULTS, username: "fox", password: "pw" };
assert.deepEqual(loginFor(withLogin, "192.168.1.9"), { username: "fox", password: "pw" }, "another device signs in");
for (const here of ["127.0.0.1", "::1", "::ffff:127.0.0.1", undefined]) assert.equal(loginFor(withLogin, here), null, `this computer doesn't (${here})`);
assert.equal(loginFor(DEFAULTS, "192.168.1.9"), null, "no login set: open");
assert.deepEqual(loginFor({ ...DEFAULTS, password: "pw" }, "10.0.0.2"), { username: "", password: "pw" }, "a password alone is a login");

const v4 = (address, internal = false) => ({ family: "IPv4", address, internal });
assert.equal(
  lanIp({ lo: [v4("127.0.0.1", true)], docker0: [v4("172.17.0.1")], tun0: [v4("10.8.0.2")], tailscale0: [v4("100.64.0.3")], wlo1: [v4("192.168.1.20")] }),
  "192.168.1.20",
  "skips loopback, containers and VPNs",
);
assert.equal(lanIp({ en0: [v4("169.254.3.4")], en1: [v4("10.0.0.7")] }), "10.0.0.7", "skips link-local");
assert.equal(lanIp({ lo: [v4("127.0.0.1", true)] }), null, "offline");

console.log("ok - settings parsing and LAN address");
