// Settings file parsing and the LAN address shown for sharing. No network.
import assert from "node:assert";
import { parseSettings, proxyHost, validPort, loginFor, telegramLink, DEFAULTS, onJoin, withNetRule } from "../dist/settings.js";
import { qrModules, qrLines } from "../dist/qr.js";
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

// The optional Apps Script relay (httprelay.ts): kept when both parts are strings, no key otherwise.
assert.deepEqual(parseSettings('{"relay":{"deploymentId":"DID","authKey":"KEY"}}'), { ...DEFAULTS, relay: { deploymentId: "DID", authKey: "KEY" } }, "valid relay kept");
assert.deepEqual(parseSettings('{"relay":{"deploymentId":"DID"}}'), DEFAULTS, "half a relay dropped (no key)");
assert.ok(!("relay" in parseSettings("{}")), "no relay key when unset");
assert.equal(parseSettings('{"proxyOnly":true}').proxyOnly, true, "Proxy only / Global TUN unticked is kept");
assert.ok(!("proxyOnly" in parseSettings('{"proxyOnly":"yes"}')), "else nothing saved: whole-system mode, the default");
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
assert.equal(lanIp({ rmnet_data0: [v4("10.71.2.9")], "v4-rmnet_data0": [v4("192.0.0.4")], ccmni1: [v4("10.8.1.2")], swlan0: [v4("192.168.43.1")] }), "192.168.43.1", "a phone's hotspot, not its mobile data");
assert.equal(lanIp({ lo: [v4("127.0.0.1", true)] }), null, "offline");

// Telegram's proxy links: t.me's for another device, with the login; its own tg:// one for this device
assert.equal(telegramLink("192.168.1.5", 1080), "https://t.me/socks?server=192.168.1.5&port=1080");
assert.equal(telegramLink("192.168.1.5", 1080, { username: "a b", password: "p&q" }), "https://t.me/socks?server=192.168.1.5&port=1080&user=a%20b&pass=p%26q", "the login, encoded");
assert.equal(telegramLink("127.0.0.1", 1189, null, true), "tg://socks?server=127.0.0.1&port=1189");
const link = telegramLink("192.168.1.5", 1080, { username: "bob", password: "s3cret" });
assert.equal(qrLines(link).length, Math.ceil((qrModules(link).length + 4) / 2), "a terminal's QR code: two modules a line, 2-module quiet zone");

// On this network: rules kept as they should be, and what joining a network does
assert.deepEqual(parseSettings(JSON.stringify({ networks: { "Wi-Fi · Home": "pause", "Mobile data": "connect", "Wi-Fi": "pause", "Wi-Fi · name hidden": "connect", "Ethernet (wired)": "maybe" } })).networks,
  { "Wi-Fi · Home": "pause", "Mobile data": "connect" }, "only networks it can tell apart, with a rule there is");
assert.equal("networks" in parseSettings(JSON.stringify({ networks: { Wi: 1 } })), false, "none: no key");
assert.deepEqual(withNetRule({ "Mobile data": "connect" }, "Wi-Fi · Home", "pause"), { "Mobile data": "connect", "Wi-Fi · Home": "pause" });
assert.equal(withNetRule({ "Wi-Fi · Home": "pause" }, "Wi-Fi · Home", null), undefined, "the last one gone: no rules");
const rules = { "Wi-Fi · Home": "pause", "Mobile data": "connect" };
const join = (n, active, paused = false) => onJoin(rules, n, { active, paused });
assert.equal(join("Wi-Fi · Home", true), "pause");
assert.equal(join("Wi-Fi · Home", false), null, "off already");
assert.equal(join("Wi-Fi · Cafe", false, true), "resume", "left the network that paused it");
assert.equal(join("Mobile data", false, true), "resume");
assert.equal(join("Mobile data", false), "connect");
assert.equal(join("Mobile data", true), null, "on already");
assert.equal(join("Wi-Fi · Cafe", false), null, "no rule");
assert.equal(onJoin({ ...rules, "Wi-Fi · Office": "pause" }, "Wi-Fi · Office", { active: false, paused: true }), null, "paused, and another network pausing it: still paused");
for (const n of [null, "Wi-Fi", "Wi-Fi · name hidden"]) assert.equal(join(n, false, true), null, `nothing to go by: ${n}`);
console.log("ok - settings parsing and LAN address, Telegram's links, network rules");
