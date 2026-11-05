// The network helper's root script (helper.ts) run for real by sh, its commands echoed instead of run. No root.
import assert from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WIN_ALLOWED, helperScript, installScript, winInstall, winScript, winScripts } from "../dist/helper.js";
import { DNS_FLUSH, NRPT_ADD, pinRoute, planStaleCleanup as winStale, ps } from "../dist/global-win32.js";
import { directRoutes } from "../dist/relay.js";
import { useSplit } from "../dist/split.js";
import { PRIVATE_CIDRS, pinCmd, planDirect, planDirectTeardown, planSetup, planStaleCleanup, planTeardown } from "../dist/global.js";

const T2S = "/usr/local/libexec/foxhole/tun2socks";
const script = helperScript("linux")
  .replace(`run() { exec "$@"; }`, `run() { echo "RUN $*"; exit 0; }`)
  .replace(`try() { "$@" 2>/dev/null; }`, `try() { echo "$*"; }`);
assert.notEqual(script, helperScript("linux"), "the test's run and try went in");
const dir = mkdtempSync(join(tmpdir(), "foxhole-helper-"));
const file = join(dir, "net");
writeFileSync(file, script);
const sh = (argv, input = "") => spawnSync("sh", [file, ...argv], { input, encoding: "utf8" });

// Every command a session runs passes as it is, with a gateway and without.
for (const orig of [{ gw: "192.168.0.1", dev: "wlo1" }, { gw: null, dev: "ppp0" }, { gw: "10.0.2.2", dev: "enp0s3.100" }, { gw: "172.20.0.1", dev: "br-1a2b@if3" }]) {
  const pins = ["151.101.1.1", "8.8.8.8"];
  const all = [
    ...planSetup(pins, orig), ...planTeardown(pins), ...planDirect("192.168.0.7", orig), ...planDirectTeardown(), ...planStaleCleanup(orig), ...planStaleCleanup(),
    ...PRIVATE_CIDRS.map((c) => pinCmd(c, orig)), ...PRIVATE_CIDRS.map((c) => ["ip", "route", "del", c]), pinCmd("9.9.9.9", orig, "replace"), ["ip", "route", "del", "9.9.9.9"],
    ["iptables", "-I", "OUTPUT", "-o", "foxhole0", "-p", "udp", "-j", "REJECT"], ["iptables", "-D", "OUTPUT", "-o", "foxhole0", "-p", "udp", "-j", "REJECT"],
    ["resolvectl", "dns", "foxhole0", "198.18.0.1:45123"], ["resolvectl", "domain", "foxhole0", "~."], ["resolvectl", "revert", "foxhole0"],
    [T2S, "--device", "foxhole0", "--proxy", "socks5://127.0.0.1:1080"],
  ];
  for (const argv of all) {
    const r = sh(argv);
    assert.equal(r.stdout, `RUN ${argv.join(" ")}\n`, `${argv.join(" ")}: ${r.stderr}`);
  }
  // The guard undoes exactly what `foxhole restore` does, once its stdin ends.
  const g = sh(["guard", orig.gw ?? "-", orig.dev]);
  assert.equal(g.stdout, planStaleCleanup(orig).map((a) => a.join(" ") + "\n").join(""), "the guard's steps are planStaleCleanup's");
}

// What another program of this user might try: no shell, no other binary, no routes but the session's.
for (const argv of [
  [], ["id"], ["sh", "-c", "id"], ["/bin/sh"], ["ip"], ["ip", "netns", "exec", "x", "sh"], ["ip", "-batch", "/tmp/x"], ["ip", "-force", "-batch", "/tmp/x"],
  ["ip", "route", "add", "default", "via", "1.2.3.4"], ["ip", "route", "replace", "default", "via", "1.2.3.4", "dev", "eth0"], ["ip", "route", "del", "default"],
  ["ip", "route", "replace", "0.0.0.0/0", "dev", "eth0"], ["ip", "route", "replace", "1.2.3.0/24", "dev", "eth0"], ["ip", "route", "add", "1.2.3.4", "dev", "eth0"],
  ["ip", "route", "replace", "1.2.3.4", "dev", "-batch"], ["ip", "route", "replace", "1.2.3.4", "via", "x", "dev", "eth0"], ["ip", "route", "replace", "1.2.3.4", "dev", "eth0", "table", "main"],
  ["ip", "route", "flush", "table", "main"], ["ip", "rule", "add", "from", "all", "lookup", "1080", "priority", "1081"], ["ip", "rule", "del", "priority", "0"], ["ip", "link", "del", "eth0"], ["ip", "link", "set", "dev", "eth0", "down"],
  ["iptables", "-F"], ["iptables", "-I", "OUTPUT", "-j", "DROP"], ["pkill", "-f", "--", "sshd"], ["pkill", "-f", "."],
  ["resolvectl", "dns", "eth0", "1.1.1.1"], ["resolvectl", "dns", "foxhole0", "1.1.1.1:53"], ["resolvectl", "dns", "foxhole0", "53"], ["resolvectl", "revert", "eth0"],
  [T2S], [T2S, "--device", "foxhole0", "--proxy", "socks5://1.2.3.4:1080"], [T2S, "--device", "foxhole0", "--proxy", "1080"], [T2S, "--device", "eth0", "--proxy", "socks5://127.0.0.1:1080"],
  [T2S, "--device", "foxhole0", "--proxy", "socks5://127.0.0.1:1080", "--tun-post-up", "id"], [T2S, "--tun-post-up=id", "foxhole0", "--proxy", "socks5://127.0.0.1:1080"],
  ["/home/me/tun2socks", "--device", "foxhole0", "--proxy", "socks5://127.0.0.1:1080"], ["guard"], ["guard", "- ; id", "eth0"], ["guard", "-", "-eth0"], ["version"], ["version", "0"],
  ["ip", "route", "replace", "1.2.3.4", "dev", "eth0;id"], ["ip", "route", "replace", "1.2.3.4", "dev", "$(id)"], ["ip route add default dev foxhole0 metric 1 ;id"],
]) {
  const r = sh(argv);
  assert.ok(!r.stdout.startsWith("RUN"), `ran: ${argv.join(" ")}`);
  assert.notEqual(r.status, 0, `allowed: ${argv.join(" ")}`);
}

// The installer: a bad rule never counts, the tun2socks path is quoted, the rule names this one script.
const inst = installScript(1000, "/home/o'brien/.cache/tun2socks", "linux");
assert.ok(inst.includes(`cp '/home/o'\\''brien/.cache/tun2socks' `), "the path quoted for the shell");
assert.ok(inst.includes(`echo '#1000 ALL=(root) NOPASSWD: /usr/local/libexec/foxhole/net' > /etc/sudoers.d/foxhole-1000.new`), "a rule for this uid and script");
assert.ok(inst.indexOf("visudo -cf") < inst.indexOf("mv -f /etc/sudoers.d/foxhole-1000.new"), "checked before it counts");
assert.equal(spawnSync("sh", ["-n", "-c", inst]).status, 0, "the installer parses");

// macOS: what global-darwin.ts and relay.ts run
const M = "/Library/PrivilegedHelperTools/foxhole";
const macFile = join(dir, "mac");
writeFileSync(macFile, helperScript("darwin").replace(`run() { exec "$@"; }`, `run() { echo "RUN $*"; exit 0; }`));
const mac = (argv) => spawnSync("sh", [macFile, ...argv], { encoding: "utf8" });
const relayRoutes = [];
const routes = directRoutes(["192.168.1.1"], async (argv) => (relayRoutes.push(argv), true));
useSplit(() => ({ default: "direct", rules: [] }));
await routes.answer("example.com", ["93.184.216.34"]);
await routes.move(["-interface", "en0"]);
await routes.clear();
assert.equal(relayRoutes.length, 3, "the relay added, moved and removed its route");
for (const argv of [
  ...relayRoutes,
  ...["0.0.0.0/1", "128.0.0.0/1"].flatMap((h) => [["route", "-n", "add", "-net", h, "198.18.0.1"], ["route", "-n", "delete", "-net", h]]),
  ...["::/1", "8000::/1"].flatMap((h) => [["route", "-n", "add", "-inet6", "-net", h, "::1", "-reject"], ["route", "-n", "delete", "-inet6", "-net", h]]),
  ...PRIVATE_CIDRS.flatMap((c) => [["route", "-n", "add", "-net", c, "192.168.1.1"], ["route", "-n", "add", "-net", c, "-interface", "en0"], ["route", "-n", "delete", "-net", c]]),
  ["route", "-n", "add", "-host", "151.101.1.1", "192.168.1.1"], ["route", "-n", "add", "-host", "151.101.1.1", "-interface", "utun4"], ["route", "-n", "delete", "-host", "151.101.1.1"],
  ["ifconfig", "utun123", "198.18.0.1", "198.18.0.1", "up"], [`${M}/tun2socks`, "--device", "utun123", "--proxy", "socks5://127.0.0.1:1080"],
  ["networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"], ["networksetup", "-setdnsservers", "USB 10/100/1000 LAN", "Empty"], ["networksetup", "-setdnsservers", "Wi-Fi", "192.168.1.1", "fe80::1"],
  ["killall", "-HUP", "mDNSResponder"], ["pkill", "-f", "utun12[3]"], ["pkill", "-f", "foxhole-dn[s]"],
]) {
  const r = mac(argv);
  assert.equal(r.stdout, `RUN ${argv.join(" ")}\n`, `${argv.join(" ")}: ${r.stderr}`);
}
for (const argv of [
  [], ["id"], ["sh", "-c", "id"], ["env", "ELECTRON_RUN_AS_NODE=1", "/Applications/Foxhole.app/Contents/MacOS/Foxhole", "-e", "1"], ["/usr/bin/node", "-e", "1"],
  ["route", "-n", "add", "-net", "0.0.0.0/0", "1.2.3.4"], ["route", "-n", "add", "-net", "1.2.3.0/24", "1.2.3.4"], ["route", "add", "-host", "1.2.3.4", "1.1.1.1"], ["route", "-n", "flush"], ["route", "-n", "delete", "default"],
  ["route", "-n", "add", "-host", "1.2.3.4"], ["route", "-n", "add", "-host", "1.2.3.4", "1.1.1.1", "-ifscope", "en0"], ["route", "-n", "add", "-host", "1.2.3.4", "-interface", "-x"],
  ["networksetup", "-setairportpower", "en0", "off"], ["networksetup", "-setdnsservers", "Wi-Fi"], ["networksetup", "-setdnsservers", "-x", "1.1.1.1"], ["networksetup", "-setdnsservers", "Wi-Fi", "$(id)"], ["networksetup", "-setdnsservers", "Wi-Fi", "1.1.1.1; id"],
  ["ifconfig", "en0", "down"], ["ifconfig", "utun123", "1.2.3.4", "1.2.3.4", "up"], ["killall", "Finder"], ["pkill", "-f", "."],
  [`${M}/tun2socks`, "--device", "utun123", "--proxy", "socks5://1.2.3.4:1080"], [`${M}/tun2socks`, "--device", "utun123", "--proxy", "socks5://127.0.0.1:1", "--tun-post-up", "id"], ["/Users/me/tun2socks", "--device", "utun123", "--proxy", "socks5://127.0.0.1:1"],
  ["guard", "-", "en0"], ["version"], ["version", "0"],
]) {
  const r = mac(argv);
  assert.ok(!r.stdout.startsWith("RUN"), `ran: ${argv.join(" ")}`);
  assert.notEqual(r.status, 0, `allowed: ${argv.join(" ")}`);
}
const macInst = installScript(501, "/Users/me/.cache/foxhole-vpn/tun2socks", "darwin");
assert.ok(macInst.includes(`echo '#501 ALL=(root) NOPASSWD: ${M}/net' > /etc/sudoers.d/foxhole-501.new`), "macOS: a rule for this uid and script");
assert.equal(spawnSync("sh", ["-n", "-c", macInst]).status, 0, "macOS: the installer parses");

// Windows: the helper's checks are .NET regexes in PowerShell; these patterns mean the same to JavaScript, with \z as $.
const winPatterns = WIN_ALLOWED.map((r) => new RegExp(r.replaceAll("\\z", "$")));
const winOk = (argv) => argv.every((a) => /^[A-Za-z0-9.\/:=_-]+$/.test(a)) && winPatterns.some((r) => r.test(argv.join(" ")));
const up = { ifIndex: 12, gw: "192.168.1.1" };
for (const argv of [
  pinRoute("add", "151.101.1.1", up), pinRoute("delete", "151.101.1.1", up), pinRoute("add", "10.0.0.0/8", up), pinRoute("delete", "100.64.0.0/10", up), pinRoute("add", "9.9.9.9", { ifIndex: 3, gw: null }),
  ...["0.0.0.0/1", "128.0.0.0/1"].flatMap((h) => [["netsh", "interface", "ipv4", "add", "route", `prefix=${h}`, "interface=foxhole0", "metric=1", "store=active"], ["netsh", "interface", "ipv4", "delete", "route", `prefix=${h}`, "interface=foxhole0", "store=active"]]),
  ["netsh", "interface", "ipv4", "set", "address", "name=foxhole0", "source=static", "address=198.18.0.1", "mask=255.254.0.0"], ["netsh", "interface", "ipv4", "set", "interface", "interface=foxhole0", "metric=1"],
  ["netsh", "advfirewall", "firewall", "add", "rule", "name=foxhole-vpn", "dir=out", "action=block", "protocol=any", "remoteip=2000::/3"], ["netsh", "advfirewall", "firewall", "add", "rule", "name=foxhole-vpn", "dir=out", "action=block", "protocol=UDP", "remoteport=443"],
  winStale()[1], ["taskkill", "/F", "/IM", "tun2socks.exe"],
]) assert.ok(winOk(argv), `refused: ${argv.join(" ")}`);
for (const argv of [
  ["cmd", "/c", "whoami"], ["powershell.exe", "-c", "id"], ["netsh", "interface", "ipv4", "add", "route", "prefix=0.0.0.0/0", "interface=12", "store=active"], ["netsh", "interface", "ipv4", "add", "route", "prefix=1.2.3.0/24", "interface=12", "store=active"],
  ["netsh", "advfirewall", "set", "allprofiles", "state", "off"], ["netsh", "advfirewall", "firewall", "delete", "rule", "name=all"], ["netsh", "advfirewall", "firewall", "add", "rule", "name=x", "dir=in", "action=allow"],
  ["netsh", "interface", "ipv4", "set", "address", "name=Ethernet", "source=dhcp"], ["taskkill", "/F", "/IM", "explorer.exe"],
  ["netsh", "interface", "ipv4", "add", "route", "prefix=1.2.3.4/32", "interface=12", "store=active", "&", "whoami"], ["netsh", "interface", "ipv4", "add", "route", "prefix=1.2.3.4/32", "interface=12", "store=active\n"],
]) assert.ok(!winOk(argv), `allowed: ${argv.join(" ")}`);
for (const line of [ps(NRPT_ADD), winStale()[0], ps(DNS_FLUSH)]) assert.ok(winScripts().includes(line.at(-1)), `not in the helper: ${line.at(-1)}`);
const sid = "S-1-5-21-1-2-3-1001";
const winFull = winInstall(sid, "C:\\Users\\o'brien\\.cache\\foxhole-vpn\\tun2socks.exe");
assert.ok(!winFull.includes('"foxhole"') && winFull.includes("C:\\Users\\o''brien"), "the install's path quoted for PowerShell");
assert.ok(winFull.includes(`(A;;GRGX;;;${sid})`), "only this user may start the task");
const winNet = winScript("foxhole-net-x");
for (const r of ["'^[A-Za-z0-9./:=_-]+\\z'", "-match '\\s'", "'^socks5://127\\.0\\.0\\.1:\\d+\\z'"]) assert.ok(winNet.includes(r), `in the script as a regex: ${r}`);
assert.ok(winFull.length < 32_000, `the install fits a command line: ${winFull.length}`);

rmSync(dir, { recursive: true });
console.log("ok - network helper");
