// The network helper's root script (helper.ts) run for real by sh, its commands echoed instead of run. No root.
import assert from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { helperScript, installScript } from "../dist/helper.js";
import { PRIVATE_CIDRS, pinCmd, planDirect, planDirectTeardown, planSetup, planStaleCleanup, planTeardown } from "../dist/global.js";

const T2S = "/usr/local/libexec/foxhole/tun2socks";
const script = helperScript()
  .replace(`run() { exec "$@"; }`, `run() { echo "RUN $*"; exit 0; }`)
  .replace(`try() { "$@" 2>/dev/null; }`, `try() { echo "$*"; }`);
assert.notEqual(script, helperScript(), "the test's run and try went in");
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
const inst = installScript(1000, "/home/o'brien/.cache/tun2socks");
assert.ok(inst.includes(`cp '/home/o'\\''brien/.cache/tun2socks' `), "the path quoted for the shell");
assert.ok(inst.includes(`echo '#1000 ALL=(root) NOPASSWD: /usr/local/libexec/foxhole/net' > /etc/sudoers.d/foxhole-1000.new`), "a rule for this uid and script");
assert.ok(inst.indexOf("visudo -cf") < inst.indexOf("mv -f /etc/sudoers.d/foxhole-1000.new"), "checked before it counts");
assert.equal(spawnSync("sh", ["-n", "-c", inst]).status, 0, "the installer parses");

rmSync(dir, { recursive: true });
console.log("ok - network helper");
