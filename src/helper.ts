// Whole-system mode without a password each time (Linux, macOS): how Windscribe and others do it, in one script. The
// password is asked once; with it, a root-owned script and a sudoers rule for it go in, and from then on sudo runs that
// script with no password. No daemon: nothing runs until whole-system mode does.
//
// The script is what makes this safe, not a detail: sudo gives any program of this user the script as root, so it only
// runs the exact commands a session needs (global.ts's and global-darwin.ts's, kept in step by test/helper.test.mjs),
// never a command or a tun2socks of the caller's. What's left to a program of this user: sending this computer's traffic
// through a SOCKS proxy on this computer, adding host routes, and (macOS) choosing the DNS server. Nothing that reaches a
// root shell. On macOS no JavaScript runs as root with it either: the DNS relay stays the user's (global-darwin.ts).
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { sudoPriv, type Priv } from "./global.js";
import { log, logStream } from "./log.js";

// macOS: /usr/local can be the user's own there (Homebrew), and a folder in a user's folder could be swapped
const dirOf = (platform: string) => (platform === "darwin" ? "/Library/PrivilegedHelperTools/foxhole" : "/usr/local/libexec/foxhole");
const NET = `${dirOf(process.platform)}/net`;
const T2S = `${dirOf(process.platform)}/tun2socks`;
const VERSION = "1"; // raised when the script changes: the next whole-system mode asks once, to put the new one in
const SUPPORTED = process.platform === "linux" || process.platform === "darwin";

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** What every platform's root script starts with. Each argument is checked before anything runs; refused: exit 126. `run` and `try` are replaced in its test. */
const preamble = (net: string) => `#!/bin/sh
# Foxhole's network helper: what whole-system mode runs as root, with no password. Only the commands below.
# Off: Foxhole's Settings, or: sudo ${net} uninstall
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
IFS=' '
run() { exec "$@"; }
try() { "$@" 2>/dev/null; }

no() { echo "foxhole helper: refused" >&2; exit 126; }
ip4() { case "$1" in ""|*[!0-9.]*) return 1;; *.*.*.*) return 0;; *) return 1;; esac; }
dev() { case "$1" in ""|-*|*[!A-Za-z0-9._@-]*) return 1;; esac; }
num() { case "$1" in ""|*[!0-9]*) return 1;; esac; }
# $1 is $2, then a port
port() { case "$1" in "$2"*) num "\${1#"$2"}" ;; *) return 1 ;; esac; }
private() { case "$1" in 10.0.0.0/8|172.16.0.0/12|192.168.0.0/16|100.64.0.0/10) return 0;; esac; return 1; }
`;

const linuxScript = () => {
  const dir = dirOf("linux"), NET = `${dir}/net`, T2S = `${dir}/tun2socks`;
  return `${preamble(NET)}
# [via GW] dev DEV, then exactly $1
uplink() {
  want=$1; shift
  if [ "$1" = via ]; then ip4 "$2" || return 1; shift 2; fi
  [ "$1" = dev ] && dev "$2" || return 1
  shift 2
  [ "$*" = "$want" ]
}

route() {
  verb=$1 dest=$2; shift 2
  case "$dest:$verb" in
    default:replace) uplink "table 1080" "$@" ;;
    10.0.0.0/8:add|172.16.0.0/12:add|192.168.0.0/16:add|100.64.0.0/10:add) uplink "" "$@" ;;
    10.0.0.0/8:del|172.16.0.0/12:del|192.168.0.0/16:del|100.64.0.0/10:del) [ $# = 0 ] || uplink "proto boot metric 0" "$@" ;;
    *:replace) ip4 "$dest" && uplink "" "$@" ;;
    *:del) ip4 "$dest" && [ $# = 0 ] ;;
    *) return 1 ;;
  esac
}

# What a killed session can leave (global.ts planStaleCleanup)
cleanup() {
  try pkill -f -- '--device foxhole[0]'
  try ip link del foxhole0
  try ip -6 route del blackhole default metric 1
  try iptables -D OUTPUT -o foxhole0 -p udp -j REJECT
  try ip rule del priority 1080
  try ip rule del priority 1081
  try ip route flush table 1080
  via=""; [ "$1" = - ] || via="via $1"
  for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do
    try ip route del $cidr $via dev "$2" proto boot metric 0
  done
}

case "$*" in
  "version ${VERSION}") [ -x ${T2S} ]; exit $? ;;
  uninstall) rm -f /etc/sudoers.d/foxhole-*; rm -rf ${dir}; exit 0 ;;
  "pkill -f -- --device foxhole[0]" | \\
  "ip addr add 198.18.0.1/15 dev foxhole0" | \\
  "ip link set dev foxhole0 up" | \\
  "ip link del foxhole0" | \\
  "ip route add default dev foxhole0 metric 1" | \\
  "ip route del default dev foxhole0 metric 1" | \\
  "ip -6 route replace blackhole default metric 1" | \\
  "ip -6 route del blackhole default metric 1" | \\
  "ip rule del priority 1080" | \\
  "ip rule del priority 1081" | \\
  "ip route flush table 1080" | \\
  "iptables -I OUTPUT -o foxhole0 -p udp -j REJECT" | \\
  "iptables -D OUTPUT -o foxhole0 -p udp -j REJECT" | \\
  "resolvectl domain foxhole0 ~." | \\
  "resolvectl revert foxhole0")
    run "$@" ;;
esac

for a; do case "$a" in ""|*[!A-Za-z0-9._:/@-]*) no ;; esac; done

case "$1" in
  guard)
    # Holds its stdin: it ends when Foxhole does, however it went.
    [ $# = 3 ] && { [ "$2" = - ] || ip4 "$2"; } && dev "$3" || no
    cat >/dev/null
    cleanup "$2" "$3"
    exit 0 ;;
  ${T2S})
    [ $# = 5 ] && [ "$2" = --device ] && [ "$3" = foxhole0 ] && [ "$4" = --proxy ] && port "$5" socks5://127.0.0.1: || no
    run "$@" ;;
  ip)
    case "$2 $3 $4" in
      "route add "*|"route replace "*|"route del "*) (shift 2; route "$@") || no ;;
      "rule add from") ip4 "$5" || no
        rest=$(shift 5; echo "$*")
        [ "$rest" = "lookup main suppress_prefixlength 0 priority 1080" ] || [ "$rest" = "lookup 1080 priority 1081" ] || no ;;
      *) no ;;
    esac
    run "$@" ;;
  resolvectl)
    [ $# = 4 ] && [ "$2 $3" = "dns foxhole0" ] && port "$4" 198.18.0.1: || no
    run "$@" ;;
esac
no
`;
};

/** macOS's: global-darwin.ts's commands, and relay.ts's direct-site routes. Linux's guard has no match here: a killed session is `foxhole restore`'s. */
const darwinScript = () => {
  const dir = dirOf("darwin"), NET = `${dir}/net`, T2S = `${dir}/tun2socks`;
  return `${preamble(NET)}
# route's way out the uplink: a gateway, or -interface DEV
out() { if [ "$1" = -interface ]; then [ $# = 2 ] && dev "$2"; else [ $# = 1 ] && ip4 "$1"; fi; }

case "$*" in
  "version ${VERSION}") [ -x ${T2S} ]; exit $? ;;
  uninstall) rm -f /etc/sudoers.d/foxhole-*; rm -rf ${dir}; exit 0 ;;
  "pkill -f utun12[3]" | \\
  "pkill -f foxhole-dn[s]" | \\
  "killall -HUP mDNSResponder" | \\
  "ifconfig utun123 198.18.0.1 198.18.0.1 up" | \\
  "route -n add -net 0.0.0.0/1 198.18.0.1" | \\
  "route -n add -net 128.0.0.0/1 198.18.0.1" | \\
  "route -n delete -net 0.0.0.0/1" | \\
  "route -n delete -net 128.0.0.0/1" | \\
  "route -n add -inet6 -net ::/1 ::1 -reject" | \\
  "route -n add -inet6 -net 8000::/1 ::1 -reject" | \\
  "route -n delete -inet6 -net ::/1" | \\
  "route -n delete -inet6 -net 8000::/1")
    run "$@" ;;
esac

# A network service's name can be anything ("USB 10/100 LAN"); it's only ever an argument.
if [ "$1 $2" = "networksetup -setdnsservers" ]; then
  case "$3" in ""|-*) no ;; esac
  (shift 3; [ $# -ge 1 ] || exit 1; for a; do case "$a" in Empty) ;; ""|*[!0-9a-fA-F:.]*) exit 1 ;; esac; done) || no
  run "$@"
fi

for a; do case "$a" in ""|*[!A-Za-z0-9._:/@-]*) no ;; esac; done

case "$1" in
  ${T2S})
    [ $# = 5 ] && [ "$2" = --device ] && [ "$3" = utun123 ] && [ "$4" = --proxy ] && port "$5" socks5://127.0.0.1: || no
    run "$@" ;;
  route)
    [ "$2" = -n ] || no
    case "$3 $4" in
      "add -host"|"change -host") ip4 "$5" && (shift 5; out "$@") || no ;;
      "delete -host") [ $# = 5 ] && ip4 "$5" || no ;;
      "add -net") private "$5" && (shift 5; out "$@") || no ;;
      "delete -net") [ $# = 5 ] && private "$5" || no ;;
      *) no ;;
    esac
    run "$@" ;;
esac
no
`;
};

/** The root script for a platform. */
export const helperScript = (platform: string = process.platform) => (platform === "darwin" ? darwinScript() : linuxScript());

/** A root shell's script putting the helper in, for this user. sudoers files with a "." are skipped, and a bad one goes before it can count. */
export const installScript = (uid: number, tun2socks: string, platform: string = process.platform) => {
  const dir = dirOf(platform), net = `${dir}/net`, t2s = `${dir}/tun2socks`;
  const rule = `/etc/sudoers.d/foxhole-${uid}`;
  return `set -e
PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022
mkdir -p ${dir}
cat > ${net}.new <<'FOXHOLE_EOF'
${helperScript(platform)}FOXHOLE_EOF
cp ${q(tun2socks)} ${t2s}.new
chown 0:0 ${dir} ${net}.new ${t2s}.new
chmod 755 ${dir} ${net}.new ${t2s}.new
mv -f ${net}.new ${net}
mv -f ${t2s}.new ${t2s}
echo '#${uid} ALL=(root) NOPASSWD: ${net}' > ${rule}.new
chmod 440 ${rule}.new
visudo -cf ${rule}.new >/dev/null || { rm -f ${rule}.new; exit 1; }
mv -f ${rule}.new ${rule}
`;
};

/** The session's commands through the helper: its own script and tun2socks, no password. */
export function helperPriv(): Priv {
  const priv = sudoPriv("", ["-n", NET]);
  return {
    ...priv,
    guard: (orig) => priv.spawn(["guard", orig.gw ?? "-", orig.dev], true),
    // macOS's DNS relay, as this user: its routes through the helper
    relay: {
      via: ["sudo", "-n", NET],
      spawn: (argv) => {
        const p = spawn(argv[0], argv.slice(1), { stdio: ["pipe", "ignore", "pipe"] });
        logStream(basename(argv[0]), p.stderr);
        return p;
      },
    },
  };
}

export const helperInstalled = () => SUPPORTED && existsSync(NET);

/** The helper's in, the version this Foxhole expects, and sudo lets this user run it. */
export const helperReady = async (): Promise<boolean> =>
  helperInstalled() && helperPriv().run(["version", VERSION]).then(() => true, () => false);

export const removeHelper = async (): Promise<void> => {
  if (helperInstalled()) await helperPriv().run(["uninstall"]);
};

/**
 * What a whole-system session runs through, if the helper can: it's in, or `password` (not asked for
 * again after this) puts it in. Null: as before, sudo with the password. `off`: the user turned it off in Settings.
 */
export async function helperFor(password: string | null, tun2socks: () => Promise<string>, off = false): Promise<{ priv: Priv; tun2socksPath: string } | null> {
  if (!SUPPORTED || password === null) return null;
  if (!(await helperReady())) {
    if (off) return null; // "" as the password: Touch ID just let sudo through (macOS)
    try {
      await sudoPriv(password).run(["sh", "-c", installScript(process.getuid!(), await tun2socks())]);
    } catch (err) {
      log(`network helper: not set up: ${(err as Error).message.split("→").pop()?.trim()}`); // the script itself isn't for the log
      return null;
    }
    if (!(await helperReady())) return log("network helper: set up, but sudo doesn't run it"), null;
    log("network helper: set up, whole-system mode won't ask for the password again");
  }
  return { priv: helperPriv(), tun2socksPath: T2S };
}
