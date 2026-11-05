// Whole-system mode without a password each time (Linux): how Windscribe and others do it, in one script. The password
// is asked once; with it, a root-owned script and a sudoers rule for it go in, and from then on sudo runs that script
// with no password. No daemon: nothing runs until whole-system mode does.
//
// The script is what makes this safe, not a detail: sudo gives any program of this user the script as root, so it only
// runs the exact commands a session needs (global.ts's plans, kept in step by test/helper.test.mjs), never a command or
// a tun2socks of the caller's. What's left to a program of this user: sending this computer's traffic through a SOCKS
// proxy on this computer, and adding host routes. Nothing that reaches a root shell.
import { existsSync } from "node:fs";
import { sudoPriv, type Priv } from "./global.js";
import { log } from "./log.js";

const DIR = "/usr/local/libexec/foxhole";
const NET = `${DIR}/net`;
const T2S = `${DIR}/tun2socks`;
const VERSION = "1"; // raised when the script changes: the next whole-system mode asks once, to put the new one in

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** The root script. Each argument is checked before anything runs; refused: exit 126. `run` and `try` are replaced in its test. */
export const helperScript = () => `#!/bin/sh
# Foxhole's network helper: what whole-system mode runs as root, with no password. Only the commands below.
# Off: Foxhole's Settings, or: sudo ${NET} uninstall
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
  uninstall) rm -f /etc/sudoers.d/foxhole-*; rm -rf ${DIR}; exit 0 ;;
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

/** A root shell's script putting the helper in, for this user. sudoers files with a "." are skipped, and a bad one goes before it can count. */
export const installScript = (uid: number, tun2socks: string) => {
  const rule = `/etc/sudoers.d/foxhole-${uid}`;
  return `set -e
umask 022
mkdir -p ${DIR}
cat > ${NET}.new <<'FOXHOLE_EOF'
${helperScript()}FOXHOLE_EOF
cp ${q(tun2socks)} ${T2S}.new
chown 0:0 ${DIR} ${NET}.new ${T2S}.new
chmod 755 ${DIR} ${NET}.new ${T2S}.new
mv -f ${NET}.new ${NET}
mv -f ${T2S}.new ${T2S}
echo '#${uid} ALL=(root) NOPASSWD: ${NET}' > ${rule}.new
chmod 440 ${rule}.new
visudo -cf ${rule}.new >/dev/null || { rm -f ${rule}.new; exit 1; }
mv -f ${rule}.new ${rule}
`;
};

/** The session's commands through the helper: its own script and tun2socks, no password. */
export function helperPriv(): Priv {
  const priv = sudoPriv("", ["-n", NET]);
  return { ...priv, guard: (orig) => priv.spawn(["guard", orig.gw ?? "-", orig.dev], true) };
}

export const helperInstalled = () => process.platform === "linux" && existsSync(NET);

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
  if (process.platform !== "linux" || password === null) return null;
  if (!(await helperReady())) {
    if (off || !password) return null;
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
