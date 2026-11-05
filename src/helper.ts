// Whole-system mode without a password each time: how Windscribe and others do it, in one script. The password is asked
// once (Windows: its admin prompt); with it, a root-owned script and a sudoers rule for it go in (Windows: a scheduled task
// running as SYSTEM that this user may start), and from then on it runs with no password. No daemon: nothing runs until
// whole-system mode does.
//
// The script is what makes this safe, not a detail: sudo gives any program of this user the script as root, so it only
// runs the exact commands a session needs (global.ts's and global-darwin.ts's, kept in step by test/helper.test.mjs),
// never a command or a tun2socks of the caller's. What's left to a program of this user: sending this computer's traffic
// through a SOCKS proxy on this computer, adding host routes, and (macOS) choosing the DNS server. Nothing that reaches a
// root shell. On macOS no JavaScript runs as root with it either: the DNS relay stays the user's (global-darwin.ts).
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { PRIVATE_CIDRS, sudoPriv, type Priv } from "./global.js";
import { DNS_FLUSH, NRPT_ADD, isWindowsAdmin, planStaleCleanup, ps, taskExists, taskPriv, uacPriv, windowsSid } from "./global-win32.js";
import { log, logStream } from "./log.js";

// macOS: /usr/local can be the user's own there (Homebrew), and a folder in a user's folder could be swapped
const dirOf = (platform: string) => (platform === "darwin" ? "/Library/PrivilegedHelperTools/foxhole" : "/usr/local/libexec/foxhole");
const NET = `${dirOf(process.platform)}/net`;
const T2S = `${dirOf(process.platform)}/tun2socks`;
const WIN_DIR = join(process.env.ProgramFiles ?? "C:\\Program Files", "Foxhole Helper"); // only administrators may write there
const WIN_NET = join(WIN_DIR, "net.ps1");
const WIN_T2S = join(WIN_DIR, "tun2socks.exe");
const IS_WIN = process.platform === "win32";
const VERSION = "1"; // raised when the script changes: the next whole-system mode asks once, to put the new one in
const SUPPORTED = process.platform === "linux" || process.platform === "darwin"; // with sudo

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

export const helperInstalled = () => (IS_WIN ? existsSync(WIN_NET) : SUPPORTED && existsSync(NET));

/** The helper's in, the version this Foxhole expects, and sudo lets this user run it. */
export const helperReady = async (): Promise<boolean> =>
  helperInstalled() && !IS_WIN && helperPriv().run(["version", VERSION]).then(() => true, () => false);

export const removeHelper = async (): Promise<void> => {
  if (!helperInstalled()) return;
  if (!IS_WIN) return helperPriv().run(["uninstall"]);
  const priv = await taskPriv(taskName(await windowsSid()));
  await priv.run(["uninstall"]);
  priv.close?.();
};

// ── Windows: PowerShell is the one runtime here that only administrators can change, so it runs the helper. The app's
// end is pipePriv (global-win32.ts), the same messages as the admin prompt's helper, but only the commands below.

const taskName = (sid: string) => `foxhole-net-${sid}`;
const IP = String.raw`(\d{1,3}\.){3}\d{1,3}`;
const PRIVATE = PRIVATE_CIDRS.map((c) => c.replaceAll(".", String.raw`\.`)).join("|");
const HALVES = String.raw`(0\.0\.0\.0/1|128\.0\.0\.0/1)`;
/** What the Windows helper runs besides tun2socks and winScripts, as one line. Exported for its test. */
export const WIN_ALLOWED = [
  String.raw`^netsh interface ipv4 (add|delete) route prefix=(${IP}/32|${PRIVATE}) interface=\d+( nexthop=${IP})? store=active\z`,
  String.raw`^netsh interface ipv4 add route prefix=${HALVES} interface=foxhole0 metric=1 store=active\z`,
  String.raw`^netsh interface ipv4 delete route prefix=${HALVES} interface=foxhole0 store=active\z`,
  String.raw`^netsh interface ipv4 set address name=foxhole0 source=static address=198\.18\.0\.1 mask=255\.254\.0\.0\z`,
  String.raw`^netsh interface ipv4 set interface interface=foxhole0 metric=1\z`,
  String.raw`^netsh advfirewall firewall add rule name=foxhole-vpn dir=out action=block protocol=any remoteip=2000::/3\z`,
  String.raw`^netsh advfirewall firewall add rule name=foxhole-vpn dir=out action=block protocol=UDP remoteport=443\z`,
  String.raw`^netsh advfirewall firewall delete rule name=foxhole-vpn\z`,
  String.raw`^taskkill /F /IM tun2socks\.exe\z`,
];
const plain = (s: string) => `'${s.replaceAll("'", "''")}'`;
const stale = planStaleCleanup();
/** The PowerShell lines a session runs through ps(), whole. */
export const winScripts = () => [stale[0].at(-1)!, NRPT_ADD, DNS_FLUSH];

/** The Windows helper, connecting to the app's pipe. If the app goes without stopping global mode, it undoes that as `foxhole restore` would. */
export const winScript = (task: string) => `# Foxhole's network helper, version ${VERSION}: what whole-system mode runs as SYSTEM, with no prompt. Only the commands below.
$ErrorActionPreference = 'Stop'
$t2s = Join-Path $PSScriptRoot 'tun2socks.exe'
$allowed = @(${WIN_ALLOWED.map(plain).join(", ")})
$scripts = @(${winScripts().map(plain).join(", ")})
$cleanup = @(${stale.map((a) => plain(JSON.stringify(a))).join(", ")})

function Allowed([string[]]$a) {
  if ($a.Count -eq 7 -and ($a[0..5] -join ' ') -ceq '${ps("").slice(0, 6).join(" ")}') { return $scripts -ccontains $a[6] }
  foreach ($x in $a) { if ($x -cnotmatch '^[A-Za-z0-9./:=_-]+\\z') { return $false } }
  $line = $a -join ' '
  foreach ($r in $allowed) { if ($line -cmatch $r) { return $true } }
  return $false
}
function Info([string[]]$a) {
  $i = New-Object Diagnostics.ProcessStartInfo $a[0]
  $i.Arguments = (($a | Select-Object -Skip 1 | ForEach-Object { if ($_ -match '\\s') { [char]34 + $_ + [char]34 } else { $_ } }) -join ' ')
  $i.UseShellExecute = $false
  $i.CreateNoWindow = $true
  $i.RedirectStandardError = $true
  return $i
}
function Run([string[]]$a) {
  $i = Info $a
  $i.RedirectStandardOutput = $true
  $p = [Diagnostics.Process]::Start($i)
  $o = $p.StandardOutput.ReadToEndAsync()
  $e = $p.StandardError.ReadToEndAsync()
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) { throw (($a -join ' ') + ' : ' + ($o.Result + $e.Result).Trim()) }
}
function Send($m) { try { $w.WriteLine(($m | ConvertTo-Json -Compress)) } catch {} }

$pipe = New-Object IO.Pipes.NamedPipeClientStream('.', '${task}', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
$pipe.Connect(20000)
$utf8 = New-Object Text.UTF8Encoding($false)
$r = New-Object IO.StreamReader($pipe, $utf8)
$w = New-Object IO.StreamWriter($pipe, $utf8)
$w.AutoFlush = $true
$kids = @{}

function Handle($m) {
  $id = $m.id
  if ($m.run) {
    $a = [string[]]$m.run
    if ($a.Count -eq 1 -and $a[0] -ceq 'uninstall') {
      Unregister-ScheduledTask -TaskName '${task}' -Confirm:$false
      Remove-Item -Recurse -Force $PSScriptRoot
      Send @{ id = $id }
      exit 0
    }
    if (-not (Allowed $a)) { return Send @{ id = $id; error = 'foxhole helper: refused' } }
    try { Run $a; Send @{ id = $id } } catch { Send @{ id = $id; error = $_.Exception.Message } }
  } elseif ($m.spawn) {
    $a = [string[]]$m.spawn
    if (-not ($a.Count -eq 5 -and $a[0] -ceq $t2s -and $a[1] -ceq '--device' -and $a[2] -ceq 'foxhole0' -and $a[3] -ceq '--proxy' -and $a[4] -cmatch '^socks5://127\\.0\\.0\\.1:\\d+\\z')) {
      return Send @{ id = $id; exit = @(-1, $null); stderr = $null }
    }
    $p = [Diagnostics.Process]::Start((Info $a))
    $kids[$id] = @{ p = $p; line = $p.StandardError.ReadLineAsync() }
  } elseif ($m.kill -and $kids[$id]) {
    try { $kids[$id].p.Kill() } catch {}
  }
}

function Pump {
  foreach ($id in @($kids.Keys)) {
    $k = $kids[$id]
    while ($k.line -and $k.line.IsCompleted) {
      if ($null -eq $k.line.Result) { $k.line = $null; break }
      Send @{ id = $id; stderr = $k.line.Result + [char]10 }
      $k.line = $k.p.StandardError.ReadLineAsync()
    }
    if ($k.p.HasExited) { Send @{ id = $id; exit = @($k.p.ExitCode, $null) }; $kids.Remove($id) }
  }
}

$read = $r.ReadLineAsync()
while ($true) {
  Pump
  try { if (-not $read.Wait(100)) { continue } } catch { break }
  if ($null -eq $read.Result) { break }
  try { Handle ($read.Result | ConvertFrom-Json) } catch {}
  $read = $r.ReadLineAsync()
}
if ($kids.Count) {
  foreach ($k in $kids.Values) { try { $k.p.Kill() } catch {} }
  foreach ($c in $cleanup) { try { Run ([string[]]($c | ConvertFrom-Json)) } catch {} }
}
`;

/** The elevated PowerShell that puts the helper in: single quotes only, as ps() wants. The task runs as SYSTEM; only this user, and administrators, may start it. */
export const winInstall = (sid: string, tun2socks: string) => {
  const task = taskName(sid);
  const file = `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${WIN_NET}"`;
  return [
    `$ErrorActionPreference = 'Stop'`,
    `$d = ${plain(WIN_DIR)}`,
    `New-Item -ItemType Directory -Force $d | Out-Null`,
    `[IO.File]::WriteAllBytes((Join-Path $d 'net.ps1'), [Convert]::FromBase64String('${Buffer.from(winScript(task)).toString("base64")}'))`,
    `Copy-Item -Force ${plain(tun2socks)} (Join-Path $d 'tun2socks.exe')`,
    `Copy-Item -Force ${plain(join(dirname(tun2socks), "wintun.dll"))} (Join-Path $d 'wintun.dll')`,
    `$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ${plain(file)}`,
    `$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest`,
    `$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)`,
    `Register-ScheduledTask -TaskName ${plain(task)} -Action $a -Principal $p -Settings $s -Force | Out-Null`,
    `$c = New-Object -ComObject Schedule.Service; $c.Connect()`,
    `$t = $c.GetFolder('\').GetTask(${plain(task)})`,
    `$sd = $t.GetSecurityDescriptor(4); if ($sd -notmatch '${sid}') { $t.SetSecurityDescriptor($sd + '(A;;GRGX;;;${sid})', 0) }`,
  ].join("; ");
};

/** Windows: the task if it's in; else the admin prompt puts it in. A refused prompt fails the session, as it always did. */
async function winHelper(tun2socks: () => Promise<string>, off: boolean): Promise<{ priv: Priv; tun2socksPath: string } | null> {
  if (await isWindowsAdmin()) return null; // nothing to ask, so nothing to spare
  const sid = await windowsSid();
  const task = taskName(sid);
  if (helperInstalled() && readFileSync(WIN_NET, "utf8").includes(`version ${VERSION}:`) && (await taskExists(task))) {
    try {
      return { priv: await taskPriv(task), tun2socksPath: WIN_T2S };
    } catch (err) {
      log(`network helper: didn't start: ${(err as Error).message}`);
    }
  }
  if (off) return null;
  const path = await tun2socks();
  const elevated = await uacPriv();
  try {
    await elevated.run(ps(winInstall(sid, path)));
    const priv = await taskPriv(task);
    elevated.close?.();
    log("network helper: set up, whole-system mode won't ask Windows again");
    return { priv, tun2socksPath: WIN_T2S };
  } catch (err) {
    log(`network helper: not set up: ${(err as Error).message.slice(-300)}`);
    return { priv: elevated, tun2socksPath: path }; // the prompt's been answered: this session goes on with it
  }
}

/**
 * What a whole-system session runs through, if the helper can: it's in, or `password` (not asked for
 * again after this) puts it in. Null: as before, sudo with the password. `off`: the user turned it off in Settings.
 */
export async function helperFor(password: string | null, tun2socks: () => Promise<string>, off = false): Promise<{ priv: Priv; tun2socksPath: string } | null> {
  if (IS_WIN) return winHelper(tun2socks, off);
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
