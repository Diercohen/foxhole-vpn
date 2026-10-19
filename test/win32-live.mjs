// LIVE end-to-end check of Windows global mode, without a VPN token: a local
// SOCKS5 server stands in for foxhole's proxy and connects directly (from the
// real uplink's address, so it can't loop through the tunnel). Proves that all
// traffic and DNS go through tun2socks → SOCKS, and that stop() undoes everything.
// Needs an elevated terminal:  npm run build && node test/win32-live.mjs
import assert from "node:assert";
import net from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { lookup } from "node:dns/promises";
import { GlobalSession, directPriv, ensureTun2socks } from "../dist/global.js";
import { isWindowsAdmin, ps, restoreWindows } from "../dist/global-win32.js";

const exec = promisify(execFile);
const psOut = async (s) => { const [c, ...a] = ps(s); return (await exec(c, a)).stdout.trim(); };
const ipify = async () => (await (await fetch("https://api.ipify.org", { signal: AbortSignal.timeout(10000) })).text()).trim();

assert.ok(process.platform === "win32", "Windows only");
assert.ok(await isWindowsAdmin(), "run this in an elevated (Administrator) terminal");

const uplinkIp = await psOut("(Find-NetRoute -RemoteIPAddress 1.1.1.1 | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress");
console.log(`uplink address ${uplinkIp}`);

// Minimal SOCKS5 (no auth, CONNECT; IPv4/domain/IPv6) dialling out from the uplink address.
const seen = [];
const socks = net.createServer((c) => {
  c.once("data", () => {
    c.write(Buffer.from([5, 0]));
    c.once("data", (req) => {
      const t = req[3];
      let host, at;
      if (t === 1) (host = [...req.subarray(4, 8)].join(".")), (at = 8);
      else if (t === 3) (host = req.subarray(5, 5 + req[4]).toString()), (at = 5 + req[4]);
      else return c.end(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
      const port = req.readUInt16BE(at);
      seen.push(`${host}:${port}`);
      const up = net.connect({ host, port, localAddress: uplinkIp, family: 4 }, () => {
        c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        c.pipe(up).pipe(c);
      });
      up.on("error", () => c.destroy());
      c.on("error", () => up.destroy());
    });
  });
});
await new Promise((r) => socks.listen(0, "127.0.0.1", r));
const socksPort = socks.address().port;

const tun2socksPath = await ensureTun2socks();
const before = await ipify();
const session = new GlobalSession({
  priv: directPriv(),
  server: { hostname: "example.com" },
  proxyHost: "127.0.0.1",
  proxyPort: socksPort,
  tun2socksPath,
  force: process.argv.includes("--force"),
});
let died = null;
session.onExit((code) => (died = code));

try {
  const { serverIp, dns } = await session.start();
  console.log(`started: server pinned ${serverIp} · DNS ${dns}`);
  assert.match(dns, /^tunnelled/, "DNS goes through the DoH forwarder");
  assert.ok(await psOut("[bool](Get-NetAdapter -Name 'foxhole0' -ErrorAction SilentlyContinue)") === "True", "foxhole0 adapter exists");
  assert.equal(await psOut("@(Get-NetRoute -AddressFamily IPv4 -InterfaceAlias 'foxhole0' | Where-Object { $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1' }).Count"), "2", "split routes on foxhole0");
  assert.equal(await psOut("@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'foxhole-vpn' }).Count"), "1", "NRPT rule present");

  seen.length = 0;
  const host = `www.wikipedia.org`;
  const addr = (await lookup(host, { family: 4 })).address;
  assert.ok(seen.some((s) => s.startsWith("cloudflare-dns.com:443")), "system DNS lookup went DoH → SOCKS");
  const after = await ipify();
  assert.ok(seen.some((s) => s.endsWith(":443") && !s.startsWith("cloudflare-dns.com")), "HTTPS went tun2socks → SOCKS");
  assert.equal(died, null, "tun2socks still running");
  console.log(`ok - routed: ${host} → ${addr}, exit IP ${after} (direct was ${before}), SOCKS saw ${seen.length} connections`);
} finally {
  await session.stop();
}

assert.equal(await psOut("[bool](Get-NetAdapter -Name 'foxhole0' -ErrorAction SilentlyContinue)"), "False", "adapter removed");
assert.equal(await psOut("@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'foxhole-vpn' }).Count"), "0", "NRPT rule removed");
assert.equal(await psOut("@(Get-NetFirewallRule -DisplayName 'foxhole-vpn' -ErrorAction SilentlyContinue).Count"), "0", "firewall rules removed");
assert.equal(await ipify(), before, "internet works directly again");
await restoreWindows(directPriv()); // idempotent: must not fail on a clean system
socks.close();
console.log("ok - Windows global mode routes everything through the tunnel and restores networking");
