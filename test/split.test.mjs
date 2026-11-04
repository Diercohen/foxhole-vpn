// Split tunneling: typed sites, which rule wins, naming a site from a connection's first bytes or
// a DNS answer, and the proxy sending each connection through the VPN or direct. Local only.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert for the fake upstream

import net from "node:net";
import tls from "node:tls";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { parseSite, parseRule, ruleFor, useSplit, route, viaOf, hits, recentSites, splitOn, splitSummary, appsOn, NO_SPLIT } from "../dist/split.js";
import { parseLsof, parseSs, parseWin, appName, appFor, desktopIcon } from "../dist/apps.js";
import { startProxy, sniffHost, setDirectFrom, holdDirect, onProxyWarning } from "../dist/proxy.js";
import { questionName, answerAddrs } from "../dist/dns.js";
import { directRoutes } from "../dist/relay.js";

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 20000).unref();

// Typed sites
const sites = {
  "bbc.co.uk": "bbc.co.uk",
  "*.co.uk": "*.co.uk",
  ".co.uk": "*.co.uk",
  " IR ": "ir",
  "*.ir": "*.ir",
  "https://www.BBC.co.uk/news?x=1": "www.bbc.co.uk",
  "bbc.co.uk/news": "bbc.co.uk",
  "1.2.3.4": "1.2.3.4",
  "10.0.0.0/8": "10.0.0.0/8",
  "2001:db8::/32": "2001:db8::/32",
  "*.google": "*.google",
};
for (const [typed, match] of Object.entries(sites)) assert.equal(parseSite(typed), match, `parseSite(${JSON.stringify(typed)})`);
for (const bad of ["", "*", "not a site", "digikala", "google", "a..b", "-x.com", "x-.com", "exa_mple.com", "10.0.0.0/33", "1.2.3.4/x", "1.2.3.4/8/9"]) {
  assert.equal(parseSite(bad), null, `parseSite(${JSON.stringify(bad)}) refused`);
}
assert.match(parseSite("ایران.ir"), /^xn--[a-z0-9-]+\.ir$/, "IDN as punycode");

// The most specific rule wins, whatever the order
const split = {
  default: "vpn",
  rules: [
    { match: "*.ir", via: "direct" },
    { match: "blocked.ir", via: "vpn" },
    { match: "bbc.co.uk", via: "direct" },
    { match: "10.0.0.0/8", via: "direct" },
    { match: "10.1.0.0/16", via: "vpn" },
    { match: "2001:db8::/32", via: "direct" },
  ],
};
const m = (name, ip) => ruleFor(split, name, ip)?.match ?? null;
assert.equal(m("www.digikala.ir"), "*.ir");
assert.equal(m("WWW.Digikala.IR."), "*.ir", "case and a trailing dot don't matter");
assert.equal(m("ir"), "*.ir", "*.x covers x itself");
assert.equal(m("blocked.ir"), "blocked.ir", "longer domain wins");
assert.equal(m("x.blocked.ir"), "blocked.ir", "subdomains follow it");
assert.equal(m("notir.com"), null);
assert.equal(m("news.bbc.co.uk"), "bbc.co.uk");
assert.equal(m("xbbc.co.uk"), null, "a suffix only at a dot");
assert.equal(m(undefined, "10.2.3.4"), "10.0.0.0/8");
assert.equal(m(undefined, "10.1.2.3"), "10.1.0.0/16", "longer prefix wins");
assert.equal(m("example.com", "10.1.2.3"), "10.1.0.0/16", "no name rule: the address decides");
assert.equal(m("news.bbc.co.uk", "10.1.2.3"), "bbc.co.uk", "a name rule beats an address rule");
assert.equal(m("10.9.9.9"), "10.0.0.0/8", "an address as the name");
assert.equal(m(undefined, "2001:db8::1"), "2001:db8::/32");
assert.equal(m(undefined, "8.8.8.8"), null);

// Apps: typed, and an app's rule deciding all its connections
for (const [typed, match] of Object.entries({ Telegram: "app:Telegram", "Google Chrome": "app:Google Chrome", "app: firefox": "app:firefox", "Telegram.exe": "app:Telegram", "Discord.app": "app:Discord", "app:org.telegram.messenger": "app:org.telegram.messenger", "bbc.co.uk": "bbc.co.uk", ir: "ir" })) {
  assert.equal(parseRule(typed), match, `parseRule(${JSON.stringify(typed)})`);
}
for (const bad of ["", "app:", "app:a/b", "a:b"]) assert.equal(parseRule(bad), null, `parseRule(${JSON.stringify(bad)}) refused`);
const withApps = { default: "vpn", rules: [...split.rules, { match: "app:Telegram", via: "direct" }, { match: "app:Bank", via: "vpn" }] };
assert.equal(ruleFor(withApps, "www.google.com", undefined, "telegram")?.match, "app:Telegram", "an app's rule, whatever the case");
assert.equal(ruleFor(withApps, "www.digikala.ir", undefined, "Bank")?.match, "app:Bank", "beats a site's");
assert.equal(ruleFor(withApps, "www.digikala.ir", undefined, "Firefox")?.match, "*.ir", "another app: the sites'");
assert.equal(ruleFor(withApps, "app")?.match ?? null, null, "an app's rule is no domain");
assert.ok(appsOn(withApps) && !appsOn(split));
assert.equal(splitSummary({ default: "vpn", rules: [{ match: "x.com", via: "direct" }, { match: "app:A", via: "direct" }, { match: "app:B", via: "direct" }] }), "1 site, 2 apps direct");
assert.equal(splitSummary({ default: "direct", rules: [{ match: "app:A", via: "vpn" }] }), "only 1 app via VPN");

// Which app holds a connection: each system's table
assert.equal(appName("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"), "Google Chrome");
assert.equal(appName("C:\\Program Files\\Telegram\\Telegram.exe"), "Telegram");
assert.equal(appName("/usr/bin/curl"), "curl");
const macLsof = `p4242
cGoogle Chrome Helper
f31
n127.0.0.1:62868->127.0.0.1:1080
p66119
cfirefox
f80
n198.18.0.1:50000->151.101.1.91:443
p7
ccurl
f5
n[::1]:50001->[::1]:1080
f6
n*:1080
`;
const macPs = "4242 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper\n66119 /Applications/Firefox.app/Contents/MacOS/firefox\n";
assert.deepEqual(parseLsof(macLsof, macPs), [
  { local: "127.0.0.1:62868", remote: "127.0.0.1:1080", pid: 4242, app: "Google Chrome", exe: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper" },
  { local: "198.18.0.1:50000", remote: "151.101.1.91:443", pid: 66119, app: "Firefox", exe: "/Applications/Firefox.app/Contents/MacOS/firefox" },
  { local: "::1:50001", remote: "::1:1080", pid: 7, app: "curl" },
]);
const ss = `ESTAB 0 0 127.0.0.1:43210 127.0.0.1:1080 users:(("Telegram",pid=123,fd=45))
ESTAB 0 0 [::ffff:127.0.0.1]:43211 [::ffff:127.0.0.1]:1080 users:(("tun2socks",pid=9,fd=3))
SYN-SENT 0 1 198.18.0.1:40000 1.2.3.4:443
`;
assert.deepEqual(parseSs(ss), [
  { local: "127.0.0.1:43210", remote: "127.0.0.1:1080", pid: 123, app: "Telegram" },
  { local: "127.0.0.1:43211", remote: "127.0.0.1:1080", pid: 9, app: "tun2socks" },
  { local: "198.18.0.1:40000", remote: "1.2.3.4:443", pid: 0, app: "" },
]);
const winNet = `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:1080           0.0.0.0:0              LISTENING       500
  TCP    127.0.0.1:52344        127.0.0.1:1080         ESTABLISHED     1234
  TCP    [::1]:52345            [::1]:1080             ESTABLISHED     77
`;
assert.deepEqual(parseWin(winNet, '"Telegram.exe","1234","Console","1","123,456 K"\r\n"chrome.exe","77","Console","1","1 K"\r\n'), [
  { local: "127.0.0.1:52344", remote: "127.0.0.1:1080", pid: 1234, app: "Telegram" },
  { local: "::1:52345", remote: "::1:1080", pid: 77, app: "chrome" },
]);
// Linux: an app's icon by the name ss gives its process (cut to 15 characters)
assert.deepEqual(desktopIcon("[Desktop Entry]\nName=Telegram\nExec=env BAMF_DESKTOP_FILE_HINT=/x.desktop LANG=C /snap/bin/telegram-desktop -- %u\nIcon=/snap/telegram-desktop/icon.png\n"), { proc: "telegram-deskto", icon: "/snap/telegram-desktop/icon.png" });
assert.deepEqual(desktopIcon('Exec="/opt/Signal/signal-desktop" --no-sandbox\nIcon=signal-desktop'), { proc: "signal-desktop", icon: "signal-desktop" });
assert.equal(desktopIcon("Exec=/usr/bin/flatpak run org.x.App\nIcon=org.x.App"), null, "a Flatpak's process isn't in its launcher");
assert.equal(desktopIcon("Name=x\nIcon=y"), null);
assert.equal(await appFor({ remoteAddress: "192.168.1.9", remotePort: 5, localAddress: "192.168.1.2", localPort: 1080 }, { host: "x.com", port: 443 }), undefined, "another device's: no app");

// Live rules, counted connections, recent sites
useSplit(() => split);
assert.equal(route("www.digikala.ir"), "direct");
assert.equal(route("example.com"), "vpn", "the default");
assert.equal(viaOf("shop.digikala.ir"), "direct");
assert.equal(hits.get("*.ir"), 1, "viaOf doesn't count");
assert.equal(hits.get(""), 1);
assert.deepEqual(recentSites.slice(0, 2), ["example.com", "www.digikala.ir"], "newest first");
assert.ok(splitOn() && !splitOn(NO_SPLIT) && splitOn({ default: "direct", rules: [] }));
assert.equal(splitSummary(NO_SPLIT), null);
assert.equal(splitSummary({ default: "vpn", rules: [{ match: "x.com", via: "direct" }] }), "1 site direct");
assert.equal(splitSummary(split), "4 sites direct", "rules going the default's way aren't counted");
assert.equal(splitSummary({ default: "direct", rules: [{ match: "a.com", via: "vpn" }, { match: "b.com", via: "vpn" }] }), "only 2 sites via VPN");

// A site's name from a connection's first bytes: a real ClientHello's SNI, an HTTP Host
const hello = await new Promise((resolve) => {
  const srv = net.createServer((s) => {
    let buf = Buffer.alloc(0);
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 5 && buf.length >= 5 + buf.readUInt16BE(3)) resolve(buf), s.destroy(), srv.close();
    });
  });
  srv.listen(0, "127.0.0.1", () => tls.connect({ host: "127.0.0.1", port: srv.address().port, servername: "www.BBC.co.uk" }).on("error", () => {}));
});
assert.equal(sniffHost(hello), "www.bbc.co.uk", "TLS SNI");
assert.equal(sniffHost(hello.subarray(0, 60)), null, "a cut-off hello names nothing");
assert.equal(sniffHost(Buffer.from("GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.COM:8080\r\n\r\n")), "example.com", "HTTP Host");
assert.equal(sniffHost(Buffer.from("SSH-2.0-OpenSSH_9.6\r\n")), null);

// A site's name from a DNS answer: the question's name for each address, through a CNAME
const label = (n) => Buffer.concat([...n.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
const question = Buffer.concat([label("www.BBC.co.uk"), Buffer.from([0, 1, 0, 1])]);
assert.equal(questionName(Buffer.concat([Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), question])), "www.bbc.co.uk");
const cname = label("www.bbc.net.uk");
const cnameRR = Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, cname.length]), cname]);
const at = 12 + question.length + 12; // the CNAME's target name, pointed to by the A record
const aRR = Buffer.from([0xc0 | (at >> 8), at & 0xff, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 151, 101, 0, 81]);
const answer = Buffer.concat([Buffer.from([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]), question, cnameRR, aRR]);
assert.deepEqual(answerAddrs(answer), [{ ip: "151.101.0.81", ttl: 3600 }]);
assert.deepEqual(answerAddrs(answer.subarray(0, answer.length - 3)), [], "a cut-off answer: what parsed");
assert.equal(questionName(Buffer.alloc(5)), null);

// macOS global mode: the DNS relay routes direct sites' addresses around the tunnel as it looks them up
const ran = [];
const routes = directRoutes(["192.168.0.1"], async (argv) => (ran.push(argv.join(" ")), !argv.includes("185.9.9.9")));
let mac = { default: "vpn", rules: [{ match: "*.ir", via: "direct" }] };
useSplit(() => mac);
await routes.answer("www.digikala.ir", ["185.1.1.1", "192.168.1.5", "2a00::1"]);
assert.deepEqual(ran, ["route -n add -host 185.1.1.1 192.168.0.1"], "a direct site's public IPv4: routed out the uplink; LAN and IPv6 left");
await routes.answer("cdn.digikala.ir", ["185.1.1.1"]);
assert.equal(ran.length, 1, "already routed");
await routes.answer("www.bbc.co.uk", ["185.1.1.1"]);
assert.equal(ran.at(-1), "route -n delete -host 185.1.1.1", "a VPN site on the same address: back into the tunnel");
await routes.answer("shop.digikala.ir", ["185.1.1.1"]);
assert.equal(ran.length, 2, "and it stays there");
await routes.answer("x.ir", ["185.3.3.3"]);
await routes.answer("y.ir", ["185.9.9.9"]); // the route command fails: not counted as routed
mac = { default: "vpn", rules: [] };
await routes.recheck();
assert.deepEqual(ran.slice(-3), ["route -n add -host 185.3.3.3 192.168.0.1", "route -n add -host 185.9.9.9 192.168.0.1", "route -n delete -host 185.3.3.3"], "rules changed: no longer direct, back in");
mac = { default: "direct", rules: [{ match: "app:Telegram", via: "vpn" }] };
await routes.answer("web.telegram.org", ["185.6.6.6"]);
assert.equal(ran.length, 5, "an app listed for the VPN: nothing goes around the tun by name");
mac = { default: "direct", rules: [] };
await routes.answer("api.ipify.org", ["185.5.5.5"]);
assert.equal(ran.length, 5, "foxhole's own exit-IP check never goes around the tunnel");
await routes.answer("z.ir", ["185.4.4.4"]);
await routes.move(["-interface", "ppp0"]);
await routes.clear();
assert.deepEqual(ran.slice(-3), ["route -n add -host 185.4.4.4 192.168.0.1", "route -n change -host 185.4.4.4 -interface ppp0", "route -n delete -host 185.4.4.4"], "moved with the uplink, then cleared");

// Through the proxy: a fake VPN upstream that counts its tunnels, and an echo "site"
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const read = (sock) => new Promise((r) => sock.once("data", r));
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-vpn-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });
const site = net.createServer((s) => s.pipe(s));
const sitePort = await listen(site);
let tunnels = 0;
const upstream = tls.createServer({ key: readFileSync(path.join(dir, "k.pem")), cert: readFileSync(path.join(dir, "c.pem")) }, (s) => {
  s.once("data", (d) => {
    tunnels++;
    const port = Number(d.toString().match(/^CONNECT [^:]+:(\d+)/)[1]);
    const t = net.connect(port, "127.0.0.1", () => (s.write("HTTP/1.1 200 OK\r\n\r\n"), s.pipe(t), t.pipe(s)));
  });
});
const conn = { server: { hostname: "127.0.0.1", port: await listen(upstream) }, currentPass: async () => ({ token: "t", notBefore: 0, expires: 2 ** 31 }) };
const proxy = await startProxy(conn, "127.0.0.1", 0);

/** A SOCKS5 CONNECT to 127.0.0.1:`port` and an echo; the reply code, and whether the echo came back. */
async function socks(port) {
  const c = net.connect(proxy.port, "127.0.0.1");
  c.on("error", () => {});
  c.write(Buffer.from([5, 1, 0]));
  await read(c);
  c.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, port >> 8, port & 0xff]));
  const rep = (await read(c))[1];
  let echoed = false;
  if (rep === 0) {
    c.write("ping");
    echoed = (await read(c)).toString() === "ping";
  }
  c.destroy();
  return { rep, echoed };
}

let rules = { default: "vpn", rules: [] };
useSplit(() => rules);
assert.deepEqual(await socks(sitePort), { rep: 0, echoed: true });
assert.equal(tunnels, 1, "no rules: through the VPN");
rules = { default: "vpn", rules: [{ match: "127.0.0.1", via: "direct" }] };
assert.deepEqual(await socks(sitePort), { rep: 0, echoed: true });
assert.equal(tunnels, 1, "a direct rule: no VPN tunnel");
rules = { default: "direct", rules: [{ match: "127.0.0.0/8", via: "vpn" }] };
assert.deepEqual(await socks(sitePort), { rep: 0, echoed: true });
assert.equal(tunnels, 2, "only these via VPN: listed, so the VPN");
rules = { default: "vpn", rules: [{ match: "127.0.0.1", via: "direct" }] };
assert.equal((await socks(1)).rep, 1, "a direct connection that fails (nothing on port 1): a SOCKS failure reply");

// An app's rule, through the proxy: curl (another process) sent direct, the site's rules notwithstanding
const web = net.createServer((s) => s.once("data", () => s.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")));
const webPort = await listen(web);
const curl = () => new Promise((r) => execFile("curl", ["-s", "--max-time", "5", "--socks5", `127.0.0.1:${proxy.port}`, `http://127.0.0.1:${webPort}/`], (err, out) => r(err ? null : out)));
rules = { default: "vpn", rules: [{ match: "app:curl", via: "direct" }] };
assert.equal(await curl(), "ok");
assert.equal(tunnels, 2, "curl's rule: direct");
rules = { default: "vpn", rules: [{ match: "app:Curl", via: "vpn" }, { match: "127.0.0.1", via: "direct" }] };
assert.equal(await curl(), "ok");
assert.equal(tunnels, 3, "curl's rule beats the address's: the VPN");
rules = { default: "vpn", rules: [{ match: "app:someone-else", via: "direct" }] };
assert.equal(await curl(), "ok");
assert.equal(tunnels, 4, "another app's rule: curl takes the default");
web.close();
rules = { default: "vpn", rules: [{ match: "127.0.0.1", via: "direct" }] };

// Global mode: while its routes go up or down, direct sites use the VPN (dialed then, they'd loop
// through the tun); with them up, until the probe says direct connections really leave.
const warnings = [];
onProxyWarning((msg) => warnings.push(msg));
holdDirect();
await socks(sitePort);
assert.equal(tunnels, 5, "routes going up or down: the VPN");
setDirectFrom(null);
await socks(sitePort);
assert.equal(tunnels, 5, "global off: direct again");
setDirectFrom("127.0.0.1");
await socks(sitePort);
assert.equal(tunnels, 6, "before the probe answers: the VPN");
const looped = net.connect(proxy.port, "127.0.0.1"); // what a loop looks like: the probe's own connection, back via tun2socks
looped.on("error", () => {});
looped.write(Buffer.from([5, 1, 0]));
await read(looped);
looped.write(Buffer.from([5, 1, 0, 1, 192, 0, 2, 1, 0, 9]));
await new Promise((r) => setTimeout(r, 1200));
await socks(sitePort);
assert.equal(tunnels, 7, "a loop: direct sites keep using the VPN");
assert.ok(warnings.some((w) => /can't get past the tun/.test(w)), "and the TUI is told");
setDirectFrom(null);

await proxy.close();
for (const s of [site, upstream]) s.close();
console.log("ok - split tunneling: rules, naming sites, VPN or direct through the proxy");
process.exit(0);
