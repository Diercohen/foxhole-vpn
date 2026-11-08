// Smart split tunneling: which sites are Iranian (the shipped lists), smart's routes, and save data's try of the
// direct way through the proxy: an answer keeps it direct, a reset, silence or the filter's page sends it through the
// VPN and teaches it's blocked. Local only, in a throwaway HOME.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed localhost cert for the fake upstream

import net from "node:net";
import tls from "node:tls";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";

// The shipped lists, read in a HOME that has none of its own
const bare = mkdtempSync(path.join(os.tmpdir(), "foxhole-smart-"));
const shipped = execFileSync(process.execPath, ["--input-type=module", "-e", `const m = await import(${JSON.stringify(new URL("../dist/smart.js", import.meta.url).href)}); console.log(m.iranian("www.digikala.com") && m.iranian("aparat.com") && m.iranian(undefined, "5.22.0.1") && !m.iranian("www.google.com"))`], { env: { ...process.env, HOME: bare, USERPROFILE: bare } });
assert.equal(shipped.toString().trim(), "true", "the shipped lists, till new ones come");

// Here, lists got lately (fresh, so nothing is downloaded): small ones, a sanctioned site among them
const home = mkdtempSync(path.join(os.tmpdir(), "foxhole-smart-"));
process.env.HOME = home; // userHome(): blocked.json and new lists go here, not in ~/.config
process.env.USERPROFILE = home;
const lists = path.join(home, ".config", "foxhole-vpn", "lists");
mkdirSync(lists, { recursive: true });
writeFileSync(path.join(lists, "iran-domains.txt"), "digikala.com\n");
writeFileSync(path.join(lists, "iran-ips.txt"), "5.22.0.0/17\n2a01:5ec0::/29\n");
writeFileSync(path.join(lists, "sanctioned.txt"), "sanctioned.example\n");

const { listLines, rangesOf, under, iranian, sanctioned, filterAddress, siteOf, knownBlocked, learnBlocked, verdictOf, verdictText, tryText, wantOf } = await import("../dist/smart.js");
const { useSplit, route, viaOf, wayOf, hits, splitOn, splitSummary, probeOn, SMART } = await import("../dist/split.js");
const { parseSettings } = await import("../dist/settings.js");
const { startProxy, netState, onNetState, NET_CUT, NET_OFF } = await import("../dist/proxy.js");
const { traffic, keyOf, runsOut, count, save } = await import("../dist/traffic.js");

setTimeout(() => {
  console.error("FAIL - test timed out");
  process.exit(1);
}, 30000).unref();

// ── the lists
assert.deepEqual(listLines("# a comment\n\nDomain:Foo.com\nfull:bar.net\r\n  baz.org  \n"), ["foo.com", "bar.net", "baz.org"], "comments, blanks and v2ray prefixes dropped");
const r = rangesOf(["5.22.0.0/17", "2a01:5ec0::/29", "junk", "1.2.3.4/x"]);
assert.ok(r.check("5.22.100.1", "ipv4") && r.check("2a01:5ec0::1", "ipv6") && !r.check("5.22.200.1", "ipv4"), "CIDRs of both families; junk skipped");
assert.ok(under(new Set(["digikala.com"]), "www.digikala.com") && !under(new Set(["digikala.com"]), "notdigikala.com"), "a domain covers its subdomains only");
assert.ok(iranian("shop.example.ir") && iranian("IR") && iranian("www.digikala.com."), ".ir, and a shipped name outside it");
assert.ok(iranian(undefined, "5.22.0.1") && iranian("5.22.0.1"), "an Iranian address, given or as the host");
assert.ok(!iranian("www.google.com") && !iranian(undefined, "8.8.8.8") && !iranian(), "not Iranian");
assert.ok(sanctioned("dl.sanctioned.example") && !sanctioned("developer.android.com"), "sanctioned sites, by the list got");
assert.ok(filterAddress("10.10.34.35") && !filterAddress("10.10.3.4"), "the filter's address");
assert.ok(filterAddress("2001:4188:2:600:10:10:34:36") && !filterAddress("2001:db8::10:10:3:4"), "and its IPv6 one");
assert.deepEqual(["rr3---sn-4g5e.googlevideo.com", "www.bbc.co.uk", "x.com", "news.google.de", "localhost"].map(siteOf), ["googlevideo.com", "bbc.co.uk", "x.com", "google.de", "localhost"], "a name's site");
console.log("ok - smart lists: shipped or got lately, Iranian by name and address, sanctioned, the filter's address, a name's site");

// ── data by site, and when the month's data runs out at its rate
assert.deepEqual(["rr3---sn-4g5e.googlevideo.com", "WWW.BBC.CO.UK.", "1.2.3.4", undefined].map(keyOf), ["googlevideo.com", "bbc.co.uk", "1.2.3.4", "(unnamed)"]);
count("a.cdn.example", "vpn", 100), count("b.cdn.example", "vpn", 50), count("b.cdn.example", "direct", 7), count("x.example", "vpn", 0);
assert.deepEqual(traffic().sites.find((x) => x.site === "cdn.example"), { site: "cdn.example", vpn: 150, direct: 7 }, "a site's hosts together, each way apart");
const GB = 2n ** 30n, day = 86_400_000, reset = new Date(2026, 11, 1); // Dec 1: this period began Nov 1
const nov = (d) => new Date(2026, 10, d).getTime();
assert.equal(runsOut(50n * GB, 25n * GB, reset, nov(11)).getDate(), 21, "half used in 10 days: the rest in 10 more");
assert.equal(runsOut(50n * GB, 40n * GB, reset, nov(11)), null, "a fifth in 10 days: lasts till it resets");
assert.equal(runsOut(50n * GB, 49n * GB, reset, nov(1) + day / 2), null, "half a day in: too early to tell");
assert.equal(runsOut(50n * GB, 25n * GB, null, nov(11)), null, "no reset date: nothing to say");
console.log("ok - data by site, the VPN's and direct, and when the month's data runs out");

// ── routes
let rules = { default: "vpn", rules: [{ match: "bank.example.ir", via: "vpn" }], smart: true };
useSplit(() => rules);
assert.ok(splitOn() && !probeOn(), "smart alone needs each site's name, but tries nothing");
assert.equal(route("www.digikala.com"), "direct", "an Iranian site: direct");
assert.equal(route("bank.example.ir"), "vpn", "a rule wins over smart");
assert.equal(route("www.google.com"), "vpn", "the rest: the VPN");
assert.equal(route(undefined, "5.22.0.1"), "direct", "an Iranian address, unnamed");
assert.ok(hits.get(SMART) >= 2, "smart's own routes counted apart");
assert.equal(viaOf("www.digikala.com"), "direct", "an Iranian site's lookup: direct too");
assert.equal(splitSummary(rules), "Iranian sites direct", "the main screen says so");
rules = { ...rules, default: "direct" };
const before = hits.get(SMART);
route("www.digikala.com");
assert.equal(hits.get(SMART), before, "with everything direct, smart decides nothing");
rules = { default: "vpn", rules: [], smart: true, probe: true };
assert.ok(probeOn(), "save data on");
assert.equal(route("www.google.com"), "probe", "saving data, the rest is tried");
assert.equal(route("www.digikala.com"), "direct", "Iranian sites need no try");
assert.equal(viaOf("www.google.com"), "vpn", "a site tried is looked up in the tunnel");
assert.equal(splitSummary(rules), "smart, saving data");
assert.equal(route("dl.sanctioned.example"), "vpn", "a sanctioned site isn't tried: it refuses Iran inside TLS");
learnBlocked("www.blocked.example");
assert.ok(knownBlocked("cdn.blocked.example"), "a blocked name's whole site is learned");
assert.equal(route("img.blocked.example"), "vpn", "and isn't tried again");
const s = parseSettings(JSON.stringify({ split: { default: "vpn", rules: [], smart: true, probe: "yes" } })).split;
assert.deepEqual(s, { default: "vpn", rules: [], smart: true }, "settings keep smart and probe only when true");
assert.equal(wayOf("www.google.com"), "probe", "the check's way now: save data's try");
const counted = hits.get("");
assert.equal(wayOf("www.example.com"), "probe");
assert.equal(hits.get(""), counted, "uncounted: a check isn't a connection");
console.log("ok - smart routes: Iranian direct, rules first, save data tries the rest, blocked sites learned");

// ── blocked or sanctioned? A site's tries, directly and through the VPN (null: not tried)
const ok = { status: 200 };
const no = { status: 403 };
const v = (direct, vpn, site = "some.example") => verdictOf(site, direct, vpn);
assert.equal(v({ fail: "filter" }, null), "blocked", "the filter's DNS answer says it alone");
assert.equal(v({ fail: "cut" }, ok), "blocked", "cut off directly, open through the VPN");
assert.equal(v({ fail: "silent" }, ok), "blocked");
assert.equal(v({ fail: "dns" }, ok), "blocked", "no name directly, yet the VPN's server finds it");
assert.equal(v({ fail: "cut" }, null), "blocked", "a cut once the name's sent is the filter's, even unconnected");
assert.equal(v({ fail: "silent" }, no, "www.sanctioned.example"), "sanctioned", "a listed site dropped directly: its CDN turns Iran away");
assert.equal(v({ fail: "filter" }, ok, "x.sanctioned.example"), "blocked", "the filter's answer wins over the list");
assert.equal(v({ fail: "silent" }, null), "unknown", "silence alone could be a slow site");
assert.equal(v({ fail: "dns" }, { fail: "silent" }), "down", "neither way");
assert.equal(v(no, ok), "sanctioned", "refused directly, let in through the VPN");
assert.equal(v({ status: 451 }, { status: 301 }), "sanctioned");
assert.equal(v(no, no), "unknown", "refused both ways: a bot check, not Iran");
assert.equal(v(no, null), "unknown", "refused, nothing to compare with");
assert.equal(v(no, null, "api.sanctioned.example"), "sanctioned", "then the list says");
assert.equal(v(ok, ok, "chat.sanctioned.example"), "partly", "a listed site whose page opens: its sign-in may not");
assert.equal(v(ok, ok), "open");
assert.equal(v({ status: 404 }, null), "open", "any answer but a refusal opens");
assert.equal(v(ok, no), "open", "a site that refuses the VPN's address opens directly all the same");
assert.equal(v(null, ok), "unknown", "not tried directly (a Mac's whole-system mode): the lists, else can't tell");
assert.equal(v(null, ok, "img.blocked.example"), "blocked", "a site learned blocked");
assert.equal(v(null, null, "x.sanctioned.example"), "partly", "a listed one: some or all of it");
assert.equal(v(null, { fail: "silent" }), "down");
assert.deepEqual([wantOf("blocked"), wantOf("sanctioned"), wantOf("partly"), wantOf("open"), wantOf("down"), wantOf("unknown")], ["vpn", "vpn", null, "direct", null, null]);
assert.deepEqual([tryText(ok), tryText(no), tryText({ fail: "cut" }), tryText(null)], ["opens", "refused (403)", "cut off", "not tried"]);
assert.match(verdictText("unknown", ok, null)[1], /Connect/, "unconnected: why it can't tell");
assert.match(verdictText("down", null, { fail: "silent" })[1], /^Not through/, "untried directly: says only the VPN");
console.log("ok - blocked or sanctioned: the filter, sanctions, open, down, and what can't be told");

// ── save data through the proxy: a fake VPN upstream that counts its tunnels, and "sites" on 127.0.0.1:443 that
// answer, reset, stay silent or answer as the filter does. 443 is privileged: macOS lets anyone have it on every
// address only (loopback's clients alone are answered), Linux not at all (skipped there unless allowed).
const listen = (srv, port = 0, host = "127.0.0.1") =>
  new Promise((res, rej) => srv.once("error", rej).listen(port, host, () => res(srv.address().port)));
const read = (sock) => new Promise((res) => sock.once("data", res));
const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-smart-cert-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });

let mode = "answer"; // how the direct "site" behaves
const site = net.createServer((sock) => {
  sock.on("error", () => {});
  if (!/^(::ffff:)?127\./.test(sock.remoteAddress ?? "")) return sock.destroy();
  sock.once("data", (d) => {
    if (mode === "answer") return sock.end(`direct:${d}`);
    if (mode === "reset") return sock.resetAndDestroy();
    if (mode === "filter") return sock.end('HTTP/1.1 403 Forbidden\r\n\r\n<iframe src="http://10.10.34.34?type=Invalid Site">');
    // silent: never answers
  });
});
try {
  await listen(site, 443).catch((err) => (err.code === "EACCES" && process.platform === "darwin" ? listen(site, 443, "0.0.0.0") : Promise.reject(err)));
} catch (err) {
  if (err.code !== "EACCES") throw err;
  console.log("ok - save data through the proxy # SKIP: can't listen on port 443 here");
  process.exit(0);
}
let tunnels = 0;
const upstream = tls.createServer({ key: readFileSync(path.join(dir, "k.pem")), cert: readFileSync(path.join(dir, "c.pem")) }, (sock) => {
  sock.on("error", () => {});
  sock.once("data", (d) => {
    tunnels++;
    sock.write("HTTP/1.1 200 OK\r\n\r\n");
    sock.once("data", (hello) => sock.end(`vpn:${hello}`)); // the "site" seen through the VPN
  });
});
const conn = { server: { hostname: "127.0.0.1", port: await listen(upstream) }, currentPass: async () => ({ token: "t", notBefore: 0, expires: 2 ** 31 }) };
const proxy = await startProxy(conn, "127.0.0.1", 0);

/** A SOCKS5 CONNECT to 127.0.0.1:443 named `name` (by its HTTP Host): what came back. */
async function get(name) {
  const c = net.connect(proxy.port, "127.0.0.1");
  c.on("error", () => {});
  c.write(Buffer.from([5, 1, 0]));
  await read(c);
  c.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, 1, 187])); // 127.0.0.1:443, as tun2socks gives it
  assert.equal((await read(c))[1], 0, "reply first: the first bytes come after it");
  c.write(`GET / HTTP/1.1\r\nHost: ${name}\r\n\r\n`);
  let got = "";
  c.on("data", (d) => (got += d));
  await new Promise((res) => c.once("close", res));
  return got.split("\r\n")[0];
}

assert.equal(await get("open.example"), "direct:GET / HTTP/1.1", "a site that answers: direct, its answer passed on");
assert.equal(tunnels, 0, "no VPN tunnel for it");
mode = "reset";
assert.equal(await get("reset.example"), "vpn:GET / HTTP/1.1", "reset: the VPN, the first bytes sent again");
mode = "filter";
assert.equal(await get("filtered.example"), "vpn:GET / HTTP/1.1", "the filter's page: the VPN");
mode = "silent";
const t0 = Date.now();
assert.equal(await get("silent.example"), "vpn:GET / HTTP/1.1", "silence: the VPN");
assert.ok(Date.now() - t0 < 5000, "after a short wait");
assert.equal(tunnels, 3);
assert.ok(knownBlocked("reset.example") && knownBlocked("filtered.example") && knownBlocked("silent.example") && !knownBlocked("open.example"), "the blocked ones learned");
mode = "answer";
assert.equal(await get("www.reset.example"), "vpn:GET / HTTP/1.1", "a learned site isn't tried again");
assert.equal(tunnels, 4);
await new Promise((res) => setTimeout(res, 2200)); // saved a moment after
assert.ok(existsSync(path.join(home, ".config", "foxhole-vpn", "lists", "blocked.json")), "and kept for the next run");
assert.ok(JSON.parse(readFileSync(path.join(home, ".config", "foxhole-vpn", "lists", "blocked.json"), "utf8"))["silent.example"] > Date.now(), "till a few days on");

// what each site's connections carried, by site: the direct one's and the VPN's apart
const t = Object.fromEntries(traffic().sites.map((x) => [x.site, x]));
assert.ok(t["open.example"]?.direct > 40 && !t["open.example"].vpn, "a direct site's data, counted direct");
assert.ok(t["reset.example"]?.vpn > 40, "a site through the VPN, counted to it, its subdomain's too");
assert.ok(traffic().sites[0].vpn >= traffic().sites.at(-1).vpn, "the VPN's biggest first");
save();
assert.ok(JSON.parse(readFileSync(path.join(home, ".config", "foxhole-vpn", "traffic.json"), "utf8")).sites["silent.example"], "kept for the month");

// ── the network itself, when the VPN's server doesn't answer: Iran's own sites and the world's, redirected here
const door = net.createServer((sock) => sock.destroy());
const doorPort = await listen(door);
const realConnect = net.connect;
let iranUp = true;
let worldUp = false;
net.connect = (o, ...rest) => {
  const to = (up) => realConnect({ ...o, host: "127.0.0.1", port: up ? doorPort : 1 }, ...rest); // port 1: refused
  if (typeof o === "object" && /digikala|aparat/.test(o.host)) return to(iranUp);
  if (typeof o === "object" && /cloudflare|microsoft/.test(o.host)) return to(worldUp);
  return realConnect(o, ...rest);
};
assert.equal(await netState(), NET_CUT, "Iran's sites open, the world's don't: cut off");
iranUp = false;
assert.equal(await netState(), NET_OFF, "none opens: offline");
worldUp = true;
assert.equal(await netState(), null, "the world opens: fine");
[iranUp, worldUp] = [true, false];
const said = [];
onNetState((x) => said.push(x));
const dead = await startProxy({ ...conn, server: { hostname: "127.0.0.1", port: 1 } }, "127.0.0.1", 0);
const viaDead = async (name) => {
  const c = net.connect(dead.port, "127.0.0.1");
  c.on("error", () => {});
  c.write(Buffer.from([5, 1, 0]));
  await read(c);
  c.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, 1, 187]));
  await read(c);
  c.write(`GET / HTTP/1.1\r\nHost: ${name}\r\n\r\n`);
  await new Promise((res) => c.once("close", res));
};
await viaDead("www.reset.example"); // learned blocked: the VPN, whose server is gone
await new Promise((res) => setTimeout(res, 300));
assert.deepEqual(said, [NET_CUT], "a failed dial looks at the network, and says it's cut off");
assert.equal(await get("www.reset.example"), "vpn:GET / HTTP/1.1");
assert.deepEqual(said, [NET_CUT, null], "and that it's back once a dial works");
net.connect = realConnect;
await dead.close();
door.close();
console.log("ok - the network: cut off (Iran's sites only) or offline, told when the VPN's dials fail, and when they work again");

await proxy.close();
site.close();
upstream.close();
console.log("ok - save data through the proxy: answers stay direct; resets, silence and the filter's page use the VPN, learned");
process.exit(0);
