// Foxhole's own sign-in in a terminal (fxalogin.ts): the desktop app's sign-in window (gui/start.js --sign-in, its
// session said on its stdout), or else a Firefox of its own (a fresh profile, its session read from there). Stand-ins
// play the app's and Firefox's side. Then what Mozilla's page in Foxhole's own window hands over (PageSignIn), a
// stand-in for Mozilla saying which sessions are confirmed.
import assert from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const home = mkdtempSync(join(tmpdir(), "foxhole-fxalogin-"));
process.env.HOME = home; // where desktop-app.json goes (userHome)
const { desktopApp, firefox, saveDesktopApp, signInWindow } = await import("../dist/fxalogin.js");

// which app: none recorded here, so this copy of the repo's own (gui/ on its Electron), where that's installed
const gui = fileURLToPath(new URL("../gui/", import.meta.url));
let repoElectron = null;
try {
  repoElectron = createRequire(join(gui, "package.json"))("electron");
} catch {
  // gui's packages aren't installed (CI)
}
assert.deepEqual(desktopApp(), repoElectron && { path: repoElectron, args: [gui] }, "the repo's own desktop app");

// no desktop app, no Firefox: said, and what to get
await assert.rejects(signInWindow(undefined, undefined, null, null), /isn't available right now: .*desktop app, or a Firefox of its own, and neither is on this computer.*releases/s);

// Linux: no screen (a container, SSH) is said first, whatever's here; Firefox is looked for on the PATH
const platform = Object.getOwnPropertyDescriptor(process, "platform");
const { DISPLAY, WAYLAND_DISPLAY, PATH } = process.env;
Object.defineProperty(process, "platform", { value: "linux" });
delete process.env.DISPLAY;
delete process.env.WAYLAND_DISPLAY;
await assert.rejects(signInWindow(undefined, undefined, null, null), /isn't available right now: there's no screen here for its window \(as in a container, or over SSH\)/);
process.env.WAYLAND_DISPLAY = "wayland-0"; // a desktop's session: on to the app, or Firefox
await assert.rejects(signInWindow(undefined, undefined, null, null), /neither is on this computer/);
mkdirSync(join(home, "bin"));
writeFileSync(join(home, "bin", "firefox"), "");
process.env.PATH = `${join(home, "nothing")}:${join(home, "bin")}`;
const official = "/opt/firefox-official/firefox"; // Mozilla's own build, where it's installed here: that one first
assert.deepEqual(firefox(), { path: existsSync(official) ? official : "firefox", args: [] }, "Firefox, on the PATH");
Object.defineProperty(process, "platform", platform);
Object.assign(process.env, { PATH }, DISPLAY === undefined ? {} : { DISPLAY }, WAYLAND_DISPLAY === undefined ? {} : { WAYLAND_DISPLAY });
if (WAYLAND_DISPLAY === undefined) delete process.env.WAYLAND_DISPLAY;

// a stand-in for the app: as STUB says, signed in, closed first, crashed, waits, or says a session that isn't one
const stub = join(home, "app.mjs");
writeFileSync(
  stub,
  `const args = process.argv.slice(2), mode = process.env.STUB;
if (!args.includes("--sign-in")) process.exit(3);
if (mode === "crash") { process.stderr.write("[1:ERROR:ozone] Missing X server or $DISPLAY\\n"); process.exit(1); }
console.log("open");
const proxied = args.includes("--proxy-server=http://127.0.0.1:1080");
if (mode === "ok") console.log(JSON.stringify({ email: proxied ? "proxied@example.com" : "me@example.com", sessionToken: "ab".repeat(32), uid: "u1", verified: true }));
if (mode === "bad") console.log(JSON.stringify({ email: "me@example.com", sessionToken: "short", uid: "u1" }));
if (mode === "wait") setInterval(() => {}, 1000);
`,
);
saveDesktopApp(process.execPath, [stub]); // as main.js says it: a development copy runs electron with the app's folder
assert.deepEqual(desktopApp(), { path: process.execPath, args: [stub] }, "the app as it last started, before the repo's");
const run = (mode, ...a) => ((process.env.STUB = mode), signInWindow(...a));
const me = { uid: "u1", email: "me@example.com", sessionToken: "ab".repeat(32) };

assert.deepEqual(await run("ok"), me);
assert.equal((await run("ok", undefined, "http://127.0.0.1:1080")).email, "proxied@example.com", "the page loads through the VPN's proxy");
assert.equal(await run("closed"), null, "closed before signing in");
assert.equal(await run("bad"), null, "what isn't a session isn't taken");
await assert.rejects(run("crash"), /window didn't open \(\[1:ERROR:ozone\] Missing X server/);

// waiting stops (esc in the TUI): the window goes, nothing's signed in
const stop = new AbortController();
const waiting = run("wait", stop.signal);
setTimeout(() => stop.abort(), 300);
assert.equal(await waiting, null);

// the app moved away since it last ran: not that one
saveDesktopApp(join(home, "gone"), []);
assert.deepEqual(desktopApp(), repoElectron && { path: repoElectron, args: [gui] });

// a stand-in for Firefox: its own profile (user.js: the proxy, no Sync), where it keeps the sign-in as Firefox does
// (signedInUser.json), as STUB says: signed in (a code first), half-written first, closed first, closed before the
// code, a session that isn't one, crashed, or waits
const ffStub = join(home, "firefox.mjs");
writeFileSync(
  ffStub,
  `import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const args = process.argv.slice(2), mode = process.env.STUB;
const dir = args[args.indexOf("--profile") + 1];
const prefs = existsSync(join(dir, "user.js")) ? readFileSync(join(dir, "user.js"), "utf8") : "";
const ok = args.includes("--no-remote") && args.at(-1) === "about:preferences#sync" && process.env.MOZ_DISABLE_UPDATE_PROCESSING === "1" && prefs.includes('user_pref("identity.sync.tokenserver.uri", "https://127.0.0.1:9/");');
if (mode === "crash" || !ok)
  process.stderr.write("Error: no DISPLAY environment variable specified\\n"), process.exit(1);
const proxied = prefs.includes('user_pref("network.proxy.ssl", "127.0.0.1");') && prefs.includes('user_pref("network.proxy.ssl_port", 1080);');
const keep = (data) => writeFileSync(join(dir, "signedInUser.json"), typeof data === "string" ? data : JSON.stringify({ version: 1, accountData: data }));
const account = (verified, sessionToken = "ab".repeat(32)) => ({ email: proxied ? "proxied@example.com" : "me@example.com", uid: "u1", sessionToken, verified });
if (mode === "closed") process.exit(0);
if (mode === "ok") keep(account(false)), setTimeout(() => keep(account(true)), 700);
if (mode === "half") keep('{"version":1,"accountData":{"email"');
if (mode === "half") setTimeout(() => keep(account(true)), 700);
if (mode === "unconfirmed") keep(account(false)), setTimeout(() => process.exit(0), 700);
if (mode === "bad") keep(account(true, "short")), setTimeout(() => process.exit(0), 1200);
setInterval(() => {}, 1000); // till it's closed
`,
);
const profiles = () => readdirSync(tmpdir()).filter((n) => n.startsWith("foxhole-sign-in-")).sort();
const before = profiles();
const ff = { path: process.execPath, args: [ffStub] };
const inFirefox = (mode, signal, proxy) => ((process.env.STUB = mode), signInWindow(signal, proxy, null, ff));
assert.deepEqual(await inFirefox("ok"), me, "verified (by a code): taken, and that Firefox closed");
assert.equal((await inFirefox("ok", undefined, "http://127.0.0.1:1080")).email, "proxied@example.com", "through the VPN's proxy");
assert.deepEqual(await inFirefox("half"), me, "half-written: read again");
assert.equal(await inFirefox("closed"), null, "closed before signing in");
assert.equal(await inFirefox("unconfirmed"), null, "closed before the code was in: not signed in");
assert.equal(await inFirefox("bad"), null, "what isn't a session isn't taken");
await assert.rejects(inFirefox("crash"), /isn't available right now: Firefox's window didn't open \(Error: no DISPLAY environment variable specified\)/);
const stopFirefox = new AbortController();
const inWait = inFirefox("wait", stopFirefox.signal);
setTimeout(() => stopFirefox.abort(), 300);
assert.equal(await inWait, null, "waiting stops: that Firefox is closed");
process.env.STUB = "ok";
assert.deepEqual(await signInWindow(undefined, undefined, { path: process.execPath, args: [stub] }, { path: join(home, "gone"), args: [] }), me, "the desktop app first");
await assert.rejects(signInWindow(undefined, undefined, null, { path: join(home, "gone"), args: [] }), /Firefox wouldn't start \(spawn .* ENOENT\)/);
await new Promise((r) => setTimeout(r, 100)); // said on its 'error', its profile goes on its 'close'
assert.deepEqual(profiles(), before, "its profile's gone each time");
console.log("ok - sign-in in a terminal: the desktop app's window (as it last ran, or the repo's), else a Firefox of its own; its session, closed, stopped, no window, no app");

// ── What the page hands over (PageSignIn): its session as the password's in, confirmed or with a code from the email
// to type; given once Mozilla has confirmed it, though the page's own last step fails ─────────────────────────────
const { PageSignIn } = await import("../dist/fxalogin.js");
const { sessionCredentials } = await import("../dist/auth.js");
const confirmed = new Set(); // the sessions Mozilla's confirmed (as by their code), by their HAWK id
let asked = 0;
let down = false; // Mozilla's account server doesn't answer
globalThis.fetch = async (url, init) => {
  assert.equal(`${init.method} ${url}`, "GET https://api.accounts.firefox.com/v1/session/status");
  asked++;
  if (down) return new Response("Service Unavailable", { status: 503 });
  const id = /id="(\w+)"/.exec(init.headers.authorization)[1];
  const yes = confirmed.has(id);
  return Response.json({ state: yes ? "verified" : "unverified", uid: "u1", details: { accountEmailVerified: true, sessionVerified: yes, sessionVerificationMeetsMinimumAAL: true } });
};
const confirm = (token) => confirmed.add(sessionCredentials(token).id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (ok) => {
  for (let i = 0; !ok() && i < 200; i++) await sleep(10);
};
const login = (token, verified) => ({ uid: "u1", email: "me@example.com", sessionToken: token, verified });
const as = (token) => ({ uid: "u1", email: "me@example.com", sessionToken: token });
const tokens = ["a", "b", "c", "d", "e", "f", "0"].map((c) => c.repeat(64));
let given = [];
const page = (every = 20) => ((given = []), new PageSignIn((s) => given.push(s), every));

// confirmed as the password's in: given at once, Mozilla not asked; once, whatever the page says after
let p = page();
p.login(login(tokens[0], true));
assert.deepEqual(given, [as(tokens[0])]);
assert.ok(p.given);
p.login(login(tokens[0], true));
p.confirmed();
await p.closed();
assert.deepEqual(given, [as(tokens[0])], "given once");
assert.equal(asked, 0, "Mozilla wasn't asked");

// a code to type: Mozilla's asked meanwhile, and once it says it's confirmed it's given, though the page's last step
// never comes (it failed: its red alert); then it isn't asked any more
p = page();
p.login(login(tokens[1], false));
await sleep(120);
assert.deepEqual(given, [], "not before its code's in");
assert.ok(asked >= 2, `asked meanwhile (${asked})`);
assert.ok(!p.given);
confirm(tokens[1]);
await until(() => given.length);
assert.deepEqual(given, [as(tokens[1])], "given once Mozilla says it's confirmed");
let n = asked;
await sleep(100);
assert.equal(asked, n, "asked no more");
p.confirmed();
await p.closed();
assert.deepEqual(given, [as(tokens[1])], "given once");

// ...and where the page's last step comes, given then, without waiting for Mozilla
p = page(60_000);
p.login(login(tokens[2], false));
p.confirmed();
assert.deepEqual(given, [as(tokens[2])]);

// the window closed before Mozilla's said (the code typed just as it closed): given as it closes
p = page(60_000);
p.login(login(tokens[3], false));
confirm(tokens[3]);
await p.closed();
assert.deepEqual(given, [as(tokens[3])], "given as it closes");

// closed before its code was in: not given, and not asked any more
p = page();
p.login(login(tokens[4], false));
await sleep(50);
await p.closed();
n = asked;
await sleep(100);
assert.deepEqual(given, [], "not given");
assert.equal(asked, n, "asked no more once closed");

// Mozilla not answering: asked again, and given once it answers
p = page();
down = true;
p.login(login(tokens[5], false));
confirm(tokens[5]);
await sleep(100);
assert.deepEqual(given, [], "nothing said, nothing given");
down = false;
await until(() => given.length);
assert.deepEqual(given, [as(tokens[5])]);

// another sign-in in the same page (another account, say) takes its place: the one before is given no more
p = page();
p.login(login(tokens[6], false));
p.login(login("9".repeat(64), false));
confirm(tokens[6]);
await sleep(100);
assert.deepEqual(given, [], "the one before isn't given");
confirm("9".repeat(64));
await until(() => given.length);
assert.deepEqual(given, [as("9".repeat(64))]);
await p.closed();

// what isn't a session isn't taken
p = page();
p.login({ uid: "u1", email: "me@example.com", sessionToken: "short", verified: true });
p.login(undefined);
p.confirmed();
await p.closed();
assert.deepEqual(given, []);
console.log("ok - the page's sign-in: given confirmed, or once Mozilla says its code's in (the page's last step failed, the window closed first), once; not before, nor once closed");
