// node mobile/node/main.test.mjs (after `npm run build` at the top): the notification's Pause and Resume in main.mjs,
// and its fetch() where there's no WebAssembly (iOS), run as the app runs it (a socket on fd 3; no JIT, as on iOS), the
// app's side played here, the Controller a stand-in (no account needed).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "foxhole-core-"));
copyFileSync(join(here, "main.mjs"), join(dir, "main.mjs")); // a copy: its imports resolve beside it
symlinkSync(join(here, "../../dist"), join(dir, "dist"));
writeFileSync(join(dir, "package.json"), '{ "type": "module" }');
writeFileSync(join(dir, "updater.js"), "export class Updater { start() {} state() { return null; } }");
// gui/controller.js as main.mjs uses it: each step takes a moment, whole-system mode through main.mjs's globalSession
writeFileSync(join(dir, "controller.js"), `
import { EventEmitter } from "node:events";
const moment = () => new Promise((r) => setTimeout(r, 80));
export class Controller extends EventEmitter {
  #android; #active = null; #global = null; #busy = false; #connecting = null;
  constructor({ android }) { super(); this.#android = android; }
  async start() {}
  via() {}
  reloadList(url, method) { return fetch(url, { method, body: method === "POST" ? "hi" : undefined }).then((r) => r.text()); }
  openSettings() {}
  #changed() { this.emit("change"); }
  async connect(code) {
    if (this.#busy) return;
    this.#busy = true; this.#connecting = code; this.#changed();
    await moment();
    this.#active = code; this.#busy = false; this.#connecting = null; this.#changed();
  }
  async disconnect() {
    if (this.#busy) return;
    if (this.#global) await this.#globalOff();
    if (!this.#active) return;
    await moment(); // the proxy closing
    this.#active = null; this.#changed();
  }
  async toggleGlobal() {
    if (this.#busy) return;
    if (this.#global) return this.#globalOff();
    this.#busy = true; this.#changed();
    const session = this.#android.globalSession({ proxyPort: 1080 });
    await session.start();
    this.#global = session; this.#busy = false; this.#changed();
  }
  async #globalOff() {
    this.#busy = true; this.#changed();
    const session = this.#global;
    this.#global = null;
    await session.stop();
    this.#busy = false; this.#changed();
  }
  state() {
    return { active: this.#active, global: this.#global ? this.#active : null, globalOn: !!this.#global, busy: this.#busy, connecting: this.#connecting,
      relayOn: false, proxy: this.#active ? { addr: "127.0.0.1:1080" } : null, countries: [{ code: "DE", name: "Germany" }, { code: "US", name: "United States" }] };
  }
}`);

const core = spawn(process.execPath, ["--jitless", "main.mjs", "3"], { cwd: dir, env: { ...process.env, HOME: dir }, stdio: ["ignore", "inherit", "inherit", "pipe"] });
const app = core.stdio[3];
const out = (m) => app.write(`${JSON.stringify(m)}\n`);
const notes = []; // what the notification said, in order: its title (" [Resume]" when paused), or "off"
const vpn = []; // Android's VPN asked up and down
const replies = new Map();
let buf = "";
app.setEncoding("utf8");
app.on("data", (chunk) => {
  buf += chunk;
  for (let i; (i = buf.indexOf("\n")) >= 0; ) {
    const m = JSON.parse(buf.slice(0, i));
    buf = buf.slice(i + 1);
    if (m.t === "reply") replies.get(m.id)?.(m.v);
    if (m.t !== "ask") continue;
    if (m.cmd === "keepAlive") notes.push(m.args.off ? "off" : `${m.args.title}${m.args.paused ? " [Resume]" : ""}`);
    if (m.cmd === "vpnStart" || m.cmd === "vpnStop") vpn.push(m.cmd);
    out({ t: "answer", id: m.id, v: null });
  }
});
let seq = 0;
/** A window's action, as the app passes it on; resolves with its answer once done. */
const act = (name, ...args) => new Promise((resolve) => (replies.set(++seq, resolve), out({ t: "act", id: seq, name, args })));
const settle = () => new Promise((r) => setTimeout(r, 500)); // the notification follows the state within 50 ms

try {
  // fetch() without WebAssembly: redirects as fetch() follows them (a POST's 302 to a GET, a 307 kept a POST)
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d)).on("end", () => {
      if (req.url === "/302" || req.url === "/307") return res.writeHead(Number(req.url.slice(1)), { location: "/to" }).end();
      res.end(`${req.method} ${req.url} ${body}`);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const at = `http://127.0.0.1:${server.address().port}`;
  assert.equal(await act("reloadList", `${at}/302`, "POST"), "GET /to ");
  assert.equal(await act("reloadList", `${at}/307`, "POST"), "POST /to hi");
  server.close();

  await act("connect", "DE");
  await act("toggleGlobal");
  await settle();
  assert.equal(notes.at(-1), "Whole system · Germany");

  // Pause: Android's VPN down, the notification straight to Paused: never gone, or its icon would go with it
  let from = notes.length;
  out({ t: "pause" });
  await settle();
  assert.deepEqual(vpn, ["vpnStart", "vpnStop"]);
  assert.ok(!notes.slice(from).includes("off"), `the notification went away: ${notes.slice(from)}`);
  assert.equal(notes.at(-1), "Paused · Germany [Resume]");

  // Resume: as it was, whole-system mode too
  from = notes.length;
  out({ t: "resume" });
  await settle();
  assert.ok(notes.slice(from).includes("Connecting… · Germany [Resume]"));
  assert.ok(!notes.slice(from).includes("off"));
  assert.deepEqual(vpn, ["vpnStart", "vpnStop", "vpnStart"]);
  assert.equal(notes.at(-1), "Whole system · Germany");

  // Paused, the app's power button resumes as the notification's Resume does, whole-system mode too; meanwhile the
  // window's state says paused
  out({ t: "pause" });
  await settle();
  assert.deepEqual((await act("state")).paused, { code: "DE", global: true });
  await act("power");
  await settle();
  assert.equal(notes.at(-1), "Whole system · Germany");
  assert.equal(vpn.at(-1), "vpnStart");
  assert.equal((await act("state")).paused, null);

  // ...and so does a country picked while paused: there
  out({ t: "pause" });
  await settle();
  await act("connect", "US");
  await settle();
  assert.equal(notes.at(-1), "Whole system · United States");

  // Disconnect while paused: the notification goes
  out({ t: "pause" });
  await settle();
  assert.equal(notes.at(-1), "Paused · United States [Resume]");
  out({ t: "disconnect" });
  await settle();
  assert.equal(notes.at(-1), "off");

  // Paused in proxy-only mode, resumed in the app, then disconnected there: Paused doesn't come back
  await act("connect", "DE");
  out({ t: "pause" });
  await settle();
  assert.equal(notes.at(-1), "Paused · Germany [Resume]");
  await act("power");
  await settle();
  assert.equal(notes.at(-1), "Proxy · Germany");
  await act("disconnect");
  await settle();
  assert.equal(notes.at(-1), "off");
  console.log("main.mjs: fetch() without WebAssembly, Pause and Resume ok");
} finally {
  core.kill();
  rmSync(dir, { recursive: true, force: true });
}
