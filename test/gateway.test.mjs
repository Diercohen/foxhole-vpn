// The router for a Smart DNS device's Telegram (gateway.ts): what it asks the helper to run, in what order, and what it
// undoes. `ifconfig` and `sysctl` are stand-ins on PATH, and the helper a list: nothing here touches this computer's network.
import assert from "node:assert";
import { EventEmitter } from "node:events";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

if (process.platform === "win32") {
  console.log("ok - the router for Smart DNS devices # SKIP: macOS's");
  process.exit(0);
}
const { startGateway } = await import("../dist/gateway.js");
const { TELEGRAM_CIDRS } = await import("../dist/global.js");

const dir = mkdtempSync(path.join(os.tmpdir(), "foxhole-gateway-"));
const up = path.join(dir, "tun"), forwarding = path.join(dir, "forwarding");
writeFileSync(path.join(dir, "ifconfig"), `#!/bin/sh\n[ -e "${up}" ]\n`);
writeFileSync(path.join(dir, "sysctl"), `#!/bin/sh\ncat "${forwarding}"\n`);
for (const f of ["ifconfig", "sysctl"]) chmodSync(path.join(dir, f), 0o755);
process.env.PATH = `${dir}:${process.env.PATH}`;

/** A helper that notes what it's asked; `refuse` fails one command. tun2socks makes the tun, and killing it (or pkill) ends it. */
function helper(refuse) {
  const ran = [];
  const procs = [];
  return {
    ran,
    procs,
    priv: {
      run: async (argv, quiet) => {
        ran.push(argv.join(" "));
        if (argv[0] === "pkill") rmSync(up, { force: true });
        if (!quiet && argv.join(" ") === refuse) throw new Error(`refused: ${refuse}`);
      },
      spawn: (argv) => {
        ran.push(argv.join(" "));
        writeFileSync(up, "");
        const p = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, kill() { p.signalCode = "SIGTERM"; p.emit("exit", null, "SIGTERM"); } });
        procs.push(p);
        return p;
      },
    },
  };
}
const options = (h, onExit = () => assert.fail("tun2socks isn't meant to stop")) => ({ priv: h.priv, tun2socksPath: "/t2s", proxyPort: 1080, onExit });
const adds = TELEGRAM_CIDRS.map((c) => `route -n add -net ${c} 198.18.0.1`);
const deletes = TELEGRAM_CIDRS.map((c) => `route -n delete -net ${c}`);
const START = ["/t2s --device utun123 --proxy socks5://127.0.0.1:1080", "ifconfig utun123 198.18.0.1 198.18.0.1 up", ...adds];
const PKILL = "pkill -f utun12[3]";

assert.ok(TELEGRAM_CIDRS.includes("149.154.160.0/20") && TELEGRAM_CIDRS.every((c) => !c.includes(":")), "Telegram's IPv4 ranges");

// forwarding off: turned on, then off again, last on and first off of what carries traffic
writeFileSync(forwarding, "0\n");
let h = helper();
let stop = await startGateway(options(h));
assert.deepEqual(h.ran, [...START, "sysctl -w net.inet.ip.forwarding=1"], "the tun, Telegram's addresses into it, then forwarding");
h.ran.length = 0;
await stop();
assert.deepEqual(h.ran, [...deletes, "sysctl -w net.inet.ip.forwarding=0", PKILL], "all of it undone");
assert.ok(!existsSync(up), "the tun is gone");

// forwarding already on (Internet Sharing): left alone
writeFileSync(forwarding, "1\n");
h = helper();
stop = await startGateway(options(h));
assert.deepEqual(h.ran, START, "forwarding isn't touched when it was on");
await stop();
assert.ok(!h.ran.some((c) => c.startsWith("sysctl")), "nor at the end");

// a killed Foxhole's tun: cleared first
writeFileSync(forwarding, "0\n");
writeFileSync(up, "");
h = helper();
stop = await startGateway(options(h));
assert.equal(h.ran[0], PKILL, "the old tun goes first");
assert.equal(h.ran[1], START[0], "then tun2socks");
await stop();

// a step refused: what was done is undone, and it's said
h = helper(adds[3]);
await assert.rejects(startGateway(options(h)), /refused/, "the failure comes out");
assert.equal(h.procs[0].signalCode, "SIGTERM", "tun2socks stopped");
assert.ok(deletes.every((d) => h.ran.includes(d)) && !h.ran.includes("sysctl -w net.inet.ip.forwarding=1"), "routes removed, forwarding never on");

// tun2socks dying by itself is said; being stopped isn't
let exited = null;
h = helper();
stop = await startGateway(options(h, (code) => (exited = code)));
h.procs[0].emit("exit", 7, null);
assert.equal(exited, 7, "its exit reported");
exited = null;
await stop();

rmSync(dir, { recursive: true, force: true });
console.log("ok - the router for Smart DNS devices: Telegram's addresses into the tun, forwarding on, all undone");
