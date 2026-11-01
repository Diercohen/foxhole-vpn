// Gets the Android app ready to build: Foxhole's core built (npm run build at the top), the desktop window and the
// core copied into the app's assets, and the two native parts fetched (and checked) into native/: Node for Android
// (nodejs-mobile) and the tunnel whole-system mode sends apps' connections through (hev-socks5-tunnel).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const mobile = join(dirname(fileURLToPath(import.meta.url)), "..");
const root = join(mobile, "..");
const native = join(mobile, "native");
const assets = join(mobile, "android/app/src/main/assets");

const NODE = {
  url: "https://github.com/nodejs-mobile/nodejs-mobile/releases/download/v18.20.4/nodejs-mobile-v18.20.4-android.zip",
  sha256: "bd7321eaa1a7602fbe0bb87302df2d79d87835cf4363fbdd17c350dbb485c2af",
};
// 2.18.0: the last one whose libraries load on Android 9 (2.19's use ELF TLS, Android 10+)
const TUNNEL = {
  url: "https://github.com/heiher/hev-socks5-tunnel/releases/download/2.18.0/hev-socks5-tunnel.aar",
  sha256: "15ec8ed121663b562c99caa5bb602d1009f24e5b09e733438b81988f12feaaab",
};

/** Downloads `url` to `file` unless the file expected is there already, and checks it's that file. */
async function fetchChecked({ url, sha256 }, file) {
  const ok = () => existsSync(file) && createHash("sha256").update(readFileSync(file)).digest("hex") === sha256;
  if (ok()) return;
  console.log(`downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  if (!ok()) {
    rmSync(file);
    throw new Error(`${url} isn't the file expected: try again`);
  }
}

mkdirSync(native, { recursive: true });
await fetchChecked(TUNNEL, join(native, "hev-socks5-tunnel.aar"));
if (!existsSync(join(native, "nodejs-mobile/bin"))) {
  const zip = join(native, "nodejs-mobile.zip");
  await fetchChecked(NODE, zip);
  execFileSync("unzip", ["-q", "-o", zip, "nodejs-mobile/bin/*", "-d", native], { stdio: "inherit" });
  rmSync(zip);
}

// The core, as the desktop app has it (gui/: controller.js and updater.js over dist/)
execFileSync("npm", ["run", "build"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });

rmSync(assets, { recursive: true, force: true });
const project = join(assets, "nodejs-project");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
mkdirSync(project, { recursive: true });
writeFileSync(join(project, "package.json"), JSON.stringify({ name: "foxhole-core", version, type: "module" }, null, 2));
for (const f of ["controller.js", "updater.js"]) cpSync(join(root, "gui", f), join(project, f));
cpSync(join(mobile, "node/main.mjs"), join(project, "main.mjs"));
cpSync(join(root, "dist"), join(project, "dist"), { recursive: true, filter: (src) => !src.endsWith(".png") }); // the screenshots are the window's

// The window: the desktop's page, with the bridge to the app (www/android.js) before its script, and the relay
// setup's screenshots where it looks for them (../dist/assets/relay)
const www = join(assets, "www");
cpSync(join(root, "gui/renderer"), join(www, "renderer"), { recursive: true });
cpSync(join(mobile, "www/android.js"), join(www, "renderer/android.js"));
const page = join(www, "renderer/index.html");
const html = readFileSync(page, "utf8");
const at = html.indexOf('<script src="app.js"');
if (at < 0) throw new Error("index.html: no app.js script to put the bridge before");
writeFileSync(page, `${html.slice(0, at)}<script src="android.js"></script>\n${html.slice(at)}`);
const shots = join(www, "dist/assets/relay");
mkdirSync(shots, { recursive: true });
for (const f of readdirSync(join(root, "assets/relay"))) if (f.endsWith(".png")) cpSync(join(root, "assets/relay", f), join(shots, f));
console.log(`ready: Foxhole ${version} in ${assets}`);
