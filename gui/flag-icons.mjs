// The tray menu's flags (menus take no SVG): build/flags/<code>.png and <code>@2x.png, round and glossy like the
// window's, drawn from renderer/flags/*.svg by Electron itself. After changing a flag there: npm run flags
import { app, BrowserWindow } from "electron";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("./renderer/flags/", import.meta.url));
const out = fileURLToPath(new URL("./build/flags/", import.meta.url));
const codes = readdirSync(src).filter((f) => f.endsWith(".svg")).map((f) => f.slice(0, -4));

app.disableHardwareAcceleration(); // offscreen, the software renderer is enough
app.on("window-all-closed", () => {}); // the first size's window closing mustn't quit before the second
app.whenReady().then(async () => {
  process.on("unhandledRejection", (err) => (console.error(err), app.exit(1)));
  mkdirSync(out, { recursive: true });
  for (const [scale, suffix] of [[1, ""], [2, "@2x"]]) {
    const size = 16 * scale;
    const win = new BrowserWindow({ show: false, width: size * codes.length, height: size, transparent: true, frame: false, webPreferences: { offscreen: true } });
    const html = `<style>
      body { margin: 0; display: flex; background: transparent; }
      .f { position: relative; width: ${size}px; height: ${size}px; padding: ${scale}px; box-sizing: border-box; }
      .f > div { position: relative; width: 100%; height: 100%; border-radius: 50%; overflow: hidden; }
      svg { display: block; width: 100%; height: 100%; filter: saturate(1.18) contrast(1.05); }
      .f > div::after { content: ""; position: absolute; inset: 0; border-radius: 50%;
        background: radial-gradient(90% 60% at 32% 10%, rgba(255,255,255,.55), rgba(255,255,255,.08) 46%, transparent 62%),
          radial-gradient(120% 70% at 50% 118%, rgba(0,0,0,.4), transparent 60%);
        box-shadow: inset 0 0 0 ${scale / 2}px rgba(0,0,0,.35); }
    </style>${codes.map((c) => `<div class="f"><div>${readFileSync(src + c + ".svg", "utf8")}</div></div>`).join("")}`;
    const page = join(mkdtempSync(join(tmpdir(), "flags-")), "flags.html");
    writeFileSync(page, html);
    await win.loadFile(page);
    rmSync(page, { force: true });
    await new Promise((r) => setTimeout(r, 300)); // a frame painted
    const all = await win.webContents.capturePage();
    codes.forEach((c, i) => writeFileSync(`${out}${c}${suffix}.png`, all.crop({ x: i * size, y: 0, width: size, height: size }).toPNG()));
    win.destroy();
  }
  console.log(`${codes.length} flags in build/flags`);
  app.quit();
});
