// The relay setup wizard's shared parts: the script with the key in it, its highlighting, reading a pasted
// Deployment ID, and the PNG decoder that draws the step screenshots in the terminal.
import assert from "node:assert";
import { deflateSync } from "node:zlib";
import { relayTemplate, relayScript, KEY_PLACEHOLDER, newAuthKey, keyOk, deploymentId, highlightJs, stepImage } from "../dist/relaysetup.js";
import { decodePng, halfBlocks, wrap } from "../dist/relaywizard.js";

// The script: the placeholder is there once, and the key replaces it
assert.equal(relayTemplate().split(KEY_PLACEHOLDER).length, 2, "Code.gs has the key placeholder once");
const key = newAuthKey();
assert.ok(keyOk(key) && key.length === 32, "a generated key is valid");
assert.ok(!keyOk("short") && !keyOk('has"quote-and-long-enough'), "short or quoting keys are refused");
assert.ok(relayScript(key).startsWith(`const AUTH_KEY = "${key}";`), "the key goes into AUTH_KEY");

// Highlighting: lossless, and the parts a reader sees colored
const tokens = highlightJs(relayTemplate());
assert.equal(tokens.map((t) => t[1]).join(""), relayTemplate(), "tokens join back to the code");
const kind = (text) => tokens.find((t) => t[1] === text)?.[0];
assert.equal(kind("function"), "kw");
assert.equal(kind(`"${KEY_PLACEHOLDER}"`), "s");
assert.equal(kind("/^https?:\\/\\/script\\.google\\.com\\/macros\\//i"), "re", "a regex literal");
assert.equal(kind("doPost"), "fn");
assert.ok(tokens.some(([k, t]) => k === "c" && t.startsWith("// Keep browser")), "a comment");
assert.deepEqual(highlightJs('a / b; x = "//not a comment"'), [["", "a / b; x = "], ["s", '"//not a comment"']], "division isn't a regex, // in a string isn't a comment");

// A pasted Deployment ID: alone, inside the web app URL, or not one at all
const id = "AKfycbx" + "a".repeat(60);
assert.equal(deploymentId(` ${id}\n`), id);
assert.equal(deploymentId(`https://script.google.com/macros/s/${id}/exec`), id);
assert.equal(deploymentId("https://example.com"), null);
assert.equal(deploymentId(""), null);

// Wrapping keeps **bold** across a line break and indents the following lines
const w = wrap("1. Click **Deploy then New deployment** now", 20, 3).map((l) => l.replace(/\x1b\[[0-9;]*m/g, ""));
assert.deepEqual(w, ["1. Click Deploy then", "   New deployment", "   now"]);

// PNG: a 2×2 RGBA image with each filter type, and the shipped screenshots
const png = (w, h, type, rows) => {
  const chunk = (name, data) => {
    const b = Buffer.alloc(12 + data.length);
    b.writeUInt32BE(data.length, 0);
    b.write(name, 4, "latin1");
    data.copy(b, 8);
    return b; // the CRC isn't checked
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0), ihdr.writeUInt32BE(h, 4), (ihdr[8] = 8), (ihdr[9] = type);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(Buffer.from(rows.flat()))), chunk("IEND", Buffer.alloc(0))]);
};
// row 0, filter None: red, green; row 1, filter Up (adds the row above): + (0,0,255) → magenta, cyan
const img = decodePng(png(2, 2, 2, [[0, 255, 0, 0, 0, 255, 0], [2, 0, 0, 255, 0, 0, 255]]));
assert.deepEqual([img.px(0, 0), img.px(1, 0), img.px(0, 1), img.px(1, 1)], [[255, 0, 0], [0, 255, 0], [255, 0, 255], [0, 255, 255]]);
// filter Sub (adds the pixel to the left, mod 256): the second pixel's alpha 255 + 1 wraps to 0, transparent over black
const rgba = decodePng(png(2, 1, 6, [[1, 10, 20, 30, 255, 5, 5, 5, 1]]));
assert.deepEqual([rgba.px(0, 0), rgba.px(1, 0)], [[10, 20, 30], [0, 0, 0]]);
assert.equal(decodePng(Buffer.from("not a png")), null);
for (let n = 1; n <= 4; n++) {
  const shot = decodePng((await import("node:fs")).readFileSync(stepImage(n)));
  assert.ok(shot && shot.w > 0, `step ${n}'s screenshot decodes`);
  const lines = halfBlocks(stepImage(n), 30, 9);
  if (lines) assert.ok(lines.length <= 9 && lines.some((l) => l.includes("▀")), `step ${n} draws in half blocks`);
}

console.log("relaysetup: ok");
