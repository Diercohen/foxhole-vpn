// Display helpers. No network.
import assert from "node:assert";
import { countryName, vw } from "../dist/ui.js";
import { fox, FOX_W, FOX_H } from "../dist/fox.js";

// Intl names a code when it can; when it only echoes the code back (an unassigned one here,
// every code on Fedora's minimal-ICU Node), the server list's own name is used.
assert.equal(countryName("XQ", "Somewhere"), "Somewhere", "no name from Intl: the server list's");
assert.ok(["Germany", "DE-list"].includes(countryName("DE", "DE-list")), "a real code: Intl's name, or the list's");

console.log("ok - country names");

// The TUI draws each frame of the fox over the last, in place: every frame keeps the same size.
for (const mood of ["off", "waiting", "proxy", "global"])
  for (let t = 0; t < 10_000; t += 50)
    for (const plain of [false, true]) {
      const lines = fox(mood, t, plain);
      assert.equal(lines.length, FOX_H, `${mood} at ${t} ms: ${FOX_H} lines`);
      for (const l of lines) assert.equal(vw(l), FOX_W, `${mood} at ${t} ms: each line ${FOX_W} columns`);
    }
assert.ok(fox("global", 0, true).every((l) => !l.includes("\x1b")), "plain: the shape alone, no colors");
assert.notDeepEqual(fox("off", 1000), fox("proxy", 1000), "asleep when off, awake when connected");

console.log("ok - fox frames");
