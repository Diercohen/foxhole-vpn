// Display helpers. No network.
import assert from "node:assert";
import { countryName } from "../dist/ui.js";

// Intl names a code when it can; when it only echoes the code back (an unassigned one here,
// every code on Fedora's minimal-ICU Node), the server list's own name is used.
assert.equal(countryName("XQ", "Somewhere"), "Somewhere", "no name from Intl: the server list's");
assert.ok(["Germany", "DE-list"].includes(countryName("DE", "DE-list")), "a real code: Intl's name, or the list's");

console.log("ok - country names");
