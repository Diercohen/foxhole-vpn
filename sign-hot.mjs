#!/usr/bin/env node
// Signs hot.json, the fixes every Foxhole picks up without a release (src/hot.ts). Edit its "data", then run
//   node sign-hot.mjs
// It sets data.issued to now (a Foxhole takes only a file issued after the one it has), signs, and writes it back:
// commit and push it. jsDelivr can keep the old one up to 12 hours: https://purge.jsdelivr.net/gh/Diercohen/foxhole-vpn@main/hot.json
// clears it. The key stays on this computer, in ~/.foxhole-release/hot-ed25519.pem (or $FOXHOLE_HOT_KEY).
//
// data can have:
//   "notice": "…"        for every user: a dialog in the app, under the buttons in the TUI (3 lines: keep it short)
//   "expires": "<ISO>"   from then on the whole file is ignored, and the built-in values hold
//   "fallback": { "146.75.": ["151.101.1.", "151.101.65.", "151.101.129.", "151.101.193."] }
//                        addresses to try after DNS's for Mozilla's hosts, in place of that built-in rule: one starting
//                        with a key adds each value, with its last number when the value ends in "."
//   "fronted": ["example.google.com"]   more of Google's sites relay mode sends straight to Google
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";

const file = new URL("./hot.json", import.meta.url);
const key = createPrivateKey(readFileSync(process.env.FOXHOLE_HOT_KEY ?? `${homedir()}/.foxhole-release/hot-ed25519.pem`));
const pub = createPublicKey(key).export({ type: "spki", format: "der" }).toString("base64");
if (!readFileSync(new URL("./src/hot.ts", import.meta.url), "utf8").includes(pub)) throw new Error("this isn't the key src/hot.ts trusts");
const { data } = JSON.parse(readFileSync(file, "utf8"));
data.issued = new Date().toISOString();
const sig = sign(null, Buffer.from(JSON.stringify(data)), key).toString("base64");
writeFileSync(file, JSON.stringify({ data, sig }, null, 2) + "\n");
console.log(`hot.json signed, issued ${data.issued}`);
