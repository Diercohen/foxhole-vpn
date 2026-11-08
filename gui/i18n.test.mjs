// node i18n.test.mjs: Foxhole's Persian (renderer/fa.js) has every t`…` text of the window, tray and phone core, and
// index.html's own words; each translation has the values its English has; and no text is there that's gone from the
// code. `--missing` lists what has no Persian yet, as fa.js keys.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import "./renderer/fa.js";

const read = (f) => readFileSync(new URL(f, import.meta.url), "utf8");
const norm = (s) => s.replace(/\s+/g, " ").trim();
const decode = (s) => s.replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (_, e) => ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", nbsp: " " })[e]);

/** A script's t`…` templates as fa.js keys (each ${} a {}), the ones inside others' ${} too. A scanner, enough for these files. */
function tagged(code) {
  const keys = [];
  let i = 0;
  let prev = ""; // the last character that isn't a space: whether a / starts a regular expression
  const skipQuoted = (q) => {
    for (i++; i < code.length && code[i] !== q; i++) if (code[i] === "\\") i++;
    i++;
  };
  const skipRegex = () => {
    for (let cls = false, j = i + 1; j < code.length; j++) {
      if (code[j] === "\\") j++;
      else if (code[j] === "[") cls = true;
      else if (code[j] === "]") cls = false;
      else if (code[j] === "/" && !cls) return void (i = j + 1);
    }
  };
  const template = () => { // from after the opening `: its texts between the ${}
    const parts = [""];
    while (i < code.length) {
      const c = code[i++];
      if (c === "\\") parts[parts.length - 1] += code[i++];
      else if (c === "`") return parts;
      else if (c === "$" && code[i] === "{") (i++), expression(), parts.push("");
      else parts[parts.length - 1] += c;
    }
    throw new Error("a template doesn't end");
  };
  const expression = () => { // up to its } (the whole file at the top), finding templates in it
    for (let depth = 0; i < code.length; ) {
      const c = code[i];
      if (c === "}" && depth === 0) return void i++;
      if (c === "/" && code[i + 1] === "/") i = code.indexOf("\n", i) + 1 || code.length;
      else if (c === "/" && code[i + 1] === "*") i = code.indexOf("*/", i) + 2;
      else if (c === '"' || c === "'") skipQuoted(c);
      else if (c === "/" && (/[(,=:[!&|?{};+\-*%<>~^]|^$/.test(prev) || /\b(return|typeof|case)$/.test(code.slice(0, i).trimEnd()))) skipRegex();
      else if (c === "`") {
        const isT = /(^|[^\w$.])t$/.test(code.slice(Math.max(0, i - 2), i));
        i++;
        const parts = template();
        if (isT) keys.push(norm(parts.join("{}")));
      } else {
        if ("({[".includes(c)) depth++;
        else if (")]".includes(c) || c === "}") depth--;
        i++;
      }
      if (!/\s/.test(code[i - 1])) prev = code[i - 1];
    }
  };
  expression();
  return keys;
}

/** index.html's words: elements marked data-t whole (as app.js translatePage), then the texts, then the attributes read out. */
function pageWords(html) {
  let body = html.slice(html.indexOf("<body")).replace(/<script[\s\S]*?<\/script>/g, "").replace(/<svg[\s\S]*?<\/svg>/g, "");
  const keys = [];
  body = body.replace(/<(\w+)\b[^>]*\sdata-t\b[^>]*>([\s\S]*?)<\/\1>/g, (_, tag, inner) => (keys.push(norm(inner)), ""));
  for (const [, , v] of body.matchAll(/\s(title|placeholder|aria-label|alt)="([^"]*)"/g)) keys.push(norm(decode(v)));
  for (const text of body.split(/<[^>]*>/)) keys.push(norm(decode(text)));
  return keys.filter((k) => /[A-Za-z]{2,}/.test(k));
}

// kept as they are in Persian too: names, and words that are the same (fa.js may have one, for tr() to translate its {})
const SAME = new Set(["Foxhole", "VPN", "English", "SOCKS5 + HTTP", "SOCKS5 + HTTP{}", "Telegram", "DNS", "IP", "Firefox", "GitHub", "Google Apps Script", "Deployment ID", "Ctrl+Shift+J", "ABC 234", "IR", "{} · {}", "LAN {}", "Foxhole · {}", "IP {}", "VPN · {}"]);

const sources = {
  "renderer/app.js": tagged(read("renderer/app.js")),
  "tray.js": tagged(read("tray.js")),
  "main.js": tagged(read("main.js")),
  "../mobile/node/main.mjs": tagged(read("../mobile/node/main.mjs")),
  "renderer/index.html": pageWords(read("renderer/index.html")),
};
const missing = new Set();
for (const keys of Object.values(sources)) for (const k of keys) if (!(k in FA) && !SAME.has(k)) missing.add(k);
if (process.argv.includes("--missing")) {
  for (const k of missing) console.log(JSON.stringify(k));
  process.exit(0);
}
assert.ok(sources["renderer/app.js"].length > 350, "app.js's texts were found");
assert.deepEqual([...missing], [], "every text has its Persian in renderer/fa.js");

// each translation has its English's values: {} as many, in order, or {0}, {1}… each one there is (some may go)
for (const [en, fa] of Object.entries(FA)) {
  const n = en.split("{}").length - 1;
  const plain = (fa.match(/\{\}/g) ?? []).length;
  const numbered = [...fa.matchAll(/\{(\d)\}/g)].map((m) => +m[1]);
  assert.ok(numbered.length ? !plain && numbered.every((x) => x < n) : plain === n, `the values of ${JSON.stringify(en)}`);
  if (!SAME.has(en)) assert.match(fa, /[؀-ۿ]|^[^A-Za-z]*$/, `Persian for ${JSON.stringify(en)}`);
}

// no text that's gone: each piece of a key between its {} is in the code (the core's words too: controller.js, updater.js, src/, and
// the phone's Kotlin), a list's ", " beside a {} aside
const kotlin = "../mobile/android/app/src/main/java/io/github/diercohen/foxhole/";
const code = ["renderer/app.js", "renderer/index.html", "controller.js", "updater.js", "tray.js", "main.js", "../mobile/node/main.mjs"]
  .concat(readdirSync(new URL("../src/", import.meta.url)).filter((f) => f.endsWith(".ts")).map((f) => `../src/${f}`))
  .concat(readdirSync(new URL(kotlin, import.meta.url)).map((f) => kotlin + f))
  .map((f) => norm(read(f)))
  .join("\n");
const coded = decode(code);
for (const en of Object.keys(FA))
  for (const piece of en.split("{}").map((p) => p.trim().replace(/^, |,$/g, "")).filter((p) => p.length > 3))
    assert.ok(code.includes(piece) || coded.includes(piece), `fa.js has ${JSON.stringify(en)}, no longer in the code (${JSON.stringify(piece)})`);

// the tag: Persian with its values put in, English as written; a country's name
const fa = foxholeWords("fa");
assert.equal(fa`Connect`, FA.Connect);
assert.equal(foxholeWords("en")`Connected · ${"Germany"}`, "Connected · Germany");
assert.equal(fa`Connected · ${"x"}`, FA["Connected · {}"].replace("{}", "x"));
for (const code of "AR AT AU BE BG BR CA CL CO DE DK ES FI FR GB GH IE IR IT JP KR MX MY NL NO NZ PE PH PT SE SG TH US ZA RELAY".split(" "))
  assert.match(FA_COUNTRIES[code] ?? "", /[؀-ۿ]/, `FA_COUNTRIES.${code}`);
console.log(`i18n: ${Object.keys(FA).length} Persian texts, all of the window's, tray's and phone core's ok`);
