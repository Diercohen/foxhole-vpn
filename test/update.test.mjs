// Pure check of the semver comparison used for update detection.
import assert from "node:assert";
import { newer, noteBlocks, releaseNotes, VERSION } from "../dist/update.js";

assert.equal(newer("1.0.0", "0.9.9"), true, "major up");
assert.equal(newer("0.2.0", "0.1.9"), true, "minor up");
assert.equal(newer("0.1.1", "0.1.0"), true, "patch up");
assert.equal(newer("0.1.0", "0.1.0"), false, "equal is not newer");
assert.equal(newer("0.1.0", "0.2.0"), false, "older is not newer");
assert.equal(newer("1.0.0", "0.99.99"), true, "major beats large minor/patch");
assert.ok(typeof VERSION === "string" && /\d+\.\d+\.\d+/.test(VERSION), "VERSION loaded from package.json");

console.log("ok - version compare detects newer releases");

// Release notes from GitHub's releases feed: the versions between, newest first, up to Downloads, as plain text
const entry = (v, html) => `<entry><link rel="alternate" type="text/html" href="https://github.com/x/y/releases/tag/v${v}"/><content type="html">${html.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</content></entry>`;
const atom = `<feed>${[
  entry("1.2.0", "<h2>What&#39;s new</h2>\n<ul>\n<li><strong>Bold</strong> and <code>code</code> &amp; more</li>\n<li>Two</li>\n</ul>\n<p>A note.</p>\n<h2>Downloads</h2><ul><li>file.dmg</li></ul><p><strong>Full Changelog</strong>: x</p>"),
  entry("1.1.0", "<p>bump</p>"),
  entry("1.0.0", "<p>installed already</p>"),
].join("")}</feed>`;
assert.deepEqual(releaseNotes(atom, "1.0.0", "1.2.0"), [
  { version: "1.2.0", blocks: [
    { kind: "li", depth: 1, mark: "•", spans: [{ text: "Bold", b: true }, { text: " and " }, { text: "code", code: true }, { text: " & more" }] },
    { kind: "li", depth: 1, mark: "•", spans: [{ text: "Two" }] },
    { kind: "p", depth: 0, spans: [{ text: "A note." }] },
  ] },
  { version: "1.1.0", blocks: [{ kind: "p", depth: 0, spans: [{ text: "bump" }] }] },
]);
assert.deepEqual(releaseNotes(atom, "1.0.0", "1.1.0").map((n) => n.version), ["1.1.0"], "none newer than the update");
console.log("ok - release notes parsed from the feed");

// Markdown's other marks, as GitHub's HTML has them: nested and numbered lists, a loose item, italic, struck, a code block;
// a link keeps its address only into the repo (all the window opens)
const html = `<ul><li><em>it</em> <del>old</del> <a href="https://github.com/Diercohen/foxhole-vpn/pull/3">#3</a> <a href="https://example.com">out</a><ul><li>child</li></ul></li></ul>
<ol start="2"><li><p>loose</p><p>more</p></li><li>next</li></ol><h3>Fixes</h3><pre><code>a\n  b\n</code></pre>`;
assert.deepEqual(noteBlocks(html), [
  { kind: "li", depth: 1, mark: "•", spans: [{ text: "it", i: true }, { text: " " }, { text: "old", s: true }, { text: " " }, { text: "#3", href: "https://github.com/Diercohen/foxhole-vpn/pull/3" }, { text: " " }, { text: "out" }] },
  { kind: "li", depth: 2, mark: "•", spans: [{ text: "child" }] },
  { kind: "li", depth: 1, mark: "2.", spans: [{ text: "loose" }] },
  { kind: "p", depth: 1, spans: [{ text: "more" }] },
  { kind: "li", depth: 1, mark: "3.", spans: [{ text: "next" }] },
  { kind: "h", depth: 0, spans: [{ text: "Fixes" }] },
  { kind: "pre", depth: 0, spans: [{ text: "a\n  b", code: true }] },
]);
console.log("ok - release notes keep Markdown's marks");
