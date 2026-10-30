// The Apps Script relay's response parsing. No network: synthetic envelopes, including the goog.script.init
// HTML wrapper Apps Script really returns and a gzipped body.
import assert from "node:assert";
import { gzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { parseEnvelope, envelopeResponse, relayUrl, loadRelay } from "../dist/httprelay.js";

// A plain JSON envelope (as script.googleusercontent.com can serve it directly).
const plain = parseEnvelope('{"s":200,"h":{"Content-Type":"application/json"},"b":"' + Buffer.from('{"token":"abc"}').toString("base64") + '"}');
assert.equal(plain.s, 200, "status read");
const res = envelopeResponse(plain);
assert.equal(res.status, 200);
assert.equal(await res.text(), '{"token":"abc"}', "base64 body decoded");
assert.equal(res.headers.get("content-type"), "application/json");

// The goog.script.init wrapper: userHtml holds the envelope, JS-escaped (\xNN, \/) inside a bootstrap page.
function wrap(envObj) {
  const userHtml = JSON.stringify(envObj);
  const inner = JSON.stringify({ userHtml }).replace(/[\\"<>&=]/g, (c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).replace(/\//g, "\\/");
  return `<!doctype html><html><body><script>goog.script.init("${inner}", "", undefined, true, false);</script></body></html>`;
}
const body = '{"token":"xyz","expires":123}';
const wrapped = parseEnvelope(wrap({ s: 200, h: { "X-Quota-Remaining": "42" }, b: Buffer.from(body).toString("base64") }));
assert.equal(wrapped.s, 200, "status out of the HTML wrapper");
assert.equal(await envelopeResponse(wrapped).text(), body, "body out of the HTML wrapper");
assert.equal(envelopeResponse(wrapped).headers.get("x-quota-remaining"), "42", "header out of the wrapper");

// A gzip-compressed body (the relay's own compression, flagged gz:1) is inflated.
const big = '{"token":"' + "j".repeat(400) + '"}';
const gzEnv = parseEnvelope(JSON.stringify({ s: 200, h: {}, b: gzipSync(Buffer.from(big)).toString("base64"), gz: 1 }));
assert.equal(await envelopeResponse(gzEnv).text(), big, "gzip body inflated");

// A target error status stays a non-ok Response (not an exception); the relay's own error throws.
assert.equal(envelopeResponse(parseEnvelope('{"s":401,"h":{},"b":""}')).status, 401, "target 401 kept");
assert.throws(() => parseEnvelope('{"e":"unauthorized"}'), /relay: unauthorized/, "relay refusal throws");
assert.throws(() => parseEnvelope("<html>not ours</html>"), /expected JSON/, "garbage throws");

// Code.gs's reply as Apps Script makes it: HtmlService refuses text that looks like broken HTML, so a site's
// Link: <…> header must still go, and come back out of Google's page (backslash as \\, the rest as \xNN) the same.
const gs = {
  HtmlService: {
    createHtmlOutput: (t) => {
      if (/[<>]/.test(t)) throw new Error(`Malformed HTML content: ${t}`);
      return { t, setXFrameOptionsMode: () => ({ t }) };
    },
    XFrameOptionsMode: { ALLOWALL: 0 },
  },
};
vm.runInNewContext(readFileSync(new URL("../assets/relay/Code.gs", import.meta.url), "utf8"), gs);
const googPage = (userHtml) =>
  `<script>goog.script.init("${JSON.stringify({ userHtml }).replace(/\\/g, "\\\\").replace(/["'<>&=[\]{}]/g, (c) => "\\x" + c.charCodeAt(0).toString(16)).replace(/\//g, "\\/")}", "", undefined, true);</script>`;
const linked = { s: 200, h: { link: '<https://x.test/a?b=1&c=2>; rel="preload"' }, b: "" };
assert.deepEqual(parseEnvelope(googPage(gs._json(linked).t)), linked, "Code.gs's reply survives HtmlService and Google's page");

// Apps Script's own error page (what the old Code.gs got back for such a site): its message, readable
const errorPage = '<html><body><div><img alt="Google Apps Script"></div><div style="text-align:center;font-family:monospace;margin:50px auto 0">Exception: Malformed HTML content: {&quot;q&quot;:[{&quot;s&quot;:403}]}</div></body></html>';
assert.throws(() => parseEnvelope(errorPage), /relay: Exception: Malformed HTML content: \{"q":\[\{"s":403/, "the script's exception, out of Google's page");

// The endpoint URL and config loading (env over settings; nothing set = no relay).
assert.equal(relayUrl("ABC123"), "https://script.google.com/macros/s/ABC123/exec");
const saved = { FOXHOLE_RELAY_ID: process.env.FOXHOLE_RELAY_ID, FOXHOLE_RELAY_KEY: process.env.FOXHOLE_RELAY_KEY };
delete process.env.FOXHOLE_RELAY_ID;
delete process.env.FOXHOLE_RELAY_KEY;
assert.equal(loadRelay(null), null, "no env, no settings: no relay");
assert.deepEqual(loadRelay({ relay: { deploymentId: "DID", authKey: "KEY" } }), { url: relayUrl("DID"), key: "KEY" }, "from settings");
process.env.FOXHOLE_RELAY_ID = "ENVID";
process.env.FOXHOLE_RELAY_KEY = "ENVKEY";
assert.deepEqual(loadRelay({ relay: { deploymentId: "DID", authKey: "KEY" } }), { url: relayUrl("ENVID"), key: "ENVKEY" }, "env wins");
for (const [k, v] of Object.entries(saved)) v === undefined ? delete process.env[k] : (process.env[k] = v);

console.log("ok - Apps Script relay parsing and config");
