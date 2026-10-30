// The relay setup wizard's content, shared by the TUI (relaywizard.ts) and the desktop app (through the Controller):
// the steps' wording, the Apps Script to paste (assets/relay/Code.gs, with the user's key put in), its highlighting,
// and reading a Deployment ID out of what the user pastes. See httprelay.ts for what the relay does.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** assets/relay/<name>, copied next to this file by the build (dist/assets/relay). */
export const relayAsset = (name: string) => fileURLToPath(new URL(`./assets/relay/${name}`, import.meta.url));

/** Each step's screenshot; a missing one is simply not shown. */
export const stepImage = (n: number) => relayAsset(`step-${n}.png`);

/** Code.gs's AUTH_KEY value, replaced by the user's key. */
export const KEY_PLACEHOLDER = "YOUR_AUTH_KEY";

let template: string | undefined;
export const relayTemplate = () => (template ??= readFileSync(relayAsset("Code.gs"), "utf8"));

/** The script to paste, with this key in it. */
export const relayScript = (key: string) => relayTemplate().replace(KEY_PLACEHOLDER, key);

/** A strong random key: 32 URL-safe characters, nothing to escape in a JS string. */
export const newAuthKey = () => randomBytes(24).toString("base64url");

/** A key the user typed is kept to these characters, so it stays a plain JS string in the script. */
export const KEY_CHARS = /^[\w-]$/;
export const keyOk = (key: string) => /^[\w-]{16,}$/.test(key);

/** The Deployment ID in a pasted ID or web app URL (…/macros/s/<id>/exec); null if it isn't one. */
export function deploymentId(text: string): string | null {
  const id = text.trim().match(/\/macros\/s\/([\w-]+)/)?.[1] ?? text.trim();
  return /^[\w-]{20,}$/.test(id) ? id : null;
}

/** The steps. **…** marks what to look for on screen (bold); each UI adds its own buttons and keys. */
export const STEPS = [
  {
    title: "Open Google Apps Script",
    short: "Open",
    lines: [
      "Google Apps Script runs small scripts for free on your own Google account. Your relay will run there.",
      "Open **script.google.com** and sign in with your Google account.",
      "Click **New project** at the top left.",
    ],
  },
  {
    title: "Paste the relay code",
    short: "Paste",
    lines: [
      "In the editor, select all of the sample code (**Ctrl+A**, on a Mac **Cmd+A**) and delete it.",
      "Copy the code below and paste it in. Your secret key is already in it.",
      "Click the **Save** icon above the code.",
    ],
  },
  {
    title: "Deploy it",
    short: "Deploy",
    lines: [
      "Click **Deploy** → **New deployment** at the top right.",
      "Click the gear next to Select type and pick **Web app**.",
      "Set Execute as to **Me** and Who has access to **Anyone**, then click **Deploy**.",
      "Google asks for access the first time: **Authorize access** → your account → **Advanced** → **Go to Untitled project (unsafe)** → **Allow**. It's your own script, so this is safe.",
    ],
  },
  {
    title: "Paste the Deployment ID",
    short: "Finish",
    lines: [
      "Google now shows a **Deployment ID** and a web app URL. Click **Copy** under either one.",
      "Paste it below. foxhole keeps it and your key, and uses the relay only when vpn.mozilla.org can't be reached directly.",
    ],
  },
];

// ── Highlighting ─────────────────────────────────────────────────────────────────────────────

/** "" plain, c comment, s string, re regex, n number, kw keyword, fn a called name. */
export type Token = [kind: "" | "c" | "s" | "re" | "n" | "kw" | "fn", text: string];

// A regex literal only where a value starts (after = ( , : ! & | ?), so a division isn't taken for one.
const TOKEN = new RegExp(
  [
    /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)/.source,
    /("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)/.source,
    /((?<=[=(,:!&|?]\s*)\/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+\/[a-z]*)/.source,
    /\b(\d+(?:\.\d+)?)\b/.source,
    /\b(const|var|let|function|return|if|else|for|in|of|while|try|catch|throw|new|typeof|instanceof|continue|break|true|false|null|undefined)\b/.source,
    /([A-Za-z_$][\w$]*)(?=\s*\()/.source,
  ].join("|"),
  "g",
);
const KINDS = ["c", "s", "re", "n", "kw", "fn"] as const;

/** JavaScript as tokens; joined back they give the code unchanged. */
export function highlightJs(code: string): Token[] {
  const out: Token[] = [];
  let at = 0;
  for (const m of code.matchAll(TOKEN)) {
    if (m.index > at) out.push(["", code.slice(at, m.index)]);
    out.push([KINDS[m.slice(1).findIndex((g) => g !== undefined)], m[0]]);
    at = m.index + m[0].length;
  }
  if (at < code.length) out.push(["", code.slice(at)]);
  return out;
}
