// The window: draws the state the main process sends (controller.js state()) and asks it for actions.
const fh = window.foxhole;

// ── Its language: English as written here, Persian (fa.js), right to left, or Russian (ru.js) ───────────────
// Settings → Language: kept here, to draw in it from the start, and in settings.json (the tray's and notification's)
let langSaved = null;
try {
  langSaved = localStorage.getItem("lang");
} catch {} // no storage
const LANG = langSaved ?? "en";
const WORDS = foxholeTable(LANG); // null in English
const norm = (s) => s.replace(/\s+/g, " ").trim();
/** t`…${x}…`: these words in the window's language (fa.js and ru.js have them by their English, each value a {}). */
const t = foxholeWords(LANG);
const MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(" ");
const trDone = new Map();
let trPatterns = null; // the language's plain texts with a {}, the longest first: [regular expression, their English as t's]
const COUNTRIES = new Map(); // the locations' English names, as the core puts them in its texts (localize fills it)
/**
 * The core's words (controller.js, src/: always English) in the window's language: as fa.js or ru.js has them, where a {}
 * matches any text (none too), translated in turn; a location's name; a short date (ui.ts shortDate, "Nov 1"), in
 * Persian by Iran's calendar. Its spaces before and after stay.
 */
function tr(text) {
  if (!WORDS || typeof text !== "string" || !text.trim()) return text;
  if (text.includes("\n")) return text.split("\n").map(tr).join("\n"); // a message a line
  let out = trDone.get(text);
  if (out !== undefined) return out;
  const key = norm(text);
  const said = WORDS[key] ?? COUNTRIES.get(key) ?? localDate(key) ?? trPattern(key);
  out = said == null ? text : text.match(/^\s*/)[0] + said + text.match(/\s*$/)[0];
  if (trDone.size < 3000) trDone.set(text, out);
  return out;
}
function trPattern(key) {
  trPatterns ??= Object.keys(WORDS)
    .filter((k) => k.includes("{}") && !k.includes("<") && /[^{}\s]/.test(k.replace(/\{\}/g, "")))
    .sort((a, b) => b.replace(/\{\}/g, "").length - a.replace(/\{\}/g, "").length)
    .map((k) => [new RegExp(`^${k.split("{}").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("(.*?)")}$`, "s"), k.split("{}")]);
  for (const [re, parts] of trPatterns) {
    const m = re.exec(key);
    if (m) return t(parts, ...m.slice(1).map(tr));
  }
  return null;
}
function localDate(key) {
  const m = /^([A-Z][a-z]{2}) (\d{1,2})$/.exec(key);
  const month = m ? MONTHS.indexOf(m[1]) : -1;
  if (month < 0) return null;
  const now = new Date();
  const d = new Date(now.getFullYear(), month, +m[2]);
  const half = 182 * 864e5; // the nearest such day: a reset's ahead, the month's count began before
  if (d - now > half) d.setFullYear(d.getFullYear() - 1);
  else if (now - d > half) d.setFullYear(d.getFullYear() + 1);
  try {
    return new Intl.DateTimeFormat(LANG === "fa" ? "fa-IR-u-nu-latn" : LANG, { day: "numeric", month: "long" }).format(d);
  } catch {
    return null;
  }
}
let regions = null;
/** A country's name in the window's language (Mozilla's are English): as the tray and notification have it, else the system's. */
function countryName(c) {
  const known = foxholeCountry(LANG, c.code);
  if (known) return known;
  try {
    regions ??= new Intl.DisplayNames([LANG], { type: "region" });
    const name = regions.of(c.code);
    if (name !== c.code) return name;
  } catch {} // not a country code
  return tr(c.name);
}
/** The state's words from the core in the window's language, as it comes; what's matched or sent back (S.net, a rule) stays. */
function localize(s) {
  if (!WORDS || !s) return s;
  for (const c of s.countries ?? []) {
    c.en ??= c.name;
    c.name = countryName(c);
    if (COUNTRIES.get(c.en) !== c.name) COUNTRIES.set(c.en, c.name), trDone.clear(); // the texts with it, anew
  }
  for (const k of ["message", "splitNote", "settingsNote", "notice", "pw", "auth", "tvWait", "share", "update", "smartDns"])
    if (s[k]) for (const f of ["text", "title", "error"]) if (typeof s[k][f] === "string") s[k][f] = tr(s[k][f]);
  for (const k of ["ipNote", "listError", "splitSummary"]) s[k] = tr(s[k]);
  if (s.share?.what) s.share.what = s.share.what.map(tr);
  for (const u of [s.usage, ...(s.accounts ?? []).map((a) => a.usage)]) if (u) (u.reset = tr(u.reset)), (u.runsOut = tr(u.runsOut));
  for (const a of s.accounts ?? []) a.error = tr(a.error);
  return s;
}
/** index.html's own words: elements marked data-t whole (words with markup in them), then each text, and the attributes read out. */
function translatePage() {
  document.documentElement.lang = LANG;
  if (!WORDS) return;
  if (LANG === "fa") document.documentElement.dir = "rtl";
  for (const el of document.querySelectorAll("[data-t]")) el.innerHTML = t([el.innerHTML]);
  const words = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (words.nextNode()) {
    const n = words.currentNode;
    const said = WORDS[norm(n.nodeValue)];
    if (said !== undefined) n.nodeValue = n.nodeValue.replace(n.nodeValue.trim(), said);
  }
  for (const a of ["title", "placeholder", "aria-label", "alt"])
    for (const el of document.querySelectorAll(`[${a}]`)) {
      const said = WORDS[norm(el.getAttribute(a))];
      if (said !== undefined) el.setAttribute(a, said);
    }
}
translatePage();
const LANG_NAMES = { en: "English", fa: "فارسی", ru: "Русский" };
document.getElementById("lang").dataset.v = Object.keys(LANG_NAMES).indexOf(LANG);

/** Settings → Language: kept here and in settings.json, then the window's drawn anew in it. */
async function setLang(lang) {
  if (lang === LANG) return;
  try {
    localStorage.setItem("lang", lang);
  } catch {}
  await act("setLang", lang).catch(() => {});
  location.reload();
}

/** The sign-in screens' way to the other languages, before Settings can be reached. */
const langLink = () => `<p class="fine lang-link" hidden>${Object.keys(LANG_NAMES).filter((l) => l !== LANG).map((l) => `<span class="link" data-lang="${l}" lang="${l}">${LANG_NAMES[l]}</span>`).join(" · ")}</p>`;

let langSynced = false;
/** Once: the language Settings set where this window's storage kept none (cleared), drawn anew in it; else the core follows the window. */
function syncLang() {
  if (langSynced || S.settings.lang === LANG) return;
  langSynced = true;
  const kept = S.settings.lang;
  if (kept && !langSaved) {
    try {
      localStorage.setItem("lang", kept);
      if (localStorage.getItem("lang") === kept) return location.reload();
    } catch {}
  }
  void act("setLang", LANG);
}
const PHONE = fh.platform === "android" || fh.platform === "ios"; // the app on a phone (mobile/): Mozilla's sign-in is its own
const IOS = fh.platform === "ios"; // its VPN Android's; iOS has none (Apple's needs a paid developer account): proxy only
// iOS 16 and older (or a version not found): no animations, transitions or 3D fox; they stop its WebKit painting (style.css)
const STILL = IOS && !(+/OS (\d+)_/.exec(navigator.userAgent)?.[1] > 16);
const TV = !!fh.tv; // Android TV (phone.js): signs in from a phone or computer on its network, driven by a remote
let remoteUsed = false; // a TV: until its first key or click, the power button keeps the focus
const DEVICE = TV ? t`TV` : PHONE ? t`phone` : t`computer`;
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
// The countries with a picture in flags/ (<code>.svg; pictures, as Windows draws no flag emoji); the rest show their code
const FLAGS = new Set("AR AT AU BE BG BR CA CL CO DE DK ES FI FR GB GH IE IR IT JP KR MX MY NL NO NZ PE PH PT SE SG TH US ZA".split(" "));
const flagSrc = (code) => `flags/${code.toLowerCase()}.svg`;
const RELAY = "RELAY"; // the Relay "location" (controller.js): the web through the user's own Apps Script
const flag = (code) =>
  code === RELAY ? `<span class="flag relay">${icon("relay")}</span>`
  : FLAGS.has(code) ? `<span class="flag"><img src="${flagSrc(code)}" alt=""></span>` : `<span class="flag code">${esc(code)}</span>`;
/** A small flag inside a line of text, or nothing. */
const flagInline = (code) => (FLAGS.has(code) ? `<img class="flag-i" src="${flagSrc(code)}" alt="">` : "");
const icon = (name) => `<svg class="i"><use href="#i-${name}"/></svg>`;
const act = (name, ...args) => fh.act(name, ...args);
const CIRCUMFERENCE = 94.25; // the data ring's: 2π × 15

let S = null; // the state as last sent
const drawn = new Map(); // section → what it was last drawn from
/** Runs draw() when `data` changed since this section was last drawn: the state comes every second. */
function section(key, data, draw) {
  const sig = JSON.stringify(data);
  if (drawn.get(key) === sig) return;
  drawn.set(key, sig);
  draw();
}

/** Plays a CSS animation again, e.g. on a title that just changed. */
function replay(el, cls) {
  el.classList.remove(cls);
  void el.offsetWidth;
  el.classList.add(cls);
}

/** A button's "done" look for a moment, e.g. after a copy. */
function flash(btn, html) {
  const was = btn.innerHTML;
  btn.classList.add("done");
  if (html) btn.innerHTML = html;
  setTimeout(() => {
    btn.classList.remove("done");
    if (html) btn.innerHTML = was;
  }, 1400);
}

const country = (code) => S.countries.find((c) => c.code === code);

function phase() {
  if (S.restoring || S.busy) return "busy";
  return S.globalOn ? "global" : S.active ? "on" : "off";
}

function render() {
  const ph = phase();
  document.body.dataset.phase = ph;
  document.body.toggleAttribute("data-relay", S.relayOn); // purple, where Firefox VPN is mint and pink
  renderHeader();
  renderHero(ph);
  renderCards();
  renderList();
  renderToast(ph);
  renderNotice();
  renderNews();
  renderEntitled();
  renderSplit();
  renderSettings();
  renderNet();
  renderDisguise();
  renderPassword();
  renderTrust();
  renderAccounts();
  renderSwitched();
  renderOnboard();
  renderTv();
  renderGive();
  $("#restoring").classList.toggle("on", S.restoring);
}

// ── Header ─────────────────────────────────────────────────────────────────────────────────

function renderHeader() {
  section("head", [S.email, S.usage, S.update, S.version, S.relayStats], () => {
    const u = S.usage;
    const r = S.relayStats; // relay mode: its requests instead of Firefox VPN's data
    $("#ver").textContent = `v${S.version}`;
    $("#about-ver").textContent = S.version;
    $("#acct-avatar").textContent = (S.email || "?")[0].toUpperCase();
    $("#acct-name").textContent = S.email || t`Mozilla account`;
    $("#data-k").textContent = r ? t`Relay` : t`Data`;
    $("#data-v").textContent = r ? t`${r.relayed.toLocaleString()} sent` : !u ? "—" : u.unlimited ? t`Unlimited` : t`${u.left} left`;
    $("#data-chip").title = r
      ? t`${r.relayed.toLocaleString()} requests through your relay and ${r.fronted.toLocaleString()} straight to Google since Foxhole started. Google allows about 20,000 relayed a day.`
      : dataLeft(u) + (u?.runsOut ? t` At this rate it runs out around ${u.runsOut}.` : "");
    $("#data-ring").style.strokeDashoffset = String(CIRCUMFERENCE * (1 - (r ? Math.max(0, 1 - r.relayed / 20000) : !u ? 0 : u.unlimited ? 1 : u.fraction)));
    // The titlebar's Update button: a click downloads the new version (the button fills as it goes), installs it, and
    // asks to restart. Where Foxhole can't update itself (updater.js) it opens the download page instead.
    const up = S.update;
    const pill = $("#update");
    pill.hidden = !up;
    pill.classList.toggle("busy", !!up?.phase);
    pill.style.setProperty("--p", `${up?.progress ?? 0}%`);
    pill.title = !up ? "" : up.error ? t`Couldn't update: ${up.error}` : up.ready ? t`Foxhole ${up.version} is ready: restart to switch to it` : t`Foxhole ${up.version} is out`;
    $("#update span").textContent = !up ? ""
      : up.phase === "downloading" ? t`Downloading ${up.progress ?? 0}%`
      : up.phase === "installing" ? t`Installing…`
      : up.error && up.file ? t`Install update`
      : up.error ? t`Update failed · retry`
      : up.ready ? (PHONE ? t`Install update` : t`Restart to update`)
      : t`Update to ${up.version}`;
    const page = t`<span class="link" data-open="releases">download page</span>`;
    $("#about-update").innerHTML = !up
      ? t`Firefox's free VPN for your whole system. Unofficial, not affiliated with Mozilla.`
      : !up.auto ? t`Version ${esc(up.version)} is out. <span class="link" id="get-update">Download it</span>`
      : up.ready && PHONE ? t`Version ${esc(up.version)} is downloaded${up.error ? t`, but couldn't be installed: ${esc(up.error)}` : ""}. <span class="link" id="get-update">${up.error ? t`Try again` : t`Install it`}</span>`
      : up.ready ? t`Version ${esc(up.version)} is ready: restart Foxhole to switch to it. <span class="link" id="get-update">Restart now</span>`
      : up.phase === "downloading" ? t`Downloading version ${esc(up.version)} · ${up.progress ?? 0}%…`
      : up.phase === "installing" ? t`Installing version ${esc(up.version)}…`
      : up.error && up.file ? t`Couldn't update to ${esc(up.version)} by itself: ${esc(up.error)}. <span class="link" id="get-update">Install it yourself</span>`
      : up.error ? t`Couldn't update to ${esc(up.version)}: ${esc(up.error)}. <span class="link" id="get-update">Try again</span> or get it from the ${page}.`
      : t`Version ${esc(up.version)} is out. <span class="link" id="get-update">Update now</span>`;
  });
}

// ── The orb and what's under it ────────────────────────────────────────────────────────────

function renderHero(ph) {
  const c = country(S.connecting ?? S.global ?? S.active ?? S.paused?.code ?? S.selected);
  const where = c ? `${flagInline(c.code)}${esc(c.name)}` : ""; // HTML: the subtitle shows the flag
  // a phone's Location card (style.css): its flag drawn again only when it changes
  section("loc", [c], () => {
    $("#loc-flag").innerHTML = c ? flag(c.code) : `<span class="ico">${icon("globe")}</span>`;
    $("#c-loc .v").textContent = c?.name ?? t`Pick a location`;
  });
  let title, sub, label;
  if (S.restoring) [title, sub, label] = [t`Restoring…`, t`Putting your routes and DNS back`, t`Wait`];
  else if (ph === "busy") [title, sub, label] = [S.connecting ? t`Connecting…` : t`Working…`, esc(S.message?.text ?? ""), t`Wait`];
  // relay mode carries the web only: the rest goes direct, so it isn't "fully protected"
  else if (ph === "global" && S.relayOn) [title, sub, label] = [t`Relay, system-wide`, t`The web through your relay · the rest direct`, t`Disconnect`];
  else if (ph === "on" && S.relayOn) [title, sub, label] = [t`Relay on`, t`Through your Google script · apps set to use the proxy`, t`Disconnect`];
  else if (ph === "global") [title, sub, label] = [t`Fully protected`, t`${where} · all of this ${DEVICE}'s traffic`, t`Disconnect`];
  else if (ph === "on") [title, sub, label] = [t`Connected`, t`${where} · apps set to use the proxy`, t`Disconnect`];
  // paused from Android's notification (mobile/node/main.mjs): the orb resumes, whole-system mode too
  else if (S.paused) [title, sub, label] = [t`Paused`, t`${TV ? t`Press OK` : t`Tap`} to resume · ${where}${S.paused.global ? t` · whole system` : ""}`, t`Resume`];
  else if (S.entitled === false) [title, sub, label] = [t`VPN not turned on`, t`Turn it on in Firefox, for this account`, t`Connect`];
  else [title, sub, label] = [t`Not connected`, c ? t`${TV ? t`Press OK` : t`Tap`} to connect · ${where}` : t`Pick a location to connect`, t`Connect`];
  const st = $("#status-title");
  if (st.textContent !== title) {
    st.textContent = title;
    replay(st, "swap");
  }
  if ($("#status-sub").dataset.html !== sub) $("#status-sub").innerHTML = $("#status-sub").dataset.html = sub; // each state, not each second: the flag stays put
  $("#orb-label").textContent = label;
  $("#orb").setAttribute("aria-label", label);
  $("#orb").disabled = ph === "busy" || S.auth.stage !== "ready";
  // the remote's next OK connects or disconnects: on opening, and once connecting's over (a disabled button loses its focus)
  if (TV && !$("#orb").disabled && (!remoteUsed || document.activeElement === document.body)) $("#orb").focus({ preventScroll: true });
  const mode = $("#mode");
  mode.dataset.v = globalMode() ? "1" : "0";
  for (const b of mode.querySelectorAll("button")) b.setAttribute("aria-pressed", String((b.dataset.mode === "global") === globalMode()));
  mode.classList.toggle("disabled", ph === "busy" || S.auth.stage !== "ready");
}

/** The mode switch's side: while off, a phone's shows the mode it connects in (mobile/node/main.mjs). */
const globalMode = () => (S.active ? S.globalOn : !!S.wantGlobal);

function renderCards() {
  section("cards", [S.net, S.netChecking, S.ip, S.ipChecking, S.ipNote, S.proxy, S.splitSummary, S.globalOn, S.lanIp, S.relayOn], () => {
    const fill = (id, v, s, cls = "") => {
      $(`${id} .v`).className = `v ${cls}`;
      $(`${id} .v`).innerHTML = v;
      $(`${id} .s`).innerHTML = s;
    };
    const skel = '<span class="skel"></span>';
    if (S.netChecking) fill("#c-net", skel, '<span class="skel short"></span>');
    else fill("#c-net", esc(tr(S.net) ?? t`offline`), (S.lanIp ? `LAN ${esc(S.lanIp)}` : t`no local address`) + showName(), S.net ? "" : "warn");
    $("#c-net use").setAttribute("href", S.net?.startsWith("Mobile") ? "#i-phone" : S.net && !S.net.startsWith("Wi-Fi") ? "#i-plug" : "#i-wifi");
    if (S.ipChecking) fill("#c-ip", skel, '<span class="skel short"></span>');
    else fill("#c-ip", esc(S.ip ?? t`unreachable`), esc(S.ip ? S.ipNote : t`the IP check didn't answer`), S.ip ? "" : "warn");
    const p = S.proxy;
    fill("#c-proxy", p ? esc(p.addr) : "—", p ? t`SOCKS5 + HTTP${p.shared ? t` · shared` : ""}` : t`SOCKS5 + HTTP, once connected`, p ? "" : "dim");
    $("#copy-proxy").hidden = !p;
    // Telegram through the proxy, the rest of this device not: Proxy only mode's (whole-system mode takes it anyway)
    $("#tg-proxy").hidden = !p || S.globalOn || TV;
    const split = S.splitSummary;
    fill("#c-split", esc(split ?? t`Off`), split ? (S.globalOn ? t`for the whole system` : t`for the proxy`) : t`everything through the ${S.relayOn ? t`relay` : "VPN"}`, split ? "" : "dim");
  });
}

// ── Locations ──────────────────────────────────────────────────────────────────────────────

let listShown = false; // the rows rise in once, on the first fill

function renderList() {
  const q = $("#search").value.trim().toLowerCase();
  section("list", [S.countries, S.active, S.connecting, S.listError, q, S.auth.stage === "ready"], () => {
    const list = $("#list");
    // Relay first, set up or not (then dimmed: a click says what it is), a line between it and the countries; none on a phone
    const relay = PHONE ? null : S.countries.find((c) => c.code === RELAY) ?? { code: RELAY, name: t`Relay`, locked: false, available: false, intro: true };
    const count = S.countries.length - (relay && !relay.intro ? 1 : 0);
    const shown = [relay, ...S.countries.filter((c) => c !== relay)].filter((c) => c && (!q || c.name.toLowerCase().includes(q) || c.en?.toLowerCase().includes(q) || c.code.toLowerCase() === q));
    $("#loc-count").textContent = count ? t`${count} countries` : "";
    if (S.listError) {
      // the relay still goes: it's for when Mozilla can't be reached
      list.innerHTML = t`${relay ? rowHtml(relay, 0, false) : ""}<div class="empty"><b>Couldn't load the locations</b>${esc(S.listError)}<br><button class="btn" data-act="reloadList">${icon("refresh")}Try again</button></div>`;
      return;
    }
    if (!S.countries.length) {
      list.innerHTML = Array.from({ length: 7 }, () => `<div class="row skeleton"><span class="flag"></span><span><span class="skel"></span></span><span></span><span></span></div>`).join("");
      return;
    }
    if (!shown.length) {
      list.innerHTML = t`<div class="empty"><b>No country matches “${esc(q)}”</b>Try a name like Germany, or a code like DE.</div>`;
      return;
    }
    const rise = !listShown;
    listShown = true;
    const sep = relay && shown[0] === relay && shown.length > 1 ? `<div class="sep${rise ? " rise" : ""}" style="--d:2"></div>` : "";
    list.innerHTML = shown.map((c, i) => rowHtml(c, i, rise) + (i === 0 ? sep : "")).join("");
  });
  reveal();
}

/** A location's row: a country, or the relay (`intro`: not set up, dimmed, and a click says what it is). */
function rowHtml(c, i, rise) {
  const cls = [c.code === S.active && "active", c.code === S.connecting && "connecting", !c.available && !c.locked && "off", rise && "rise"].filter(Boolean).join(" ");
  const relay = c.code === RELAY;
  const tiers = relay ? t`<span class="tier relay">relay</span>`
    : !c.available && !c.locked ? t`<span class="tier none">no servers</span>`
    : c.locked ? t`<span class="tier paid">paid</span><span class="tier free">free</span>` : t`<span class="tier free">free</span>`;
  const title = c.code === S.active ? t`Connected` : c.intro ? t`What's Relay? Set it up` : relay ? t`Browse through your own relay` : t`Connect to ${esc(c.name)}`;
  return `<button class="row ${cls}" ${c.intro ? 'id="relay-intro"' : `data-code="${esc(c.code)}"`} style="--i:${i}" title="${title}">
    ${flag(c.code)}<span><div class="nm">${esc(c.name)}</div><div class="cd">${c.intro ? t`Not set up yet` : relay ? t`via Google · your Apps Script` : esc(c.code)}</div></span>
    <span class="tiers">${tiers}</span><span class="state-dot"></span></button>`;
}

let revealed = null; // the country last brought into view

/** Brings the country being connected to (then the one connected) into view once, e.g. on the connect at launch. */
function reveal() {
  const code = S.connecting ?? S.active;
  if (code === revealed) return;
  const row = code && $(`#list .row[data-code="${CSS.escape(code)}"]`);
  if (code && !row) return; // the list is still loading, or the search hides it: the next state tries again
  revealed = code;
  if (!row) return;
  const box = $("#list").getBoundingClientRect();
  const r = row.getBoundingClientRect();
  // the list fades out over its top 10 and bottom 18 px (style.css)
  if (r.top < box.top + 10 || r.bottom > box.bottom - 18) {
    row.scrollIntoView({ block: "center", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  }
}

// ── Toast: the last message, once nothing is in progress (the orb's subtitle shows progress) ─

let toastTimer = 0;

function renderNotice() {
  section("notice", [S.notice?.id], () => {
    if (!S.notice) return;
    $("#notice-modal use").setAttribute("href", "#i-user");
    $("#notice-title").textContent = S.notice.title;
    $("#notice-text").textContent = S.notice.text;
    $("#notice-modal").classList.add("on");
    newsOpen = null; // an alert in its place: the news comes again on the next start
    tvModal(false); // signed in from another device (controller.js tvAccept)
  });
}

// The hot config's notice (hot.ts), from Foxhole's developer: in the same dialog, till its OK (newsShown)
let newsOpen = null;
function renderNews() {
  section("news", [S.news], () => {
    if (!S.news || S.news === newsOpen) return;
    $("#notice-modal use").setAttribute("href", "#i-spark");
    $("#notice-title").textContent = t`News from Foxhole`;
    $("#notice-text").textContent = newsOpen = S.news;
    $("#notice-modal").classList.add("on");
  });
}

function noticeClose() {
  $("#notice-modal").classList.remove("on");
  if (newsOpen) void act("newsShown", newsOpen);
  newsOpen = null;
}

/** The account in use hasn't turned on Firefox's VPN: everything in dark red, the fox sad (fox3d.js), and how to turn it on. */
function renderEntitled() {
  const off = S.entitled === false;
  if (off) document.body.dataset.unentitled = "";
  else delete document.body.dataset.unentitled;
  section("unentitled", [off, S.unentitledAsk], () => {
    $("#unentitled-email").textContent = S.email || t`This account`;
    $("#unentitled-modal").classList.toggle("on", off);
  });
}

function renderToast(ph) {
  section("toast", [S.message?.id, ph === "busy"], () => {
    const el = $("#toast");
    const m = S.message;
    clearTimeout(toastTimer);
    if (!m || ph === "busy") return void el.classList.remove("on");
    el.dataset.tone = m.tone;
    el.title = m.text;
    $("#toast-text").textContent = m.text;
    replay(el, "on");
    if (m.tone === "ok" || m.tone === "info") toastTimer = setTimeout(() => el.classList.remove("on"), 6000);
  });
}

// ── Blocked or sanctioned? The typed site tried directly and through the VPN (controller.js checkSite) ─────────────

let checked = null; // the check shown
let checking = 0; // only the latest check's answer is shown
const VERDICT_ICON = { blocked: "shield", sanctioned: "lock", partly: "lock", open: "check", down: "close", unknown: "search" };

async function checkTyped() {
  const text = $("#split-input").value.trim();
  const box = $("#split-check");
  const n = ++checking;
  box.hidden = false;
  box.dataset.v = "";
  box.innerHTML = t`<span class="spin"></span><div><b>Checking ${esc(text || "…")}</b><span>${S.active ? t`Directly and through the VPN` : t`Directly`}: a few seconds.</span></div>`;
  const c = await act("checkSite", text);
  if (n !== checking) return;
  if (!c) return void (box.hidden = true); // not a site: the note says so
  drawCheck(c);
}

function drawCheck(c) {
  checked = c;
  const box = $("#split-check");
  box.dataset.v = c.verdict;
  const now = c.now === "probe" ? t`Save data sends it the way it opens.` : t`It ${c.now === "vpn" ? t`uses the VPN` : t`goes direct`} now.`;
  box.innerHTML = t`<span class="dot">${icon(VERDICT_ICON[c.verdict])}</span>
    <div><b>${esc(tr(c.title))}<span class="site">${esc(c.site)}</span></b>${c.more ? `<span>${esc(tr(c.more))}</span>` : ""}
    <span class="ways">Directly: ${esc(tr(c.direct))} · VPN: ${esc(tr(c.vpn))}</span><span>${now}</span></div>
    ${c.offer ? `<button class="btn" type="button" data-check-via="${c.offer}">${c.offer === "vpn" ? t`Use the VPN` : t`Send direct`}</button>` : ""}`;
}

// ── Data: the month's data left, and the sites that spent the VPN's (controller.js traffic) ───────────

let dataTimer = null;

/** Draws the Data sheet, and again every 2 s while it's open: the counts climb as sites load. */
async function drawData() {
  clearTimeout(dataTimer);
  if (openSheet !== "data") return;
  const tf = await act("traffic");
  const u = S.usage;
  $("#data-left").innerHTML = !u ? t`Not known yet <small>till connected</small>` : u.unlimited ? t`Unlimited` : t`${esc(u.left)} left <small>of ${esc(u.max)}${u.reset ? t` · resets ${esc(u.reset)}` : ""}</small>`;
  $("#data-pace").dataset.tone = u?.runsOut ? "warn" : "";
  $("#data-pace").textContent = u?.runsOut ? t`At this rate it runs out around ${u.runsOut}: send big sites direct below.` : u?.reset ? t`At this rate it lasts till it resets.` : "";
  $("#data-since").textContent = t`since ${tr(tf.since)}`;
  const top = tf.sites[0]?.vpn || 1;
  $("#data-sites").innerHTML = tf.sites.length
    ? tf.sites.map((x) => `<div class="site-row"><span class="m" title="${esc(x.site)}">${esc(x.site)}</span>
        <span class="bar"><i style="width:${Math.max(3, Math.round((x.vpn / top) * 100))}%"></i></span><span class="n">${esc(x.size)}</span>
        ${x.rule === "direct" ? t`<span class="tag-direct">Direct now</span>`
          : tf.canSend && !x.rule && !x.stuck ? t`<button class="btn" data-direct="${esc(x.site)}" title="New connections to it skip the VPN">Send direct</button>`
          : `<span class="tag-direct" title="${x.stuck ? t`It doesn't open direct here` : t`It has a rule in Split tunneling`}">${x.stuck ? t`Blocked here` : ""}</span>`}</div>`).join("")
    : t`<div class="empty"><b>Nothing through the VPN yet</b>Sites show here as they load.</div>`;
  $("#data-direct").textContent = tf.direct ? t`Direct this month: ${tf.direct}, none of it the VPN's data.` : "";
  dataTimer = setTimeout(drawData, 2000);
}

// ── Split tunneling ────────────────────────────────────────────────────────────────────────

let knownRules = null; // the rules last drawn: a new one pops in
let appIcons = {}; // apps' icons by id, data: URLs, asked for apart from the state (controller.js appIcons)
let iconsAsked = -1; // how many the controller knew when last asked

/** An app's icon, or "" (none, or not an image). */
const appIcon = (id) => {
  const url = appIcons[id];
  return typeof url === "string" && /^data:image\/(png|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(url) ? `<img class="app-ico" src="${url}" alt="">` : "";
};

function renderSplit() {
  if (S.split.icons !== iconsAsked) {
    iconsAsked = S.split.icons;
    void act("appIcons").then((m) => ((appIcons = m ?? {}), renderSplit())); // the icons' count redraws the rows and chips
  }
  section("split", [S.split.default, S.split.rules, S.split.smart, S.split.probe, S.splitNote, S.split.apps === null, S.globalOn, Object.keys(appIcons).length], () => {
    const sp = S.split;
    const apps = sp.apps !== null; // iOS: only sites
    const what = apps ? t`sites and apps` : t`sites`;
    $("#split-card-s").textContent = t`Choose ${what} that skip the VPN`;
    $("#split-what").textContent = t`Choose which ${what} use the VPN and which go direct.`;
    $("#split-add-label").textContent = apps ? t`Add a site or app` : t`Add a site`;
    $("#split-list-label").textContent = apps ? t`Sites and apps` : t`Sites`;
    $("#split-input").placeholder = apps ? t`bbc.co.uk, *.ir, 1.2.3.4 or an app: Telegram` : t`bbc.co.uk, *.ir, 1.2.3.4 or 10.0.0.0/8`;
    $("#split-fine").textContent = t`${apps ? t`An app's rule covers all its connections; a site` : t`A site`} covers its subdomains, and the most specific rule wins. Direct ${what} see your real IP. Changes apply to new connections.`;
    // Android's own VPN does apps: only in whole-system mode (a TV's only one), and while some apps are listed for the
    // VPN with everything else direct, only they go into it
    const appRules = sp.rules.filter((r) => r.app !== null);
    $("#split-apps-hint").textContent =
      fh.platform !== "android" || !appRules.length ? ""
        : !S.globalOn && !TV ? t`Apps follow their rules in Whole system mode.`
        : sp.default === "direct" && appRules.some((r) => r.via === "vpn") && sp.rules.some((r) => r.app === null && r.via === "vpn") ? t`With apps listed for the VPN, only they use it: the sites listed for the VPN do too, but only in those apps.`
        : "";
    $("#split-default").dataset.v = sp.default === "vpn" ? "0" : "1";
    $("#split-default-hint").innerHTML =
      (sp.default === "vpn" ? t`${apps ? t`Sites and apps` : t`Sites`} not listed use the <b>VPN</b>: list the ones to bypass it.` : t`${apps ? t`Sites and apps` : t`Sites`} not listed go <b>direct</b>: list the ones that need the VPN.`) +
      (sp.defaultHits ? t` · ${sp.defaultHits} matched` : "");
    $("#split-new-hint").innerHTML = t`A new ${apps ? t`site or app` : t`site`} goes <b>${sp.default === "vpn" ? t`direct` : t`through the VPN`}</b>: the other way from the rest.`;
    const note = $("#split-note");
    note.dataset.tone = S.splitNote?.tone ?? "";
    note.textContent = S.splitNote?.text ?? "";
    // smart (smart.ts) only decides with everything else through the VPN
    $("#split-smart").hidden = sp.default !== "vpn";
    for (const [id, on] of [["smart", sp.smart], ["probe", sp.probe]]) {
      $(`#${id}`).classList.toggle("on", on);
      $(`#${id}`).setAttribute("aria-checked", String(on));
    }
    $("#probe-row").hidden = !sp.smart;
    // macOS's whole-system mode routes a direct address around the tun for every app: nothing's tried there (proxy.ts)
    const macGlobal = fh.platform === "darwin" && S.globalOn;
    $("#probe-hint").dataset.tone = sp.probe && macGlobal ? "warn" : "";
    $("#probe-hint").textContent = sp.probe && macGlobal
      ? t`On a Mac, other sites are tried directly in Proxy only mode. In Whole system mode they use the VPN.`
      : t`Other sites go direct too where they open; blocked ones use the VPN. Your internet provider sees which sites you visit.`;
    $("#split-count").textContent = sp.rules.length ? `(${sp.rules.length})` : "";
    const before = knownRules;
    knownRules = new Set(sp.rules.map((r) => r.match));
    $("#split-rules").innerHTML = sp.rules.length
      ? sp.rules
          .map((r) => `<div class="rule${before && !before.has(r.match) ? " fresh" : ""}" data-match="${esc(r.match)}">
            ${r.app !== null ? `<span class="m app" title="${esc(r.match.slice(4))}">${appIcon(r.match.slice(4)) || `<span class="tag">${t`App`}</span>`}${esc(r.app)}</span>` : `<span class="m" title="${esc(r.match)}">${esc(r.match)}</span>`}
            <span class="hits">${r.hits ? t`${r.hits} matched` : ""}</span>
            <button class="via ${r.via}" data-toggle title="Switch between VPN and direct">${r.via === "vpn" ? "VPN" : t`Direct`}</button>
            <button class="mini" data-remove title="Remove">${icon("trash")}</button></div>`)
          .join("")
      : t`<div class="empty"><b>No ${what} yet</b>Everything goes ${sp.default === "vpn" ? t`through the VPN` : t`direct`}.</div>`;
  });
  // the counts climb as sites load: just the numbers, the rows stay put
  $("#smart-hint").textContent = t`Iran's banks, shops and other sites skip the VPN, on Iran's cheaper data.${S.split.smart && S.split.smartHits ? t` · ${S.split.smartHits} matched` : ""}`;
  for (const r of S.split.rules) {
    const el = document.querySelector(`.rule[data-match="${CSS.escape(r.match)}"] .hits`);
    if (el) el.textContent = r.hits ? t`${r.hits} matched` : "";
  }
  section("recent", [S.split.recent, S.split.apps, $("#split-input").value, Object.keys(appIcons).length], drawRecent);
  drawPicker();
}

function drawRecent() {
  const typed = $("#split-input").value.trim().toLowerCase();
  const found = S.split.recent.filter((s) => s.includes(typed)).slice(0, 10);
  $("#split-recent").innerHTML = found.length
    ? t`<span class="k">Seen lately</span>${found.map((s) => `<button type="button" class="chip-btn" data-site="${esc(s)}">${esc(s)}</button>`).join("")}`
    : "";
  const all = S.split.apps;
  const apps = (all ?? []).filter((a) => a.name.toLowerCase().includes(typed)).slice(0, typed ? 11 : 8);
  // last, every app: the picker, searching for what's typed
  const more = `<button type="button" class="chip-btn more" data-pick-open title="Search every app"><svg class="i"><use href="#i-apps"/></svg>${all?.length ? t`All ${all.length} apps` : t`All apps`}</button>`;
  $("#split-apps").innerHTML = all
    ? t`<span class="k">Apps</span>${apps.map((a) => `<button type="button" class="chip-btn" data-site="app:${esc(a.id)}" title="${esc(a.id)}">${appIcon(a.id)}${esc(a.name)}</button>`).join("")}${more}`
    : "";
}

// ── Split tunneling's app picker: every app, found by name ─────────────────────────────────

const pickerOn = () => $("#apps-modal").classList.contains("on");

/** Opens the picker, searching for `query` (what was typed in the sheet). A phone's keyboard waits for a tap on the field. */
function openPicker(query = "") {
  $("#apps-search").value = query;
  drawn.delete("picker");
  $("#apps-modal").classList.add("on");
  drawPicker();
  $("#apps-list").scrollTop = 0;
  // a computer types at once; a TV's remote starts in the list (↑ to the field); a phone's keyboard waits for a tap
  if (TV) setTimeout(() => $("#apps-list .app-row")?.focus(), 60);
  else if (!PHONE) setTimeout(() => $("#apps-search").focus(), 60);
}

function closePicker() {
  $("#apps-modal").classList.remove("on");
  if (TV || document.activeElement === document.body) $("#split-apps .more")?.focus(); // the remote carries on from where it was
}

/** `name` with where `q` is in it marked. */
function marked(name, q) {
  const i = q ? name.toLowerCase().indexOf(q) : -1;
  return i < 0 ? esc(name) : `${esc(name.slice(0, i))}<mark>${esc(name.slice(i, i + q.length))}</mark>${esc(name.slice(i + q.length))}`;
}

/** The apps that have what's searched for, those starting with it first; on Android by package too. */
function pickerApps() {
  const q = $("#apps-search").value.trim().toLowerCase();
  const all = S.split.apps ?? [];
  if (!q) return all;
  const has = all.filter((a) => a.name.toLowerCase().includes(q) || (a.id !== a.name && a.id.toLowerCase().includes(q)));
  return [...has.filter((a) => a.name.toLowerCase().startsWith(q)), ...has.filter((a) => !a.name.toLowerCase().startsWith(q))];
}

function drawPicker() {
  if (!pickerOn()) return;
  const sp = S.split;
  const typed = $("#apps-search").value.trim();
  const q = typed.toLowerCase();
  section("picker", [sp.apps, sp.appsLoading, sp.default, q, Object.keys(appIcons).length, S.splitNote], () => {
    const found = pickerApps();
    const way = sp.default === "vpn" ? t`Direct` : "VPN";
    const n = (sp.apps ?? []).length;
    $("#apps-count").textContent = sp.appsLoading && !n ? t`Looking for apps…` : t`${n} app${n === 1 ? "" : "s"}${q ? t` · ${found.length} found` : ""}`;
    const focused = document.activeElement?.closest?.(".app-row")?.dataset.pick; // kept through a redraw (icons coming in)
    $("#apps-list").innerHTML = found.length
      ? found
          .map((a) => `<button type="button" class="app-row" role="option" data-pick="${esc(a.id)}">
            ${appIcon(a.id) || `<span class="app-ico none">${esc(a.name.slice(0, 1).toUpperCase())}</span>`}
            <span class="nm"><span>${marked(a.name, q)}</span>${a.id !== a.name ? `<small>${marked(a.id, q)}</small>` : ""}</span>
            <span class="go">${way}</span></button>`)
          .join("")
      : sp.appsLoading
        ? t`<div class="empty"><b>Looking for apps…</b></div>`
        : q
          ? t`<div class="empty"><b>No app has “${esc(typed)}”</b>${
              sp.canTypeApp
                ? t`Not running now? Add it by its name.<br><button type="button" class="btn" data-pick-typed>${icon("plus")}Add “${esc(typed.slice(0, 40))}”</button>`
                : t`Only apps with an icon in the launcher are here.`
            }</div>`
          : t`<div class="empty"><b>No apps found</b>${sp.canTypeApp ? t`Type an app's name to add it.` : ""}</div>`;
    if (focused) $(`#apps-list [data-pick="${CSS.escape(focused)}"]`)?.focus({ preventScroll: true });
    const hint = $("#apps-hint");
    hint.innerHTML = S.splitNote ? esc(S.splitNote.text) : t`The app you pick goes <b>${sp.default === "vpn" ? t`direct` : t`through the VPN`}</b>: the other way from the rest.`;
    hint.dataset.tone = S.splitNote?.tone ?? "";
  });
}

/** Adds the app (its id), closing the picker once it's in the list. */
async function pick(id) {
  if (await act("addRule", `app:${id}`)) closePicker();
}

$("#apps-search").addEventListener("input", () => S && drawPicker());
$("#apps-modal").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) return closePicker(); // the backdrop
  const btn = e.target.closest("button");
  if (!btn || !S) return;
  e.stopPropagation(); // not the window's own handler
  if (btn.id === "apps-close") return closePicker();
  if (btn.dataset.pick) return pick(btn.dataset.pick);
  if (btn.hasAttribute("data-pick-typed")) return pick($("#apps-search").value.trim());
});
// The keyboard on a computer (a TV's remote moves the focus itself): Enter in the field picks the first one found,
// ↓/↑ go through the list and back up to the field
$("#apps-modal").addEventListener("keydown", (e) => {
  if (TV || !S) return;
  const rows = [...$("#apps-list").querySelectorAll(".app-row")];
  const at = rows.indexOf(document.activeElement);
  const inField = document.activeElement === $("#apps-search");
  if (e.key === "Enter" && inField) {
    e.preventDefault();
    if (rows[0]) return void pick(rows[0].dataset.pick);
    if ($("[data-pick-typed]")) return void pick($("#apps-search").value.trim());
  }
  const step = { ArrowDown: 1, ArrowUp: -1 }[e.key];
  if (!step || (!inField && at < 0)) return;
  e.preventDefault();
  const next = inField ? (step > 0 ? 0 : -1) : at + step;
  if (next < 0) return $("#apps-search").focus();
  rows[Math.min(next, rows.length - 1)]?.focus();
  rows[Math.min(next, rows.length - 1)]?.scrollIntoView({ block: "nearest" });
});

// ── Settings ───────────────────────────────────────────────────────────────────────────────

/** On this network: what joining the network does (controller.js #joined), and the other networks' rules. */
function renderNet() {
  section("net", [S.net, S.netRules], () => {
    const net = S.net, rule = S.netRules[net] ?? "";
    const known = !!net && !/^(Wi-Fi|Wi-Fi · name hidden|Online)$/.test(net); // settings.ts ruleable
    $("#net-rule").dataset.v = String(["", "connect", "pause"].indexOf(rule));
    $("#net-rule").classList.toggle("disabled", !known);
    $("#net-hint").innerHTML = !net ? t`Not on a network.`
      : !known ? t`Foxhole can't see this Wi-Fi's name, so it can't tell it from another.${showName()}`
      : `<b>${esc(tr(net))}</b>: ` + {
        "": t`Foxhole can connect by itself when this ${DEVICE} joins it, or pause here (say, at home, where the router has a VPN) and connect again when it leaves.`,
        connect: t`Foxhole connects when this ${DEVICE} joins it, in the mode last picked.`,
        pause: t`Foxhole disconnects when this ${DEVICE} joins it, and connects again as before when it leaves.`,
      }[rule];
    const others = Object.entries(S.netRules).filter(([n]) => n !== net);
    $("#net-rules").innerHTML = others.length
      ? t`<span class="k">Other networks</span>${others.map(([n, r]) => `<button type="button" class="chip-btn" data-net-forget="${esc(n)}" title="Forget this rule">${esc(n)} · ${r === "connect" ? t`Connect` : t`Pause`} ✕</button>`).join("")}`
      : "";
  });
}

/** Look like a calculator (Android, Disguise.kt): the code that opens Foxhole there, or the field to pick one. */
function renderDisguise() {
  section("disguise", [S.disguise], () => {
    const code = S.disguise;
    $("#disguise-set").hidden = !!code;
    $("#disguise-off").hidden = !code;
    $("#disguise-hint").innerHTML = code
      ? t`On: once you leave Foxhole, it's <b>Calculator</b> among your apps, and works as one. To open Foxhole, type <b>${esc(code)}</b> in it, then <b>=</b>. While connected, Android still shows Foxhole's VPN, so disconnect before a search, and remove Foxhole's widget and tile if you added them. Forgot the code? Clearing Foxhole's storage in Android's Settings ends this, and signs you out.`
      : t`For when your phone may be searched: Foxhole's icon and name become a calculator's, one that works, and the code you pick here, then =, opens Foxhole. Android's own Settings still list Foxhole.`;
  });
}

function renderSettings() {
  section("settings", [S.settings.share, S.settings.port, S.settings.username, S.settings.password, S.settings.relay, S.lanIp, S.fwHint, S.caOk, S.shareTg?.link, S.settings.smartDns, S.smartDns, !!S.active], () => {
    const s = S.settings;
    const share = $("#share");
    share.classList.toggle("on", s.share);
    share.setAttribute("aria-checked", String(s.share));
    $("#share-hint").textContent = s.share ? t`Other devices on this Wi-Fi can use the VPN through this ${DEVICE}.` : t`Only this ${DEVICE} can use the proxy.`;
    const addr = `${S.lanIp ?? t`this ${DEVICE}'s IP`}:${s.port}`;
    $("#share-box").innerHTML = s.share
      ? t`<div class="hint">Set ${PHONE ? t`the other device's` : t`your phone's`} Wi-Fi proxy to</div>
         <div class="addr"><span class="mono">${esc(addr)}</span><button class="mini" data-copy="${esc(addr)}" title="Copy">${icon("copy")}</button></div>
         ${s.username || s.password ? t`<div class="hint">Devices sign in with the username and password below.</div>` : t`<div class="warn-line">No password: anyone on this network can use it. Set one below.</div>`}
         ${S.shareTg ? t`<div class="tg-share"><svg class="tg-qr" viewBox="0 0 ${S.shareTg.qr.size} ${S.shareTg.qr.size}" role="img" aria-label="Telegram's QR code for this proxy"><rect width="100%" height="100%" fill="#fff"/><path d="${S.shareTg.qr.path}"/></svg>
           <div><b>${icon("telegram")}Telegram on ${PHONE ? t`another phone` : t`your phone`}</b><span>Scan this with its camera: Telegram asks to use this proxy, with its sign-in.</span><button class="mini" data-copy="${esc(S.shareTg.link)}" title="Copy the link">${icon("copy")}</button></div></div>` : ""}
         ${S.fwHint ? t`<div class="hint">If they can't connect, open the port in the firewall:</div>${S.fwHint.map((c) => `<div class="cmd"><span class="mono">${esc(c)}</span><button class="mini" data-copy="${esc(c)}" title="Copy">${icon("copy")}</button></div>`).join("")}` : ""}`
      : t`<div class="hint">Turn on to use the VPN from ${PHONE ? t`a computer or another phone` : t`your phone`}, on the same Wi-Fi.</div>`;
    drawSmartDns();
    $("#give-hint").textContent = S.platform === "android"
      ? t`Foxhole itself for a phone nearby, from this one with no internet, and your relay and split tunneling for the family's other devices.`
      : t`Your relay and split tunneling, for the family's other devices: a QR code for a phone to scan, or a link to send.`;
    // typed values stay until saved; a change from elsewhere (a save) shows here
    if (document.activeElement !== $("#port")) $("#port").value = String(s.port);
    if (document.activeElement !== $("#username")) $("#username").value = s.username;
    if (document.activeElement !== $("#password")) $("#password").value = s.password;
    // The relay: the auth key never reaches the window, so its field stays empty (placeholder says if one is set).
    const r = s.relay; // { deploymentId, set } or null
    if (document.activeElement !== $("#relay-id")) $("#relay-id").value = r?.deploymentId ?? "";
    $("#relay-key").placeholder = r?.set ? t`•••••••• — type to replace` : t`Auth key`;
    $("#relay-badge").className = r ? "tier on" : "tier off";
    $("#relay-badge").textContent = r ? t`enabled` : t`disabled`;
    $("#relay-state").innerHTML = r
      ? t`<strong>On:</strong> Firefox VPN goes through it when <code>vpn.mozilla.org</code> can't be reached, and <b>Relay</b> is first in Locations.`
      : t`<strong>Off:</strong> Foxhole talks to Mozilla directly.`;
    $("#cert-group").hidden = !r && !S.caOk;
    $("#cert-state").className = S.caOk ? "ok" : "warn";
    $("#cert-state").textContent = S.caOk ? t`Trusted on this ${DEVICE}` : t`Not trusted yet: sites won't open through the relay`;
    $("#cert-btn").textContent = S.caOk ? t`Remove` : t`Trust it`;
    $("#cert-btn").classList.toggle("primary", !S.caOk);
  });
  const note = $("#settings-note");
  note.dataset.tone = S.settingsNote?.tone ?? "";
  note.textContent = S.settingsNote?.text ?? "";
}

/** Smart DNS (controller.js, smartdns.ts): what to set on the TV, or why it couldn't start. Not on a phone. */
function drawSmartDns() {
  $("#dns-group").hidden = !S.smartDns;
  if (!S.smartDns) return;
  const on = !!S.settings.smartDns;
  $("#smart-dns").classList.toggle("on", on);
  $("#smart-dns").setAttribute("aria-checked", String(on));
  $("#dns-hint").textContent = on
    ? t`The sites Iran blocks, and those that refuse Iran, go through the VPN for the devices that use it. The rest go direct.`
    : t`YouTube and blocked or sanctioned sites on a TV, game console or iPhone, with no app: only its DNS is set to this ${DEVICE}.`;
  const err = S.smartDns.error;
  const cmd = err?.match(/sudo .+$/)?.[0];
  const ip = S.lanIp ?? t`this ${DEVICE}'s IP`;
  $("#dns-box").innerHTML = !on ? ""
    : S.smartDns.yields ? t`<div class="warn-line">On a Mac it works in Proxy only mode: Whole system mode needs port 53 for its own DNS.</div>`
    : err ? `<div class="warn-line">${esc(cmd ? err.slice(0, err.indexOf(cmd)) : err)}</div>${cmd ? t`<div class="cmd"><span class="mono">${esc(cmd)}</span><button class="mini" data-copy="${esc(cmd)}" title="Copy">${icon("copy")}</button></div><div class="hint">Then turn this off and on again.</div>` : ""}`
    : t`<div class="hint">On the device, in its network settings, set DNS by hand to</div>
       <div class="addr"><span class="mono">${esc(ip)}</span><button class="mini" data-copy="${esc(ip)}" title="Copy">${icon("copy")}</button></div>
       ${S.active ? "" : t`<div class="warn-line">Not connected: until you connect, it gets the network's own answers, blocked sites included.</div>`}
       <div class="hint">Only the web goes through, not games or calls. An iPhone's Private Relay, and a browser's secure DNS, skip it. When this ${DEVICE} is off, set the device's DNS back to automatic.</div>`;
}

// ── The administrator password ─────────────────────────────────────────────────────────────

function renderPassword() {
  section("pw", [S.pw], () => {
    const modal = $("#pw-modal");
    const open = !!S.pw;
    const wasOpen = modal.classList.contains("on");
    modal.classList.toggle("on", open);
    $("#scrim").classList.toggle("on", open || !!openSheet);
    if (!open) return;
    const input = $("#pw-input");
    input.disabled = S.pw.checking;
    const f = S.pw.for ?? "global"; // what it's for: whole-system mode, or relay mode's certificate
    $("#pw-why").innerHTML = t`${f === "global" ? t`Whole-system mode routes all of this computer's traffic through the VPN, which needs` : t`${f === "trust" ? t`Trusting` : t`Removing`} Foxhole's certificate for the system and its browsers needs`} administrator rights. Enter your <b>login password</b> (used by sudo)${f === "global" && S.helper === false ? t`, once: Foxhole sets up a small network helper with it, so it won't ask again` : ""}:`;
    $("#pw-ok").innerHTML = S.pw.checking ? t`<span class="spin"></span><span>Checking…</span>` : `<span>${{ global: t`Go whole system`, trust: t`Trust it`, untrust: t`Remove it` }[f]}</span>`;
    $("#pw-ok").disabled = S.pw.checking;
    const note = $("#pw-note");
    note.dataset.tone = "error";
    note.textContent = S.pw.error ?? "";
    if (S.pw.error && wasOpen) replay($("#pw-form"), "shake");
    if (!S.pw.checking) setTimeout(() => input.focus(), wasOpen ? 0 : 250);
  });
}

// ── Relay mode's certificate ───────────────────────────────────────────────────────────────

function renderTrust() {
  section("trust", [S.trustAsk], () => {
    $("#trust-modal").classList.toggle("on", S.trustAsk);
    const how = { darwin: t`macOS asks for your password once`, win32: t`Windows asks you to confirm once: choose Yes` }[fh.platform] ?? t`It takes your login password once`;
    $("#trust-how").textContent = IOS
      ? t`iOS has you install it yourself: Safari downloads it, and Foxhole says what to tap in Settings then. Safari and other apps trust it then.`
      : PHONE
        ? t`Android has you install it yourself: Foxhole opens the screen for it and says what to tap there. Chrome trusts it then; most other apps don't.`
        : t`${how}, then restart your browser.`;
  });
}

// ── Accounts ───────────────────────────────────────────────────────────────────────────────

/** Data left, short: "12.3 GB left", "Unlimited". */
const left = (u) => (!u ? "" : u.unlimited ? t`Unlimited` : t`${u.left} left`);

/** Data left, in full: the data chip's and the accounts' rings' tooltip. */
const dataLeft = (u) => (!u ? t`Data left this month: not known yet` : u.unlimited ? t`Unlimited data` : t`${u.left} of ${u.max} left this month${u.reset ? t` · resets ${u.reset}` : ""}`);

/** An account's data left as a ring, as the top bar's (#data-ring): where it's known. */
const gauge = (u) => !u ? "" : `<svg class="gauge" viewBox="0 0 36 36" role="img" aria-label="${esc(dataLeft(u))}"><title>${esc(dataLeft(u))}</title><circle class="track" cx="18" cy="18" r="15"/>
  <circle class="bar" cx="18" cy="18" r="15" transform="rotate(-90 18 18)" style="stroke-dashoffset:${CIRCUMFERENCE * (1 - (u.unlimited ? 1 : u.fraction))}"/></svg>`;

/** An account's row: tapped, it's the one in use (data-use); its button signs it out of Foxhole. */
function accountRow(a, { remove = true } = {}) {
  const what = [a.current ? t`In use` : "", a.error ?? left(a.usage), a.firefox ? t`Firefox's sign-in` : ""].filter(Boolean).join(" · ");
  const title = a.firefox ? t`Stop using Firefox's sign-in (Firefox stays signed in)` : t`Sign out of this account`;
  return `<div class="account-line acct-row${a.current ? " current" : ""}" data-use="${esc(a.id)}">
    <span class="avatar big">${esc((a.email || "?")[0].toUpperCase())}</span>
    <div class="grow"><b>${esc(a.email || (a.firefox ? t`Firefox's account` : t`Mozilla account`))}</b><span>${esc(what)}</span></div>
    ${gauge(a.usage)}
    ${remove ? `<button class="icon-btn" type="button" data-logout="${esc(a.id)}" title="${title}" aria-label="${title}">${icon("logout")}</button>` : ""}
  </div>`;
}

/**
 * The ways to sign in: Foxhole's own (Mozilla's page in a window of Foxhole's: nothing to allow), or Firefox's sign-in
 * (macOS asks to let Foxhole read Firefox's data). `email`: Firefox's account, where it could be read without asking.
 */
function choices(email, { firefox = true } = {}) {
  const mac = fh.platform === "darwin";
  const ff = !firefox || PHONE ? ""
    : `<button class="choice" type="button" data-act="addAccount" data-arg="firefox">${icon("external")}<span><b>${email ? t`Use Firefox's account, ${esc(email)}` : t`Use Firefox's sign-in`}</b>
        <span>${email ? t`Firefox is signed in to it on this computer.` : mac ? t`macOS asks you to let Foxhole read Firefox's data (Full Disk Access).` : t`Firefox signed in to your Mozilla account, on this computer.`}</span></span></button>`;
  return t`<button class="choice primary" type="button" data-act="addAccount" data-arg="mozilla">${icon("user")}<span><b>Sign in to a Mozilla account</b>
      <span>Mozilla's own page opens in Foxhole. Nothing to allow, and no Firefox needed.</span></span></button>${ff}`;
}

/** Asks before an account's signed out of Foxhole (logout-ok then does it). */
function askLogout(id) {
  const a = S.accounts.find((x) => x.id === id);
  if (!a) return;
  const name = a.email || (a.firefox ? t`Firefox's account` : t`this account`);
  $("#logout-title").textContent = a.firefox ? t`Stop using Firefox's sign-in?` : t`Sign out of ${name}?`;
  $("#logout-why").textContent = a.firefox
    ? t`Foxhole stops using ${name}. Firefox itself stays signed in, and you can add it again any time.`
    : t`Foxhole signs out of it and forgets it. You can sign in again any time.`;
  $("#logout-label").textContent = a.firefox ? t`Stop using it` : t`Sign out`;
  $("#logout-ok").dataset.arg = id;
  $("#logout-modal").classList.add("on");
}

/** Switched to another account (controller.js useAccount, signed in with it): Settings closes, the toast says so. */
function renderSwitched() {
  section("switched", [S.switched], () => S.switched && openSheet === "settings" && closeSheet());
}

let lowShown = ""; // the low-data warning shown for this account and amount: once, until it changes

function renderAccounts() {
  section("accounts", [S.accounts, S.firefoxEmail], () => {
    $("#accounts").innerHTML = S.accounts.map((a) => accountRow(a)).join("") || t`<div class="hint">None yet.</div>`;
    $("#add-choices").innerHTML = choices(S.firefoxEmail, { firefox: !S.accounts.some((a) => a.firefox) });
  });
  section("low", [S.low, S.accounts], () => {
    const low = S.low;
    if (!low) return $("#low-modal").classList.remove("on");
    $("#low-why").textContent = t`${low.email || t`This account`} has ${low.left} left this month. Switch to another account, or add one, to carry on without a break.`;
    $("#low-accounts").innerHTML = S.accounts.filter((a) => !a.current).map((a) => accountRow(a, { remove: false })).join("");
    const key = `${low.email} ${low.left}`;
    if (lowShown !== key) $("#low-modal").classList.add("on");
    lowShown = key;
  });
}

/** Adds an account: on a phone, Mozilla's sign-in at once (no Firefox there); else the choice. */
function addAccount() {
  if (TV) return tvModal(true);
  if (PHONE) return act("addAccount", "mozilla");
  act("refreshAccounts"); // Firefox's account, freshly read where that asks nothing
  $("#add-modal").classList.add("on");
}

// ── Signing in ─────────────────────────────────────────────────────────────────────────────

/** The Browser Console snippet with a few colors (strings first, so words inside them aren't colored). */
function highlight(code) {
  return esc(code).replace(
    /(&#34;(?:(?!&#34;).)*&#34;)|\b(async|await|const)\b|\b(ChromeUtils|console|fetch|JSON)\b|(=&#62;|\?\?|\?\.)/g,
    (_, str, kw, fn, op) => (str ? `<span class="s">${str}</span>` : kw ? `<span class="kw">${kw}</span>` : fn ? `<span class="fn">${fn}</span>` : `<span class="op">${op}</span>`),
  );
}

function renderOnboard() {
  const a = S.auth;
  section("onboard", [a, S.accounts.map((x) => [x.id, x.email, x.current]), TV && [S.tvWait, S.net]], () => {
    $("#onboard").classList.toggle("on", a.stage !== "ready");
    $("#onboard").classList.toggle("wait", a.stage === "checking"); // shown only if the check takes a while
    $("#onboard-box").classList.toggle("wide", a.stage === "console" || (TV && TV_STAGES.has(a.stage)));
    if (a.stage === "ready") return;
    const fox = '<svg class="fox-hero"><use href="#fox"/></svg>';
    const err = a.error ? `<div class="err-box">${esc(a.error)}</div>` : "";
    const wait = (text) => `<div class="waiting"><span class="spin"></span>${text}</div>`;
    const mac = fh.platform === "darwin";
    // the other accounts on the list, to use one of them instead
    const others = S.accounts.filter((x) => !x.current);
    const rest = others.length ? t`<p class="fine">Or use another account:</p><div class="accounts">${others.map((x) => accountRow(x, { remove: false })).join("")}</div>` : "";
    // settings from the family (share.ts): their relay gets the sign-in through where Mozilla is blocked
    const take = t`<p class="fine">Got Foxhole settings from your family? <span class="link" id="onboard-take">Import them</span>: a relay in them gets through where Mozilla is blocked.</p>`;
    // instead of Firefox's sign-in: Foxhole's own
    const own = t`<p class="fine">Or <span class="link" data-act="addAccount" data-arg="mozilla">sign in to a Mozilla account here</span>, without Firefox.</p>`;
    // a phone: Mozilla's sign-in page opens in the app itself (App.tsx), no Firefox needed
    const phone = {
      checking: () => t`${fox}<h2>Waking up the fox…</h2><p>Getting the VPN token from your Mozilla account.</p>${wait(t`One moment`)}`,
      choose: () => t`${fox}<h2>Sign in to your Mozilla account</h2>
        <p>Foxhole uses Firefox's free VPN, which comes with a <b>Mozilla account</b>: the one Firefox signs in with. Sign in with yours, or make one: it's free.</p>
        ${err}
        <div class="buttons"><button class="btn primary" data-act="addAccount" data-arg="mozilla">${icon("user")}Sign in</button></div>
        <p class="fine">You sign in on Mozilla's own page. Foxhole keeps the sign-in on this phone, to get the VPN's token with.</p>${take}`,
    };
    // a TV: signed in from a phone or computer on its network (tvPanel)
    const tv = {
      checking: phone.checking,
      choose: () => t`<h2>Sign in to your Mozilla account</h2>
        <p>Foxhole uses Firefox's free VPN, which comes with a <b>Mozilla account</b>. Sign in to yours from your phone or computer, with Foxhole on it:</p>
        ${err}${tvPanel()}`,
      expired: () => t`<h2>Sign in again</h2>
        <p>The sign-in to <b>${esc(a.email || t`your account`)}</b> has ended. Sign in again from your phone or computer, with Foxhole on it:</p>
        ${tvPanel()}<div class="buttons"><button class="btn" data-act="removeAccount" data-arg="${esc(a.id)}">${icon("logout")}Remove it</button></div>${rest}`,
    };
    $("#onboard-box").innerHTML = ((TV && tv[a.stage]) || (PHONE && phone[a.stage]) || {
      checking: () => t`${fox}<h2>Waking up the fox…</h2><p>Getting the VPN token from your Mozilla account.</p>${wait(t`One moment`)}`,
      // none yet: how to sign in (Firefox's account named where reading it asks nothing)
      choose: () => t`${fox}<h2>Sign in to your Mozilla account</h2>
        <p>Foxhole uses Firefox's free VPN, which comes with a <b>Mozilla account</b>. Sign in with yours (or make one: it's free), or use the one Firefox is signed in to.</p>
        ${err}<div class="choices">${choices(a.firefox?.email)}</div>${take}`,
      expired: () => t`${fox}<h2>Sign in again</h2>
        <p>The sign-in to <b>${esc(a.email || t`your account`)}</b> has ended: signed out elsewhere, or expired.</p>
        <div class="buttons"><button class="btn primary" data-act="addAccount" data-arg="mozilla">${icon("user")}Sign in again</button>
        <button class="btn" data-act="removeAccount" data-arg="${esc(a.id)}">${icon("logout")}Remove it</button></div>${rest}`,
      offline: () => t`${fox}<h2>Can't reach Mozilla</h2>
        <p>Foxhole couldn't get the VPN's token for <b>${esc(a.email || t`your account`)}</b>.</p>${err}
        <div class="buttons"><button class="btn primary" data-act="retrySignIn">${icon("refresh")}Try again</button></div>
        ${wait(t`Trying again in a moment…`)}${take}${rest}`,
      signin: () => t`${fox}<h2>Sign in to Firefox</h2>
        <p>Foxhole uses Firefox's built-in VPN, so the <b>Firefox browser</b> must be signed in to your Mozilla account: inside the browser, not on a website.</p>
        ${err}
        <ol class="steps">
          <li><span>Firefox is opening its <b>Sync</b> settings: click <b>Sign in</b> there. Didn't open? In Firefox: menu <b>☰</b> → <b>Sign in</b>.</span></li>
          <li><span><b>Sync is optional</b>: Foxhole only needs the sign-in, so you can turn off everything on the <b>Choose what to sync</b> screen.</span></li>
        </ol>
        <div class="buttons"><button class="btn primary" data-act="openFirefox">${icon("external")}Open Firefox sign-in</button><button class="btn" data-open="firefox">Get Firefox</button></div>
        ${wait(t`Waiting for Firefox to sign in…`)}${own}${rest}`,
      console: () => t`<div class="ok-line">${icon("check")}You are signed in to Firefox${a.email ? ` (${esc(a.email)})` : ""}</div>
        ${err}<h2>Let's grab a token from Firefox</h2>
        <div class="cols">
          <ol class="steps">
            <li><span>In Firefox open <kbd>about:config</kbd> and set <kbd>devtools.chrome.enabled</kbd> to <b>true</b> (first time only).</span></li>
            <li><span>Open the <b>Browser Console</b>: <kbd>${mac ? "⌘ ⇧ J" : t`Ctrl+Shift+J`}</kbd> (the Browser Console, not the page's web console).</span></li>
            <li><span>Paste the snippet (<b>it's already in your clipboard</b>) and press <b>Enter</b>.</span></li>
          </ol>
          <div class="snippet"><pre>${highlight(a.snippet)}</pre><button class="btn" data-act="copySnippet" data-copied>${icon("copy")}Copy</button></div>
        </div>
        ${wait(t`Waiting for the token from Firefox…`)}
        <p class="fine">The token comes back over localhost only and is saved, readable only by you, for next time.</p>${own}${rest}`,
      blocked: () => fh.platform === "darwin"
        ? t`${fox}<h2>Let Foxhole read your Firefox sign-in</h2>
          <p>macOS keeps other apps out of Firefox's data until you allow it. Foxhole only reads the sign-in, to get your VPN token.</p>
          <ol class="steps">
            <li><span>Open <b>System Settings → Privacy & Security → Full Disk Access</b> (the button below goes there).</span></li>
            <li><span>Turn on <b>${esc(a.app)}</b>. Not in the list? Click <b>+</b> and pick ${esc(a.app)} in Applications.</span></li>
            ${a.app === "Foxhole"
              ? t`<li><span>Click <b>Quit & reopen</b> (here or in System Settings).</span></li>`
              // started from a terminal (or a development copy): macOS asks about that app, so it's the one to restart
              : t`<li><span>Quit <b>${esc(a.app)}</b> completely (<kbd>⌘Q</kbd>), open it again, and start Foxhole from it.</span></li>`}
          </ol>
          <p class="fine">If macOS asks whether ${esc(a.app)} may access data from other apps, click <b>Allow</b>.</p>
          <div class="buttons"><button class="btn primary" data-open="fda">${icon("lock")}Open Full Disk Access</button>${a.app === "Foxhole" ? t`<button class="btn" data-act="relaunch">${icon("refresh")}Quit & reopen</button>` : ""}</div>
          ${wait(t`Waiting for access…`)}${own}${rest}`
        : t`${fox}<h2>Can't read your Firefox sign-in</h2>${err}${wait(t`Trying again…`)}${own}${rest}`,
    }[a.stage])() + langLink();
  });
}

// ── A TV's sign-in from a phone or computer (controller.js tvWait) ──────────────────────────────

const TV_STAGES = new Set(["choose", "expired"]); // the sign-in screens that show tvPanel

/** The TV's QR code and code, for a phone or computer on its network to sign it in with, and that network. */
function tvPanel() {
  const w = S.tvWait;
  if (w?.error) return `<div class="err-box">${esc(w.error)}</div>`;
  if (!w) return t`<div class="waiting"><span class="spin"></span>Getting a code…</div>`;
  const net = w.host
    ? t`<div class="tv-net">${icon("wifi")}<span>This TV is on <b>${esc(tr(S.net) ?? t`a network`)}</b> · ${esc(w.host)}${showName()}. The phone or computer must be on it too.</span></div>`
    : t`<div class="tv-net warn">${icon("wifi")}<span>This TV isn't on a network: connect it to the Wi-Fi or a cable first.</span></div>`;
  const qr = w.qr
    ? `<svg class="tv-qr" viewBox="0 0 ${w.qr.size} ${w.qr.size}" role="img" aria-label="The QR code to sign in with"><rect width="100%" height="100%" fill="#fff"/><path d="${w.qr.path}"/></svg>`
    : "";
  return t`<div class="tvpair">${qr}<div class="tv-how">
    <ol class="steps">
      <li><span>On your phone or computer, open <b>Foxhole</b>, then <b>Settings</b> → <b>Sign in a TV</b>.</span></li>
      <li><span>Scan this QR code, or type this code:</span></li>
    </ol>
    <div class="tv-code">${esc(w.code.slice(0, 3))} ${esc(w.code.slice(3))}</div>
    ${net}
    <p class="fine">Or <span class="link" data-act="addAccount" data-arg="mozilla">sign in on the TV, with the remote</span>.</p>
  </div></div>`;
}

let tvWanted = false; // the TV's waiting for a sign-in, as last asked
/** The TV waits for a sign-in from another device while its panel's on screen. */
function syncTv() {
  const want = TV && !!S && ($("#tvwait-modal").classList.contains("on") || ($("#onboard").classList.contains("on") && TV_STAGES.has(S.auth.stage)));
  if (want !== tvWanted) void act("tvWait", (tvWanted = want));
}

function tvModal(on) {
  $("#tvwait-modal").classList.toggle("on", on);
  if (on) $("#tvwait-body").innerHTML = tvPanel();
  syncTv();
}

function renderTv() {
  section("tvsendnet", [S.net, S.lanIp], () => $("#tvsend-modal").classList.contains("on") && drawSendNet());
  if (!TV) return;
  section("tvwait", [S.tvWait, S.net], () => $("#tvwait-modal").classList.contains("on") && ($("#tvwait-body").innerHTML = tvPanel()));
  syncTv();
}

// ── Sharing Foxhole (controller.js shareOpen, share.ts) ────────────────────────────────────

let giveRelay = false; // the Share dialog's "my relay too", as last ticked: off each time it opens

function giveOpen() {
  giveRelay = false;
  $("#give-modal").classList.add("on");
  drawGive();
  void act("shareOpen", true, giveRelay);
}

function giveClose() {
  $("#give-modal").classList.remove("on");
  void act("shareOpen", false);
}

function renderGive() {
  section("give", [S.share, S.net], () => $("#give-modal").classList.contains("on") && drawGive());
}

/** The Share dialog: the page's QR code (the app, the settings in it), what it shares, the relay's switch, the link. */
function drawGive() {
  const g = S.share;
  if (!g) return void ($("#give-body").innerHTML = t`<div class="waiting"><span class="spin"></span>Getting ready…</div>`);
  if (g.error) return void ($("#give-body").innerHTML = `<div class="err-box">${esc(g.error)}</div>`);
  const what = g.what.map((w) => `<li>${icon("check")}<span>${esc(w)}</span></li>`);
  if (g.relay) what.push(t`<li class="warn">${icon("shield")}<span>Anyone with this code or link can use your relay, on your Google account.</span></li>`);
  const qr = g.host && g.qr && (g.link || g.apk)
    ? t`<svg class="give-qr" viewBox="0 0 ${g.qr.size} ${g.qr.size}" role="img" aria-label="The QR code to scan"><rect width="100%" height="100%" fill="#fff"/><path d="${g.qr.path}"/></svg>
       <p>Scan it with the other phone's camera, on this ${DEVICE}'s Wi-Fi${g.apk ? t` or its hotspot` : ""}: ${g.apk ? (g.link ? t`it gets Foxhole from this phone, and these settings in it.` : t`it gets Foxhole from this phone, with no internet.`) : t`these settings open in its Foxhole.`}</p>`
    : !g.host && (g.link || g.apk)
      ? t`<div class="tv-net warn">${icon("wifi")}<span>This ${DEVICE} isn't on a network: connect it to the Wi-Fi${g.apk ? t`, or turn its hotspot on,` : ""} for the QR code.</span></div>`
      : g.link && !g.qr
        ? '<div class="tv-net warn">' + icon("split") + t`<span>Too many sites for a QR code: send the link instead.</span></div>`
        : "";
  $("#give-body").innerHTML = `${qr}
    ${g.link || g.relay ? `<ul class="give-what">${what.join("")}</ul>` : t`<p>Nothing to share yet: no relay, and split tunneling as it comes.${g.apk ? "" : t` Set them up first.`}</p>`}
    ${g.hasRelay ? t`<div class="row-line"><div><div class="label">${icon("shield")}My VPN relay too</div><div class="hint">So the other device needs no relay of its own.</div></div>
      <button class="switch${giveRelay ? " on" : ""}" id="give-relay" role="switch" aria-checked="${giveRelay}" aria-label="My VPN relay too"></button></div>` : ""}
    ${g.link ? t`<div class="hint">Elsewhere? Send this link, to paste in Foxhole's <b>Settings → Import settings</b>:</div>
      <div class="addr"><span class="mono">${esc(g.link)}</span><button class="mini" data-copy="${esc(g.link)}" title="Copy the link">${icon("copy")}</button></div>` : ""}`;
}

// ── Importing shared settings (controller.js importCheck, importSettings) ─────────────────

let takeAsk = 0; // the newest check of the link typed: an older one's answer is dropped

function takeOpen(link = "") {
  $("#take-link").value = link;
  $("#take-modal").classList.add("on");
  void takeCheck();
  if (!link && !PHONE) $("#take-link").focus();
}

const takeClose = () => $("#take-modal").classList.remove("on");

function takeNote(tone, text) {
  $("#take-note").dataset.tone = tone;
  $("#take-note").textContent = text;
}

/** What the link typed would change here, before Import. */
async function takeCheck() {
  const text = $("#take-link").value.trim();
  const ask = ++takeAsk;
  $("#take-go").disabled = true;
  $("#take-what").innerHTML = "";
  takeNote("", "");
  if (!text) return;
  try {
    const what = await act("importCheck", text);
    if (ask !== takeAsk) return;
    $("#take-what").innerHTML = what.map((w) => `<li>${icon("check")}<span>${esc(tr(w))}</span></li>`).join("") +
      (what.some((w) => w.startsWith("VPN relay")) ? t`<li class="warn">${icon("shield")}<span>A relay sees what goes through it: take one only from someone you trust.</span></li>` : "");
    $("#take-go").disabled = false;
  } catch (err) {
    if (ask === takeAsk) takeNote("error", why(err));
  }
}

$("#take-link").addEventListener("input", () => void takeCheck());
$("#take-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#take-go");
  btn.disabled = true;
  try {
    await act("importSettings", $("#take-link").value.trim());
    takeNote("ok", t`Imported: Foxhole uses them from now on.`);
    setTimeout(takeClose, 1800);
  } catch (err) {
    takeNote("error", why(err));
    btn.disabled = false;
  }
});

/** Android opened Foxhole with shared settings (App.tsx: the share page's "Open in Foxhole"). */
window.foxholeImport = (link) => (S ? takeOpen(link) : setTimeout(() => window.foxholeImport(link), 200));

// ── Signing in a TV from here (controller.js tvSend) ───────────────────────────────────────

/** An action's error, without Electron's wrapping. */
const why = (err) => tr(String(err?.message ?? err).replace(/^Error invoking remote method '\w+': (\w*Error: )?/, ""));

// "foxhole" as a QR code (21 rows of 21 modules, base 36), to see whether this device's QR reader reads at all
const TEST_QR = ["18ltr", "mv5t", "wspp", "ws4d", "wr4t", "mywx", "18prz", "5j4", "xe9o", "mprd", "6xyi", "17mq5", "2qyy", "3e9", "18mti", "myi7", "wrde", "wt80", "wthg", "mva4", "18owi"];
let canScan = null; // a promise: there's a camera API and a QR reader that works (not on Windows and Linux, nor phones without Google Play)
let camera = null; // the camera's stream, while scanning
let tvLooking = 0; // the search for TVs waiting, again while none is found

async function scanWorks() {
  if (!("BarcodeDetector" in window) || !navigator.mediaDevices?.getUserMedia) return false;
  try {
    const c = document.createElement("canvas");
    c.width = c.height = 29 * 6;
    const g = c.getContext("2d");
    g.fillStyle = "#fff";
    g.fillRect(0, 0, c.width, c.height);
    g.fillStyle = "#000";
    TEST_QR.forEach((row, y) => [...parseInt(row, 36).toString(2).padStart(21, "0")].forEach((b, x) => b === "1" && g.fillRect((x + 4) * 6, (y + 4) * 6, 6, 6)));
    return (await new BarcodeDetector({ formats: ["qr_code"] }).detect(c))[0]?.rawValue === "foxhole";
  } catch {
    return false;
  }
}

function tvNote(tone, text) {
  $("#tvsend-note").dataset.tone = tone;
  $("#tvsend-note").textContent = text;
}

function drawFound(tvs) {
  const names = tvs.map((tv) => `<b>${esc(tv.name)}</b>`).join(", ");
  $("#tvsend-found").innerHTML = tvs.length
    ? t`${icon("tv")}<span>Waiting to sign in: ${names}</span>`
    : t`${icon("tv")}<span>No TV waiting here yet. Is it showing its code, on the same network as this ${DEVICE}?</span>`;
  $("#tvsend-found").classList.toggle("warn", !tvs.length);
  clearTimeout(tvLooking);
  if (!tvs.length && $("#tvsend-modal").classList.contains("on")) tvLooking = setTimeout(findTvs, 4000);
}
const findTvs = () => act("tvFind").then(drawFound, () => drawFound([]));

/** The "Sign in a TV" dialog; with a TV's QR code's `link` (scanned with the phone's camera app: App.tsx), it sends at once. */
function tvSendOpen(link) {
  const accts = S.accounts.filter((a) => a.send);
  $("#tvsend-acct").innerHTML = accts.map((a) => `<option value="${esc(a.id)}"${a.current ? " selected" : ""}>${esc(a.email || t`Firefox's account`)}</option>`).join("");
  $("#tvsend-acct-wrap").hidden = accts.length < 2;
  drawSendNet();
  $("#tvsend-found").innerHTML = t`${icon("tv")}<span>Looking for TVs on this network…</span>`;
  $("#tvsend-found").classList.remove("warn");
  $("#tvsend-code").value = "";
  tvNote("", accts.length ? "" : t`Sign in to a Mozilla account on this device first: Foxhole sends the TV a sign-in of it.`);
  $("#tvsend-modal").classList.add("on");
  void findTvs();
  void (canScan ??= scanWorks()).then((ok) => ($("#tvsend-scan").hidden = !ok || !!camera));
  if (link) void tvSend({ link });
  else if (!PHONE) $("#tvsend-code").focus();
}

const drawSendNet = () => ($("#tvsend-net").innerHTML = t`This ${DEVICE} is on <b>${esc(tr(S.net) ?? t`no network`)}</b>${S.lanIp ? ` · ${esc(S.lanIp)}` : ""}${showName()}`);

function tvSendClose() {
  stopScan();
  clearTimeout(tvLooking);
  $("#tvsend-modal").classList.remove("on");
}

async function tvSend(to) {
  const id = $("#tvsend-acct").value;
  if (!id) return;
  const btn = $("#tvsend-form button");
  btn.disabled = true;
  tvNote("", t`Signing in the TV…`);
  try {
    const name = await act("tvSend", to, id);
    tvNote("ok", t`${name} is signed in.`);
    setTimeout(tvSendClose, 2500);
  } catch (err) {
    tvNote("error", why(err));
  }
  btn.disabled = false;
}

async function startScan() {
  try {
    camera = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch (err) {
    return tvNote("error", err.name === "NotAllowedError" ? t`Foxhole isn't allowed to use the camera. Type the code instead.` : t`No camera to scan with. Type the code instead.`);
  }
  const video = $("#tvsend-video");
  video.srcObject = camera;
  $("#tvsend-cam").hidden = false;
  $("#tvsend-scan").hidden = true;
  tvNote("", t`Point the camera at the QR code on the TV.`);
  await video.play().catch(() => {});
  const reader = new BarcodeDetector({ formats: ["qr_code"] });
  for (let warned = false; camera; await new Promise((r) => setTimeout(r, 200))) {
    const read = (await reader.detect(video).catch(() => [])).map((c) => c.rawValue);
    const link = read.find((r) => /^http:\/\/[^/]+\/#[\w-]+\.[\w-]+$/.test(r));
    if (link) {
      stopScan();
      return tvSend({ link });
    }
    if (read.length && !warned) (warned = true), tvNote("warn", t`That isn't a Foxhole TV's QR code.`);
  }
}

function stopScan() {
  for (const track of camera?.getTracks() ?? []) track.stop();
  camera = null;
  $("#tvsend-video").srcObject = null;
  $("#tvsend-cam").hidden = true;
  void canScan?.then((ok) => ($("#tvsend-scan").hidden = !ok || !!camera));
}

$("#tvsend-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const code = $("#tvsend-code").value.replace(/\s/g, "");
  if (code.length < 6) return tvNote("error", t`The code on the TV has 6 letters and digits.`);
  void tvSend({ code });
});
// typed as on the TV: capitals, in two threes; sent once it's all there
$("#tvsend-code").addEventListener("input", (e) => {
  const v = e.target.value.toUpperCase().replace(/[^0-9A-Z]/g, "").slice(0, 6);
  e.target.value = v.length > 3 ? `${v.slice(0, 3)} ${v.slice(3)}` : v;
  if (v.length === 6) $("#tvsend-form").requestSubmit();
});

/** A TV's QR code scanned with the phone's camera app opens Foxhole with it (App.tsx). */
window.foxholeTvLink = (link) => (S ? tvSendOpen(link) : setTimeout(() => window.foxholeTvLink(link), 200));

// ── The Wi-Fi's name, which macOS, Windows and Android show only to apps allowed Location ─────────────────

const OS = IOS ? "iOS" : PHONE ? "Android" : { darwin: "macOS", win32: "Windows" }[fh.platform] ?? t`The system`;
/** " · Show the name", where the system hides it (netinfo.ts WIFI_HIDDEN): what it takes is told first (askWifi). */
const showName = () => (S.net?.endsWith("name hidden") && OS !== "macOS" ? t` · <span class="link" data-wifi>Show the name</span>` : "");

/** Why Foxhole would want Location, and what the system then asks: before it asks (the user may say not now). */
function askWifi() {
  $("#wifi-why").textContent = t`${OS} shows apps the Wi-Fi's name only if they're allowed Location, as a Wi-Fi's name can tell where you are.`;
  $("#wifi-how").textContent = {
    Windows: t`Windows' Location settings open: turn on Location services and Let desktop apps access your location. You can turn them off there any time.`,
    Android: t`Android asks you once: choose Precise and While using the app. You can change it any time in Android's settings.`,
  }[OS] ?? "";
  $("#wifi-note").textContent = "";
  $("#wifi-ok").textContent = t`Continue`;
  $("#wifi-modal").classList.add("on");
}

async function wifiAsk(btn) {
  btn.disabled = true;
  btn.textContent = t`One moment…`;
  const how = await act("showWifiName").catch((err) => ({ error: why(err) }));
  btn.disabled = false;
  btn.textContent = t`Continue`;
  const note = (tone, text) => (($("#wifi-note").dataset.tone = tone), ($("#wifi-note").textContent = text));
  if (how?.error) return note("error", tr(how.error));
  if (how === "approximate") return note("warn", t`Android gives apps the Wi-Fi's name only with Precise location: Continue, and choose Precise.`);
  if (how === "denied") return note("warn", t`Not allowed, so the name stays hidden. You can allow it here any time.`);
  if (how === "settings") fh.open("location");
  $("#wifi-modal").classList.remove("on"); // allowed (the name shows within seconds), or it's turned on in Settings
}

// ── Sheets ─────────────────────────────────────────────────────────────────────────────────

let openSheet = null;

/** Settings' switch, as the system has it: read each time the sheet opens, as it can be changed there too. Null: this copy can't (main.js). */
function drawAutostart(on) {
  $("#autostart-group").hidden = on === null;
  $("#autostart").classList.toggle("on", !!on);
  $("#autostart").setAttribute("aria-checked", String(!!on));
  $("#autostart-hint").textContent = t`Foxhole opens in the ${fh.platform === "darwin" ? t`menu bar` : t`tray`} and connects to your last location.`;
}

// .locations: a sheet on a phone (style.css), the side panel elsewhere
function showSheet(name) {
  for (const el of document.querySelectorAll(".sheet, .locations")) el.classList.toggle("on", el.id === `sheet-${name}`);
  openSheet = name;
  $("#scrim").classList.add("on");
  if (name === "settings") act("openSettings");
  if (name === "settings" && !PHONE) void act("autostart").then(drawAutostart);
  if (name === "split") act("openSplit");
  if (name === "logs") void act("logs").then((lines) => ((logBuf = lines.slice(-1000)), drawLogs(true)));
  if (name === "data") void drawData();
}

function closeSheet() {
  for (const el of document.querySelectorAll(".sheet, .locations")) el.classList.remove("on");
  openSheet = null;
  if (!S?.pw) $("#scrim").classList.remove("on");
}

// ── An update to install by hand ───────────────────────────────────────────────────────────

/** The downloaded file and how to install it, when it didn't go in by itself (updater.js keeps it in Downloads). */
function showManual(up) {
  const name = esc(up.file.split(/[\\/]/).pop());
  $("#manual-why").innerHTML = t`Foxhole ${esc(up.version)} couldn't be installed automatically (${esc(up.error ?? "")}). It's saved in your Downloads folder as <b>${name}</b>.`;
  const then = {
    mac: [t`Foxhole quits and opens it.`, t`Drag <b>Foxhole</b> onto <b>Applications</b> and click <b>Replace</b>.`, t`Open Foxhole again.`],
    win: [t`Foxhole quits, puts your network back, and opens the installer.`, t`Follow it: Foxhole starts again when it's done.`],
    appimage: [t`Foxhole quits and starts the new version from your Downloads folder.`, t`Keep that file, or move it where the old one was and delete the old one.`],
    deb: [t`Foxhole quits and opens it in your software center: click <b>Install</b>.`,
      t`Or in a terminal: <code>sudo apt install "${esc(up.file)}"</code>`, t`Open Foxhole again.`],
  }[up.kind] ?? [];
  $("#manual-steps").innerHTML = then.map((l) => `<li><span>${l}</span></li>`).join("");
  $("#manual-install").disabled = false;
  $("#manual-install").textContent = t`Quit & install`;
  $("#manual-modal").classList.add("on");
}
$("#manual-later").addEventListener("click", () => $("#manual-modal").classList.remove("on"));

/** A run of the notes' text, set as GitHub set it (update.ts Span); a link into the repo opens it. */
const noteSpan = (s) => {
  let h = esc(s.text);
  for (const [k, tag] of [["code", "code"], ["b", "b"], ["i", "i"], ["s", "s"]]) if (s[k]) h = `<${tag}>${h}</${tag}>`;
  return s.href ? `<span class="link" data-open="${esc(s.href)}">${h}</span>` : h;
};
/** A heading, paragraph, list item or code block of the notes (update.ts Block). */
const noteBlock = (b) => {
  const body = b.spans.map(noteSpan).join("");
  return b.kind === "h" ? `<h4>${body}</h4>`
    : b.kind === "pre" ? `<pre>${body}</pre>`
    : b.kind === "li" ? `<div class="li" style="--d:${b.depth}"><span class="m">${esc(b.mark)}</span><span>${body}</span></div>`
    : `<p style="--d:${b.depth}">${body}</p>`;
};

/** A new version's changelog (updater.js notes: each version's, newest first), with the button that gets it. */
function showNotes(up) {
  const many = up.notes?.length > 1;
  $("#notes-title").textContent = t`Foxhole ${up.version} is out`;
  $("#notes-body").innerHTML = up.notes?.some((n) => n.blocks.length)
    ? up.notes.map((n) => (many ? `<h3>${esc(n.version)}</h3>` : "") + n.blocks.map(noteBlock).join("")).join("")
    : t`<p>See what's new on the <span class="link" data-open="releases">download page</span>.</p>`;
  $("#notes-body").scrollTop = 0;
  $("#notes-update").textContent = up.auto ? t`Update now` : t`Download`;
  $("#notes-modal").classList.add("on");
  setTimeout(() => $("#notes-update").focus({ preventScroll: true }), 60); // a TV's remote and the keyboard start on it
}

/** Downloads and installs the new version; once it's ready, asks to restart; failed with the file there, offers it by hand. */
async function startUpdate() {
  if (await act("update")) return $("#update-modal").classList.add("on");
  const now = localize(await act("state")).update;
  if (now?.file) showManual(now);
}

// ── The relay's setup, step by step ────────────────────────────────────────────────────────

const wz = { step: 0, shot: 0, key: "", id: "", setup: null }; // setup: the steps and the script's tokens (controller.relaySetup); shot: a step of several clicks' line shown

/** A strong random key: 32 URL-safe characters, as relaysetup.ts newAuthKey(). */
const newKey = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24)))).replace(/\+/g, "-").replace(/\//g, "_");

async function openWizard() {
  wz.setup ??= await act("relaySetup");
  Object.assign(wz, { step: 0, shot: 0, key: newKey(), id: "" });
  drawWizard();
  $("#wizard").classList.add("on");
}
const closeWizard = () => $("#wizard").classList.remove("on");

/** The script, highlighted, a line to a row (numbered by CSS), the key marked where it goes. */
function codeHtml() {
  let html = "";
  for (const [kind, text] of wz.setup.tokens) {
    const keyed = text.includes(wz.setup.placeholder);
    html += text.split("\n").map((part) => {
      if (!part) return "";
      const h = keyed ? esc(part).replace(wz.setup.placeholder, `<mark>${esc(wz.key)}</mark>`) : esc(part);
      return kind ? `<span class="${kind}">${h}</span>` : h;
    }).join("\n");
  }
  return html.split("\n").map((l) => `<span class="ln">${l}</span>`).join("");
}
const showKey = () => document.querySelectorAll("#wz-code mark").forEach((m) => (m.textContent = wz.key));

function drawWizard() {
  const { steps } = wz.setup;
  const st = steps[wz.step];
  const last = wz.step === steps.length - 1;
  const many = st.shots.length > 1; // a screenshot a line: Next goes through them
  $("#wz-stepper").innerHTML = steps.map((s, i) =>
    `<li class="${i < wz.step ? "done" : i === wz.step ? "on" : ""}"><span>${i < wz.step ? icon("check") : i + 1}</span>${esc(tr(s.short))}</li>`).join("");
  const widget = [
    t`<div class="buttons"><button class="btn primary" data-open="gas">${icon("external")}Open script.google.com</button></div>`,
    t`<div class="label">Your secret key</div>
     <div class="input-row"><input id="wz-key" class="mono" value="${esc(wz.key)}" spellcheck="false" autocomplete="off" aria-label="Your secret key"><button class="mini big" type="button" id="wz-newkey" title="Make a new key">${icon("refresh")}</button></div>
     <div class="code"><pre id="wz-code">${codeHtml()}</pre><button class="btn" type="button" id="wz-copy">${icon("copy")}Copy code</button></div>`,
    "",
    "",
    `<input id="wz-id" class="mono" placeholder="Paste the Deployment ID or web app URL" value="${esc(wz.id)}" spellcheck="false" autocomplete="off" aria-label="Deployment ID">`,
  ][wz.step];
  $("#wz-body").innerHTML = `<div class="wz-top">
      <div><h3>${wz.step + 1}. ${esc(tr(st.title))}</h3><ol class="steps${many ? " clicks" : ""}">${st.lines.map((l, i) =>
        `<li${many ? ` data-shot="${i}" class="${i === wz.shot ? "on" : i < wz.shot ? "done" : ""}"` : ""}><span>${esc(tr(l)).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")}</span></li>`).join("")}</ol></div>
      <figure class="wz-shot" title="Click to enlarge"><img src="../dist/assets/relay/${st.shots[wz.shot]}" alt="Step ${wz.step + 1}">${many ? t`<figcaption>${wz.shot + 1} of ${st.shots.length}</figcaption>` : ""}</figure>
    </div>${widget}`;
  $("#wz-body img").addEventListener("error", (e) => e.target.parentElement.remove()); // no screenshot for this step
  $("#wz-prev").disabled = wz.step === 0 && wz.shot === 0;
  $("#wz-next").innerHTML = last ? t`${icon("check")}Finish` : t`Next${icon("chevron")}`;
  $("#wz-note").textContent = "";
  $("#wz-key")?.addEventListener("input", (e) => {
    e.target.value = e.target.value.replace(/[^\w-]/g, ""); // a plain JS string in the script: nothing to escape
    wz.key = e.target.value;
    showKey();
  });
  $("#wz-id")?.addEventListener("input", (e) => (wz.id = e.target.value));
  $("#wz-id")?.focus();
}

/** As relaysetup.ts: a Deployment ID (alone, or in the web app's URL), or null; and a key the setup would make. */
const deploymentId = (text) => {
  const id = (text.match(/\/macros\/s\/([\w-]+)/)?.[1] ?? text).trim();
  return /^[\w-]{20,}$/.test(id) ? id : null;
};
const keyOk = (key) => /^[\w-]{16,}$/.test(key.trim());

async function wizardNext() {
  const note = (text) => (($("#wz-note").textContent = text), replay($("#wz-note"), "shake"));
  if (wz.step === 1 && !keyOk(wz.key)) return note(t`The key needs at least 16 letters, digits, - or _. Press ↻ for a new one.`);
  if (wz.shot < wz.setup.steps[wz.step].shots.length - 1) return void (wz.shot++, drawWizard());
  if (wz.step < wz.setup.steps.length - 1) return void (wz.step++, (wz.shot = 0), drawWizard());
  const id = deploymentId(wz.id);
  if (!id) return note(wz.id.trim() ? t`That isn't a Deployment ID or web app URL: copy it again from Google.` : t`Paste the Deployment ID first.`);
  if (await act("setRelay", id, wz.key)) {
    closeWizard();
    flash($("#relay-wizard"), t`${icon("check")}Relay set up`);
    void checkRelay(id, wz.key); // whether it works, at once (the form's fields may not show them yet)
  } else note(t`Couldn't save it: see the note in Settings.`);
}

/** Previous: the line before in a step of several clicks, else the step before (on its last line). */
function wizardPrev() {
  if (wz.shot > 0) wz.shot--;
  else if (wz.step > 0) wz.shot = wz.setup.steps[--wz.step].shots.length - 1;
  drawWizard();
}

$("#wz-body").addEventListener("click", (e) => {
  const line = e.target.closest("[data-shot]");
  if (line) return void ((wz.shot = +line.dataset.shot), drawWizard());
  e.target.closest(".wz-shot")?.classList.toggle("zoom");
});
$("#wz-body").addEventListener("keydown", (e) => e.key === "Enter" && e.target.id === "wz-id" && wizardNext());

// ── Logs ───────────────────────────────────────────────────────────────────────────────────

let logBuf = [];
const logLine = (l) => `<div class="ln"><time>${esc(l.slice(0, 8))}</time>${esc(l.slice(10))}</div>`;

function drawLogs(all, added = []) {
  const box = $("#logs");
  const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  if (all) box.innerHTML = logBuf.length ? logBuf.map(logLine).join("") : t`<div class="empty"><b>Nothing logged yet</b>Proxy failures (e.g. ports the VPN refuses) and tun2socks output in whole-system mode appear here.</div>`;
  else {
    box.querySelector(".empty")?.remove();
    box.insertAdjacentHTML("beforeend", added.map(logLine).join(""));
    while (box.childElementCount > 1000) box.firstElementChild.remove();
  }
  $("#logs-count").textContent = t`${logBuf.length} line${logBuf.length === 1 ? "" : "s"} · proxy failures and tun2socks output, live`;
  if (all || atEnd) box.scrollTop = box.scrollHeight;
}

fh.onLog((lines) => {
  logBuf.push(...lines);
  if (logBuf.length > 1000) logBuf.splice(0, logBuf.length - 1000);
  if (openSheet === "logs") drawLogs(false, lines);
});

// ── Events ─────────────────────────────────────────────────────────────────────────────────

// the update dialog's words on a phone: Android's installer replaces the app (updater.js), closing it and the VPN
const PHONE_UPDATE = t`Android asks you to install it. Foxhole closes while it does, and the VPN with it: open Foxhole again after.`;
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button, .link, #toast");
  // an account's row (not its button): use it
  const row = !btn && e.target.closest("[data-use]");
  if (row && S) {
    for (const m of ["#low-modal", "#add-modal"]) $(m).classList.remove("on");
    return act("useAccount", row.dataset.use);
  }
  if (!btn || !S) return;
  if (btn.dataset.lang) return setLang(btn.dataset.lang);
  if (btn.dataset.act === "addAccount") $("#add-modal").classList.remove("on"), TV && tvModal(false);
  if (btn.dataset.logout !== undefined) return askLogout(btn.dataset.logout);
  if (btn.hasAttribute("data-wifi")) return askWifi();
  if (btn.dataset.netRule !== undefined) return act("setNetRule", S.net, btn.dataset.netRule || null);
  if (btn.dataset.netForget !== undefined) return act("setNetRule", btn.dataset.netForget, null);
  if (btn.id === "logout-ok") $("#logout-modal").classList.remove("on");
  if (btn.id === "toast") return btn.classList.remove("on");
  if (btn.dataset.act) {
    if (btn.hasAttribute("data-copied")) flash(btn, t`${icon("check")}Copied`);
    return btn.dataset.arg === undefined ? act(btn.dataset.act) : act(btn.dataset.act, btn.dataset.arg);
  }
  if (btn.dataset.open) return fh.open(btn.dataset.open);
  if (btn.dataset.copy) {
    act("copy", btn.dataset.copy);
    return flash(btn, icon("check"));
  }
  if (btn.dataset.code) {
    closeSheet(); // a phone's Locations sheet: the orb behind it shows the connecting
    return act("connect", btn.dataset.code);
  }
  if (btn.dataset.mode) return (btn.dataset.mode === "global") !== globalMode() && act("toggleGlobal");
  if (btn.dataset.via) return act("setSplitDefault", btn.dataset.via);
  if (btn.dataset.site) return act("addRule", btn.dataset.site);
  if (btn.dataset.direct) return act("addRule", btn.dataset.direct).then(drawData); // the Data sheet's "Send direct"
  if (btn.dataset.checkVia && checked) return act("addRule", checked.site, btn.dataset.checkVia).then((ok) => ok && drawCheck({ ...checked, now: btn.dataset.checkVia, offer: null }));
  if (btn.hasAttribute("data-pick-open")) return openPicker($("#split-input").value.trim());
  if (btn.hasAttribute("data-close")) return closeSheet();
  const rule = btn.closest(".rule")?.dataset.match;
  if (rule && btn.hasAttribute("data-toggle")) return act("toggleRule", rule);
  if (rule && btn.hasAttribute("data-remove")) {
    btn.closest(".rule").classList.add("leaving");
    return setTimeout(() => act("removeRule", rule), 260);
  }
  switch (btn.id) {
    case "orb": {
      if (!STILL) { // its ripple (old iOS: no animations, style.css)
        const shock = document.createElement("i");
        shock.className = "shock";
        $("#orb-wrap").append(shock);
        shock.addEventListener("animationend", () => shock.remove());
      }
      return act("power");
    }
    // Telegram's own link: it asks to use the proxy (this device's, so no sign-in)
    case "tg-proxy": return fh.open(`tg://socks?server=127.0.0.1&port=${S.settings.port}`);
    case "copy-proxy":
      act("copy", S.proxy?.addr ?? "");
      return flash(btn, icon("check"));
    case "c-split": return showSheet("split");
    case "split-check-btn": return checkTyped();
    case "data-chip": return showSheet("data");
    case "c-loc": return showSheet("locations");
    case "open-settings": case "account": return showSheet("settings");
    case "open-logs": return showSheet("logs");
    case "copy-logs": return (await act("copyLogs")) && flash(btn, t`${icon("check")}Copied`);
    case "share": return act("setShare", !S.settings.share);
    case "smart-dns": return act("setSmartDns", !S.settings.smartDns);
    case "disguise-off": return act("disguise", null).catch((err) => ($("#disguise-hint").textContent = why(err)));
    case "autostart": return drawAutostart(await act("autostart", !btn.classList.contains("on")));
    case "smart": return act("setSmart", !S.split.smart);
    case "probe": return act("setSmart", true, !S.split.probe);
    case "reveal": {
      const pw = $("#password");
      pw.type = pw.type === "password" ? "text" : "password";
      return;
    }
    case "relay-reveal": {
      const k = $("#relay-key");
      k.type = k.type === "password" ? "text" : "password";
      return;
    }
    case "relay-wizard": return openWizard();
    case "relay-check": return checkRelay();
    case "wz-close": return closeWizard();
    case "wz-prev": return wizardPrev();
    case "wz-next": return wizardNext();
    case "wz-newkey":
      $("#wz-key").value = wz.key = newKey();
      return showKey();
    case "wz-copy":
      act("copy", wz.setup.tokens.map((tk) => tk[1]).join("").replace(wz.setup.placeholder, wz.key));
      return flash(btn, t`${icon("check")}Copied`);
    case "add-account": return addAccount();
    case "wifi-later": return $("#wifi-modal").classList.remove("on");
    case "wifi-ok": return wifiAsk(btn);
    case "tvwait-close": return tvModal(false);
    case "tvsend-open": return tvSendOpen();
    case "give-open": return giveOpen();
    case "give-close": return giveClose();
    case "give-relay":
      giveRelay = !giveRelay;
      return act("shareOpen", true, giveRelay);
    case "take-open": case "onboard-take": return takeOpen();
    case "take-close": return takeClose();
    case "tvsend-close": return tvSendClose();
    case "tvsend-scan": return startScan();
    case "add-later": return $("#add-modal").classList.remove("on");
    case "logout-cancel": return $("#logout-modal").classList.remove("on");
    case "notice-ok": return noticeClose();
    case "unentitled-close": return $("#unentitled-modal").classList.remove("on");
    case "unentitled-check":
      btn.disabled = true;
      await act("checkEntitled");
      btn.disabled = false;
      return;
    case "low-later":
      $("#low-modal").classList.remove("on");
      return act("dismissLow");
    case "low-add":
      $("#low-modal").classList.remove("on");
      return addAccount();
    case "open-repo": return fh.open("repo");
    case "update": case "get-update": {
      const up = S.update;
      if (!up) return fh.open("releases");
      if (up.phase) return;
      if (!up.auto || (!up.ready && !up.error)) return showNotes(up); // what's new first; its button gets it
      if (up.error && up.file && !PHONE) return showManual(up); // it didn't go in by itself: install it by hand (a phone's ready one tries Android's installer again)
      if (up.ready) {
        // a phone's last try at Android's installer failed: why, in the dialog (a TV has no tooltip to show it)
        if (PHONE) $("#update-modal p").textContent = up.error ? t`It didn't install: ${up.error}.` : PHONE_UPDATE;
        return $("#update-modal").classList.add("on");
      }
      return startUpdate(); // failed before: tries again
    }
    case "notes-later": return $("#notes-modal").classList.remove("on");
    case "notes-update":
      $("#notes-modal").classList.remove("on");
      return S.update?.auto ? startUpdate() : fh.open("releases");
    case "manual-show": return act("showUpdateFile");
    case "manual-install":
      btn.disabled = true;
      btn.textContent = t`Quitting…`;
      return act("installUpdateFile");
    case "up-later": return $("#update-modal").classList.remove("on");
    case "blocked-later": return $("#blocked-modal").classList.remove("on");
    case "trust-later": return act("dismissTrust");
    case "trust-ok": return act("trustCa");
    case "cert-btn": return act(S.caOk ? "untrustCa" : "trustCa");
    case "blocked-setup":
      $("#blocked-modal").classList.remove("on");
      return openWizard();
    case "relay-intro": return $("#relay-modal").classList.add("on");
    case "relay-later": return $("#relay-modal").classList.remove("on");
    case "relay-setup":
      $("#relay-modal").classList.remove("on");
      return openWizard();
    case "up-restart":
      // a phone's installer asks first: the dialog goes, to come back if the user says no there
      if (PHONE) {
        $("#update-modal").classList.remove("on");
        return act("restartToUpdate");
      }
      btn.disabled = true;
      btn.textContent = t`Restarting…`;
      return act("restartToUpdate");
    case "pw-cancel": return act("cancelPassword");
  }
});

$("#scrim").addEventListener("click", () => (S?.pw ? act("cancelPassword") : closeSheet()));

$("#split-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#split-input");
  if (await act("addRule", input.value)) (input.value = ""), ($("#split-check").hidden = true);
  drawRecent();
});
$("#split-input").addEventListener("input", () => S && (drawRecent(), ($("#split-check").hidden = true))); // its check was of what was typed before

$("#port-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  if (await act("setPort", Number($("#port").value))) flash(btn, t`${icon("check")}Saved`);
});
$("#port").addEventListener("input", (e) => (e.target.value = e.target.value.replace(/\D/g, "")));

$("#disguise-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = $("#disguise-code").value;
  if (!/^\d{4,12}$/.test(code)) return replay($("#disguise-set"), "shake");
  try {
    await act("disguise", code);
    $("#disguise-code").value = "";
  } catch (err) {
    $("#disguise-hint").textContent = why(err); // Android refused
  }
});
$("#disguise-code").addEventListener("input", (e) => (e.target.value = e.target.value.replace(/\D/g, "")));

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button[type=submit]");
  if (await act("setLogin", $("#username").value, $("#password").value)) flash(btn, t`${icon("check")}Saved`);
});

// The relay's fields save themselves when typing stops, once there's a Deployment ID and a key (typed, or else the saved
// one: the window never gets that); the ID field left empty turns the relay off.
let relayTimer = null;
let keySaved = false; // the key field still shows the key it saved, having had focus: emptied once it's left
let checks = 0; // an answer is shown only from the latest check, and only if the fields weren't typed over since

/** Saves the relay's fields, then checks them. */
async function saveRelay() {
  clearTimeout(relayTimer);
  relayTimer = null;
  const id = $("#relay-id").value;
  const field = $("#relay-key");
  const key = field.value;
  if (!(await act("setRelay", id, key))) return;
  if (document.activeElement === field) keySaved = field.value === key;
  else if (field.value === key) field.value = ""; // the key isn't kept in the window
  if (id.trim()) void checkRelay(id, key); // whether they're right
}

for (const f of ["#relay-id", "#relay-key"])
  $(f).addEventListener("input", () => {
    checks++;
    $("#relay-check-state").textContent = "";
    keySaved = false;
    clearTimeout(relayTimer);
    const ready = deploymentId($("#relay-id").value) && ($("#relay-key").value.trim() || S.settings.relay?.set);
    relayTimer = ready ? setTimeout(saveRelay, 800) : null;
  });
$("#relay-id").addEventListener("blur", (e) => {
  if (relayTimer) return void saveRelay(); // left before it saved: now
  // left empty: the relay off (not when it's the window that's left, as to copy another ID)
  if (!e.target.value.trim() && S.settings.relay && document.hasFocus()) void saveRelay();
});
$("#relay-key").addEventListener("blur", (e) => {
  if (relayTimer) return void saveRelay(); // left before it saved: now
  if (keySaved) e.target.value = "";
  keySaved = false;
});

/** The relay's Check (relaymode.ts relayVerdict) of the ID and key in its fields, the answer beside the button. */
async function checkRelay(id = $("#relay-id").value, key = $("#relay-key").value) {
  const n = ++checks;
  const out = $("#relay-check-state");
  out.dataset.tone = "";
  out.textContent = t`Checking your relay…`;
  const v = await act("checkRelay", id, key).catch((err) => ({ tone: "error", text: why(err) }));
  if (n !== checks) return;
  out.dataset.tone = v.tone;
  out.textContent = tr(v.text);
}

$("#pw-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = $("#pw-input");
  void act("submitPassword", input.value);
  input.value = "";
});

$("#search").addEventListener("input", () => S && renderList());

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (S?.pw) return void act("cancelPassword");
    if (S?.trustAsk) return void act("dismissTrust");
    if ($("#wizard").classList.contains("on")) return closeWizard();
    if ($("#update-modal").classList.contains("on")) return $("#update-modal").classList.remove("on");
    if ($("#notes-modal").classList.contains("on")) return $("#notes-modal").classList.remove("on");
    if ($("#blocked-modal").classList.contains("on")) return $("#blocked-modal").classList.remove("on");
    if ($("#relay-modal").classList.contains("on")) return $("#relay-modal").classList.remove("on");
    if ($("#manual-modal").classList.contains("on")) return $("#manual-modal").classList.remove("on");
    if ($("#notice-modal").classList.contains("on")) return noticeClose();
    if ($("#wifi-modal").classList.contains("on")) return $("#wifi-modal").classList.remove("on");
    if ($("#tvsend-modal").classList.contains("on")) return tvSendClose();
    if ($("#take-modal").classList.contains("on")) return takeClose();
    if ($("#give-modal").classList.contains("on")) return giveClose();
    if ($("#tvwait-modal").classList.contains("on")) return tvModal(false);
    if ($("#unentitled-modal").classList.contains("on")) return $("#unentitled-modal").classList.remove("on");
    if ($("#logout-modal").classList.contains("on")) return $("#logout-modal").classList.remove("on");
    if ($("#add-modal").classList.contains("on")) return $("#add-modal").classList.remove("on");
    if ($("#low-modal").classList.contains("on")) return $("#low-modal").classList.remove("on");
    if (pickerOn()) return closePicker();
    if (openSheet) return closeSheet();
    if (document.activeElement === $("#search")) {
      $("#search").value = "";
      renderList();
    }
  }
  if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName ?? "")) {
    e.preventDefault();
    $("#search").focus();
  }
});

// The soft light on the panels, and the orb tilting toward the pointer
document.addEventListener("pointermove", (e) => {
  if (e.pointerType === "touch") return; // a finger scrolling isn't a pointer to follow
  for (const el of document.querySelectorAll(".spot")) {
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  }
  const o = $("#orb-wrap").getBoundingClientRect();
  const dx = (e.clientX - (o.left + o.width / 2)) / window.innerWidth;
  const dy = (e.clientY - (o.top + o.height / 2)) / window.innerHeight;
  $("#orb-wrap").style.setProperty("--tx", `${(dx * 14).toFixed(2)}deg`);
  $("#orb-wrap").style.setProperty("--ty", `${(-dy * 14).toFixed(2)}deg`);
});

// Out of focus, the backdrop holds still
window.addEventListener("blur", () => document.body.classList.add("idle"));
window.addEventListener("focus", () => document.body.classList.remove("idle"));

// ── Built once: the dial's ticks and the embers ────────────────────────────────────────────

{
  const ns = "http://www.w3.org/2000/svg";
  const ticks = $("#ticks");
  for (let i = 0; i < 72; i++) {
    const a = (i / 72) * 2 * Math.PI;
    const major = i % 6 === 0;
    const [r1, r2] = [major ? 128 : 132, 140];
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", String(150 + r1 * Math.sin(a)));
    line.setAttribute("y1", String(150 - r1 * Math.cos(a)));
    line.setAttribute("x2", String(150 + r2 * Math.sin(a)));
    line.setAttribute("y2", String(150 - r2 * Math.cos(a)));
    if (major) line.classList.add("major");
    line.style.setProperty("--i", String(i));
    ticks.append(line);
  }
  const embers = $("#embers");
  for (let i = 0; i < 26; i++) {
    const e = document.createElement("i");
    const rnd = (a, b) => a + Math.random() * (b - a);
    e.style.setProperty("--x", `${rnd(0, 100)}%`);
    e.style.setProperty("--s", `${rnd(1.5, 4).toFixed(1)}px`);
    e.style.setProperty("--t", `${rnd(14, 30).toFixed(1)}s`);
    e.style.setProperty("--d", `${-rnd(0, 30).toFixed(1)}s`);
    e.style.setProperty("--dx", `${rnd(-80, 80).toFixed(0)}px`);
    e.style.setProperty("--o", rnd(0.25, 0.8).toFixed(2));
    embers.append(e);
  }
  if (fh.platform === "darwin") document.body.classList.add("mac");
  if (PHONE) {
    document.body.classList.add("phone", fh.platform); // .ios: no whole-system mode (style.css)
    $("#blocked-later").textContent = t`OK`; // the blocked dialog's only button there: no relay on a phone (controller.js NO_RELAY)
    // Android's installer replaces the app (updater.js): it closes, the VPN with it
    $("#update-modal h2").textContent = t`The update is downloaded`;
    $("#update-modal p").textContent = PHONE_UPDATE;
    $("#up-restart").textContent = t`Install`;
    if (STILL) document.body.classList.add("still");
    // the page's own words, written for a computer
    const words = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (words.nextNode()) words.currentNode.nodeValue = words.currentNode.nodeValue.replaceAll(t`this computer`, t`this ${DEVICE}`);
  }
  $("#split-smart .flag").outerHTML = flag("IR");
}

// ── A TV's remote: its arrows move the focus to the nearest control that way, in the layer on top ────────

if (TV) {
  document.body.classList.add("tv");
  $("#mode").hidden = true; // a TV is whole-system only: nothing on it can be set to use a proxy (mobile/node/main.mjs)
  const CONTROLS = "button:not([disabled]), input, select, [data-use], .link";
  const LAYERS = ".modal.on, .overlay.on, .sheet.on, .locations.on";
  // the open dialog, sign-in screen or sheet that's highest (the last, of the same height), else the window
  const layer = () => [...document.querySelectorAll(LAYERS)].reduce((top, el) =>
    !top || +getComputedStyle(el).zIndex >= +getComputedStyle(top).zIndex ? el : top, null);
  // shown: closed sheets, dialogs and sign-in screens are hidden (style.css), the Locations panel beside the orb isn't
  // (WebView 111-120 know the options by their first names, checkOpacity and checkVisibilityCSS: without them, faded out counts as shown)
  const shown = (el) => el.checkVisibility({ opacityProperty: true, visibilityProperty: true, checkOpacity: true, checkVisibilityCSS: true }) && el.getClientRects().length > 0;
  // on screen, not scrolled out of its list nor covered; a list's rows out of view are reached from within it
  const inView = (el) => {
    const q = el.getBoundingClientRect();
    return el.contains(document.elementFromPoint((q.left + q.right) / 2, (q.top + q.bottom) / 2));
  };
  const scroller = (el) => {
    for (let p = el?.parentElement; p; p = p.parentElement) if (/auto|scroll/.test(getComputedStyle(p).overflowY)) return p;
    return null;
  };
  // A field the remote lands on is read-only: else Android's keyboard takes the arrows, and the remote is stuck in it
  // until Back. OK opens it for typing, and it's read-only again once the keyboard's gone (App.tsx) or it's left.
  const FIELD = 'input:not([type="checkbox"], [type="radio"], [type="range"])'; // one typed in
  let opening = null; // the field OK is opening
  const typing = (el, on) => {
    if (!el?.matches?.(FIELD) || el.dataset.tvKeys === undefined) return;
    if (!on) return void (el.readOnly = true);
    opening = el;
    el.blur(); // focused again, editable: the keyboard comes up
    el.readOnly = false;
    el.focus();
    opening = null;
  };
  window.foxholeKeyboard = (up) => up || typing(document.activeElement, false);
  document.addEventListener("focusout", (e) => typing(e.target, false));
  // Android's first focus (App.tsx) goes to the page's first control, not to the power button
  for (const type of ["keydown", "pointerdown"]) document.addEventListener(type, () => (remoteUsed = true), true);
  document.addEventListener("focusin", () => remoteUsed || $("#orb").disabled || $("#orb").focus({ preventScroll: true }));
  // a field focused some other way (the page's own, as a search opens) is read-only too
  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (el.matches?.(FIELD) && el !== opening && !el.readOnly) (el.dataset.tvKeys = ""), (el.readOnly = true);
  });
  const focus = (el) => {
    if (!el.matches("button, input, select")) el.tabIndex = -1; // a row or link: focusable from here
    if (el.matches(FIELD) && !el.readOnly) (el.dataset.tvKeys = ""), (el.readOnly = true);
    el.focus({ preventScroll: true });
    el.scrollIntoView({ block: "nearest", inline: "nearest" });
  };
  const DIRS = { ArrowUp: [0, -1], ArrowDown: [0, 1], ArrowLeft: [-1, 0], ArrowRight: [1, 0] };
  document.addEventListener("keydown", (e) => {
    const at = document.activeElement;
    const d = DIRS[e.key];
    if (!d && e.key !== "Enter") return;
    // a field's caret moves left and right inside it, up to its ends
    if (at?.matches("input") && d?.[0] && (d[0] < 0 ? at.selectionStart > 0 : at.selectionEnd < at.value.length)) return;
    const top = layer();
    const all = [...(top ?? document).querySelectorAll(CONTROLS)].filter((el) => shown(el) && (inView(el) || (scroller(el) && scroller(el) === scroller(at))));
    // nothing focused here yet (the WebView's own first focus can be behind what's on top): the first press lands here
    if (!all.includes(at)) {
      if (!all.length) return;
      e.preventDefault();
      return focus(all.find((el) => el.matches("#orb, .primary")) ?? all[0]);
    }
    // OK on a field opens it for typing (once open, it keeps Enter: its form's sent); else OK clicks, not left to the
    // WebView, which clicks only on a key's character
    if (!d && at.matches(FIELD) && at.readOnly && at.dataset.tvKeys !== undefined) return e.preventDefault(), typing(at, true);
    if (!d) return !at.matches("input, select") && (e.preventDefault(), at.click());
    e.preventDefault();
    // the nearest the way pressed: the gap along it, then (twice as costly) across it
    const r = at.getBoundingClientRect();
    let best = null, bestCost = Infinity;
    for (const el of all) {
      if (el === at) continue;
      const q = el.getBoundingClientRect();
      const ahead = d[0] * (q.left + q.right - r.left - r.right) + d[1] * (q.top + q.bottom - r.top - r.bottom);
      const gap = d[0] ? (d[0] > 0 ? q.left - r.right : r.left - q.right) : (d[1] > 0 ? q.top - r.bottom : r.top - q.bottom);
      // not that way: its middle not past this one's, or (unless one holds the other: a row's button) overlapping it
      if (ahead <= 1 || (gap < -8 && !at.contains(el) && !el.contains(at))) continue;
      const across = d[0] ? Math.max(0, q.top - r.bottom, r.top - q.bottom) : Math.max(0, q.left - r.right, r.left - q.right);
      const cost = Math.max(0, gap) + 2 * across + ahead / 100;
      if (cost < bestCost) (best = el), (bestCost = cost);
    }
    if (best) focus(best);
  });
}

let blockedSeen = 0; // the controller's count of times vpn.mozilla.org was found blocked, as far as the window said so
/** Says vpn.mozilla.org is blocked here, offering the relay's setup, each time the controller finds it anew. */
function sayBlocked() {
  if (S.blocked > blockedSeen && !S.settings.relay) $("#blocked-modal").classList.add("on");
  blockedSeen = S.blocked;
}
fh.onState((state) => {
  S = localize(state);
  syncLang();
  render();
  sayBlocked();
});
void act("state").then((state) => {
  S ??= localize(state);
  syncLang();
  render();
  sayBlocked();
});
