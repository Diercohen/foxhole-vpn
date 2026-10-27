// The window: draws the state the main process sends (controller.js state()) and asks it for actions.
const fh = window.foxhole;
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const NO_FLAGS = fh.platform === "win32"; // Windows draws no flag emoji, just two letters
const emoji = (code) => String.fromCodePoint(...[...code].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
const flag = (code) => (NO_FLAGS || code.length !== 2 ? `<span class="flag code">${esc(code)}</span>` : `<span class="flag">${emoji(code)}</span>`);
const flagText = (code) => (NO_FLAGS || code.length !== 2 ? "" : `${emoji(code)} `);
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
  renderHeader();
  renderHero(ph);
  renderCards();
  renderList();
  renderToast(ph);
  renderSplit();
  renderSettings();
  renderPassword();
  renderOnboard();
  $("#restoring").classList.toggle("on", S.restoring);
}

// ── Header ─────────────────────────────────────────────────────────────────────────────────

function renderHeader() {
  section("head", [S.email, S.usage, S.update, S.version], () => {
    const u = S.usage;
    $("#ver").textContent = `v${S.version}`;
    $("#about-ver").textContent = S.version;
    for (const el of [$("#acct-avatar"), $("#acct-avatar-2")]) el.textContent = (S.email ?? "?")[0].toUpperCase();
    $("#acct-name").textContent = S.email ?? "Firefox account";
    $("#acct-email").textContent = S.email ?? "unknown";
    $("#data-v").textContent = !u ? "—" : u.unlimited ? "Unlimited" : `${u.left} left`;
    $("#data-chip").title = !u ? "Data left this month: not known yet" : u.unlimited ? "Unlimited data" : `${u.left} of ${u.max} left this month${u.reset ? ` · resets ${u.reset}` : ""}`;
    $("#data-ring").style.strokeDashoffset = String(CIRCUMFERENCE * (1 - (!u ? 0 : u.unlimited ? 1 : u.fraction)));
    // The titlebar speaks up once there's something to do: restart into the downloaded version, or (where Foxhole
    // can't replace itself) download it. Until then a download runs quietly; Settings shows how far it got.
    const up = S.update;
    const pill = $("#update");
    pill.hidden = !up || (up.auto && !up.ready);
    pill.title = !up ? "" : up.ready ? `Foxhole ${up.version} is downloaded: restart to switch to it, or it goes in when you quit` : `Foxhole ${up.version} is out`;
    $("#update span").textContent = up?.ready ? "Restart to update" : `Update ${up?.version ?? ""}`;
    $("#about-update").innerHTML = !up
      ? "Firefox's free VPN for your whole system. Unofficial, not affiliated with Mozilla."
      : up.ready
        ? `Version ${esc(up.version)} is ready: it goes in when Foxhole restarts or quits. <span class="link" id="get-update">Restart now</span>`
        : up.auto
          ? `Downloading version ${esc(up.version)} in the background${up.progress === null ? "" : ` · ${up.progress}%`}…`
          : `Version ${esc(up.version)} is out. <span class="link" id="get-update">Download it</span>`;
  });
}

// ── The orb and what's under it ────────────────────────────────────────────────────────────

function renderHero(ph) {
  const c = country(S.connecting ?? S.global ?? S.active ?? S.selected);
  const where = c ? `${flagText(c.code)}${c.name}` : "";
  let title, sub, label;
  if (S.restoring) [title, sub, label] = ["Restoring…", "Putting your routes and DNS back", "Wait"];
  else if (ph === "busy") [title, sub, label] = [S.connecting ? "Connecting…" : "Working…", S.message?.text ?? "", "Wait"];
  else if (ph === "global") [title, sub, label] = ["Fully protected", `${where} · all of this computer's traffic`, "Disconnect"];
  else if (ph === "on") [title, sub, label] = ["Connected", `${where} · apps set to use the proxy`, "Disconnect"];
  else [title, sub, label] = ["Not connected", c ? `Tap to connect · ${where}` : "Pick a location to connect", "Connect"];
  const t = $("#status-title");
  if (t.textContent !== title) {
    t.textContent = title;
    replay(t, "swap");
  }
  $("#status-sub").textContent = sub;
  $("#orb-label").textContent = label;
  $("#orb").setAttribute("aria-label", label);
  $("#orb").disabled = ph === "busy" || S.auth.stage !== "ready";
  const mode = $("#mode");
  mode.dataset.v = S.globalOn ? "1" : "0";
  for (const b of mode.querySelectorAll("button")) b.setAttribute("aria-pressed", String((b.dataset.mode === "global") === S.globalOn));
  mode.classList.toggle("disabled", ph === "busy" || S.auth.stage !== "ready");
}

function renderCards() {
  section("cards", [S.net, S.netChecking, S.ip, S.ipChecking, S.ipNote, S.proxy, S.splitSummary, S.globalOn, S.lanIp], () => {
    const fill = (id, v, s, cls = "") => {
      $(`${id} .v`).className = `v ${cls}`;
      $(`${id} .v`).innerHTML = v;
      $(`${id} .s`).innerHTML = s;
    };
    const skel = '<span class="skel"></span>';
    if (S.netChecking) fill("#c-net", skel, '<span class="skel short"></span>');
    else fill("#c-net", esc(S.net ?? "offline"), S.lanIp ? `LAN ${esc(S.lanIp)}` : "no local address", S.net ? "" : "warn");
    $("#c-net use").setAttribute("href", S.net && !S.net.startsWith("Wi-Fi") ? "#i-plug" : "#i-wifi");
    if (S.ipChecking) fill("#c-ip", skel, '<span class="skel short"></span>');
    else fill("#c-ip", esc(S.ip ?? "unreachable"), esc(S.ip ? S.ipNote : "the IP check didn't answer"), S.ip ? "" : "warn");
    const p = S.proxy;
    fill("#c-proxy", p ? esc(p.addr) : "—", p ? `SOCKS5 + HTTP${p.shared ? " · shared" : ""}` : "SOCKS5 + HTTP, once connected", p ? "" : "dim");
    $("#copy-proxy").hidden = !p;
    const split = S.splitSummary;
    fill("#c-split", esc(split ?? "Off"), split ? (S.globalOn ? "for the whole system" : "for the proxy") : "everything through the VPN", split ? "" : "dim");
  });
}

// ── Locations ──────────────────────────────────────────────────────────────────────────────

let listShown = false; // the rows rise in once, on the first fill

function renderList() {
  const q = $("#search").value.trim().toLowerCase();
  section("list", [S.countries, S.active, S.connecting, S.listError, q, S.auth.stage === "ready"], () => {
    const list = $("#list");
    const shown = S.countries.filter((c) => !q || c.name.toLowerCase().includes(q) || c.code.toLowerCase() === q);
    $("#loc-count").textContent = S.countries.length ? `${S.countries.length} countries` : "";
    if (S.listError) {
      list.innerHTML = `<div class="empty"><b>Couldn't load the locations</b>${esc(S.listError)}<br><button class="btn" data-act="reloadList">${icon("refresh")}Try again</button></div>`;
      return;
    }
    if (!S.countries.length) {
      list.innerHTML = Array.from({ length: 7 }, () => `<div class="row skeleton"><span class="flag"></span><span><span class="skel"></span></span><span></span><span></span></div>`).join("");
      return;
    }
    if (!shown.length) {
      list.innerHTML = `<div class="empty"><b>No country matches “${esc(q)}”</b>Try a name like Germany, or a code like DE.</div>`;
      return;
    }
    const rise = !listShown;
    listShown = true;
    list.innerHTML = shown
      .map((c, i) => {
        const cls = [c.code === S.active && "active", c.code === S.connecting && "connecting", !c.available && !c.locked && "off", rise && "rise"].filter(Boolean).join(" ");
        const tiers = !c.available && !c.locked
          ? '<span class="tier none">no servers</span>'
          : c.locked ? '<span class="tier paid">paid</span><span class="tier free">free</span>' : '<span class="tier free">free</span>';
        return `<button class="row ${cls}" data-code="${esc(c.code)}" style="--i:${i}" title="${c.code === S.active ? "Connected" : `Connect to ${esc(c.name)}`}">
          ${flag(c.code)}<span><div class="nm">${esc(c.name)}</div><div class="cd">${esc(c.code)}</div></span>
          <span class="tiers">${tiers}</span><span class="state-dot"></span></button>`;
      })
      .join("");
  });
  reveal();
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

function renderToast(ph) {
  section("toast", [S.message?.id, ph === "busy"], () => {
    const t = $("#toast");
    const m = S.message;
    clearTimeout(toastTimer);
    if (!m || ph === "busy") return void t.classList.remove("on");
    t.dataset.tone = m.tone;
    t.title = m.text;
    $("#toast-text").textContent = m.text;
    replay(t, "on");
    if (m.tone === "ok" || m.tone === "info") toastTimer = setTimeout(() => t.classList.remove("on"), 6000);
  });
}

// ── Split tunneling ────────────────────────────────────────────────────────────────────────

let knownRules = null; // the rules last drawn: a new one pops in

function renderSplit() {
  section("split", [S.split.default, S.split.rules, S.splitNote], () => {
    const sp = S.split;
    $("#split-default").dataset.v = sp.default === "vpn" ? "0" : "1";
    $("#split-default-hint").innerHTML =
      (sp.default === "vpn" ? "Sites not listed use the <b>VPN</b>: list the ones to bypass it." : "Sites not listed go <b>direct</b>: list the ones that need the VPN.") +
      (sp.defaultHits ? ` · ${sp.defaultHits} matched` : "");
    $("#split-new-hint").innerHTML = `A new site goes <b>${sp.default === "vpn" ? "direct" : "through the VPN"}</b>: the other way from the rest.`;
    const note = $("#split-note");
    note.dataset.tone = S.splitNote?.tone ?? "";
    note.textContent = S.splitNote?.text ?? "";
    $("#split-suggest").hidden = !!sp.rules.length || sp.default !== "vpn";
    $("#split-count").textContent = sp.rules.length ? `(${sp.rules.length})` : "";
    const before = knownRules;
    knownRules = new Set(sp.rules.map((r) => r.match));
    $("#split-rules").innerHTML = sp.rules.length
      ? sp.rules
          .map((r) => `<div class="rule${before && !before.has(r.match) ? " fresh" : ""}" data-match="${esc(r.match)}">
            <span class="m" title="${esc(r.match)}">${esc(r.match)}</span>
            <span class="hits">${r.hits ? `${r.hits} matched` : ""}</span>
            <button class="via ${r.via}" data-toggle title="Switch between VPN and direct">${r.via === "vpn" ? "VPN" : "Direct"}</button>
            <button class="mini" data-remove title="Remove">${icon("trash")}</button></div>`)
          .join("")
      : `<div class="empty"><b>No sites yet</b>Everything goes ${sp.default === "vpn" ? "through the VPN" : "direct"}.</div>`;
  });
  // the counts climb as sites load: just the numbers, the rows stay put
  for (const r of S.split.rules) {
    const el = document.querySelector(`.rule[data-match="${CSS.escape(r.match)}"] .hits`);
    if (el) el.textContent = r.hits ? `${r.hits} matched` : "";
  }
  section("recent", [S.split.recent, $("#split-input").value], drawRecent);
}

function drawRecent() {
  const typed = $("#split-input").value.trim().toLowerCase();
  const found = S.split.recent.filter((s) => s.includes(typed)).slice(0, 10);
  $("#split-recent").innerHTML = found.length
    ? `<span class="k">Seen lately</span>${found.map((s) => `<button type="button" class="chip-btn" data-site="${esc(s)}">${esc(s)}</button>`).join("")}`
    : "";
}

// ── Settings ───────────────────────────────────────────────────────────────────────────────

function renderSettings() {
  section("settings", [S.settings.share, S.settings.port, S.settings.username, S.settings.password, S.lanIp, S.fwHint], () => {
    const s = S.settings;
    const share = $("#share");
    share.classList.toggle("on", s.share);
    share.setAttribute("aria-checked", String(s.share));
    $("#share-hint").textContent = s.share ? "Other devices on this Wi-Fi can use the VPN through this computer." : "Only this computer can use the proxy.";
    const addr = `${S.lanIp ?? "this computer's IP"}:${s.port}`;
    $("#share-box").innerHTML = s.share
      ? `<div class="hint">Set your phone's Wi-Fi proxy to</div>
         <div class="addr"><span class="mono">${esc(addr)}</span><button class="mini" data-copy="${esc(addr)}" title="Copy">${icon("copy")}</button></div>
         ${s.username || s.password ? '<div class="hint">Devices sign in with the username and password below.</div>' : '<div class="warn-line">No password: anyone on this network can use it. Set one below.</div>'}
         ${S.fwHint ? `<div class="hint">If they can't connect, open the port in the firewall:</div>${S.fwHint.map((c) => `<div class="cmd"><span class="mono">${esc(c)}</span><button class="mini" data-copy="${esc(c)}" title="Copy">${icon("copy")}</button></div>`).join("")}` : ""}`
      : '<div class="hint">Turn on to use the VPN from your phone, on the same Wi-Fi.</div>';
    // typed values stay until saved; a change from elsewhere (a save) shows here
    if (document.activeElement !== $("#port")) $("#port").value = String(s.port);
    if (document.activeElement !== $("#username")) $("#username").value = s.username;
    if (document.activeElement !== $("#password")) $("#password").value = s.password;
  });
  const note = $("#settings-note");
  note.dataset.tone = S.settingsNote?.tone ?? "";
  note.textContent = S.settingsNote?.text ?? "";
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
    $("#pw-ok").innerHTML = S.pw.checking ? '<span class="spin"></span><span>Checking…</span>' : "<span>Go whole system</span>";
    $("#pw-ok").disabled = S.pw.checking;
    const note = $("#pw-note");
    note.dataset.tone = "error";
    note.textContent = S.pw.error ?? "";
    if (S.pw.error && wasOpen) replay($("#pw-form"), "shake");
    if (!S.pw.checking) setTimeout(() => input.focus(), wasOpen ? 0 : 250);
  });
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
  section("onboard", [a], () => {
    $("#onboard").classList.toggle("on", a.stage !== "ready");
    $("#onboard").classList.toggle("wait", a.stage === "checking"); // shown only if the check takes a while
    $("#onboard-box").classList.toggle("wide", a.stage === "console");
    if (a.stage === "ready") return;
    const fox = '<svg class="fox-hero"><use href="#fox"/></svg>';
    const err = a.error ? `<div class="err-box">${esc(a.error)}</div>` : "";
    const wait = (text) => `<div class="waiting"><span class="spin"></span>${text}</div>`;
    const mac = fh.platform === "darwin";
    $("#onboard-box").innerHTML = {
      checking: () => `${fox}<h2>Waking up the fox…</h2><p>Getting the VPN token from your Firefox login.</p>${wait("One moment")}`,
      signin: () => `${fox}<h2>Sign in to Firefox</h2>
        <p>Foxhole uses Firefox's built-in VPN, so the <b>Firefox browser</b> must be signed in to your Mozilla account: inside the browser, not on a website.</p>
        ${err}
        <ol class="steps">
          <li><span>Firefox is opening its <b>Sync</b> settings: click <b>Sign in</b> there. Didn't open? In Firefox: menu <b>☰</b> → <b>Sign in</b>.</span></li>
          <li><span><b>Sync is optional</b>: Foxhole only needs the sign-in, so you can turn off everything on the <b>Choose what to sync</b> screen.</span></li>
        </ol>
        <div class="buttons"><button class="btn primary" data-act="openFirefox">${icon("external")}Open Firefox sign-in</button><button class="btn" data-open="firefox">Get Firefox</button></div>
        ${wait("Waiting for Firefox to sign in…")}`,
      console: () => `<div class="ok-line">${icon("check")}You are signed in to Firefox${a.email ? ` (${esc(a.email)})` : ""}</div>
        ${err}<h2>Let's grab a token from Firefox</h2>
        <div class="cols">
          <ol class="steps">
            <li><span>In Firefox open <kbd>about:config</kbd> and set <kbd>devtools.chrome.enabled</kbd> to <b>true</b> (first time only).</span></li>
            <li><span>Open the <b>Browser Console</b>: <kbd>${mac ? "⌘ ⇧ J" : "Ctrl+Shift+J"}</kbd> (the Browser Console, not the page's web console).</span></li>
            <li><span>Paste the snippet (<b>it's already in your clipboard</b>) and press <b>Enter</b>.</span></li>
          </ol>
          <div class="snippet"><pre>${highlight(a.snippet)}</pre><button class="btn" data-act="copySnippet" data-copied>${icon("copy")}Copy</button></div>
        </div>
        ${wait("Waiting for the token from Firefox…")}
        <p class="fine">The token comes back over localhost only and is saved, readable only by you, for next time.</p>`,
      switch: () => `${fox}<h2>Switch account</h2>
        <p>In Firefox's <b>Sync</b> settings click <b>Sign out</b>, then sign in with the other account. Foxhole carries on once it sees the new one.</p>
        <div class="buttons"><button class="btn primary" data-act="openFirefox">${icon("external")}Open Firefox's Sync settings</button>${a.email ? `<button class="btn" data-act="keepAccount">Keep ${esc(a.email)}</button>` : ""}</div>
        ${wait("Waiting for the other account…")}`,
    }[a.stage]();
  });
}

// ── Sheets ─────────────────────────────────────────────────────────────────────────────────

let openSheet = null;

function showSheet(name) {
  for (const el of document.querySelectorAll(".sheet")) el.classList.toggle("on", el.id === `sheet-${name}`);
  openSheet = name;
  $("#scrim").classList.add("on");
  if (name === "settings") act("openSettings");
  if (name === "split") act("openSplit");
  if (name === "logs") void act("logs").then((lines) => ((logBuf = lines.slice(-1000)), drawLogs(true)));
}

function closeSheet() {
  for (const el of document.querySelectorAll(".sheet")) el.classList.remove("on");
  openSheet = null;
  if (!S?.pw) $("#scrim").classList.remove("on");
}

// ── Logs ───────────────────────────────────────────────────────────────────────────────────

let logBuf = [];
const logLine = (l) => `<div class="ln"><time>${esc(l.slice(0, 8))}</time>${esc(l.slice(10))}</div>`;

function drawLogs(all, added = []) {
  const box = $("#logs");
  const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  if (all) box.innerHTML = logBuf.length ? logBuf.map(logLine).join("") : '<div class="empty"><b>Nothing logged yet</b>Proxy failures (e.g. ports the VPN refuses) and tun2socks output in whole-system mode appear here.</div>';
  else {
    box.querySelector(".empty")?.remove();
    box.insertAdjacentHTML("beforeend", added.map(logLine).join(""));
    while (box.childElementCount > 1000) box.firstElementChild.remove();
  }
  $("#logs-count").textContent = `${logBuf.length} line${logBuf.length === 1 ? "" : "s"} · proxy failures and tun2socks output, live`;
  if (all || atEnd) box.scrollTop = box.scrollHeight;
}

fh.onLog((lines) => {
  logBuf.push(...lines);
  if (logBuf.length > 1000) logBuf.splice(0, logBuf.length - 1000);
  if (openSheet === "logs") drawLogs(false, lines);
});

// ── Events ─────────────────────────────────────────────────────────────────────────────────

document.addEventListener("click", async (e) => {
  const t = e.target.closest("button, .link, #toast");
  if (!t || !S) return;
  if (t.id === "toast") return t.classList.remove("on");
  if (t.dataset.act) {
    if (t.hasAttribute("data-copied")) flash(t, `${icon("check")}Copied`);
    return act(t.dataset.act);
  }
  if (t.dataset.open) return fh.open(t.dataset.open);
  if (t.dataset.copy) {
    act("copy", t.dataset.copy);
    return flash(t, icon("check"));
  }
  if (t.dataset.code) return act("connect", t.dataset.code);
  if (t.dataset.mode) return (t.dataset.mode === "global") !== S.globalOn && act("toggleGlobal");
  if (t.dataset.via) return act("setSplitDefault", t.dataset.via);
  if (t.dataset.site) return act("addRule", t.dataset.site);
  if (t.hasAttribute("data-close")) return closeSheet();
  const rule = t.closest(".rule")?.dataset.match;
  if (rule && t.hasAttribute("data-toggle")) return act("toggleRule", rule);
  if (rule && t.hasAttribute("data-remove")) {
    t.closest(".rule").classList.add("leaving");
    return setTimeout(() => act("removeRule", rule), 260);
  }
  switch (t.id) {
    case "orb": {
      const shock = document.createElement("i");
      shock.className = "shock";
      $("#orb-wrap").append(shock);
      shock.addEventListener("animationend", () => shock.remove());
      return act("power");
    }
    case "copy-proxy":
      act("copy", S.proxy?.addr ?? "");
      return flash(t, icon("check"));
    case "c-split": return showSheet("split");
    case "open-settings": case "account": return showSheet("settings");
    case "open-logs": return showSheet("logs");
    case "copy-logs": return (await act("copyLogs")) && flash(t, `${icon("check")}Copied`);
    case "share": return act("setShare", !S.settings.share);
    case "reveal": {
      const pw = $("#password");
      pw.type = pw.type === "password" ? "text" : "password";
      return;
    }
    case "switch-account":
      closeSheet();
      return act("switchAccount");
    case "open-repo": return fh.open("repo");
    case "update": case "get-update":
      if (!S.update?.ready) return fh.open("releases");
      $("#update span").textContent = "Restarting…";
      return act("restartToUpdate");
    case "add-ir": return act("addRule", "*.ir");
    case "pw-cancel": return act("cancelPassword");
  }
});

$("#scrim").addEventListener("click", () => (S?.pw ? act("cancelPassword") : closeSheet()));

$("#split-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#split-input");
  if (await act("addRule", input.value)) input.value = "";
  drawRecent();
});
$("#split-input").addEventListener("input", () => S && drawRecent());

$("#port-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  if (await act("setPort", Number($("#port").value))) flash(btn, `${icon("check")}Saved`);
});
$("#port").addEventListener("input", (e) => (e.target.value = e.target.value.replace(/\D/g, "")));

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button[type=submit]");
  if (await act("setLogin", $("#username").value, $("#password").value)) flash(btn, `${icon("check")}Saved`);
});

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
  $("#split-suggest .flag").outerHTML = flag("IR");
}

fh.onState((state) => {
  S = state;
  render();
});
void act("state").then((state) => {
  S ??= state;
  render();
});
