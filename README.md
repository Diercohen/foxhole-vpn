# foxhole-vpn 🦊 — Firefox's free VPN for your whole system

[![npm version](https://img.shields.io/npm/v/foxhole-vpn)](https://www.npmjs.com/package/foxhole-vpn)
[![npm downloads](https://img.shields.io/npm/dm/foxhole-vpn)](https://www.npmjs.com/package/foxhole-vpn)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Node.js >= 18.18](https://img.shields.io/badge/node-%3E%3D18.18-brightgreen)](https://nodejs.org)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

Use **Firefox's built-in VPN** (the free "IP Protection" / Mozilla VPN proxy
baked into Firefox) from your whole system, not just the browser, via a small
terminal app. It gives you a **local SOCKS5 + HTTP proxy** and optional
**system-wide VPN routing (TUN)** on **Linux, macOS and Windows**. Node.js, zero
runtime dependencies.

```sh
npm install -g foxhole-vpn && foxhole
```

On **Ubuntu 24.04** the system's own Node.js is enough:
`sudo apt install nodejs npm`, then `sudo npm install -g foxhole-vpn`.
Ubuntu 22.04's is too old; `sudo snap install node --classic` gives a current one.
Rather not install it? Run it [in a sandbox (Docker)](#in-a-sandbox-docker), or
use the [desktop app](#desktop-app), which needs no Node.js at all.

> Unofficial. Not affiliated with Mozilla. Routing all your system traffic
> through Firefox's VPN is probably outside Mozilla's intended use; your account
> and its monthly data cap are your responsibility.

## Features

- 🌍 **Free VPN servers** from Firefox's IP Protection: US, Germany, Japan,
  Australia, Argentina, South Africa
- 🧦 **SOCKS5 and HTTP proxy on one port** for any app (curl, git, Chrome, Telegram…)
- 🛡️ **System-wide VPN mode** through a TUN device, with **DNS over HTTPS**
  inside the tunnel (no DNS leaks) and IPv6/QUIC leak protection
- 🖥️ **Interactive terminal UI (TUI)**: pick a country, toggle global routing, view live logs
- 📊 **Remaining data / monthly usage** and a `doctor` command for diagnostics
- 🐧🍎🪟 Works on **Linux, macOS and Windows**

## How it works

Firefox's VPN is an authenticated HTTP `CONNECT` proxy on Fastly servers.
foxhole-vpn:

1. reads your Firefox Account login from your local Firefox profile,
2. exchanges it for a short-lived **proxy pass** from Mozilla's Guardian API,
3. runs a local **SOCKS5 + HTTP proxy** (one port) that tunnels through the Fastly server, and
4. (optionally) routes the whole system through that proxy.

## Status

| Piece | State |
|---|---|
| Country list (free vs paid) | ✅ working |
| Remaining-data / usage | ✅ working (needs token) |
| Local SOCKS5 + HTTP proxy | ✅ working + tested |
| Firefox login detection / open | ✅ working |
| Interactive TUI | ✅ working |
| Whole-system (TUN) routing | ✅ built + unit-tested (needs sudo; untested live) |

Step 2's VPN token comes straight from your Firefox login: foxhole-vpn signs
FxA's OAuth token request with the session Firefox keeps in your profile, as
Firefox does for its own VPN. See [AUTH.md](AUTH.md) for how.

## Desktop app

The same foxhole-vpn in a window (`gui/`, Electron): the countries, a power
button with a 3D fox on it that shows how you're connected (asleep, searching,
watching your pointer, or glowing in a ring of stars), **Whole system** mode (it asks for your password, or Touch ID, in the
app, as the TUI does), split tunneling, settings, sharing with your phone and
the logs. It carries its own Node.js, so whoever downloads it installs nothing
else. It keeps its settings, saved token and last country where the TUI does
(`~/.config/foxhole-vpn`); don't run both at once, as they'd want the same port.

Download it from the [latest release](https://github.com/Diercohen/foxhole-vpn/releases/latest):

- **Mac:** `Foxhole-<version>-arm64.dmg` if it has an Apple chip (M1 or later;
  **Apple menu → About This Mac**), `Foxhole-<version>-x64.dmg` if it's an Intel
  Mac. Either needs macOS 13 or later.
- **Windows:** the `.exe` installer.
- **Linux:** the `.deb` (Ubuntu, Debian) or the `.AppImage`.

The builds aren't signed by Apple or Microsoft: macOS asks you to allow the app
once (**System Settings → Privacy & Security → Open Anyway**), and Windows
SmartScreen once (**More info → Run anyway**). On Windows, whole-system mode
asks for administrator rights in Windows' own prompt as it turns on: allow
**Windows PowerShell**, which starts Foxhole's networking helper (the app itself
needs no **Run as administrator**). On Linux, prefer the
`.deb`: Ubuntu 24.04 and later keep Electron AppImages from starting unless they
get `--no-sandbox`.

Its tray icon (in the menu bar, on macOS) shows whether you're connected, and
where, and connects, disconnects, switches location or turns whole-system mode
on without the window. Closing the window leaves Foxhole running there: quit it
from the tray (or ⌘Q), which first puts the routes and DNS back if whole-system
mode is on. The app's icon shows the state too, as the tray's does: an amber
dot while it connects, mint with a plug on the proxy, pink with a screen in
whole-system mode. It's on the Dock's icon on macOS, and on the window's (the
taskbar's) on Windows and Linux. Pinned to the Windows taskbar, Foxhole gets
Windows' own overlay badge instead; docks that always draw the installed app's
icon (Ubuntu's) don't show it.

It keeps itself up to date. A minute after it starts, then every 6 hours, it
looks for a newer release on GitHub, and an orange **Update** button appears at
the top right. Click it: the button fills as it downloads the file for your
system (through the VPN once connected; a broken-off download carries on where
it stopped), installs it, and asks to restart into the new version:

- **macOS**: the disk image for your Mac's chip, checked (its signature and
  version), swapped in on the restart, or the next time Foxhole quits. That
  needs Foxhole in a folder it can write to, such as Applications.
- **Windows**: the installer, run silently once Foxhole has quit and put the
  network back, then the new version starts.
- **Linux**: an AppImage replaces itself (in a folder it can write to); the
  `.deb` installs at once, after the system asks for your password.

The downloaded file stays in your **Downloads** folder until the new version
runs. If the update doesn't go in by itself, Foxhole says so and offers it to
install by hand: **Quit & install** quits Foxhole (putting the network back
first), then opens it. A copy that can't update itself (opened straight from
the disk image, Linux on Arm) links to the download instead.

To build it from a checkout (Node.js 22.12 or newer, for Electron's installer):

```sh
npm install                  # the core's TypeScript toolchain
cd gui && npm install        # Electron and electron-builder
npm start                    # run it from here
npm run dist                 # an installer for this OS in gui/release: .dmg, .exe (NSIS), .deb and .AppImage
```

Where GitHub is slow or blocked, `ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/`
in front of those commands fetches Electron from a mirror. `npm run dist` fetches
Electron (about 130 MB for each architecture) again on every build: on a slow
connection, keep the zips it needs (`electron-v44.7.0-darwin-arm64.zip` and so on)
in a folder and build with `npx electron-builder -c.electronDist=<that folder>`.

To publish a version, push a tag: `git tag v0.5.2 && git push origin v0.5.2`.
GitHub then builds the Mac, Windows and Linux apps, versioned after the tag
(`.github/workflows/release.yml`), and puts them in a draft release. Check it on
the Releases page and click **Publish release**: everyone can download it from
there, and installed apps offer it within 6 hours. Your own builds work
too: `gh release create v0.5.2 gui/release/*.dmg`. A release without the disk
images (the CLI's alone) changes nothing for the Mac app.

## In a sandbox (Docker)

To run foxhole-vpn without installing it or Node on your computer, run it in a
container. Of your files it sees only your Firefox login (`signedInUser.json`,
read-only), not the rest of your Firefox profile (passwords, cookies, history)
or your home folder, plus a volume for its own settings. You need Docker. Build
the image once. Docker fetches this repository from GitHub itself, so there's
nothing to clone (add `#` and a branch, tag or commit to the URL to build that
one, as in `foxhole-vpn.git#main`; in a clone, use `.` in place of the URL to
build your copy):

```sh
docker build -t foxhole-sandbox -f sandbox/Dockerfile https://github.com/Diercohen/foxhole-vpn.git
```

Sign in to the Firefox browser on your computer first: the container can't open
Firefox for you. Then run it one of two ways, below. In both, the first line
finds your Firefox login (the most recently changed profile that's signed in),
and options after the image name go to foxhole: `foxhole-sandbox doctor`,
`foxhole-sandbox global --country US`.

**Global mode and split tunneling for your whole computer** (Linux): foxhole
runs in your computer's own network, so global mode's tun, its routes, DNS and
its IPv6 and UDP blocks go on your computer, as they do outside Docker, and the
TUI's **`g`** and **`t`** work as described under [Usage](#usage) (`g` asks for
no password: foxhole is root in the container).

```sh
f=$(find ~/.mozilla ~/.config/mozilla ~/snap/firefox/common/.mozilla ~/.var/app/org.mozilla.firefox/.mozilla -name signedInUser.json -exec grep -q sessionToken {} ';' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-) &&
docker run -it --rm --init --network host --cap-add NET_ADMIN --device /dev/net/tun \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "${f:?sign in to Firefox first}:/root/.mozilla/firefox/sandbox.default/signedInUser.json:ro" \
  -v foxhole-config:/root/.config/foxhole-vpn \
  foxhole-sandbox
```

- `--network host` puts foxhole in your computer's network, `--cap-add NET_ADMIN`
  and `/dev/net/tun` let it create the tun and change routes and firewall rules
  there (no `--privileged`: it gets no other devices and no disks). The D-Bus
  socket lets it point your computer's systemd-resolved at its DNS-over-HTTPS
  relay, so lookups stay in the tunnel. It's required: without it, global mode
  can't set your computer's DNS, and lookups fail.
- That D-Bus socket, as root, can also ask your computer's system services
  (systemd among them) to do things, which comes close to root on your computer.
  So in this mode the sandbox spares you installing foxhole and runs the
  published code, but it isn't a security boundary. If that matters to you, use
  proxy only, below.
- It needs Docker Engine (`docker` itself) with systemd-resolved on the computer
  (Ubuntu, Fedora, Arch with resolved…). Docker Desktop (on macOS and Windows,
  and Docker Desktop for Linux) keeps containers in a VM of its own, so global
  mode there would route that VM, not your computer. Rootless Docker and Podman
  can't change your computer's routes either.
- The container shares your computer's ports: if foxhole is already running on
  your computer, stop it, or pick another port (**`s`** for Settings in the TUI,
  or `--port 1081`).
- Quitting the TUI, Ctrl+C or `docker stop` restore your networking. If the
  container is killed (`docker kill`, a crash), your computer stays online, but
  IPv6 is still blocked and some routes and rules are left: run the same command
  with `restore` after the image name to remove them.

**Proxy only** (Linux, macOS, Windows): the safest way, with no access to your
computer's networking. The proxy is on `127.0.0.1:1080` as usual (SOCKS5 and
HTTP); only apps you point at it use the VPN. Global mode (**`g`**) doesn't work
in this one: it needs the command above.

```sh
f=$(find ~/.mozilla ~/.config/mozilla ~/snap/firefox/common/.mozilla ~/.var/app/org.mozilla.firefox/.mozilla -name signedInUser.json -exec grep -q sessionToken {} ';' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-) &&
docker run -it --rm --init -p 127.0.0.1:1080:1080 \
  -v "${f:?sign in to Firefox first}:/root/.mozilla/firefox/sandbox.default/signedInUser.json:ro" \
  -v foxhole-config:/root/.config/foxhole-vpn \
  foxhole-sandbox proxy --host 0.0.0.0
```

That `f=` line is for Linux. On macOS, the login is under
`~/Library/Application Support/Firefox/Profiles/*/signedInUser.json`; on Windows,
under `%APPDATA%\Mozilla\Firefox\Profiles\*\signedInUser.json`. Put that file's
path in place of `${f:?…}`. `--host 0.0.0.0` is needed: inside the container,
the proxy must listen where Docker's published port reaches it; the `-p
127.0.0.1:…` keeps it on your computer only.

For either way:

- Where Docker Hub refuses (Iran), take the base image from a mirror:
  `docker build --build-arg BASE=registry.docker.ir/library/node:22-bookworm-slim -t foxhole-sandbox -f sandbox/Dockerfile https://github.com/Diercohen/foxhole-vpn.git`
- If you sign in to Firefox again while it runs, restart the container: it keeps
  seeing the login file it started with.
- Updating from inside doesn't last, since each run starts fresh from the image:
  run the build command again instead, for the latest foxhole-vpn and tun2socks.
- To remove everything: `docker rmi foxhole-sandbox` and `docker volume rm foxhole-config`.

## Usage

```sh
npm install -g foxhole-vpn

foxhole                     # interactive TUI (default)
foxhole countries           # list countries (no login needed)
foxhole login               # sign in to the Firefox browser (sync optional)
foxhole usage               # remaining data this month
foxhole doctor              # check login, server list, entitlement
foxhole proxy --country US  # local SOCKS5 + HTTP proxy through the US
sudo env "PATH=$PATH" foxhole global --country US   # route the whole system
foxhole --verbose                  # also show per-connection errors and tun2socks logs
```

On **Windows**, `foxhole` needs no elevated terminal: **`g`** asks for
administrator rights in Windows' own prompt (allow **Windows PowerShell**: it
starts foxhole's networking helper), and should foxhole be killed, that helper
restores networking. `foxhole global` runs in an elevated terminal —
**Terminal (Admin)** — instead of using `sudo`; if one is ever killed without
restoring networking, `foxhole restore` (also elevated) removes what it left behind.
On **Linux** a global session undoes itself even when foxhole is killed; should
the computer still be left offline, the same `foxhole restore` (it asks for your
password) removes what's left.

`foxhole-vpn` works too, as an alias. From a checkout: `npm install && npm run build`,
then `node dist/cli.js` in place of `foxhole`.

In the **TUI**, pick a country and press **`g`** to route the whole system
through it — foxhole-vpn asks for your sudo password in-app, or on Windows in
Windows' own prompt (no need to launch the whole app with `sudo`, or as
administrator), and `g` again turns it back off. Only the networking is
elevated; the proxy and your Firefox login stay unprivileged.

A fox at the top shows how you're connected: grey and asleep when
disconnected, busy while connecting, awake with a green dot on the proxy, and
glowing pink in global mode. In a window at least 103 columns wide, your
connection's details and the countries sit side by side, and the fox needs 27
rows; a narrower window stacks them, with the fox once it's 38 rows tall.

Press **`l`** for **Logs**: a popup with proxy failures (e.g. ports the VPN
refuses) and tun2socks output, updating live; **Esc** closes it. Logs are
collected in every session, not only with `--verbose`.

Press **`t`** for **Split tunneling**: pick the sites that skip the VPN, or the
only ones that use it. Add a site — `bbc.co.uk` (it covers its subdomains, as
`*.co.uk` would), `ir` (a whole top-level domain), `1.2.3.4` or `10.0.0.0/8`;
**Tab** fills in sites foxhole saw lately — and **Enter** flips it between VPN
and direct. **Enter** on *Everything else* flips the rest, turning the list into
the only sites the VPN carries. The most specific rule wins, so their order
doesn't matter, and each shows how many connections it took. It works the same
in proxy and global mode, and `foxhole proxy` and `foxhole global` follow the
same rules. Direct sites see your real IP.

Point a single app at the proxy. The same port speaks **SOCKS5 and HTTP**
(foxhole-vpn tells them apart by the first byte), so use whichever the app
supports:

```sh
export ALL_PROXY=socks5://127.0.0.1:1080                 # SOCKS5
export HTTPS_PROXY=http://127.0.0.1:1080 HTTP_PROXY=http://127.0.0.1:1080   # HTTP
```

The HTTP proxy carries `https://` sites through `CONNECT`, so they stay
end-to-end encrypted. You don't need an `https://` proxy address.

`global` mode sends everything through the VPN: it runs a local proxy, obtains
`tun2socks` (see below), creates a `foxhole0` TUN device, routes the default
through it (pinning the VPN server's own IP to the real uplink), forces DNS over
TCP, and restores all of it on Ctrl+C.

**Getting tun2socks** — foxhole-vpn finds it automatically, in this order:
1. `tun2socks` already on your `PATH`, `~/go/bin`, or `~/.cache/foxhole-vpn`;
2. else it **downloads the prebuilt binary from GitHub releases** (no Go, no
   Google servers — works behind the Go-proxy block);
3. else it builds via `go install` using the `goproxy.cn` mirror.

If all three are blocked, grab the binary yourself from
<https://github.com/xjasonlyu/tun2socks/releases> and drop it on your `PATH`.

### Getting a token

If you're signed in to the Firefox browser, there's nothing to do: on each
start foxhole-vpn gets a VPN access token from your Firefox login, keeps it in
memory only, and renews it before it expires (about a day). If you're signed
out, it opens Firefox's sign-in page and carries on as soon as you've signed in
(`foxhole login` does the same on its own).

If you're signed in but that still fails (e.g. the Firefox account server can't
be reached), foxhole-vpn falls back to getting a token through Firefox's
Browser Console. You only do this once per token:

1. Run `foxhole` (or `foxhole proxy` / `foxhole global`) in a terminal. With no
   usable token it opens a window with the steps, the reason in red, and a
   ready-made snippet.
2. In Firefox, set `devtools.chrome.enabled` to `true` in `about:config`.
3. Open the **Browser Console** (⌘ ⇧ J on macOS, Ctrl+Shift+J on Linux and Windows — not the
   page's web console), paste the snippet and press Enter.

The snippet sends the token back to foxhole-vpn, which saves it to
`~/.config/foxhole-vpn/token` (readable only by you, mode 0600) and uses it on
every later run, so you don't repeat the steps.

A token from the window lasts about a day. On each start foxhole-vpn checks it; if it has
expired or Mozilla rejects it, the window appears again with a red error and
the old token is deleted. If it's rejected while the TUI is running, the TUI
says so in red — quit and start `foxhole` again to get a new one.

**How the token gets back safely:** while the window is open, foxhole-vpn runs a
one-shot HTTP receiver on `127.0.0.1:47380` (a random port if that one is
busy). The snippet posts to a path containing a random 192-bit secret, and the
receiver sends no CORS headers, so web pages can't reach it. It accepts only a
well-formed, unexpired token with the VPN scope, never logs it, and shuts down
as soon as one arrives. If none arrives within 2 minutes, foxhole exits. Another program running as you on
the same machine could still read the terminal and use the secret.

**Using your own token instead:** set `FOXHOLE_ACCESS_TOKEN`. It takes priority
over the Firefox login and the saved token. If it has expired, the window tells you to unset it.

```sh
export FOXHOLE_ACCESS_TOKEN=<an FxA access token with the VPN scope>
foxhole doctor   # should print entitlement + remaining data
```

Free-tier countries: 🇺🇸 US · 🇩🇪 DE · 🇯🇵 JP · 🇦🇺 AU · 🇦🇷 AR · 🇿🇦 ZA.

### Where `vpn.mozilla.org` is blocked (e.g. Iran)

On some networks — Iranian IPs among them — `vpn.mozilla.org`, the control API
foxhole-vpn asks for a proxy pass, is blocked, while the Firefox account server
and the server list still work. foxhole shows `can't reach vpn.mozilla.org` and
can't connect, even though the VPN's own servers (on Fastly) are reachable.

For that case foxhole can relay **only those control calls** through a Google
Apps Script web app — [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN).
`script.google.com` is reachable where `vpn.mozilla.org` isn't; the script
fetches Guardian from Google's servers and returns the reply. It carries just
the small control calls (the pass, your remaining data, the entitlement), and
only when the direct connection fails — **never the VPN's traffic**, which flows
straight through the tunnel to Fastly as usual. So once you're connected, your
browsing never touches the relay. In whole-system mode the control calls, too,
go directly through the tunnel once it's up, so the relay is used only to get
the first connection.

Set it up with your **own** deployment (the script sees the short-lived,
VPN-scoped access token while it relays, so don't use someone else's). The
easy way: **Settings → VPN relay → Set up step by step**, in the terminal UI
(press `S`) or the desktop app. It makes your secret key, puts it into the
script for you to copy, shows each click with a screenshot, and saves the
Deployment ID you paste (or the whole web app URL) at the end.
The terminal UI shows the screenshots as real pictures in kitty, Ghostty,
iTerm2, WezTerm, foot, Konsole and Windows Terminal, and as colored blocks
elsewhere; `FOXHOLE_IMAGES=kitty`, `iterm`, `sixel` or `blocks` picks the kind
for a terminal it doesn't know.

By hand:

1. Create a project at <https://script.google.com>, paste in
   [`assets/relay/Code.gs`](assets/relay/Code.gs), and set `AUTH_KEY` to a long
   random secret of your own.
2. **Deploy → New deployment → Web app**, *Execute as: Me*, *Who has access:
   Anyone*. Copy the **Deployment ID**.
3. Give both to foxhole, by environment:

   ```sh
   export FOXHOLE_RELAY_ID=<the Deployment ID>
   export FOXHOLE_RELAY_KEY=<the same AUTH_KEY you set in Code.gs>
   foxhole doctor      # entitlement + data should now load through the relay
   ```

   or save them in `~/.config/foxhole-vpn/settings.json` (mode 0600; the
   environment wins and takes effect without a restart):

   ```json
   { "relay": { "deploymentId": "<Deployment ID>", "authKey": "<AUTH_KEY>" } }
   ```

The desktop app reads the same settings. Keep the auth key secret, and note
Apps Script's free quota (about 20,000 URL-fetch calls a day) — far more than
foxhole's occasional control calls need.

## Limits

- **TCP only.** The upstream is HTTP `CONNECT`; UDP/QUIC won't tunnel. Global
  mode rejects UDP into the tunnel (via iptables) so Chrome's QUIC/HTTP-3 falls
  back to TCP immediately instead of hanging; WebRTC and VoIP still won't work.
  IPv6 is blackholed so apps use IPv4 through the tunnel, not native IPv6.
- **DNS resolves through the tunnel (DoH).** The VPN refuses port-53 traffic, so
  global mode runs a local resolver that forwards every lookup as DNS-over-HTTPS
  over the proxy (port 443) and points systemd-resolved at it. Lookups stay
  inside the tunnel — not visible to, or blockable by, the local network. (On
  systems without systemd-resolved it falls back to pinning your resolvers to the
  real uplink, which *is* a DNS leak — a note is printed when that happens.)
- Non-web ports may be refused by the VPN (e.g. SSH's `:22`, Google's `:5228`
  push) — that's the VPN's policy and doesn't affect normal browsing. git over
  SSH to GitHub works anyway: foxhole-vpn sends it to `ssh.github.com:443`, which
  has the same host key.
- **Split tunneling** decides each connection by the site's name: the one an app
  asks the proxy for, or, when global mode's tun gives only an address, the name
  in its TLS hello or HTTP request, else foxhole's own DNS answers (Linux and
  Windows). A site with Encrypted Client Hello may then go by its address and
  the default. On Linux, direct sites are also looked up on the local network's
  DNS. **On macOS**, global mode sends direct sites around the tunnel by
  address: as foxhole's DNS looks one up, it routes the answer's addresses out
  the real network (macOS refuses to let a connection out any other way while
  the tunnel's routes are up). An address that a VPN site also uses stays in
  the tunnel, and a direct site an app reaches without foxhole's DNS (its own
  secure DNS, or an address cached from before global mode) uses the VPN.
- Conflicts with another active full-tunnel VPN — `global` refuses to start if it
  detects one (a VPN on the default route, or `0/1`+`128/1` split routes). Stop
  it first, or pass `--force`.
- **macOS:** global mode uses a `utun` device, `route` (0/1 + 128/1 split
  routes) and `networksetup` to point the uplink's DNS at a local DoH relay on
  `127.0.0.1:53`; all restored on exit. UDP isn't rejected there (no pf rules),
  so QUIC takes a moment longer to fall back to TCP.
- **Windows:** global mode uses a Wintun adapter (foxhole-vpn downloads
  `tun2socks.exe` and the checksum-verified `wintun.dll` into
  `%USERPROFILE%\.cache\foxhole-vpn`), `netsh` 0/1 + 128/1 split routes, an
  NRPT rule sending all DNS to a local DoH relay on `127.0.0.1:53`, and Windows
  Firewall rules blocking IPv6 and QUIC; all removed on exit (routes also vanish
  on reboot). With Windows Firewall off, IPv6 isn't blocked and a note says so.
  The token is saved to `%USERPROFILE%\.config\foxhole-vpn\token`.

## FAQ

**Is Firefox's VPN free?**
Firefox's built-in VPN (IP Protection) has a free tier with a monthly data cap
and a fixed set of countries. `foxhole countries` lists them; `foxhole usage`
shows how much data you have left.

**Can I use Firefox's VPN outside Firefox, e.g. in Chrome or the terminal?**
Yes, that is what foxhole-vpn is for. Run `foxhole proxy` and point any app at
`127.0.0.1:1080` (SOCKS5 or HTTP), or run `foxhole global` to send all system
traffic through it.

**Is this the same as Mozilla VPN?**
No. Mozilla VPN is a separate paid WireGuard product. foxhole-vpn uses the
proxy built into Firefox (IP Protection), which runs on Fastly servers.

**Does it leak DNS?**
In global mode, DNS goes through the tunnel as DNS over HTTPS. See [Limits](#limits)
for the one fallback case that does leak, and when it happens.

**Does UDP / gaming / WebRTC work?**
No. The VPN is an HTTP `CONNECT` proxy, so only TCP is carried.

## License

[MIT](LICENSE) © Dier Cohen
