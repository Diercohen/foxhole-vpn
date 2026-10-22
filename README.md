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

The token exchange (step 2's auth) is a single ~30-line function left as a
documented stub. Everything else is complete and works the moment it returns a
token. See [AUTH.md](AUTH.md) for why and exactly what it must do.

## Usage

```sh
npm install -g foxhole-vpn

foxhole                     # interactive TUI (default)
foxhole countries           # list countries (no login needed)
foxhole login               # sign in to the Firefox browser (sync optional)
foxhole usage               # remaining data this month
foxhole doctor              # check login, server list, entitlement
foxhole proxy --country US  # local SOCKS5 + HTTP proxy through the US
sudo -E env "PATH=$PATH" foxhole global --country US   # route the whole system
foxhole --verbose                  # also show per-connection errors and tun2socks logs
```

On **Windows**, run `foxhole global` (or `foxhole` and press **`g`**) in an
elevated terminal — **Terminal (Admin)** — instead of using `sudo`. If a global
session is ever killed without restoring networking, `foxhole restore` (also
elevated) removes what it left behind.
On **Linux** the same `foxhole restore` (it asks for your password) undoes a
killed global session that left the computer offline.

`foxhole-vpn` works too, as an alias. From a checkout: `npm install && npm run build`,
then `node dist/cli.js` in place of `foxhole`.

In the **TUI**, pick a country and press **`g`** to route the whole system
through it — foxhole-vpn asks for your sudo password in-app (no need to launch
the whole app with `sudo`), and `g` again turns it back off. Only the networking
is elevated; the proxy and your Firefox login stay unprivileged.

Press **`l`** for **Logs**: a popup with proxy failures (e.g. ports the VPN
refuses) and tun2socks output, updating live; **Esc** closes it. Logs are
collected in every session, not only with `--verbose`.

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

Until the token exchange in `AUTH.md` is implemented, foxhole-vpn needs a VPN
access token from Firefox. You only do this once per token:

1. Run `foxhole` (or `foxhole proxy` / `foxhole global`) in a terminal. With no
   usable token it opens a window with the steps and a ready-made snippet.
2. In Firefox, set `devtools.chrome.enabled` to `true` in `about:config`.
3. Open the **Browser Console** (⌘ ⇧ J on macOS, Ctrl+Shift+J on Linux and Windows — not the
   page's web console), paste the snippet and press Enter.

The snippet sends the token back to foxhole-vpn, which saves it to
`~/.config/foxhole-vpn/token` (readable only by you, mode 0600) and uses it on
every later run, so you don't repeat the steps.

The token lasts about a day. On each start foxhole-vpn checks it; if it has
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
over the saved token. If it has expired, the window tells you to unset it.

```sh
export FOXHOLE_ACCESS_TOKEN=<an FxA access token with the VPN scope>
foxhole doctor   # should print entitlement + remaining data
```

Free-tier countries: 🇺🇸 US · 🇩🇪 DE · 🇯🇵 JP · 🇦🇺 AU · 🇦🇷 AR · 🇿🇦 ZA.

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
