# foxhole-vpn 🦊

Use **Firefox's built-in VPN** (the free "IP Protection" / Mozilla VPN proxy
baked into Firefox) from your whole system — not just the browser — via a small
terminal app. Node.js, zero runtime dependencies.

> Unofficial. Not affiliated with Mozilla. Routing all your system traffic
> through Firefox's VPN is probably outside Mozilla's intended use; your account
> and its monthly data cap are your responsibility.

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
| **FxA token exchange** | ⛔ **not implemented — see [AUTH.md](AUTH.md)** |

The token exchange (step 2's auth) is a single ~30-line function left as a
documented stub. Everything else is complete and works the moment it returns a
token. See [AUTH.md](AUTH.md) for why and exactly what it must do.

## Usage

```sh
npm install -g foxhole-vpn

foxhole                     # interactive TUI (default)
foxhole countries           # list countries (no login needed)
foxhole login               # open Firefox to sign in
foxhole usage               # remaining data this month
foxhole doctor              # check login, server list, entitlement
foxhole proxy --country US  # local SOCKS5 + HTTP proxy through the US
sudo -E foxhole global --country US   # route the whole system
foxhole --verbose                  # also show per-connection errors and tun2socks logs
```

On **Windows**, run `foxhole global` (or `foxhole` and press **`g`**) in an
elevated terminal — **Terminal (Admin)** — instead of using `sudo`. If a global
session is ever killed without restoring networking, `foxhole restore` (also
elevated) removes what it left behind.

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
3. Open the **Browser Console** (⌘⇧J on macOS, Ctrl+Shift+J on Linux and Windows — not the
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
- Non-web ports may be refused by the VPN (e.g. Google's `:5228` push) — that's
  the VPN's policy and doesn't affect normal browsing.
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

## Test

```sh
npm test   # builds, then runs the SOCKS5 bridge integration test
```

The proxy and DNS tests generate a certificate with `openssl`; on Windows, Git
for Windows ships one (add its `bin` folder to `PATH`). In an elevated Windows
terminal, `node test/win32-live.mjs` checks global mode end to end — no VPN
token needed — and verifies everything is restored afterwards.
