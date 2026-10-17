# escapedfox 🦊

Use **Firefox's built-in VPN** (the free "IP Protection" / Mozilla VPN proxy
baked into Firefox) from your whole system — not just the browser — via a small
terminal app. Node.js, zero runtime dependencies.

> Unofficial. Not affiliated with Mozilla. Routing all your system traffic
> through Firefox's VPN is probably outside Mozilla's intended use; your account
> and its monthly data cap are your responsibility.

## How it works

Firefox's VPN is an authenticated HTTP `CONNECT` proxy on Fastly servers.
escapedfox:

1. reads your Firefox Account login from your local Firefox profile,
2. exchanges it for a short-lived **proxy pass** from Mozilla's Guardian API,
3. runs a local **SOCKS5 proxy** that tunnels through the Fastly server, and
4. (optionally) routes the whole system through that proxy.

## Status

| Piece | State |
|---|---|
| Country list (free vs paid) | ✅ working |
| Remaining-data / usage | ✅ working (needs token) |
| Local SOCKS5 proxy | ✅ working + tested |
| Firefox login detection / open | ✅ working |
| Interactive TUI | ✅ working |
| Whole-system (TUN) routing | ✅ built + unit-tested (needs sudo; untested live) |
| **FxA token exchange** | ⛔ **not implemented — see [AUTH.md](AUTH.md)** |

The token exchange (step 2's auth) is a single ~30-line function left as a
documented stub. Everything else is complete and works the moment it returns a
token. See [AUTH.md](AUTH.md) for why and exactly what it must do.

## Usage

```sh
npm install && npm run build

node dist/cli.js                     # interactive TUI (default)
node dist/cli.js countries           # list countries (no login needed)
node dist/cli.js login               # open Firefox to sign in
node dist/cli.js usage               # remaining data this month
node dist/cli.js doctor              # check login, server list, entitlement
node dist/cli.js proxy --country US  # local SOCKS5 proxy through the US
sudo -E node dist/cli.js global --country US   # route the whole system
```

In the **TUI**, pick a country and press **`g`** to route the whole system
through it — escapedfox asks for your sudo password in-app (no need to launch
the whole app with `sudo`), and `g` again turns it back off. Only the networking
is elevated; the proxy and your Firefox login stay unprivileged.

Point a single app at the proxy:

```sh
export ALL_PROXY=socks5://127.0.0.1:1080
```

`global` mode sends everything through the VPN: it runs a local proxy, obtains
`tun2socks` (see below), creates a `escapedfox0` TUN device, routes the default
through it (pinning the VPN server's own IP to the real uplink), forces DNS over
TCP, and restores all of it on Ctrl+C.

**Getting tun2socks** — escapedfox finds it automatically, in this order:
1. `tun2socks` already on your `PATH`, `~/go/bin`, or `~/.cache/escapedfox`;
2. else it **downloads the prebuilt binary from GitHub releases** (no Go, no
   Google servers — works behind the Go-proxy block);
3. else it builds via `go install` using the `goproxy.cn` mirror.

If all three are blocked, grab the binary yourself from
<https://github.com/xjasonlyu/tun2socks/releases> and drop it on your `PATH`.

### Testing before the token exchange is implemented

Until `AUTH.md` is filled in, you can supply a VPN access token yourself to
exercise the entire proxy / TUI / global stack:

```sh
export ESCAPEDFOX_ACCESS_TOKEN=<an FxA access token with the VPN scope>
node dist/cli.js doctor   # should print entitlement + remaining data
```

When set, every command uses that token instead of the Firefox session.
(`FOXHOLE_ACCESS_TOKEN` is still accepted as an alias.)

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

## Test

```sh
npm test   # builds, then runs the SOCKS5 bridge integration test
```
