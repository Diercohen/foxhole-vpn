# The one unimplemented piece: `FirefoxAuth.#exchangeForVpnToken`

`src/auth.ts` can read your Firefox session token but does **not** turn it into a
VPN access token. That single function is the only thing between foxhole and a
working connection. This document is its spec.

## Contract

```ts
#exchangeForVpnToken(sessionToken: string /* hex */): Promise<string /* access_token */>
```

- **Input:** the hex `sessionToken` from `signedInUser.json` (already loaded).
- **Output:** an FxA OAuth **access token** string whose scope is
  `VPN_SCOPES` (`profile https://identity.mozilla.com/apps/vpn`).
- `guardian.ts` sends that token as `Authorization: Bearer <token>`.

## The HTTP call (public FxA OAuth)

Firefox performs an FxA **`fxa-credentials`** OAuth grant:

```
POST https://api.accounts.firefox.com/v1/oauth/token
Content-Type: application/json
Authorization: <session-token auth, see below>

{
  "client_id": "5882386c6d801776",            // Firefox desktop's public FxA client id
  "grant_type": "fxa-credentials",
  "scope": "profile https://identity.mozilla.com/apps/vpn",
  "ttl": 300
}
```

The response contains `{ "access_token": "..." }` — that is the return value.

## Authenticating the request with the session token

The POST is authenticated **by the session token**, not a password. There are
two accepted modes; implement whichever you prefer:

1. **Typed Bearer** (Firefox ≥ ~155, simplest): derive the token id and send
   `Authorization: Bearer fxs_<tokenId>`. No request signing.
2. **Legacy HAWK**: sign the request with HAWK credentials derived from the
   session token.

Both derive their key material from the session token using Mozilla's
**onepw / "picl"** key-derivation scheme (an HKDF with a fixed context string).
That derivation is documented here — do not guess it, follow the spec:

- onepw protocol (key derivation, `KW`/context strings):
  <https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol>
- FxA OAuth, `fxa-credentials` grant & PKCE:
  <https://mozilla.github.io/ecosystem-platform/reference/oauth-details>
- Typed Bearer token scheme (`fxs_`, `fxk_` prefixes):
  <https://mozilla.github.io/ecosystem-platform/reference/tokens>

Node has everything needed in `node:crypto` (`hkdf`, `createHmac`) — **no new
dependency**. Keep the token in memory only; never log it or write it to disk.

## Verifying it works

Once implemented:

```
npm run build && node dist/cli.js doctor
```

`doctor` prints your remaining data (e.g. `31.2 / 50 GB, resets Nov 1`). If you
see that, the whole chain (login → token → Guardian → quota) works.
