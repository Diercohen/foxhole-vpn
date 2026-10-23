# How foxhole-vpn gets a VPN token: `FirefoxAuth` in `src/auth.ts`

Guardian (`guardian.ts`) wants an FxA OAuth **access token** with the scopes in
`VPN_SCOPES` (`profile https://identity.mozilla.com/apps/vpn`), sent as
`Authorization: Bearer <token>`. foxhole-vpn mints one from your Firefox login,
the same way Firefox does for its own VPN.

## 1. The session token

Firefox keeps its account login in `signedInUser.json` in the profile
(`profile.ts` finds the profile in use). `accountData.sessionToken` is 32 bytes
in hex. It never leaves your computer: only keys derived from it are used.

## 2. The request

```
POST https://api.accounts.firefox.com/v1/oauth/token
Content-Type: application/json
Authorization: Hawk id="…", ts="…", nonce="…", hash="…", mac="…"

{
  "client_id": "5882386c6d801776",            // Firefox desktop's public FxA client id
  "grant_type": "fxa-credentials",
  "scope": "profile https://identity.mozilla.com/apps/vpn",
  "ttl": 86400                                // a day, as Firefox asks for
}
```

The answer's `access_token` (a JWT) is the token; `expires_in` says how long it lasts.

## 3. Signing it with the session token

The request is signed with [HAWK](https://github.com/mozilla/hawk), using
credentials derived by FxA's [onepw](https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol)
scheme (`sessionCredentials`):

- `HKDF-SHA256(sessionToken, salt = empty, info = "identity.mozilla.com/picl/v1/sessionToken", 64 bytes)`
- the first 32 bytes, in hex, are the HAWK `id` (the token id);
- the last 32 bytes are the HMAC key.

`test/auth.test.mjs` checks this against the onepw spec's test vector.

## Behavior

- The token stays in memory, is never logged or written to disk, and is reused
  until 5 minutes before it expires, then renewed.
- If the computer's clock is off, FxA answers errno 111 with its own time and
  the request is retried once on that time.
- errno 110 means Firefox's login is no longer valid: sign in to Firefox again
  (`foxhole login`).
- If minting fails at startup, foxhole-vpn falls back to a token saved from the
  Browser Console window (`tokenserver.ts`), then to showing that window.

## Checking it

```
npm run build && node dist/cli.js doctor
```

`doctor` shows `Token source : Firefox login` and your remaining data (e.g.
`40.9 GB of 50 GB`). If you see that, the whole chain (login → token →
Guardian → quota) works.
