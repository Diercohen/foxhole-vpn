# Android's native UI: the plan

**Status (2026-11-20):** planned, not started. The open decisions are at the end.

Today the Android app (phones and Android TV) shows the desktop app's window (`gui/renderer`) in a WebView, inside
React Native (`mobile/App.tsx`). This plan replaces both with native Kotlin screens (Jetpack Compose) that look and
behave as the window does on Android now, keeps the core as it is, and removes the iOS app.

## Where it ends up

- **Native screens:** every screen, on phones and TVs, is drawn by Compose.
- **The core doesn't change:** Node runs `mobile/node/main.mjs` over the desktop Controller (`gui/controller.js`), on
  the same lines of JSON.
- **Gone:** React Native, the WebView window and the iOS app.
- **One WebView stays:** Mozilla's sign-in page, which is Mozilla's own website.
- **Already native, left untouched:**
  - the VPN service (`FoxholeService`), the Quick Settings tile and the widget
  - the calculator disguise, the notification and the APK updater
  - `Phone.kt`'s 15 commands

## The core's lines (unchanged)

`Core.kt` holds the socket pair to Node. `Phone.kt` answers the lines with `"t":"ask"`. Everything else goes to the UI:
through `FoxholeModule.kt` today, straight to the Kotlin client after this.

- **To the UI:**
  - `state`: the whole state, at most every 50 ms, and each second while the app is on screen.
  - `log`: batches of log lines.
  - `reply`: an action's answer or error, by its id.
  - `signIn`: open Mozilla's page. With `open: false`, close it.
- **From the UI:**
  - `act`: `id`, `name` and `args`, where `name` is one of the 59 in `ACTIONS`.
  - `ui`: whether the app is on screen, sent from `FoxholeActivity`'s `onResume` and `onPause`.
  - From the sign-in page: `signedIn`, `signInDone` and `signInClosed`.
- **The app's own, never sent to the core:**
  - `open`: the links in `App.tsx`'s `LINKS`, pages of the repo, and Telegram's `tg://socks` link to this phone's proxy.
  - Back with nothing open, which sends the app to the background.

`mobile/www/phone.js` is today's client of these lines, in JavaScript. The Kotlin client does the same.

## Design

1. **A Kotlin client for `Core.kt`.**
   - It keeps the latest state and the log, and has `act(name, args)`, which waits for its `reply`.
   - The state is read with `org.json`, as `Core.kt` and `Phone.kt` do, into immutable classes. Compose then redraws
     only what changed, which is what `section()` does in `app.js`.
2. **One set of translations.**
   - `gui/renderer/fa.js` and `ru.js` stay the only ones, keyed by the English. `prepare.mjs` writes them into the
     app's assets as JSON.
   - A Kotlin port of `foxholeWords` (`t`) and of `app.js`'s `tr()` and `localize()` reads them. It covers:
     - the window's words
     - the core's English messages, with their `{}` patterns
     - country names, falling back to Java's `Locale` names
     - dates, in Persian by Iran's calendar, using `android.icu` (which nodejs-mobile lacks)
   - Words with markup in them (bold, or a link or a pill button inside a sentence) keep their keys. A small parser
     turns them into styled, tappable text.
   - `gui/i18n.test.mjs` also reads the Kotlin's `t("…")` keys.
3. **Its own look, no Material.**
   - Compose's foundation, with a few components of our own: pill button, switch, segmented control, card, sheet,
     dialog, and an inline pill.
   - Colors and sizes come from `style.css`'s Android look, which already has no blur and no 3D fox.
   - The background and the orb's dial, ripples and embers are drawn on a Canvas, with the animations the window shows
     on Android.
   - Fonts: TTF builds of Golos Text and Vazirmatn, since Android can't read the window's `.woff2`.
   - A script in `mobile/scripts/` converts `index.html`'s 43 icons and `gui/renderer/flags/`' 34 flags to vector
     drawables. Re-run it when they change.
4. **The platform's own parts.**
   - Edge-to-edge, with room for the system bars and the keyboard.
   - Back closes the top sheet or dialog, as `foxholeBack` does in `phone.js`. With nothing open, the app goes to the
     background.
   - The `foxhole://tv?l=…` link that a TV's QR code opens.
   - Notification permission, asked on the first connect.
   - On a TV, Compose's own D-pad focus, starting on the power button. It replaces the remote's code at the end of
     `app.js`.
5. **QR codes.**
   - Drawn from the path the core sends (`qr.size`, `qr.path`).
   - Scanned in *Sign in a TV or phone* with CameraX and ZXing. Unlike the window's `BarcodeDetector`, they don't need
     Google Play.
6. **Mozilla's sign-in, sturdier.**
   - A WebView in a full-screen dialog, with `App.tsx`'s Firefox user agent, sign-in URL, `FXA_CHANNEL` and allowed
     hosts.
   - Today `App.tsx` injects the channel's script as a page starts loading (which can still be the page before), and
     again once it has loaded. With androidx.webkit it runs at document start, before the page's own scripts.
   - Messages are taken only from `https://accounts.firefox.com`.
   - Cookies and storage are wiped before each sign-in. That's safe, since it's the app's only WebView.
   - On a WebView too old for Mozilla's page, the screen says to update it, and offers *Sign in from another device*.

## Screens to build, and where they are in the window

| Screen | In the window (`index.html` ids, `app.js` functions) |
|---|---|
| Home | `.bg`, `.titlebar` (`renderHeader`), `.hero` (`renderHero`; the dial's ticks and the embers are built near the end of `app.js`), `#mode`, `.cards` (`renderCards`), `#toast` (`renderToast`) |
| Sign-in | `#onboard` (`renderOnboard`: its `phone` and `tv` stages, then the shared ones), `#tvwait-modal` (`tvPanel`, `tvModal`), Mozilla's page (`SignIn` in `App.tsx`) |
| Locations | `#sheet-locations` (`renderList`), `#relay-modal`, `#blocked-modal` (`sayBlocked`) |
| Split tunneling | `#sheet-split` (`renderSplit`), `#apps-modal` (`openPicker`) |
| Shield | `#sheet-shield` (`renderShield`) |
| Settings | `#sheet-settings` (`renderSettings`, `renderNet`, `renderDisguise`, `renderTrust`, `renderAccounts`), `#wifi-modal` (`askWifi`), `#trust-modal`, `#relaywait-modal` (`relayPanel`, `relayWait`), `#tvsend-modal` (`tvSendOpen`), `#add-modal`, `#logout-modal` |
| Data, Logs | `#sheet-data`, `#sheet-logs` |
| Other dialogs | `#notes-modal` (`showNotes`, `noteBlock`), `#update-modal` (`startUpdate`), `#offline-modal` (`renderOffline`), `#unentitled-modal` (`renderEntitled`), `#low-modal`, `#notice-modal` (`renderNotice`), `#relaytest-modal` (`renderRelayTest`), `renderNews`, `renderSwitched` |

Where phones and TVs differ:
- In `app.js`, the `PHONE` and `TV` branches. They hold the update dialog's `PHONE_UPDATE`, the blocked dialog's steps,
  and "this computer" said as "this phone".
- In `index.html`, the `.android-only`, `.not-tv` and `.tv-only` parts.

Not built, since Android doesn't show them:
- **Computers only:** the relay setup wizard, the administrator password, install by hand, start at login, restoring
  networking, and Smart DNS.
- **Hidden everywhere** (`SHARE_FOXHOLE = false`): Share Foxhole and Import settings, with the `foxhole://settings` link.
  They get built when they're turned on.

## Phases

The work happens on a branch, `native-ui`. Until the last phase, the Compose UI is a second activity in the same app,
beside today's window, started with `adb shell am start`. Releases from main don't change.

A stand-in core puts both in the same state, so each screen can be checked against today's window side by side on the
same emulator.
- It's a `controller.js` that sends fixed states, switched over a local port, and never shipped.
- The states include signed out, connecting, connected, whole system, relay, no internet, low data and update ready.
- On the TV emulator, which has no root, it's built into a test APK.

| # | What | Checked on |
|---|---|---|
| 0 | Compose in Gradle; the Kotlin client; the translations, with one test of `tr`; colors, fonts, icons, flags; the stand-in core; the VPN consent and Location answers (in `FoxholeActivity` today) for the new activity too | phone |
| 1 | Home: header (update pill, data ring, account), background, orb with its dial and embers, status, mode switch, the five cards, toast (a tap opens the Logs at its line) | all three |
| 2 | Sign-in screens and Mozilla's sign-in page; the TV's QR code and code | phone; Android 9 (WebView 66); TV |
| 3 | Locations (search, list, relay row); the Relay and Blocked dialogs | phone, TV |
| 4 | Split tunneling, the app picker, the site check | phone, TV |
| 5 | Shield: YouTube ads, block lists, custom rules | phone, TV |
| 6 | Settings: language (live, right to left for Persian), the network rule and the Wi-Fi's name, sharing, port, login, disguise, relay (get, check, send, remove), certificate, accounts, *Sign in a TV or phone*, About | all three |
| 7 | Data and Logs | phone, Android 9 |
| 8 | The other dialogs (update and its notes, offline, Firefox VPN not turned on, low data, notices, relay test, sign out); the remote on every screen | all three; the update end to end |
| 9 | The switch-over release (below) | all three, then a real Android 9 phone |

The emulators:
- phone: `foxhole-test` (Android 15)
- Android 9: `foxhole-p` (stock WebView 66)
- TV: `foxhole-tv` (Android TV 12, WebView 91)
- all three: each of them

How testing changes:
- `uiautomator dump` sees the native screens, where it saw nothing inside the WebView. Checks go by text, content
  description, or test tags shown as resource ids.
- Screenshots come from `adb exec-out screencap`.
- Speed is judged on release builds only, since debug Compose is much slower.

## The switch-over release

- **The launcher activity:** `FoxholeActivity` itself becomes the Compose activity, so the `MainActivity` alias (home
  screen icons, disguise mode) stays as it is.
- **React Native goes:**
  - `App.tsx`, `index.js`, `specs/`, `babel.config.js`, `metro.config.js` and `tsconfig.json`.
  - Its packages in `mobile/package.json`, and its Gradle plugin (`build.gradle`, `settings.gradle`).
  - `FoxholeModule.kt`, the React host in `MainApplication.kt`, and `www/phone.js`.
  - The "Update your WebView" screen.
  - `prepare.mjs`'s copy of the window. It copies the words and `img/firefox-vpn.png` instead.
- **iOS goes:**
  - `mobile/ios/`, `native/nodejs-mobile-ios*`, `prepare.mjs`'s iOS branch and the `build-ios` script.
  - The iOS parts of `main.mjs` and of `main.test.mjs`: `fetch` over `node:http` for a Node without WebAssembly, and
    the certificate served to Safari.
  - The iOS checks in `gui/controller.js` (`NO_RELAY`, `APPS`), `src/accounts.ts` and `src/proxy.ts`.
  - The README's lines about the iOS app. The ones about iPhones using Smart DNS or the proxy stay.
  - A version bump no longer touches `mobile/ios/…/project.pbxproj`.
- **R8 on for release builds:** APK size, cold start and memory are measured on Android 9, before and after.
- **CI and the README:** `.github/workflows/release.yml`'s Android job no longer installs React Native. The README's
  Building section says what the app is made of now.
- **Afterwards, in a commit of its own,** the desktop window drops what only phones and TVs used:
  - `PHONE`, `TV`, `IOS` and `STILL` in `app.js`
  - the `.phone`, `.android` and `.tv` rules in `style.css`
  - the remote's code, and `fox3d.js`'s phone check

  `i18n.test.mjs` then shows the words no one uses anymore.

## Risks

- **Two windows:** from the switch on, every change to what Android shows has to be made in Kotlin too.
- **Mozilla's page on old WebViews** (66 on stock Android 9, 91 on the TV emulator): unknown until phase 2. Signing in
  from another device is the way around it.
- **Text fields on a TV:** the window keeps them read-only until OK, so the keyboard doesn't trap the remote. This gets
  tried early, on the Locations search (phase 3).
- **Speed on old phones:** judged on release builds only. Endless animations stop while the app isn't on screen.
- **Google's Maven** (Compose, CameraX) isn't reachable from every network, so the first Gradle sync may need the VPN.

## Open decisions (defaults until decided)

1. **The in-app QR scanner:** **kept** (CameraX + ZXing), or dropped, since a phone's camera app already opens Foxhole
   from a TV's QR code.
2. **Window changes that Android shows, made during the rewrite:** **made in both**, or paused until the switch.
3. **Where the work happens:** **a branch**, or main with the Compose activity in debug builds only.

The size: about 6,000 to 9,000 lines of Kotlin, over ten phases. Nothing reaches users before phase 9.
