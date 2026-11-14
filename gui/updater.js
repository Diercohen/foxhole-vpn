// New versions from GitHub's releases: looked for at launch (again a minute in if nothing turned up), then every 6 hours; the window's Update button
// downloads the one for this system, with its progress, and gets it ready to go in. Both go by ways.ts's ways: through
// Firefox VPN while it's on; else directly, then through Firefox VPN opened for it, then the relay; each when the one
// before can't (a download that breaks off, or is too slow, carries on by the next from where it stopped). Then:
// - macOS: the .dmg for this architecture, unpacked and checked, then swapped in for the app on the restart or quit;
// - Windows: the installer, run silently once the app has quit (and put its routes back) on "Restart now";
// - Linux, an AppImage: the new AppImage, put over the old file on the restart or quit;
// - Linux, the .deb: installed at once with pkexec dpkg (the system asks for the password);
// - Android (mobile/), the APK: checked by the app (this app, this version, its key), then given to Android's installer.
// The file goes to the user's Downloads and stays there until the new version runs, to install by hand if it doesn't
// go in by itself. The app's own folder keeps a mark of each (got-<version>): the Downloads folder is looked in only
// once the Update button is pressed (macOS asks the user for it the first time).
// A copy that can't update itself (run from the disk image, a development copy, Linux on Arm) links to the download.
import { execFile, spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, rmdirSync, statSync, statfsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { promisify } from "node:util";
import { download, get, httpError, throughWays, triedText } from "./dist/ways.js";
import { log } from "./dist/log.js";
import { newer, releaseNotes, VERSION } from "./dist/update.js";
import { REPO_URL } from "./dist/ui.js";

const exec = promisify(execFile);
// FOXHOLE_RELEASES: a server laid out like GitHub's releases, for testing
const RELEASES = process.env.FOXHOLE_RELEASES ?? `${REPO_URL}/releases`;
const SEMVER = /^\d+\.\d+\.\d+$/;

/** The latest release's version, from where /releases/latest redirects (GitHub's API allows few requests per IP, and NAT and VPN exits share one). `way`: ways.ts's. */
export async function latest(way) {
  const res = await get(`${RELEASES}/latest`, way);
  res.resume();
  return /\/releases\/tag\/v?(\d+\.\d+\.\d+)$/.exec(res.headers.location ?? "")?.[1] ?? null;
}

/** What's new in the releases after this one, up to `to`, from the releases' feed (update.ts releaseNotes). */
export async function notes(way, to) {
  const res = await get(`${RELEASES}.atom`, way);
  if (res.statusCode !== 200) {
    res.resume();
    throw httpError(res.statusCode);
  }
  let atom = "";
  res.setEncoding("utf8");
  for await (const c of res) atom += c;
  return releaseNotes(atom, VERSION, to);
}

/** Copies Foxhole.app out of the disk image to `app` once it checks out: intact, signed, this app and the version expected. */
async function unpack(dmg, app, bundle, version) {
  const mnt = mkdtempSync(join(tmpdir(), "foxhole-update-"));
  const tmp = `${app}.tmp`;
  try {
    await exec("hdiutil", ["attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mnt, dmg]); // checks the image's checksums
    try {
      rmSync(tmp, { recursive: true, force: true });
      await exec("ditto", [join(mnt, "Foxhole.app"), tmp]);
    } finally {
      await exec("hdiutil", ["detach", "-force", mnt]).catch(() => {});
    }
    const plist = (a, key) => exec("plutil", ["-extract", key, "raw", join(a, "Contents/Info.plist")]).then((r) => r.stdout.trim());
    if ((await plist(tmp, "CFBundleIdentifier")) !== (await plist(bundle, "CFBundleIdentifier"))) throw new Error("the download isn't Foxhole");
    if ((await plist(tmp, "CFBundleShortVersionString")) !== version) throw new Error(`the download isn't version ${version}`);
    await exec("codesign", ["--verify", "--deep", "--strict", tmp]); // every file as it was built: none cut short or changed
    renameSync(tmp, app);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    try {
      rmdirSync(mnt);
    } catch {} // still mounted: the system's temp cleanup gets it
  }
}

/** The release file for each kind of copy, as package.json's build section names them. */
export const ASSET = {
  mac: (v) => `Foxhole-${v}-${process.arch}.dmg`,
  win: (v) => `Foxhole-${v}-setup.exe`, // x64: Windows on Arm runs it too
  appimage: (v) => `Foxhole-${v}.AppImage`, // x64
  deb: (v) => `foxhole-desktop_${v}_amd64.deb`,
  apk: (v) => `phone-and-TV-android-foxhole-${v}.apk`, // every phone's and TV's (.github/workflows/release.yml)
};
// The names before: a release has its APK by this one too (release.yml), for Foxhole 1.0.0 to update itself, and a
// download by that one is cleared once its version is in
const LEGACY = { apk: (v) => `phone-and-TV-android-${v}.apk` };

/** The versions of this kind's file in `dir`: { version, name } for each complete one (not a .part). */
function downloaded(dir, kind) {
  const [pre, post] = ASSET[kind]("\0").split("\0");
  const out = [];
  try {
    for (const name of readdirSync(dir)) {
      const v = name.startsWith(pre) && name.endsWith(post) ? name.slice(pre.length, name.length - post.length) : "";
      if (SEMVER.test(v)) out.push({ version: v, name });
    }
  } catch {} // no Downloads folder
  return out;
}

export class Updater {
  #dir; // the app's own: the Mac's new app unpacked, the old one it replaced, the marks of downloads and of tries to install
  #downloads; // where the release file goes, and stays: to install by hand if it doesn't go in by itself
  // how this copy updates itself: { kind: "mac", bundle } | { kind: "win", exe } | { kind: "appimage", file } | { kind: "deb" }
  // | { kind: "apk", check(file, version), open(file) } (the phone's: promises);
  // null: it can't, and the window links to the download instead
  #target;
  #ways; // () => the ways to GitHub, in the order they're tried (ways.ts updateWays)
  #changed;
  #version = null; // a newer release
  #notes = null; // what's new in it (and any between), once GitHub's answered: update.ts Notes
  #phase = null; // null, "downloading" or "installing"
  #progress = null; // the download, in percent
  #via = null; // the way it's downloading by: "direct", "vpn" or "relay"
  #ready = null; // the new version, waiting to go in: the app (macOS) or the file (Windows, AppImage); true once installed (.deb)
  #error = null; // why the last try failed

  constructor({ dir, downloads, target, ways, changed }) {
    this.#dir = dir;
    this.#downloads = downloads;
    this.#target = target;
    this.#ways = ways;
    this.#changed = changed;
  }

  /** Clears what earlier updates left, then looks for a newer release (#schedule). */
  start() {
    mkdirSync(this.#dir, { recursive: true });
    // an update's leftovers: the app it replaced, and what's of versions no newer than this one (it's in: no longer needed)
    const done = (v) => SEMVER.test(v) && !newer(v, VERSION);
    const t = this.#target;
    const got = readdirSync(this.#dir).filter((f) => f.startsWith("got-")).map((f) => f.slice(4)).filter((v) => SEMVER.test(v));
    if (t) for (const v of got.filter(done)) for (const n of [ASSET[t.kind](v), LEGACY[t.kind]?.(v)].filter(Boolean)) for (const f of [n, `${n}.part`]) rmSync(join(this.#downloads, f), { force: true });
    for (const f of readdirSync(this.#dir)) if (f === "old.app" || done(f) || done(f.replace(/^(tried|got)-/, ""))) rmSync(join(this.#dir, f), { recursive: true, force: true });
    if (!t) return this.#schedule();
    // one downloaded before: ready at once (it goes in even on a quit before the first look), or installed by hand
    const waiting = got.filter((v) => !done(v)).sort((a, b) => (newer(a, b) ? -1 : 1))[0];
    if (waiting) {
      this.#version = waiting;
      this.#ready = t.kind === "mac" ? (existsSync(this.#readyPath(waiting)) ? this.#readyPath(waiting) : null) : t.kind === "deb" ? null : this.#readyPath(waiting);
      // it was put in at the last quit, yet this is still the old version: it didn't take (the mark holds why, if it knows)
      const mark = join(this.#dir, `tried-${waiting}`);
      if (existsSync(mark)) {
        const why = readFileSync(mark, "utf8").trim();
        this.#error = why ? `the last try failed: ${why}` : "the last try didn't take";
      }
    }
    this.#schedule();
  }

  // At once (by the ways there are yet: the account may not be signed in); if that found nothing (GitHub blocked, or no
  // answer yet), again a minute in, after the connect at launch, so through the VPN; then every 6 hours.
  #schedule() {
    const next = (ms) => setTimeout(() => void this.check().then(() => next(6 * 3600_000)), ms).unref();
    void this.check().then(() => next(this.#version ? 6 * 3600_000 : 60_000));
  }

  /** The downloaded release file of version v; the new app unpacked from it on a Mac. */
  #file = (v) => join(this.#downloads, ASSET[this.#target.kind](v));
  #readyPath(v) {
    return this.#target.kind === "mac" ? join(this.#dir, v, "Foxhole.app") : this.#file(v);
  }

  /** The downloaded file, kept to install by hand: its path while it's there, else null. */
  file() {
    const v = this.#version;
    return v && this.#target && existsSync(join(this.#dir, `got-${v}`)) && existsSync(this.#file(v)) ? this.#file(v) : null;
  }

  /** What the window and tray show: null, or the new version, whether (and how) this copy updates itself, and how far it got. */
  state() {
    return this.#version && {
      version: this.#version, auto: !!this.#target, kind: this.#target?.kind ?? null,
      phase: this.#phase, progress: this.#progress, via: this.#via, ready: !!this.#ready, error: this.#error, file: this.file(), notes: this.#notes,
    };
  }

  /** Looks for a newer release. */
  async check() {
    try {
      const v = await this.#try((way) => latest(way));
      if (v && newer(v, VERSION) && v !== this.#version && !this.#phase) {
        [this.#version, this.#ready, this.#error, this.#notes] = [v, null, null, null];
        this.#changed();
      }
      // the update dialog's changelog: asked again at the next look if GitHub didn't answer
      const to = this.#version;
      if (to && !this.#notes) {
        const n = await this.#try((way) => notes(way, to));
        if (to === this.#version) {
          this.#notes = n;
          this.#changed();
        }
      }
    } catch (err) {
      log(`update: ${err.message}`);
    }
  }

  /** By each way in turn till one gets GitHub's answer (ways.ts throughWays): `fn(way, last)`. */
  #try(fn) {
    return throughWays(this.#ways(), fn);
  }

  /** The Update button: downloads the new version for this system and gets it ready to go in. True once it's ready. */
  async update() {
    const t = this.#target;
    if (this.#ready || !t || !this.#version || this.#phase) return !!this.#ready;
    const v = this.#version;
    [this.#phase, this.#progress, this.#error] = ["downloading", 0, null];
    this.#changed();
    const file = this.#file(v);
    try {
      for (const d of [this.#downloads, this.#dir]) mkdirSync(d, { recursive: true });
      // an older version's download: not needed now
      for (const d of downloaded(this.#downloads, t.kind)) if (d.version !== v) for (const f of [d.name, `${d.name}.part`]) rmSync(join(this.#downloads, f), { force: true });
      for (const f of readdirSync(this.#dir)) if (f !== v && f !== `got-${v}`) rmSync(join(this.#dir, f), { recursive: true, force: true });
      if (!existsSync(file)) {
        const { bavail, bsize } = statfsSync(this.#downloads);
        const need = t.kind === "mac" ? 1e9 : 4e8; // the download (and on a Mac the app in it, and the one it replaces)
        if (bavail * bsize < need) throw new Error(`it needs ${need / 1e9} GB free on the disk`);
        // into .part, carried on from there after a break (download() resumes, by any way), then renamed: a file by its own name is whole
        await this.#try((way, last) => {
          this.#via = way.via;
          this.#changed();
          return download(`${RELEASES}/download/v${v}/${basename(file)}`, `${file}.part`, way, (p) => {
            if (p === this.#progress) return;
            this.#progress = p;
            this.#changed();
          }, { last });
        });
        renameSync(`${file}.part`, file);
      }
      writeFileSync(join(this.#dir, `got-${v}`), "");
      [this.#phase, this.#progress] = ["installing", null];
      this.#changed();
      if (t.kind === "mac") {
        const app = this.#readyPath(v);
        mkdirSync(dirname(app), { recursive: true });
        // an image that doesn't check out (damaged, or not this app's, or unsigned) goes, and isn't offered to install by hand
        await unpack(file, app, t.bundle, v).catch((err) => {
          rmSync(file, { force: true });
          throw err;
        });
        this.#ready = app;
      } else if (t.kind === "deb") {
        await exec("pkexec", ["dpkg", "-i", file]).catch((err) => {
          // 126: the password dialog was dismissed; 127: no one to ask (no polkit agent)
          throw new Error(err.code === 126 ? "it needs your password to install" : err.code === 127 ? "the system couldn't ask for your password" : err.message);
        });
        this.#ready = true;
      } else if (t.kind === "apk") {
        // one that isn't this app, this version, or signed with its key goes (Android would refuse it, after asking)
        await t.check(file, v).catch((err) => {
          rmSync(file, { force: true });
          throw err;
        });
        this.#ready = file;
      } else {
        if (t.kind === "appimage") chmodSync(file, 0o755);
        this.#ready = file;
      }
    } catch (err) {
      // a full disk: give the space back rather than keep a part of the download
      if (err.code === "ENOSPC") rmSync(`${file}.part`, { force: true });
      // no way got it: what came (by any) is kept for the next try; with nothing, which ways didn't get through
      const some = existsSync(`${file}.part`) && statSync(`${file}.part`).size > 0;
      const tried = triedText(err.tried);
      this.#error = err.status === 404 ? "this release has no download for your system yet"
        : err.code === "ENOSPC" ? "the disk is full"
        : this.#phase === "downloading" && !err.status ? (some || !tried ? "the download broke off; try again and it carries on where it stopped" : `couldn't download it ${tried}`)
        : err.message;
      log(`update: ${err.message}`);
    }
    [this.#phase, this.#progress, this.#via] = [null, null, null];
    this.#changed();
    return !!this.#ready;
  }

  /**
   * To install by hand: opens the downloaded file once this app has exited (until then it holds its own files, and on
   * Windows the installer would close it without putting the network back). The caller quits the app. False: no file.
   */
  installByHand() {
    const f = this.file();
    if (!f) return false;
    if (process.platform === "win32") {
      spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", "Wait-Process -Id $env:FOXHOLE_PID -ErrorAction SilentlyContinue; Start-Process -FilePath $env:FOXHOLE_SETUP"], {
        detached: true, stdio: "ignore", windowsHide: true, env: { ...process.env, FOXHOLE_PID: String(process.pid), FOXHOLE_SETUP: f },
      }).unref();
    } else {
      // macOS opens the disk image; Linux the .deb in the software center; an AppImage runs itself (the new version)
      const open = this.#target.kind === "appimage" ? [] : [process.platform === "darwin" ? "open" : "xdg-open"];
      spawn("sh", ["-c", 'while kill -0 "$0" 2>/dev/null; do sleep 0.3; done; exec "$@"', String(process.pid), ...open, f], { detached: true, stdio: "ignore" }).unref();
    }
    return true;
  }

  /**
   * Puts the new version in, as the app quits (its routes and DNS already back). `relaunch`: the quit is "Restart now";
   * `args`: the new version's arguments then. True when this starts the new version itself (Windows); else the app relaunches.
   * The downloaded file stays: if the new version doesn't start, the next start says so and offers it to install by hand.
   */
  install({ relaunch = false, args = [] } = {}) {
    const t = this.#target;
    if (!this.#ready || this.#ready === true) return false; // nothing waiting, or a .deb that's in already
    // Android's installer asks, then replaces this app (ending it); asked again if the user says no now
    if (t.kind === "apk") {
      // a failure's shown (the window's Install update tries again), not only logged
      if (this.#error) {
        this.#error = null;
        this.#changed();
      }
      t.open(this.#ready).catch((err) => {
        log(`update: couldn't open Android's installer: ${err.message}`);
        this.#error = err.message;
        this.#changed();
      });
      return true;
    }
    if (t.kind === "win" && !relaunch) return false; // an installer cut off by a shutdown would leave half an app: it waits for "Restart now"
    const mark = join(this.#dir, `tried-${this.#version}`); // the new version's first start deletes it; the old one's says it didn't take
    try {
      writeFileSync(mark, "");
      if (t.kind === "mac") {
        // two renames, quick enough while quitting
        const old = join(this.#dir, "old.app"); // the next start deletes it
        rmSync(old, { recursive: true, force: true });
        renameSync(t.bundle, old);
        try {
          renameSync(this.#ready, t.bundle);
        } catch (err) {
          renameSync(old, t.bundle);
          throw err;
        }
      } else if (t.kind === "appimage") {
        copyFileSync(this.#ready, `${t.file}.new`); // a copy (the download stays), then a rename: the old file is never half-written
        chmodSync(`${t.file}.new`, 0o755);
        renameSync(`${t.file}.new`, t.file); // the running one keeps its own copy until it exits
      } else if (t.kind === "win") {
        // Once this process has exited (the files are free): the installer, silently, then the new version
        const ps = [
          "Wait-Process -Id $env:FOXHOLE_PID -ErrorAction SilentlyContinue",
          "Start-Process -Wait -FilePath $env:FOXHOLE_SETUP -ArgumentList '/S','--updated'",
          "if ($env:FOXHOLE_ARGS) { Start-Process -FilePath $env:FOXHOLE_EXE -ArgumentList $env:FOXHOLE_ARGS } else { Start-Process -FilePath $env:FOXHOLE_EXE }",
        ].join("; ");
        spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps], {
          detached: true, stdio: "ignore", windowsHide: true,
          env: { ...process.env, FOXHOLE_PID: String(process.pid), FOXHOLE_SETUP: this.#ready, FOXHOLE_EXE: t.exe, FOXHOLE_ARGS: args.join(" ") },
        }).unref();
        this.#ready = null;
        return true;
      }
      this.#ready = null;
    } catch (err) {
      log(`update: couldn't install it: ${err.message}`);
      try {
        writeFileSync(mark, err.message); // for the next start to show: the log goes with this process
      } catch {}
    }
    return false;
  }
}
