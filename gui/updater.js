// New versions from GitHub's releases: looked for a minute after launch, then every 6 hours. A Mac app that can replace
// itself downloads the new one in the background (through the VPN when connected) and swaps it in when it restarts or
// next quits; anywhere else (Windows, Linux, a copy run from the disk image) the window links to the download.
import { execFile } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, rmdirSync, statSync, statfsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { promisify } from "node:util";
import { httpsGet } from "./dist/global.js";
import { log } from "./dist/log.js";
import { newer, VERSION } from "./dist/update.js";
import { REPO_URL } from "./dist/ui.js";

const exec = promisify(execFile);
// FOXHOLE_RELEASES: a server laid out like GitHub's releases, for testing
const RELEASES = process.env.FOXHOLE_RELEASES ?? `${REPO_URL}/releases`;
const SEMVER = /^\d+\.\d+\.\d+$/;
const httpError = (status) => Object.assign(new Error(`HTTP ${status}`), { status });

/** The latest release's version, from where /releases/latest redirects (GitHub's API allows few requests per IP, and NAT and VPN exits share one). */
export async function latest(proxy) {
  const res = await httpsGet(`${RELEASES}/latest`, proxy);
  res.resume();
  return /\/releases\/tag\/v?(\d+\.\d+\.\d+)$/.exec(res.headers.location ?? "")?.[1] ?? null;
}

/** Downloads `url` to `file`, carrying on from what an earlier try left there; `progress(percent)` as it goes. */
export async function download(url, file, proxy, progress) {
  for (let hops = 0; hops < 6; hops++) {
    const have = existsSync(file) ? statSync(file).size : 0;
    const res = await httpsGet(url, proxy, have ? { range: `bytes=${have}-` } : {});
    const { statusCode, headers } = res;
    if (statusCode >= 300 && statusCode < 400 && headers.location) {
      res.resume();
      url = new URL(headers.location, url).href;
      continue;
    }
    if (statusCode === 416 && have) {
      res.resume();
      if (Number(/\/(\d+)$/.exec(headers["content-range"] ?? "")?.[1]) === have) return; // it's all there already
      rmSync(file); // what's there doesn't fit: from the start
      continue;
    }
    if (statusCode !== 200 && statusCode !== 206) {
      res.resume();
      throw httpError(statusCode);
    }
    const from = statusCode === 206 ? have : 0; // a 200 is the whole file again
    const total = statusCode === 206 ? Number(/\/(\d+)$/.exec(headers["content-range"] ?? "")?.[1]) : Number(headers["content-length"]);
    if (!(total > 0)) throw new Error("the server didn't say the file's size");
    let got = from;
    await pipeline(
      res,
      async function* (chunks) {
        for await (const c of chunks) {
          progress(Math.floor(((got += c.length) / total) * 100));
          yield c;
        }
      },
      createWriteStream(file, { flags: from ? "a" : "w" }),
    );
    if (statSync(file).size !== total) throw new Error("download cut short");
    return;
  }
  throw new Error("too many redirects");
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

export class Updater {
  #dir; // where a download and the new version wait
  #bundle; // this app's .app folder when it can swap a new version in; null: the window links to the download instead
  #via; // () => the VPN's proxy when connected
  #changed;
  #version = null; // a newer release
  #progress = null; // its download, in percent
  #ready = null; // the new version's app, checked and waiting
  #soon = false; // the download broke off: try again in minutes, not hours

  constructor({ dir, bundle, via, changed }) {
    this.#dir = dir;
    this.#bundle = bundle;
    this.#via = via;
    this.#changed = changed;
  }

  /** Looks a minute in (after the connect at launch, so through the VPN), then every 6 hours; every 10 minutes while a download is broken off. */
  start() {
    mkdirSync(this.#dir, { recursive: true });
    // an update's leftovers: the app it replaced, and versions no newer than this one
    for (const f of readdirSync(this.#dir)) if (f === "old.app" || (SEMVER.test(f) && !newer(f, VERSION))) rmSync(join(this.#dir, f), { recursive: true, force: true });
    // one downloaded before goes in even on a quit before the first look
    const waiting = this.#bundle && readdirSync(this.#dir).find((f) => SEMVER.test(f) && existsSync(join(this.#dir, f, "Foxhole.app")));
    if (waiting) [this.#version, this.#ready] = [waiting, join(this.#dir, waiting, "Foxhole.app")];
    const next = (ms) => setTimeout(() => void this.#check().then(() => next(this.#soon ? 10 * 60_000 : 6 * 3600_000)), ms);
    next(60_000);
  }

  /** What the window and tray show: null, or the new version and how far along it is. */
  state() {
    return this.#version && { version: this.#version, auto: !!this.#bundle, progress: this.#progress, ready: !!this.#ready };
  }

  async #check() {
    this.#soon = false;
    try {
      const v = await this.#try((proxy) => latest(proxy));
      if (!v || !newer(v, VERSION)) return;
      if (v !== this.#version) [this.#version, this.#ready] = [v, null];
      this.#changed();
      if (this.#bundle && !this.#ready) await this.#fetch(v);
    } catch (err) {
      if (err.status === 404) this.#version = null; // that release has no app for this Mac (yet)
      // a full disk: give the space back rather than keep a part of the download
      if (err.code === "ENOSPC") for (const f of readdirSync(this.#dir)) rmSync(join(this.#dir, f), { recursive: true, force: true });
      log(`update: ${err.message}`);
    }
    this.#progress = null;
    this.#changed();
  }

  /** Through the VPN when connected, else (or when that fails short of an answer) directly. */
  async #try(fn) {
    const proxy = this.#via();
    if (proxy) {
      try {
        return await fn(proxy);
      } catch (err) {
        if (err.status) throw err; // the server answered: asking again directly won't change that
      }
    }
    return fn(undefined);
  }

  /** Downloads version `v` and unpacks it next to the download, ready to swap in. */
  async #fetch(v) {
    for (const f of readdirSync(this.#dir)) if (f !== v) rmSync(join(this.#dir, f), { recursive: true, force: true }); // an older pending version
    const app = join(this.#dir, v, "Foxhole.app");
    if (!existsSync(app)) {
      mkdirSync(join(this.#dir, v), { recursive: true });
      const { bavail, bsize } = statfsSync(this.#dir);
      if (bavail * bsize < 1e9) throw new Error("waiting for 1 GB free on the disk"); // the download, the app in it, the one it replaces
      const name = `Foxhole-${v}-${process.arch}.dmg`;
      const dmg = join(this.#dir, v, name);
      await this.#try((proxy) =>
        download(`${RELEASES}/download/v${v}/${name}`, dmg, proxy, (p) => {
          if (p === this.#progress) return;
          this.#progress = p;
          this.#changed();
        }),
      ).catch((err) => {
        this.#soon = !err.status && err.code !== "ENOSPC"; // the network, not the server or the disk
        throw err;
      });
      // a bad image goes either way: the next try downloads it again
      await unpack(dmg, app, this.#bundle, v).finally(() => rmSync(dmg, { force: true }));
    }
    this.#ready = app;
  }

  /** Swaps the new version in for this app: two renames, quick enough while quitting. True once it's in. */
  install() {
    if (!this.#ready) return false;
    const old = join(this.#dir, "old.app"); // the next start deletes it
    try {
      rmSync(old, { recursive: true, force: true });
      renameSync(this.#bundle, old);
      try {
        renameSync(this.#ready, this.#bundle);
      } catch (err) {
        renameSync(old, this.#bundle);
        throw err;
      }
      this.#ready = null;
      return true;
    } catch (err) {
      log(`update: couldn't install it: ${err.message}`);
      return false;
    }
  }
}
