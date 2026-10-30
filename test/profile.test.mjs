// Which Firefox profile foxhole reads, with fake installs in a throwaway HOME. No Firefox needed.
import assert from "node:assert";
import { mkdtempSync, mkdirSync, writeFileSync, utimesSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findAccount } from "../dist/profile.js";

const home = mkdtempSync(join(tmpdir(), "foxhole-profile-"));
process.env.HOME = home; // userHome() reads it on each call
const DEB = join(home, ".mozilla", "firefox");
const SNAP = join(home, "snap", "firefox", "common", ".mozilla", "firefox"); // Ubuntu's own Firefox

/** A profile in `root`, signed in as `email` (null: signed out), last used `ago` seconds back. */
function profile(root, email, ago) {
  mkdirSync(join(root, "p.default-release"), { recursive: true });
  writeFileSync(join(root, "profiles.ini"), "[Profile0]\nName=default\nIsRelative=1\nPath=p.default-release\nDefault=1\n");
  const data = email ? { accountData: { email, verified: true, sessionToken: "aa" } } : null;
  writeFileSync(join(root, "p.default-release", "signedInUser.json"), JSON.stringify(data));
  const prefs = join(root, "p.default-release", "prefs.js");
  writeFileSync(prefs, "");
  const t = Date.now() / 1000 - ago;
  utimesSync(prefs, t, t);
}

profile(SNAP, "snap@example.com", 10);
assert.equal(findAccount()?.email, "snap@example.com", "Ubuntu's snap Firefox is found");

profile(DEB, "old@example.com", 3600); // left over from before Firefox became a snap
assert.equal(findAccount()?.email, "snap@example.com", "the snap's live profile beats a stale ~/.mozilla");

profile(DEB, "deb@example.com", 1); // Mozilla's .deb, used now; the snap one is the stale one
assert.equal(findAccount()?.email, "deb@example.com", "a live ~/.mozilla beats a stale snap profile");

profile(DEB, null, 1); // signed out in the Firefox in use
assert.equal(findAccount()?.signedIn, false, "signed out where it counts, despite an older signed-in profile");

// Unreadable (macOS's privacy protection says EPERM; a chmod gives EACCES, the same path): no crash, and how to allow it
if (process.platform !== "win32" && process.getuid() !== 0) {
  profile(DEB, "deb@example.com", 1);
  chmodSync(join(DEB, "profiles.ini"), 0);
  const a = findAccount();
  assert.equal(a?.signedIn, false, "an unreadable profile isn't taken as signed in");
  assert.equal(a?.blocked?.code, "EACCES");
  assert.equal(a.blocked.path, join(DEB, "profiles.ini"));
  assert.match(a.blocked.message, process.platform === "darwin" ? /Full Disk Access/ : /chown/, "it says how to allow it");
  chmodSync(join(DEB, "profiles.ini"), 0o644);
  chmodSync(join(DEB, "p.default-release", "signedInUser.json"), 0); // the sign-in itself: not skipped as "signed out"
  assert.equal(findAccount()?.blocked?.path, join(DEB, "p.default-release", "signedInUser.json"));
  chmodSync(join(DEB, "p.default-release", "signedInUser.json"), 0o644);
  assert.equal(findAccount()?.blocked, undefined, "readable again: found as before");
}

rmSync(home, { recursive: true, force: true });
console.log("ok - Firefox profile: snap, Flatpak and ~/.mozilla, the one in use first; an unreadable one says how to allow it");
