// Relay mode's certificate authority (mitm.ts), trusted once on this computer so that browsers and apps take the
// sites' certificates it makes: in the system's store (Safari, Chrome, Edge, Firefox on macOS and Windows, most apps),
// and on Linux, where browsers keep their own, by Firefox's and the Chromium family's policies too. Taken out the same way.
// Command-line tools mostly bring their own list of CAs: envLines points them at ours.
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import type { Priv } from "./global.js";
import { caFiles, caFingerprints, caPem, loadCa } from "./mitm.js";
import { userHome } from "./profile.js";

const exec = promisify(execFile);
const hidden = { windowsHide: true };

// Linux's system store (curl, git, wget, apt, Go, the distro's Python): the first of these there is, and what refreshes it
const ANCHORS: [string, string][] = [
  ["/usr/local/share/ca-certificates", "update-ca-certificates"], // Debian, Ubuntu
  ["/etc/pki/ca-trust/source/anchors", "update-ca-trust"], // Fedora, RHEL
  ["/etc/ca-certificates/trust-source/anchors", "update-ca-trust"], // Arch
  ["/etc/pki/trust/anchors", "update-ca-certificates"], // openSUSE
];
const FILE = "foxhole-relay-ca.crt"; // update-ca-certificates takes only .crt
// Firefox's policies, deb and snap alike (the snap reads nothing else in /etc, so the certificate goes beside them),
// and the Chromium family's CACertificates (Chrome 132 on): Chrome, Chromium (deb, snap), Brave, Edge
const FIREFOX = "/etc/firefox/policies";
const FIREFOX_CA = `${FIREFOX}/foxhole-relay-ca.pem`;
// ponytail: Chrome before 132 and Vivaldi read only NSS (~/.pki/nssdb), which needs certutil (libnss3-tools); add it if they turn up
const CHROMIUM = ["/etc/opt/chrome", "/etc/chromium", "/etc/chromium-browser", "/etc/brave", "/etc/opt/edge"].map((d) => `${d}/policies/managed/foxhole-relay-ca.json`);

const keychain = () => join(userHome(), "Library", "Keychains", "login.keychain-db");

/** True when this computer trusts the CA; false before relay mode made it. */
export async function caTrusted(): Promise<boolean> {
  const pem = caPem();
  if (!pem) return false;
  const ok = (p: Promise<unknown>) => p.then(() => true, () => false);
  if (process.platform === "darwin") return ok(exec("security", ["verify-cert", "-c", caFiles().cert, "-l", "-L", "-q"]));
  if (process.platform === "win32") return ok(exec("certutil", ["-user", "-store", "Root", caFingerprints(pem).sha1], hidden));
  return [...ANCHORS.map(([d]) => join(d, FILE)), FIREFOX_CA].some((f) => caPem(f) === pem);
}

/**
 * Trusts the CA, made first if need be; `add` false: stops trusting it. macOS asks for the user's password itself
 * and Windows to confirm; Linux needs root, `priv`. Browsers already open may need a restart to see it. Fails
 * with what the tool said (macOS: "…canceled by the user.").
 */
export async function setCaTrust(add: boolean, priv?: Priv): Promise<void> {
  try {
    await trust(add, priv);
  } catch (err) {
    // a tool's last line on stderr, or what follows sudoPriv's "→" (the command before it is this whole script)
    const e = err as Error & { stderr?: string };
    throw new Error(e.stderr?.trim().split("\n").pop() || e.message.split(" → ").pop()!.trim());
  }
}

async function trust(add: boolean, priv?: Priv): Promise<void> {
  const pem = add ? loadCa().pem : caPem();
  if (!pem) return;
  const { cert } = caFiles();
  const { sha1 } = caFingerprints(pem);
  if (process.platform === "darwin") {
    if (add) return void (await exec("security", ["add-trusted-cert", "-r", "trustRoot", "-k", keychain(), cert]));
    await exec("security", ["remove-trusted-cert", cert]).catch(() => {});
    return void (await exec("security", ["delete-certificate", "-Z", sha1, keychain()]).catch(() => {}));
  }
  if (process.platform === "win32") return void (await exec("certutil", ["-user", add ? "-addstore" : "-delstore", "Root", add ? cert : sha1], hidden));
  if (!priv) throw new Error("trusting a certificate needs root");
  const tmp = mkdtempSync(join(tmpdir(), "foxhole-ca-"));
  try {
    await priv.run(["sh", "-c", linuxScript(add, cert, pem, tmp)]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** The root shell script that trusts the CA on Linux (or stops), with the files it installs written to `tmp`. */
function linuxScript(add: boolean, cert: string, pem: string, tmp: string): string {
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const put = (from: string, to: string) => `mkdir -p ${q(dirname(to))} && install -m 644 ${q(from)} ${q(to)}`;
  const lines = ["set -e"];
  const anchors = ANCHORS.filter(([d]) => existsSync(d));
  for (const [d, refresh] of add ? anchors.slice(0, 1) : anchors) lines.push(add ? put(cert, join(d, FILE)) : `rm -f ${q(join(d, FILE))}`, `${refresh} >/dev/null`);

  const current = existsSync(`${FIREFOX}/policies.json`) ? readFileSync(`${FIREFOX}/policies.json`, "utf8") : null;
  let policies: string | null | undefined;
  try {
    if (add || current?.includes(FIREFOX_CA)) policies = firefoxPolicies(current, FIREFOX_CA, add);
  } catch {
    /* someone else's policies.json, and not JSON: left alone, and Firefox goes without */
  }
  if (policies !== undefined) {
    lines.push(add ? put(cert, FIREFOX_CA) : `rm -f ${FIREFOX_CA}`);
    if (policies === null) lines.push(`rm -f ${FIREFOX}/policies.json`);
    else {
      writeFileSync(join(tmp, "policies.json"), policies);
      lines.push(put(join(tmp, "policies.json"), `${FIREFOX}/policies.json`));
    }
  }

  writeFileSync(join(tmp, "chromium.json"), JSON.stringify({ CACertificates: [new X509Certificate(pem).raw.toString("base64")] }));
  for (const f of CHROMIUM) lines.push(add ? put(join(tmp, "chromium.json"), f) : `rm -f ${f}`);
  return lines.join("\n");
}

type Policies = { policies?: { Certificates?: { Install?: string[] } } };

/** Firefox's policies.json with the certificate at `ca` installed (`add`) or not; null when nothing's left in it. Pure. */
export function firefoxPolicies(current: string | null, ca: string, add: boolean): string | null {
  const j = (current ? JSON.parse(current) : {}) as Policies;
  if (typeof j !== "object" || !j || Array.isArray(j)) throw new Error("not a policies file");
  const p = (j.policies ??= {});
  const c = (p.Certificates ??= {});
  const install = (c.Install ?? []).filter((f) => f !== ca);
  if (add) install.push(ca);
  if (install.length) c.Install = install;
  else delete c.Install;
  if (!Object.keys(c).length) delete p.Certificates;
  if (!Object.keys(p).length) delete j.policies;
  return Object.keys(j).length ? JSON.stringify(j, null, 2) + "\n" : null;
}

/**
 * Shell lines for command-line tools: the CA where each looks for one (most replace their list with the file, so the
 * bundle has the usual CAs too; Node adds to its own), and the proxy at `proxy`. For eval, or PowerShell's iex.
 */
export function envLines(proxy: string, powershell = process.platform === "win32"): string[] {
  const { cert, bundle } = caFiles();
  const vars: [string, string][] = [
    ["NODE_EXTRA_CA_CERTS", cert], // Node, npm, yarn, pnpm
    ...["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "AWS_CA_BUNDLE", "CARGO_HTTP_CAINFO", "DENO_CERT"].map((k): [string, string] => [k, bundle]),
    // curl reads only the lowercase http_proxy; both for the rest
    ...["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"].map((k): [string, string] => [k, `http://${proxy}`]),
    ...["no_proxy", "NO_PROXY"].map((k): [string, string] => [k, "localhost,127.0.0.1,::1"]),
  ];
  return vars.map(([k, v]) => (powershell ? `$env:${k} = '${v.replace(/'/g, "''")}'` : `export ${k}='${v.replace(/'/g, `'\\''`)}'`));
}
