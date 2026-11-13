// The terminal's "Sign in from another device": this computer waits as a TV does (tvpair.ts), its 6-character code and
// its QR code on the terminal, for a phone, computer or TV where Foxhole is signed in to send it a sign-in (its
// Settings → Sign in a TV or phone), with its VPN relay where it has one. The first start's question and `foxhole
// login` wait here (cli.ts); the TUI's Accounts shows the same lines in a popup of its own (tui.ts). It takes no
// window and no Firefox: the way in where there's no screen for one (a container, SSH).
import { hostname } from "node:os";
import { AlreadySignedIn, FIREFOX, loadAccounts, saveAccounts, signOut, takeSent, withSent, without } from "./accounts.js";
import { useRelay } from "./guardian.js";
import { loadRelay } from "./httprelay.js";
import { firewallHint, lanIp, network } from "./netinfo.js";
import { qrLines } from "./qr.js";
import { wrap } from "./relaywizard.js";
import { loadSettings, saveSettings } from "./settings.js";
import { TV_PORT, waitForSignIn, type TvSignIn, type TvWaiting } from "./tvpair.js";
import { bold, box, centerIn, cyan, dim, green, purple, red, under, vw, yellow } from "./ui.js";

/** This computer's name, as the other device says it. */
export const deviceName = (): string => hostname().replace(/\.local$/, "");

/** Why it can't wait, said for the user: the port's taken where another Foxhole here waits already (its window's dialog). */
export const waitProblem = (err: NodeJS.ErrnoException, port = TV_PORT): string =>
  err.code === "EADDRINUSE" ? `Another app on this computer is using Foxhole's sign-in port (${port}): another Foxhole, waiting for a sign-in too?` : err.message;

/**
 * What the terminal shows while it waits: how to send the sign-in, the code, and its QR code where there's room,
 * beside the words in a wide terminal, under them in a tall one (the code alone is all it takes); then, while there
 * are lines left of `height`, the network the other device must be on too, what opens the port in a firewall that's
 * on (`fw`), and that a relay comes along. No line is wider than `width`.
 */
export function deviceLines(w: TvWaiting, o: { width: number; height: number; net?: string | null; fw?: string[] | null }): string[] {
  let qr: string[] = [];
  try {
    if (w.link) qr = qrLines(w.link);
  } catch {
    // too long for a QR code: the code alone
  }
  const qw = qr.length ? vw(qr[0]) : 0;
  const code = bold(cyan(`${[...w.code.slice(0, 3)].join(" ")}   ${[...w.code.slice(3)].join(" ")}`)); // read a letter at a time, in two threes
  const words = (width: number, scan: boolean) => ({
    how: [...wrap(`On a phone, computer or TV where Foxhole is signed in, open **Settings → Sign in a TV or phone**, and ${scan ? "scan this QR code or type" : "type"} this code:`, width), "", centerIn(code, width)],
    net: w.host
      ? wrap(`This computer is on **${o.net || "a network"}** · ${w.host}: the other device must be on it too.`, width)
      : wrap("This computer isn't on a network: connect it to the Wi-Fi or a cable first.", width).map(yellow),
    fw: o.fw?.length ? [...wrap("If it can't find this computer, open the port in the firewall:", width).map(dim), ...o.fw.flatMap((c) => wrap(c, width)).map(cyan)] : [],
    relay: wrap("Where Mozilla is blocked or refuses your country, the other device's VPN relay comes along with the sign-in.", width).map(dim),
  });
  // each of `more` under `first`, a blank line between, while it fits in `room` lines
  const stack = (first: string[], more: string[][], room: number) => more.reduce((lines, b) => (b.length && lines.length + 1 + b.length <= room ? [...lines, "", ...b] : lines), first);

  const col = Math.min(o.width - qw - 3, 50); // the words' column beside the QR code
  if (qr.length && col >= 34 && qr.length <= o.height) {
    const t = words(col, true);
    const text = stack(t.how, [t.net, t.fw, t.relay], qr.length);
    const top = Math.floor((qr.length - text.length) / 2);
    return qr.map((l, i) => `${l}   ${text[i - top] ?? ""}`);
  }
  const width = Math.min(o.width, 62);
  const t = words(width, qr.length > 0 && qw <= width);
  const withQr = [...t.how, "", ...qr.map((l) => centerIn(l, width))];
  if (qr.length && qw <= width && withQr.length <= o.height) return stack(withQr, [t.net, t.fw, t.relay], o.height);
  const plain = words(width, false);
  return stack(plain.how, [plain.net, plain.fw, qr.length ? wrap("A larger terminal shows a QR code to scan, too.", width).map(dim) : [], plain.relay], o.height);
}

/**
 * The first start's and `foxhole login`'s "Sign in from another device": the lines above on the terminal (`say`;
 * again when the code or the network changes), till a sign-in comes. A VPN relay, with it or alone, is saved (in
 * place of one here) and reaches Mozilla at once; the sign-in is checked with Mozilla (accounts.ts takeSent), and
 * then it's the account in use: Firefox's sign-in, which didn't work here, leaves the list (the TUI's Accounts adds
 * it back). Resolves with the account's email; null once `signal` aborts. Throws, said for the user, where it can't
 * wait. `host`, `port` and `size`: the tests'.
 */
export async function deviceLogin(o: {
  signal: AbortSignal;
  say: (text: string) => void;
  host?: () => string | null;
  port?: number;
  size?: () => { cols: number; rows: number };
}): Promise<string | null> {
  const port = o.port ?? TV_PORT;
  let took: (email: string) => void = () => {};
  const signedIn = new Promise<string>((resolve) => (took = resolve));
  let wait: TvSignIn | null = null;
  let net: string | null = null, fw: string[] | null = null;
  let shown = ""; // the code and link on the terminal now
  let over = false; // it waits no more: what's still on its way isn't taken
  const gone = () => new Error("the other device stopped waiting");
  const show = async () => {
    const w = wait?.waiting();
    const now = `${w?.code} ${w?.link}`;
    if (!w || now === shown) return;
    const first = !shown;
    shown = now;
    if (!first) net = await network().catch(() => null); // another network, perhaps
    const { cols, rows } = o.size?.() ?? { cols: process.stdout.columns || 80, rows: process.stdout.rows || 24 };
    o.say(
      [
        "",
        ...box(["", ...deviceLines(w, { width: Math.min(cols - 4, 98), height: rows - 7, net, fw }), ""], { title: cyan("🦊 Sign in from another device") }),
        dim(`Waiting for the sign-in · press ${under("q")} or ${under("Ctrl+C")} to cancel`),
      ].join("\n"),
    );
  };
  try {
    wait = await waitForSignIn({
      name: deviceName(),
      host: o.host ?? (() => lanIp()),
      port,
      changed: () => void show(),
      accept: async ({ account, relay }, from) => {
        const who = from || "another device";
        try {
          if (over) throw gone();
          if (relay) {
            const settings = { ...loadSettings(), relay };
            saveSettings(settings);
            useRelay(loadRelay(settings)); // Mozilla's reached through it from now on, where it's blocked
            o.say(purple(`✓ Your VPN relay came from ${who}.`));
          }
          if (!account) return o.say(dim("Still waiting for the sign-in…"));
          const taken = await takeSent(without(loadAccounts(), FIREFOX), account);
          if (over) throw gone(); // cancelled while Mozilla was asked
          saveAccounts(withSent(without(loadAccounts(), FIREFOX), taken));
          if (taken.replaced) void signOut(taken.replaced); // the sign-in it replaces
          o.say(green(`✓ Signed in with ${account.email}${from ? `, sent from ${from}` : ""}.`));
          took(account.email);
        } catch (err) {
          if (over) throw err; // nothing more on a terminal that has moved on
          if (!(err instanceof AlreadySignedIn)) {
            o.say(red(`The sign-in from ${who} wasn't taken: ${(err as Error).message}`));
            throw err;
          }
          // on the list all along, and its sign-in works: that one, then (the sender's told, and ends the one it made)
          saveAccounts({ ...without(loadAccounts(), FIREFOX), current: err.id });
          o.say(green(`✓ ${err.email} is signed in here already: it's the account in use.`));
          took(err.email);
          throw err;
        }
      },
    });
  } catch (err) {
    throw new Error(waitProblem(err as NodeJS.ErrnoException, port));
  }
  [net, fw] = await Promise.all([network().catch(() => null), firewallHint(port).catch(() => null)]);
  await show();
  const timer = setInterval(() => void show(), 3000); // the network's address changes with the network
  const stopped = new Promise<null>((resolve) => (o.signal.aborted ? resolve(null) : o.signal.addEventListener("abort", () => resolve(null), { once: true })));
  try {
    return await Promise.race([signedIn, stopped]);
  } finally {
    over = true;
    clearInterval(timer);
    const { stop } = wait;
    setTimeout(stop); // once the sender has its answer
  }
}
