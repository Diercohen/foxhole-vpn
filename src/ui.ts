// Tiny zero-dependency terminal helpers (color, flags, sizes).

const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const wrap = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

export const bold = wrap("1");
export const dim = wrap("2");
export const red = wrap("31");
export const green = wrap("32");
export const yellow = wrap("33");
export const cyan = wrap("36");

/** ISO 3166-1 alpha-2 → regional-indicator flag emoji. */
export function flag(code: string): string {
  if (code.length !== 2) return "  ";
  const A = 0x1f1e6;
  return String.fromCodePoint(A + (code.charCodeAt(0) - 65), A + (code.charCodeAt(1) - 65));
}

const displayNames =
  typeof Intl !== "undefined" && "DisplayNames" in Intl
    ? new Intl.DisplayNames(["en"], { type: "region" })
    : null;

/** Friendly country name for a code, falling back to the given name. */
export function countryName(code: string, fallback: string): string {
  try {
    return displayNames?.of(code) ?? fallback;
  } catch {
    return fallback;
  }
}

/** Formats a byte count as GB with one decimal. */
export function gb(bytes: bigint): string {
  const n = Number(bytes) / 1e9;
  return `${n.toFixed(1)} GB`;
}

/** A short date like "Nov 1". */
export function shortDate(d: Date): string {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
