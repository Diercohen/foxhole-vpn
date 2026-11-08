// A QR code for a text (the TV's sign-in link, tvpair.ts; a shared settings link, share.ts): byte mode, error correction
// level M, versions 1-40 (up to 2331 bytes), as an SVG path of its dark modules. After Project Nayuki's QR Code
// generator (MIT).

// Level M's error correction for each version: codewords per block, and blocks
const ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
const FORMAT_M = 0; // level M's two format bits

/** GF(256) multiplication, modulo x^8 + x^4 + x^3 + x^2 + 1. */
function mul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

/** Reed-Solomon: the divisor polynomial of `degree`, then a block's remainder by it. */
function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = mul(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = mul(root, 2);
  }
  return result;
}
function rsRemainder(data: number[], divisor: number[]): number[] {
  const result = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    divisor.forEach((coef, i) => (result[i] ^= mul(coef, factor)));
  }
  return result;
}

/** The data modules a version holds, in bits. */
function rawModules(ver: number): number {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (ver >= 7) n -= 36;
  }
  return n;
}
const dataCodewords = (ver: number) => Math.floor(rawModules(ver) / 8) - ECC_PER_BLOCK[ver] * BLOCKS[ver];

function alignmentPositions(ver: number, size: number): number[] {
  if (ver === 1) return [];
  const count = Math.floor(ver / 7) + 2;
  const step = Math.floor((ver * 8 + count * 3 + 5) / (count * 4 - 4)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

/** The QR code of `text`: its size in modules and its dark modules as an SVG path, with a 4-module quiet zone. */
export function qrSvgPath(text: string): { size: number; path: string } {
  const dark = qrModules(text);
  let path = "";
  dark.forEach((row, y) => row.forEach((on, x) => on && (path += `M${x + 4},${y + 4}h1v1h-1z`)));
  return { size: dark.length + 8, path };
}

/** The QR code of `text` for a terminal: two modules a line in half blocks, black on white, with a 2-module quiet zone. */
export function qrLines(text: string): string[] {
  const dark = qrModules(text);
  const at = (x: number, y: number) => dark[y - 2]?.[x - 2] === true;
  const lines: string[] = [];
  for (let y = 0; y < dark.length + 4; y += 2) {
    let line = "";
    for (let x = 0; x < dark.length + 4; x++) line += at(x, y) ? (at(x, y + 1) ? "█" : "▀") : at(x, y + 1) ? "▄" : " ";
    lines.push(`\x1b[30;107m${line}\x1b[0m`);
  }
  return lines;
}

/** The QR code of `text`: its modules, dark or not, without a quiet zone. */
export function qrModules(text: string): boolean[][] {
  const bytes = [...Buffer.from(text, "utf8")];
  let ver = 1;
  while (ver <= 40 && 4 + (ver < 10 ? 8 : 16) + bytes.length * 8 > dataCodewords(ver) * 8) ver++;
  if (ver > 40) throw new Error("too long for a QR code");

  // the bits: byte mode, the length, the bytes, a terminator, then padding to the version's capacity
  const bits: number[] = [];
  const put = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(4, 4);
  put(bytes.length, ver < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capacity = dataCodewords(ver) * 8;
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) put(pad, 8);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));

  // the blocks, each with its error correction, interleaved
  const blocks = BLOCKS[ver], eccLen = ECC_PER_BLOCK[ver], raw = Math.floor(rawModules(ver) / 8);
  const shortBlocks = blocks - (raw % blocks), shortLen = Math.floor(raw / blocks);
  const divisor = rsDivisor(eccLen);
  const split: number[][] = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const dat = data.slice(k, (k += shortLen - eccLen + (i < shortBlocks ? 0 : 1)));
    const block = [...dat, ...rsRemainder(dat, divisor)];
    if (i < shortBlocks) block.splice(shortLen - eccLen, 0, 0); // a placeholder, skipped below
    split.push(block);
  }
  const codewords: number[] = [];
  for (let i = 0; i < split[0].length; i++)
    split.forEach((b, j) => (i !== shortLen - eccLen || j >= shortBlocks) && codewords.push(b[i]));

  // the function patterns
  const size = ver * 4 + 17;
  const dark = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const set = (x: number, y: number, on: boolean) => ((dark[y][x] = on), (fixed[y][x] = true));
  for (let i = 0; i < size; i++) set(6, i, i % 2 === 0), set(i, 6, i % 2 === 0);
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]])
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
  const align = alignmentPositions(ver, size);
  align.forEach((ay, i) =>
    align.forEach((ax, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }),
  );
  const drawFormat = (mask: number) => {
    const d = (FORMAT_M << 3) | mask;
    let rem = d;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const f = ((d << 10) | rem) ^ 0x5412;
    const bit = (i: number) => ((f >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6)), set(8, 8, bit(7)), set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  drawFormat(0); // reserves its modules
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const v = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const on = ((v >>> i) & 1) === 1, a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, on), set(b, a, on);
    }
  }

  // the codewords, in two-column zigzags from the bottom right
  for (let right = size - 1, i = 0; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++)
      for (let j = 0; j < 2; j++) {
        const x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (!fixed[y][x] && i < codewords.length * 8) dark[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1, i++;
      }
  }

  // the mask that leaves the fewest look-alike patterns
  const masks: ((x: number, y: number) => boolean)[] = [
    (x, y) => (x + y) % 2 === 0, (_, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];
  const apply = (m: number) => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y][x] && masks[m](x, y)) dark[y][x] = !dark[y][x];
  };
  // ponytail: the penalty counts runs, 2x2 blocks and balance, not finder look-alikes (any mask scans; this one scans best)
  const penalty = () => {
    let p = 0, darkCount = 0;
    for (let a = 0; a < size; a++)
      for (const line of [(b: number) => dark[a][b], (b: number) => dark[b][a]]) {
        let run = 1;
        for (let b = 1; b <= size; b++) {
          if (b < size && line(b) === line(b - 1)) run++;
          else (p += run >= 5 ? run - 2 : 0), (run = 1);
        }
      }
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++) {
        darkCount += dark[y][x] ? 1 : 0;
        if (x < size - 1 && y < size - 1 && dark[y][x] === dark[y][x + 1] && dark[y][x] === dark[y + 1][x] && dark[y][x] === dark[y + 1][x + 1]) p += 3;
      }
    return p + Math.floor(Math.abs(darkCount * 20 - size * size * 10) / (size * size)) * 10;
  };
  let best = 0, bestPenalty = Infinity;
  for (let m = 0; m < 8; m++) {
    apply(m);
    drawFormat(m);
    const p = penalty();
    if (p < bestPenalty) (best = m), (bestPenalty = p);
    apply(m); // undone
  }
  apply(best);
  drawFormat(best);
  return dark;
}
