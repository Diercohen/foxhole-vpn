// The VPN server list is published openly via Mozilla Remote Settings, so it
// needs no authentication. Same collection Firefox reads (IPProtectionServerlist).
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { mozillaFetch } from "./guardian.js";
import { userHome } from "./profile.js";

export const SERVERLIST_URL =
  "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";

// Reserved code for the anycast "recommended" entry; not a real country.
const RECOMMENDED_CODE = "REC";

export interface Server {
  hostname: string;
  port: number;
  quarantined: boolean;
  /** Pinned connect IP (global mode): dial this exact address, SNI the hostname. */
  ip?: string;
}

export interface Country {
  code: string; // ISO 3166-1 alpha-2
  name: string;
  locked: boolean; // true = requires a paid upgrade; free tier cannot use it
  available: boolean; // has at least one usable (non-quarantined) server
  servers: Server[]; // flattened across the country's cities
}

interface RawServer {
  hostname?: string;
  port?: number;
  quarantined?: boolean;
}
interface RawCity {
  servers?: RawServer[];
}
interface RawCountry {
  code?: string;
  name?: string;
  locked?: boolean;
  cities?: RawCity[];
}

function toCountry(raw: RawCountry): Country {
  const servers: Server[] = (raw.cities ?? [])
    .flatMap((city) => city.servers ?? [])
    .map((s) => ({
      hostname: s.hostname ?? "",
      port: s.port ?? 443,
      quarantined: !!s.quarantined,
    }))
    .filter((s) => s.hostname);
  return {
    code: raw.code ?? "",
    name: raw.name ?? raw.code ?? "",
    locked: !!raw.locked,
    available: servers.some((s) => !s.quarantined),
    servers,
  };
}

type Body = { data?: RawCountry[] };

// The list last fetched, kept in serverlist.json for when it can't be: where the network drops most of Fastly's
// addresses (Iran, in the evening), Remote Settings' answer often doesn't come, and without a relay 2 of 6 starts
// failed there on it alone, the VPN's token being kept (auth.ts) and Guardian answering. The list changes seldom.
const keptFile = () => join(userHome(), ".config", "foxhole-vpn", "serverlist.json");

/** The list kept, or null if there's none (or the file isn't one). */
function keptList(): Body | null {
  try {
    const kept = JSON.parse(readFileSync(keptFile(), "utf8")) as Body;
    return Array.isArray(kept?.data) && kept.data.length ? kept : null;
  } catch {
    return null;
  }
}

/** Remote Settings' answer, kept for next time; through the relay where it's blocked. */
async function fetchBody(signal?: AbortSignal): Promise<Body> {
  const res = await mozillaFetch(SERVERLIST_URL, {}, signal);
  if (!res.ok) {
    throw new Error(`Server list fetch failed: HTTP ${res.status}`);
  }
  const body = (await res.json()) as Body;
  if (body.data?.length) {
    try {
      mkdirSync(dirname(keptFile()), { recursive: true, mode: 0o700 });
      writeFileSync(`${keptFile()}.tmp`, JSON.stringify(body));
      renameSync(`${keptFile()}.tmp`, keptFile());
    } catch {} // unwritten: fetched again next time
  }
  return body;
}

/**
 * Fetches the public country/server list; failing, the one kept from before (`orKept`: the doctor asks for the fetch's
 * own result). Excludes the reserved anycast entry. Picks the first record per country code (the collection ships
 * duplicates for the anycast catch-all).
 */
export async function fetchServerList(signal?: AbortSignal, orKept = true): Promise<Country[]> {
  let body: Body;
  try {
    body = await fetchBody(signal);
  } catch (err) {
    const kept = orKept ? keptList() : null;
    if (!kept) throw err;
    body = kept;
  }
  const seen = new Set<string>();
  const out: Country[] = [];
  for (const raw of body.data ?? []) {
    if (raw.code === RECOMMENDED_CODE || !raw.code) continue;
    if (seen.has(raw.code)) continue;
    seen.add(raw.code);
    out.push(toCountry(raw));
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

/** Picks a random non-quarantined server for a country, or null if none. */
export function pickServer(country: Country): Server | null {
  const usable = country.servers.filter((s) => !s.quarantined);
  if (usable.length === 0) return null;
  return usable[Math.floor(Math.random() * usable.length)];
}
