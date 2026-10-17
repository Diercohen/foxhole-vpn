// The VPN server list is published openly via Mozilla Remote Settings, so it
// needs no authentication. Same collection Firefox reads (IPProtectionServerlist).
const SERVERLIST_URL =
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

/**
 * Fetches the public country/server list. Excludes the reserved anycast entry.
 * Picks the first record per country code (the collection ships duplicates for
 * the anycast catch-all).
 */
export async function fetchServerList(signal?: AbortSignal): Promise<Country[]> {
  const res = await fetch(SERVERLIST_URL, { signal });
  if (!res.ok) {
    throw new Error(`Server list fetch failed: HTTP ${res.status}`);
  }
  const body = (await res.json()) as { data?: RawCountry[] };
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
