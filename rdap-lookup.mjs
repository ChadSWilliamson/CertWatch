/**
 * CertWatch — domain registration expiry lookup
 * -----------------------------------------------------------------
 * Strategy: try RDAP first (free, no key, structured JSON, run by
 * the registries themselves). Only fall back to a paid WHOIS API
 * for TLDs that don't have an RDAP server yet — mostly older
 * ccTLDs (.io, .co, some country codes).
 *
 * Why this matters: RDAP eliminates the two biggest WHOIS pain
 * points — rate limiting on free tiers, and unstructured text you
 * have to regex-parse (registrar formats aren't consistent).
 */

const WHOIS_API_KEY = process.env.WHOIS_API_KEY; // fallback only

// ---- RDAP bootstrap: maps TLD -> RDAP server -------------------
// IANA publishes this list and updates it periodically. Cache it
// for a week — no reason to refetch on every domain check.

let rdapServerCache = null;
let rdapCacheFetchedAt = 0;
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 1 week

async function getRdapServer(tld) {
  const now = Date.now();
  if (!rdapServerCache || now - rdapCacheFetchedAt > CACHE_TTL_MS) {
    const res = await fetch("https://data.iana.org/rdap/dns.json");
    if (!res.ok) throw new Error("Failed to fetch RDAP bootstrap file");
    const data = await res.json();
    rdapServerCache = new Map();
    for (const [tlds, servers] of data.services) {
      for (const t of tlds) {
        rdapServerCache.set(t.toLowerCase(), servers[0].replace(/\/$/, ""));
      }
    }
    rdapCacheFetchedAt = now;
  }
  return rdapServerCache.get(tld.toLowerCase()) || null;
}

// ---- RDAP lookup -------------------------------------------------

async function rdapLookup(domain) {
  const tld = domain.split(".").pop();
  const server = await getRdapServer(tld);
  if (!server) return null; // no RDAP support for this TLD

  const res = await fetch(`${server}/domain/${domain}`, {
    headers: { Accept: "application/rdap+json" },
  });

  if (res.status === 404) throw new Error(`${domain} not found in registry`);
  if (res.status === 429) throw new Error(`Rate limited by RDAP server for ${tld}`);
  if (!res.ok) throw new Error(`RDAP lookup failed for ${domain} (${res.status})`);

  const data = await res.json();
  const expirationEvent = (data.events || []).find(
    (e) => e.eventAction === "expiration"
  );
  if (!expirationEvent) throw new Error(`No expiration date in RDAP response for ${domain}`);

  const expiresAt = new Date(expirationEvent.eventDate);
  const daysLeft = Math.ceil((expiresAt - Date.now()) / 86_400_000);
  return { domain, expiresAt, daysLeft, source: "rdap" };
}

// ---- WHOIS fallback (only reached if RDAP has no server for the TLD) --

async function whoisLookup(domain) {
  if (!WHOIS_API_KEY) {
    throw new Error(`No RDAP support for ${domain} and no WHOIS_API_KEY configured`);
  }
  const res = await fetch(`https://whoisjsonapi.com/v1/${domain}`, {
    headers: { Authorization: `Bearer ${WHOIS_API_KEY}` },
  });
  if (!res.ok) throw new Error(`WHOIS fallback failed for ${domain} (${res.status})`);
  const data = await res.json();
  const expiresAt = new Date(data.domain.expiration_date);
  const daysLeft = Math.ceil((expiresAt - Date.now()) / 86_400_000);
  return { domain, expiresAt, daysLeft, source: "whois" };
}

// ---- Public entry point -------------------------------------------

export async function checkDomainExpiry(domain) {
  try {
    const rdapResult = await rdapLookup(domain);
    if (rdapResult) return rdapResult;
  } catch (err) {
    console.warn(`RDAP failed for ${domain}, falling back to WHOIS:`, err.message);
  }
  return whoisLookup(domain);
}

// ---- Simple retry wrapper for transient failures --------------------
// RDAP servers occasionally rate-limit or hiccup. Retry twice with
// backoff before giving up and marking the domain "check failed"
// on the dashboard rather than silently skipping it.

export async function checkDomainExpiryWithRetry(domain, attempts = 3) {
  let lastError;
  for (let i = 0; i < attempts; i++) {
    try {
      return await checkDomainExpiry(domain);
    } catch (err) {
      lastError = err;
      await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    }
  }
  throw lastError;
}
