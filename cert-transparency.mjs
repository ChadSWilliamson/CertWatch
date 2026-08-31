cat > cert-transparency.mjs << 'EOF'
/**
 * cert-transparency.mjs
 * -----------------------------------------------------------------
 * Checks crt.sh (a free, public log of every SSL certificate ever
 * issued for a domain) for certificates we haven't seen before.
 *
 * Why this matters: it's the one check that can catch something
 * genuinely serious — if a certificate shows up for a domain that
 * the site owner didn't request, that can mean someone compromised
 * their DNS or their certificate authority account. Most of the
 * time, a "new" certificate just means the site auto-renewed —
 * this module doesn't try to guess which; it just surfaces it so
 * a human can glance at it.
 *
 * No API key needed. crt.sh is free and public, but it's a
 * community-run service that can occasionally be slow — this
 * includes a longer timeout and a couple of retries to handle that.
 */

async function fetchCertificates(domain, attempts = 3) {
  const url = `https://crt.sh/?q=${domain}&output=json`;
  let lastError;

  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
      if (!res.ok) throw new Error(`crt.sh returned status ${res.status}`);
      return await res.json();
    } catch (err) {
      lastError = err;
      await new Promise((r) => setTimeout(r, 2000 * (i + 1)));
    }
  }
  throw new Error(`crt.sh lookup failed for ${domain}: ${lastError.message}`);
}

/**
 * Compares today's certificates against a list of certificate IDs
 * we've already seen and alerted on before.
 *
 * @param {string} domain
 * @param {number[]} knownCertIds - IDs seen on a previous run (from
 *   your saved state — empty array on the very first run).
 * @returns {{ newCertificates: object[], allCertIds: number[], allCerts: object[] }}
 *   allCerts is the full raw crt.sh response — subdomain-takeover.mjs
 *   reads subdomain names out of it so it doesn't need its own
 *   separate crt.sh call.
 */
export async function checkNewCertificates(domain, knownCertIds = []) {
  const certs = await fetchCertificates(domain);
  const knownSet = new Set(knownCertIds);

  const newCertificates = certs.filter((c) => !knownSet.has(c.id));
  const allCertIds = certs.map((c) => c.id);

  return { newCertificates, allCertIds, allCerts: certs };
}
EOF