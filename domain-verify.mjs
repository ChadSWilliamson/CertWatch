/**
 * domain-verify.mjs
 * -----------------------------------------------------------------
 * Proves a customer actually controls a domain before Vigía Recon
 * runs any ACTIVE checks against it (requesting sensitive file
 * paths, etc.). Passive checks run on everything; active checks
 * only run on verified domains.
 *
 * Why: without this, anyone could add someone else's domain and
 * use Vigía Recon to probe it. That's unauthorized scanning, and it
 * would make Vigía Recon the tool doing it.
 *
 * How: same method Google Search Console and most SaaS tools use.
 * The dashboard shows a unique token; the customer adds it as a
 * DNS TXT record; we look for it here. It's re-checked on every
 * run, so if the domain changes hands and the record disappears,
 * active scanning stops automatically.
 *
 * Accepted record locations (either works):
 *   TXT  example.com                    "certwatch-verify=<token>"
 *   TXT  _certwatch.example.com         "certwatch-verify=<token>"
 */

import dns from "node:dns/promises";

export function hasVerificationRecord(txtRecords, token) {
  if (!token) return false;
  const expected = `certwatch-verify=${token}`;
  return txtRecords.some((chunks) => chunks.join("").trim() === expected);
}

export async function isDomainVerified(hostname, token) {
  const [root, sub] = await Promise.all([
    dns.resolveTxt(hostname).catch(() => []),
    dns.resolveTxt(`_certwatch.${hostname}`).catch(() => []),
  ]);
  return hasVerificationRecord([...root, ...sub], token);
}
