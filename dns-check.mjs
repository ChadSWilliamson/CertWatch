/**
 * dns-check.mjs
 * -----------------------------------------------------------------
 * Takes a "snapshot" of a domain's important DNS records — the
 * ones most likely to matter if they suddenly change without the
 * site owner knowing (which usually means something's been
 * hijacked or misconfigured, not that it's "expiring").
 *
 * No API key, no external service — this uses Node's own built-in
 * DNS resolver, since DNS is a public, standardized system with
 * no signup required to query it.
 *
 * What we check:
 *   - MX records: where the domain's email gets delivered. If
 *     these change unexpectedly, someone may be intercepting email.
 *   - TXT records: this is where SPF (anti-spoofing) and DKIM
 *     (email authenticity) rules live. Silent changes here are a
 *     classic sign of email-spoofing setup.
 */

import { resolveMx, resolveTxt } from "node:dns/promises";

export async function getDnsSnapshot(domain) {
  const [mxRecords, txtRecords] = await Promise.all([
    resolveMx(domain).catch(() => []),
    resolveTxt(domain).catch(() => []),
  ]);

  // Sort so the comparison later isn't thrown off by the order
  // records happen to come back in — only the actual content matters.
  const mx = mxRecords
    .map((r) => `${r.priority} ${r.exchange}`)
    .sort();
  const txt = txtRecords
    .map((r) => r.join(""))
    .sort();

  return { mx, txt };
}

/**
 * Compares today's snapshot against a previously saved one.
 * Returns true if anything meaningful changed.
 */
export function hasDnsChanged(previousSnapshot, currentSnapshot) {
  if (!previousSnapshot) return false; // first run ever — nothing to compare against yet
  return (
    JSON.stringify(previousSnapshot.mx) !== JSON.stringify(currentSnapshot.mx) ||
    JSON.stringify(previousSnapshot.txt) !== JSON.stringify(currentSnapshot.txt)
  );
}
