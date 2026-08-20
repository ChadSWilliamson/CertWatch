/**
 * CertWatch — core monitoring check
 * -----------------------------------------------------------------
 * Designed to run on a free scheduled runner (GitHub Actions cron
 * is the simplest option — real TLS socket access like this needs
 * Node's `tls` module, which isn't available inside Cloudflare
 * Workers. Workers are still fine for the dashboard/API/auth layer;
 * just run THIS script as a separate scheduled job.)
 *
 * What it does, once a day per domain:
 *   1. Opens a real TLS connection and reads the certificate's
 *      actual expiration date (not a guess — the live cert).
 *   2. Looks up domain registration expiry via a free WHOIS API.
 *   3. Fires an email through Resend if either crosses the
 *      30 / 14 / 3-day thresholds.
 *
 * Free-tier hosting for the cron itself: GitHub Actions
 * (free for public repos, 2,000 min/mo free on private) on a
 * schedule like:
 *   on:
 *     schedule:
 *       - cron: '0 13 * * *'   # once daily
 */
 
import { readFile, writeFile } from "node:fs/promises";
import { checkSSLExpiry } from "./ssl-check.mjs";
import { checkDomainExpiryWithRetry } from "./rdap-lookup.mjs";
import { checkNewCertificates } from "./cert-transparency.mjs";
import { getDnsSnapshot, hasDnsChanged } from "./dns-check.mjs";
 
const ALERT_THRESHOLDS = [30, 14, 3]; // days out, largest first
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const STATE_FILE = "./alert-state.json";
 
// ---- 1. SSL certificate check --------------------------------------
// Handled by ssl-check.mjs — see the checkSSLExpiry import above.
 
// ---- 2. Domain registration check -----------------------------------
// Handled by rdap-lookup.mjs (RDAP first, WHOIS fallback) — see
// the checkDomainExpiryWithRetry import above.
 
// ---- 3. The "notebook" — remembering what we already alerted about --
//
// Shape of the file:
// {
//   "example.com": {
//     "ssl": 30,              <- last SSL alert tier sent, or null
//     "domain": null,         <- last domain alert tier sent, or null
//     "knownCertIds": [1,2],  <- every CT certificate ID we've seen
//     "dnsSnapshot": {...}    <- last known MX/TXT records
//   }
// }
 
function defaultDomainState() {
  return { ssl: null, domain: null, knownCertIds: [], dnsSnapshot: null };
}
 
async function loadState() {
  try {
    const raw = await readFile(STATE_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    // First run ever, or file got deleted — start with a blank notebook.
    return {};
  }
}
 
async function saveState(state) {
  await writeFile(STATE_FILE, JSON.stringify(state, null, 2));
}
 
// Given how many days are left, which "zone" are we in right now?
// Returns the smallest threshold that still applies, or null if
// we're outside all of them (nothing to worry about).
function currentTier(daysLeft) {
  const sorted = [...ALERT_THRESHOLDS].sort((a, b) => a - b); // [3, 14, 30]
  for (const t of sorted) {
    if (daysLeft <= t) return t;
  }
  return null;
}
 
// ---- 4. Alerting -------------------------------------------------
 
async function sendAlert(toEmail, subject, body) {
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      // onboarding@resend.dev works immediately with no setup, but
      // only sends to the email address you signed up to Resend
      // with. Once you verify your own domain (later), swap this
      // to something like "alerts@certwatch.app" and you'll be
      // able to send to any customer's email.
      from: "onboarding@resend.dev",
      to: toEmail,
      subject,
      text: body,
    }),
  });
}
 
// Decides whether to actually send, and updates the notebook either way.
// Returns true if an alert should go out.
function shouldAlert(state, domain, checkType, daysLeft) {
  const tier = currentTier(daysLeft);
  const lastAlerted = state[domain][checkType];
 
  if (tier === null) {
    // Fully outside the danger zone (e.g. just renewed) — reset the
    // notebook so a future re-entry into the 30-day zone alerts again.
    state[domain][checkType] = null;
    return false;
  }
 
  if (tier === lastAlerted) {
    // Already warned about this exact zone — stay quiet today.
    return false;
  }
 
  // New zone (either first warning, or it got more urgent) — alert,
  // and write down that we've now warned about this zone.
  state[domain][checkType] = tier;
  return true;
}
 
// ---- 4. Main runner ------------------------------------------------
 
async function runChecks(accounts) {
  // accounts = [{ email, domains: ["example.com", ...] }, ...]
  // pulled from your DB (Supabase) at the top of the run.
  const state = await loadState();
 
  for (const account of accounts) {
    for (const domain of account.domains) {
      console.log(`Checking ${domain}...`);
      // Merge in any new notebook fields (like knownCertIds, dnsSnapshot)
      // for domains that were already being tracked before those
      // features existed — without this, an old entry missing those
      // fields would crash when we try to read them.
      state[domain] = { ...defaultDomainState(), ...state[domain] };
      try {
        const ssl = await checkSSLExpiry(domain);
        console.log(`  SSL: ${ssl.daysLeft} days left`);
        if (shouldAlert(state, domain, "ssl", ssl.daysLeft)) {
          console.log(`  → Sending SSL alert to ${account.email}`);
          await sendAlert(
            account.email,
            `⚠️ SSL certificate for ${domain} expires in ${ssl.daysLeft} days`,
            `The SSL certificate for ${domain} expires on ${ssl.expiresAt.toDateString()}. Renew it before then to avoid a browser security warning.`
          );
        } else {
          console.log(`  (no new alert needed)`);
        }
 
        const reg = await checkDomainExpiryWithRetry(domain);
        console.log(`  Domain: ${reg.daysLeft} days left`);
        if (shouldAlert(state, domain, "domain", reg.daysLeft)) {
          console.log(`  → Sending domain alert to ${account.email}`);
          await sendAlert(
            account.email,
            `⚠️ Domain registration for ${domain} expires in ${reg.daysLeft} days`,
            `${domain} is registered until ${reg.expiresAt.toDateString()}. Renew it to keep the domain from lapsing.`
          );
        } else {
          console.log(`  (no new alert needed)`);
        }
 
        // TODO: write ssl.daysLeft / reg.daysLeft back to Supabase
        // so the dashboard health score reflects today's scan.
 
        // ---- Certificate Transparency check ----
        try {
          const { newCertificates, allCertIds } = await checkNewCertificates(
            domain,
            state[domain].knownCertIds
          );
          const isFirstRun = state[domain].knownCertIds.length === 0;
          console.log(`  CT: ${newCertificates.length} new certificate(s) since last check`);
 
          // Don't alert on the very first run — that would just be
          // "here's every certificate this domain has ever had,"
          // which isn't useful. Only alert on genuinely NEW activity
          // after we already have a baseline.
          if (!isFirstRun && newCertificates.length > 0) {
            console.log(`  → Sending CT alert to ${account.email}`);
            const summary = newCertificates
              .map((c) => `- Issued ${c.not_before} by ${c.issuer_name}`)
              .join("\n");
            await sendAlert(
              account.email,
              `🔍 New SSL certificate detected for ${domain}`,
              `A new SSL certificate was just issued for ${domain}. If you just renewed it, this is nothing to worry about. If you didn't, this could mean someone else issued a certificate for your domain — worth checking immediately.\n\n${summary}`
            );
          }
          state[domain].knownCertIds = allCertIds;
        } catch (err) {
          console.error(`  CT check failed (crt.sh may be temporarily down):`, err.message);
          // Don't touch state[domain].knownCertIds — just try again next run.
        }
 
        // ---- DNS change check ----
        try {
          const currentSnapshot = await getDnsSnapshot(domain);
          const previousSnapshot = state[domain].dnsSnapshot;
          const changed = hasDnsChanged(previousSnapshot, currentSnapshot);
          console.log(`  DNS: ${changed ? "changed since last check" : "unchanged"}`);
 
          if (changed) {
            console.log(`  → Sending DNS change alert to ${account.email}`);
            await sendAlert(
              account.email,
              `⚠️ DNS records changed for ${domain}`,
              `The MX or TXT records for ${domain} have changed since the last check. If you made this change on purpose, no action needed. If not, this can be a sign of a security issue — worth double-checking your DNS settings.`
            );
          }
          state[domain].dnsSnapshot = currentSnapshot;
        } catch (err) {
          console.error(`  DNS check failed:`, err.message);
        }
      } catch (err) {
        console.error(`Check failed for ${domain}:`, err.message);
        // A failed check is itself worth surfacing on the dashboard
        // as "last checked: error" rather than silently skipping.
      }
    }
  }
 
  await saveState(state);
  console.log("\nSaved alert-state.json");
}
 
// Example account fetch — replace with a real Supabase query later.
// For now, this is YOUR real info, so this is a genuine live test,
// not a simulation.
async function getAccountsFromDB() {
  return [
    {
      email: "zonaazulcrconsulting@gmail.com",
      domains: ["revelrybeverages.com"],
    },
  ];
}
 
console.log("Starting CertWatch check run...\n");
getAccountsFromDB()
  .then(runChecks)
  .then(() => console.log("\nCheck run finished."));
 
