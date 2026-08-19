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

import { checkSSLExpiry } from "./ssl-check.mjs";
import { checkDomainExpiryWithRetry } from "./rdap-lookup.mjs";

const ALERT_THRESHOLDS = [30, 14, 3]; // days out
const RESEND_API_KEY = process.env.RESEND_API_KEY;

// ---- 1. SSL certificate check --------------------------------------
// Handled by ssl-check.mjs — see the checkSSLExpiry import above.

// ---- 2. Domain registration check -----------------------------------
// Handled by rdap-lookup.mjs (RDAP first, WHOIS fallback) — see
// the checkDomainExpiryWithRetry import above.

// ---- 3. Alerting -------------------------------------------------

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

function crossedThreshold(daysLeft) {
  // Alerts fire once the days-left drops to 30 or fewer — not just
  // on the exact day. A cert with 23 days left should still alert,
  // even though 23 isn't one of the exact numbers in the list.
  //
  // Heads up: with no database yet, this will re-send an email
  // every single day once you're inside 30 days, rather than once
  // per threshold. That's fine for testing — for real customers,
  // you'll want to store "last alert sent" so it doesn't spam them.
  const highestThreshold = Math.max(...ALERT_THRESHOLDS);
  return daysLeft <= highestThreshold;
}

// ---- 4. Main runner ------------------------------------------------

async function runChecks(accounts) {
  // accounts = [{ email, domains: ["example.com", ...] }, ...]
  // pulled from your DB (Supabase) at the top of the run.
  for (const account of accounts) {
    for (const domain of account.domains) {
      console.log(`Checking ${domain}...`);
      try {
        const ssl = await checkSSLExpiry(domain);
        console.log(`  SSL: ${ssl.daysLeft} days left`);
        if (crossedThreshold(ssl.daysLeft)) {
          console.log(`  → Sending SSL alert to ${account.email}`);
          await sendAlert(
            account.email,
            `⚠️ SSL certificate for ${domain} expires in ${ssl.daysLeft} days`,
            `The SSL certificate for ${domain} expires on ${ssl.expiresAt.toDateString()}. Renew it before then to avoid a browser security warning.`
          );
        }

        const reg = await checkDomainExpiryWithRetry(domain);
        console.log(`  Domain: ${reg.daysLeft} days left`);
        if (crossedThreshold(reg.daysLeft)) {
          console.log(`  → Sending domain alert to ${account.email}`);
          await sendAlert(
            account.email,
            `⚠️ Domain registration for ${domain} expires in ${reg.daysLeft} days`,
            `${domain} is registered until ${reg.expiresAt.toDateString()}. Renew it to keep the domain from lapsing.`
          );
        }

        // TODO: write ssl.daysLeft / reg.daysLeft back to Supabase
        // so the dashboard health score reflects today's scan.
      } catch (err) {
        console.error(`Check failed for ${domain}:`, err.message);
        // A failed check is itself worth surfacing on the dashboard
        // as "last checked: error" rather than silently skipping.
      }
    }
  }
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
