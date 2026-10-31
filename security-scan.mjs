/**
 * security-scan.mjs
 * -----------------------------------------------------------------
 * Runs every outside-in check for one domain and combines them
 * into a single report: findings sorted by severity, a 0–100
 * score, and a letter grade.
 *
 *   Passive (every domain):   email-security, web-exposure, vuln-intel
 *   Active  (verified only):  active-scan
 */

import { scanEmailSecurity } from "./email-security.mjs";
import { scanWebExposure } from "./web-exposure.mjs";
import { scanVulnIntel } from "./vuln-intel.mjs";
import { runActiveScan } from "./active-scan.mjs";
import { resolvePublicIps } from "./net-guard.mjs";
import { finding, sortFindings, scoreFindings, gradeForScore } from "./findings.mjs";

async function safely(label, fn) {
  try {
    return await fn();
  } catch (err) {
    console.error(`    ${label} failed:`, err.message);
    return { findings: [], failed: true };
  }
}

export async function runSecurityScan(hostname, { verified = false } = {}) {
  const findings = [];
  const meta = { verified, activeScanRan: false, tech: [], hosts: [], behindCdn: false };

  const email = await safely("Email scan", () => scanEmailSecurity(hostname));
  findings.push(...email.findings);
  meta.email = email.summary || null;

  // Everything below connects to the site, so make sure it's a real
  // public host first (blocks internal/private addresses).
  let ips = null;
  try {
    ips = await resolvePublicIps(hostname);
  } catch (err) {
    console.error(`    Skipping web/network checks: ${err.message}`);
  }

  if (ips) {
    const web = await safely("Web exposure scan", () => scanWebExposure(hostname));
    findings.push(...web.findings);
    meta.tech = web.tech || [];

    const intel = await safely("Vulnerability intel", () => scanVulnIntel(ips, meta.tech));
    findings.push(...intel.findings);
    meta.hosts = intel.hosts || [];
    meta.behindCdn = intel.behindCdn || false;

    if (verified) {
      const active = await safely("Active scan", () => runActiveScan(hostname, { verified }));
      findings.push(...active.findings);
      meta.activeScanRan = !active.failed;
    } else {
      findings.push(finding(
        "meta:unverified", "exposure", "info",
        "Active checks are off until you verify this domain",
        "Exposed-file checks (.git, .env, database dumps) only run on domains you've proven you own.",
        "Add the verification TXT record shown in your dashboard."
      ));
    }
  }

  const score = scoreFindings(findings);
  return {
    findings: sortFindings(findings),
    score,
    grade: gradeForScore(score),
    meta,
    scannedAt: new Date().toISOString(),
  };
}
