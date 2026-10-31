/**
 * vuln-intel.mjs
 * -----------------------------------------------------------------
 * "What does the internet already know about this server?"
 *
 * Attackers don't port-scan from scratch anymore. They look the IP
 * up in Shodan, which scans the whole internet continuously. We do
 * the same thing, using Shodan's free, keyless services:
 *
 *   - InternetDB (internetdb.shodan.io): open ports + known CVEs per IP
 *   - CVEDB (cvedb.shodan.io): CVE details — CVSS score, and whether
 *     it's on CISA's Known Exploited Vulnerabilities (KEV) list
 *
 * Passive: we never touch the customer's server here, we only ask
 * Shodan what it already saw.
 *
 * Licensing note: InternetDB and CVEDB are free for non-commercial
 * use. Fine for CertWatch as a portfolio project; a paid launch
 * would need a Shodan license (same situation as Google Safe
 * Browsing, which we skipped for that reason).
 */

import { finding, cvssToSeverity } from "./findings.mjs";
import { isPrivateIp } from "./net-guard.mjs";
import { USER_AGENT } from "./web-exposure.mjs";

const MAX_CVES_ENRICHED = 25; // be polite to a free service
const TIMEOUT_MS = 10000;

// Services that shouldn't be reachable from the whole internet.
const RISKY_PORTS = {
  21: { name: "FTP", severity: "medium", why: "sends passwords unencrypted and is a frequent brute-force target" },
  23: { name: "Telnet", severity: "high", why: "sends everything, including passwords, unencrypted" },
  445: { name: "SMB (Windows file sharing)", severity: "high", why: "is the entry point for many ransomware worms" },
  1433: { name: "Microsoft SQL Server", severity: "high", why: "exposes the database directly to password guessing and exploits" },
  2375: { name: "Docker API (unencrypted)", severity: "critical", why: "lets anyone run containers on the host — full takeover" },
  3306: { name: "MySQL", severity: "high", why: "exposes the database directly to password guessing and exploits" },
  3389: { name: "Remote Desktop (RDP)", severity: "high", why: "is one of the most common ransomware entry points" },
  5432: { name: "PostgreSQL", severity: "high", why: "exposes the database directly to password guessing and exploits" },
  5900: { name: "VNC", severity: "high", why: "gives remote screen control, often with weak or no passwords" },
  6379: { name: "Redis", severity: "critical", why: "often runs with no password and can be abused to run commands" },
  9200: { name: "Elasticsearch", severity: "critical", why: "frequently leaks entire databases when left open" },
  10250: { name: "Kubernetes kubelet", severity: "high", why: "can allow running commands inside cluster containers" },
  11211: { name: "Memcached", severity: "high", why: "leaks cached data and is abused for DDoS amplification" },
  27017: { name: "MongoDB", severity: "critical", why: "frequently leaks entire databases when left open" },
};

async function getJson(url) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
  });
  if (res.status === 404) return null; // Shodan's "nothing known"
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

export async function lookupIp(ip) {
  return getJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
}

const cveCache = new Map();
export async function lookupCve(cveId) {
  if (!cveCache.has(cveId)) {
    cveCache.set(cveId, getJson(`https://cvedb.shodan.io/cve/${encodeURIComponent(cveId)}`).catch(() => null));
  }
  return cveCache.get(cveId);
}

export async function cvesForCpe(cpe23) {
  const data = await getJson(
    `https://cvedb.shodan.io/cves?cpe23=${encodeURIComponent(cpe23)}&limit=${MAX_CVES_ENRICHED}`
  ).catch(() => null);
  return data?.cves || [];
}

// ---- Pure analysis (testable) -------------------------------------

export function analyzePorts(ip, ports) {
  const out = [];
  for (const port of ports) {
    // eslint-disable-next-line security/detect-object-injection -- port is a number from Shodan
    const risk = RISKY_PORTS[port];
    if (!risk) continue;
    out.push(finding(
      `network:port-${port}`, "network", risk.severity,
      `${risk.name} is open to the internet (port ${port})`,
      `Shodan sees port ${port} open on ${ip}. ${risk.name} ${risk.why}.`,
      `Close port ${port} at the firewall, or restrict it to a VPN / specific IPs.`
    ));
  }
  return out;
}

export function cveFinding(cve, source) {
  const cvss = cve.cvss_v3 ?? cve.cvss ?? null;
  let severity = cvssToSeverity(cvss);
  if (cve.kev) severity = "critical";

  const summary = (cve.summary || "").replace(/\s+/g, " ").slice(0, 240);
  const tags = [
    cvss != null ? `CVSS ${cvss}` : null,
    cve.kev ? "actively exploited (CISA KEV)" : null,
    cve.epss != null ? `${Math.round(cve.epss * 100)}% exploit probability (EPSS)` : null,
  ].filter(Boolean).join(", ");

  return finding(
    `vuln:${cve.cve_id}`, "network", severity,
    `${cve.cve_id}${cve.kev ? " — known exploited" : ""}`,
    `${source}. ${tags ? tags + ". " : ""}${summary}`,
    "Update the affected software. Version-based matches can be false positives if your vendor backported the fix; confirm with your host."
  );
}

// ---- Main ---------------------------------------------------------

/**
 * @param ips   public IPv4 addresses for the hostname
 * @param tech  fingerprinted software from web-exposure.mjs
 */
export async function scanVulnIntel(ips, tech = []) {
  const findings = [];
  const cveSources = new Map(); // cveId -> where we saw it
  const hosts = [];

  for (const ip of ips.slice(0, 5)) {
    if (isPrivateIp(ip)) continue;
    let data;
    try {
      data = await lookupIp(ip);
    } catch (err) {
      console.error(`  InternetDB lookup failed for ${ip}:`, err.message);
      continue;
    }
    if (!data) continue;
    hosts.push({ ip, ports: data.ports || [], tags: data.tags || [] });

    // Shared CDN edge IPs belong to Cloudflare/Akamai/etc., not the
    // customer — their ports and CVEs would be misleading.
    if ((data.tags || []).includes("cdn")) continue;

    findings.push(...analyzePorts(ip, data.ports || []));
    for (const id of data.vulns || []) {
      if (!cveSources.has(id)) cveSources.set(id, `Shodan matched this to software on ${ip}`);
    }
  }

  for (const t of tech) {
    for (const cve of await cvesForCpe(t.cpe23)) {
      if (!cveSources.has(cve.cve_id)) {
        cveSources.set(cve.cve_id, `Possible match for ${t.name} ${t.version} shown in your site's headers`);
        cveCache.set(cve.cve_id, Promise.resolve(cve));
      }
    }
  }

  const ids = [...cveSources.keys()].slice(0, MAX_CVES_ENRICHED);
  for (const id of ids) {
    const cve = await lookupCve(id);
    if (cve) findings.push(cveFinding(cve, cveSources.get(id)));
  }

  if (cveSources.size > MAX_CVES_ENRICHED) {
    findings.push(finding(
      "vuln:many-more", "network", "info",
      `${cveSources.size - MAX_CVES_ENRICHED} more CVEs not shown`,
      "This server matches a large number of known vulnerabilities, which usually means seriously outdated software.",
      "Prioritize updating the server's software stack."
    ));
  }

  return { findings, hosts, behindCdn: hosts.some((h) => h.tags.includes("cdn")) };
}
