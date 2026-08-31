/**
 * subdomain-takeover.mjs
 * -----------------------------------------------------------------
 * Checks whether any subdomain has a DNS record pointing at a
 * third-party cloud resource that's since been deleted — a
 * "dangling CNAME." Attackers scan for exactly this: they find the
 * dangling record, register the same resource name on the same
 * provider (a free GitHub Pages site, a Heroku app name, etc.), and
 * suddenly their content is served under your domain.
 *
 * Where the subdomain list comes from:
 *   No new network call. cert-transparency.mjs already fetches
 *   every certificate ever issued for the domain from crt.sh, and
 *   those certificates' names ARE mostly subdomains (SANs). We just
 *   read that same data differently.
 */

import { resolveCname } from "node:dns/promises";

const FINGERPRINTS = [
  { name: "GitHub Pages", cnamePattern: /\.github\.io$/i, fingerprint: "There isn't a GitHub Pages site here" },
  { name: "Heroku", cnamePattern: /\.herokudns\.com$|\.herokuapp\.com$/i, fingerprint: "No such app" },
  { name: "AWS S3", cnamePattern: /\.s3[.-][\w-]*\.amazonaws\.com$/i, fingerprint: "NoSuchBucket" },
  { name: "Azure App Service", cnamePattern: /\.azurewebsites\.net$/i, fingerprint: "Web Site not found" },
  { name: "Azure Traffic Manager", cnamePattern: /\.trafficmanager\.net$/i, fingerprint: "not found" },
  { name: "Shopify", cnamePattern: /\.myshopify\.com$/i, fingerprint: "Sorry, this shop is currently unavailable" },
  { name: "Fastly", cnamePattern: /\.fastly\.net$/i, fingerprint: "Fastly error: unknown domain" },
  { name: "Unbounce", cnamePattern: /\.unbouncepages\.com$/i, fingerprint: "The requested URL was not found on this server" },
  { name: "Zendesk", cnamePattern: /\.zendesk\.com$/i, fingerprint: "Help Center Closed" },
  { name: "Surge.sh", cnamePattern: /\.surge\.sh$/i, fingerprint: "project not found" },
  { name: "Webflow", cnamePattern: /\.webflow\.io$/i, fingerprint: "The page you are looking for doesn't exist" },
  { name: "Cargo Collective", cnamePattern: /\.cargocollective\.com$/i, fingerprint: "404 Not Found" },
];

export function extractSubdomains(certs, rootDomain) {
  const names = new Set();
  const root = rootDomain.toLowerCase();

  for (const cert of certs) {
    const raw = cert.name_value || "";
    for (const line of raw.split("\n")) {
      const host = line.trim().toLowerCase();
      if (!host || host.startsWith("*")) continue;
      if (host === root || host.endsWith(`.${root}`)) {
        names.add(host);
      }
    }
  }

  return [...names];
}

async function checkSubdomain(hostname) {
  let chain;
  try {
    chain = await resolveCname(hostname);
  } catch {
    return null;
  }

  const target = chain[chain.length - 1];
  const provider = FINGERPRINTS.find((f) => f.cnamePattern.test(target));
  if (!provider) return null;

  try {
    const res = await fetch(`https://${hostname}`, {
      signal: AbortSignal.timeout(10000),
      redirect: "follow",
    });
    const body = await res.text();
    if (body.includes(provider.fingerprint)) {
      return { hostname, cnameTarget: target, service: provider.name, confirmed: true };
    }
    return null;
  } catch {
    return { hostname, cnameTarget: target, service: provider.name, confirmed: false };
  }
}

export async function checkSubdomainTakeovers(subdomains, previouslyFlagged = []) {
  const CONCURRENCY = 5;
  const queue = [...subdomains];
  const findings = [];

  async function worker() {
    while (queue.length) {
      const hostname = queue.shift();
      const result = await checkSubdomain(hostname);
      if (result) findings.push(result);
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  const allFlaggedHostnames = findings.map((f) => f.hostname);
  const newFindings = findings.filter((f) => !previouslyFlagged.includes(f.hostname));

  return { newFindings, allFlaggedHostnames };
}
