/**
 * active-scan.mjs
 * -----------------------------------------------------------------
 * The "attacker poking at the door" tier. Requests a short list of
 * paths that commonly leak secrets when a deploy goes wrong — a
 * copied .git folder, a .env file full of API keys, a database
 * dump left in the web root.
 *
 * ⚠ ONLY runs on domains the customer has verified they own
 * (see domain-verify.mjs). check.js enforces that; this module
 * also refuses private/internal addresses (net-guard.mjs).
 *
 * Kept deliberately small and polite:
 *   - ~15 GET requests per domain, one at a time
 *   - identifies itself with a Vigía Recon User-Agent
 *   - never follows redirects, never sends data, never logs in
 *   - only reads the first 64 KB of any response
 *
 * Each check confirms the CONTENT looks like the real thing, not
 * just a 200 status — many sites return 200 for every URL.
 */

import { finding } from "./findings.mjs";
import { resolvePublicIps } from "./net-guard.mjs";
import { USER_AGENT } from "./web-exposure.mjs";

const MAX_BYTES = 64 * 1024;
const TIMEOUT_MS = 8000;
const DELAY_MS = 300;

const looksLikeHtml = (t) => /<(html|!doctype|head|body)\b/i.test(t.slice(0, 500));

export const PROBES = [
  {
    path: "/.git/HEAD", key: "exposed-git", severity: "critical",
    title: "Git repository is downloadable",
    detail: "The .git folder is public. Attackers can rebuild your full source code, history, and any secrets ever committed.",
    fix: "Block access to /.git in your web server config and remove the folder from the web root.",
    test: (t) => /^ref: refs\/heads\/\S+\s*$/m.test(t) || /^[0-9a-f]{40}\s*$/.test(t),
  },
  {
    path: "/.git/config", key: "exposed-git-config", severity: "critical",
    title: "Git config is public",
    detail: "The .git/config file is readable and may include repository URLs with embedded credentials.",
    fix: "Block access to /.git in your web server config.",
    test: (t) => /\[core\]/.test(t) && !looksLikeHtml(t),
  },
  {
    path: "/.env", key: "exposed-env", severity: "critical",
    title: ".env file is public",
    detail: "The .env file is readable. These usually hold database passwords and API keys. Treat every value in it as compromised.",
    fix: "Remove .env from the web root, block dotfiles in your server config, and rotate every secret it contained.",
    test: (t) => !looksLikeHtml(t) && /^[A-Z][A-Z0-9_]{2,}=.+$/m.test(t),
  },
  {
    path: "/wp-config.php.bak", key: "exposed-wp-config-backup", severity: "critical",
    title: "WordPress config backup is public",
    detail: "A backup of wp-config.php is downloadable as plain text, exposing database credentials.",
    fix: "Delete the backup file and rotate the database password.",
    test: (t) => /DB_PASSWORD|DB_USER/.test(t),
  },
  {
    path: "/backup.sql", key: "exposed-sql-dump", severity: "critical",
    title: "Database dump is public",
    detail: "A SQL dump is downloadable from the web root.",
    fix: "Delete the file and assume its data is exposed.",
    test: (t) => /CREATE TABLE|INSERT INTO/i.test(t) && !looksLikeHtml(t),
  },
  {
    path: "/dump.sql", key: "exposed-sql-dump-2", severity: "critical",
    title: "Database dump is public",
    detail: "A SQL dump is downloadable from the web root.",
    fix: "Delete the file and assume its data is exposed.",
    test: (t) => /CREATE TABLE|INSERT INTO/i.test(t) && !looksLikeHtml(t),
  },
  {
    path: "/.htpasswd", key: "exposed-htpasswd", severity: "high",
    title: ".htpasswd is public",
    detail: "Password hashes for protected areas are downloadable and can be cracked offline.",
    fix: "Move .htpasswd outside the web root and change those passwords.",
    test: (t) => !looksLikeHtml(t) && /^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$5\$|\$6\$)/m.test(t),
  },
  {
    path: "/.svn/wc.db", key: "exposed-svn", severity: "high",
    title: "Subversion metadata is public",
    detail: "The .svn folder is readable, exposing source code file lists and history.",
    fix: "Block access to /.svn and remove it from the web root.",
    test: (t) => t.startsWith("SQLite format 3"),
  },
  {
    path: "/.DS_Store", key: "exposed-ds-store", severity: "low",
    title: ".DS_Store file is public",
    detail: "A macOS folder index is downloadable, revealing file and folder names on the server.",
    fix: "Delete .DS_Store files from the web root and block dotfiles.",
    test: (t) => t.slice(4, 8) === "Bud1",
  },
  {
    path: "/server-status", key: "exposed-server-status", severity: "medium",
    title: "Apache server-status page is public",
    detail: "Shows live requests, client IPs, and internal URLs.",
    fix: "Restrict /server-status to localhost in the Apache config.",
    test: (t) => /Apache Server Status/i.test(t),
  },
  {
    path: "/phpinfo.php", key: "exposed-phpinfo", severity: "medium",
    title: "phpinfo() page is public",
    detail: "Reveals PHP version, extensions, server paths, and sometimes environment variables.",
    fix: "Delete phpinfo.php from the server.",
    test: (t) => /<title>phpinfo\(\)<\/title>|PHP Version \d/i.test(t),
  },
  {
    path: "/actuator/env", key: "exposed-spring-actuator", severity: "high",
    title: "Spring Boot actuator is public",
    detail: "The /actuator/env endpoint exposes configuration and sometimes credentials.",
    fix: "Disable or secure actuator endpoints (management.endpoints.web.exposure.include).",
    test: (t) => /"propertySources"|"activeProfiles"/.test(t),
  },
  {
    path: "/phpmyadmin/", key: "exposed-phpmyadmin", severity: "high",
    title: "phpMyAdmin login is public",
    detail: "A database admin panel is reachable from the whole internet and is a constant brute-force target.",
    fix: "Restrict phpMyAdmin to a VPN or specific IP addresses.",
    test: (t) => /phpMyAdmin/.test(t) && /pma_username|input_username/i.test(t),
  },
  {
    path: "/wp-login.php", key: "wordpress-login", severity: "info",
    title: "WordPress login page is public",
    detail: "Normal for WordPress, but it's the most brute-forced URL on the internet.",
    fix: "Turn on two-factor authentication and a login rate-limiting plugin.",
    test: (t) => /wp-submit|user_login/.test(t),
  },
];

async function readLimited(res) {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let total = 0;
  while (total < MAX_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  reader.cancel().catch(() => {});
  return Buffer.concat(chunks).subarray(0, MAX_BYTES).toString("latin1");
}

async function probe(hostname, path) {
  try {
    const res = await fetch(`https://${hostname}${path}`, {
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "User-Agent": USER_AGENT },
    });
    if (res.status !== 200) {
      res.body?.cancel().catch(() => {});
      return null;
    }
    return await readLimited(res);
  } catch {
    return null;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Caller MUST have confirmed domain ownership first.
 */
export async function runActiveScan(hostname, { verified }) {
  if (!verified) throw new Error(`Refusing active scan of unverified domain ${hostname}`);
  await resolvePublicIps(hostname); // throws on private/internal targets

  const findings = [];
  let securityTxt = false;

  for (const p of PROBES) {
    const body = await probe(hostname, p.path);
    if (body !== null && p.test(body)) {
      findings.push(finding(
        `exposure:${p.key}`, "exposure", p.severity,
        p.title, `Found at https://${hostname}${p.path}. ${p.detail}`, p.fix
      ));
    }
    await sleep(DELAY_MS);
  }

  const st = await probe(hostname, "/.well-known/security.txt");
  if (st && /^Contact:/im.test(st)) securityTxt = true;
  if (!securityTxt) {
    findings.push(finding(
      "exposure:no-security-txt", "exposure", "info",
      "No security.txt",
      "Security researchers who find a problem have no published way to reach you.",
      "Publish /.well-known/security.txt with a Contact: line (see securitytxt.org)."
    ));
  }

  return { findings };
}
