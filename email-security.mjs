/**
 * email-security.mjs
 * -----------------------------------------------------------------
 * Looks at a domain's email defenses the way a phisher would:
 * "Can I send email that claims to be from this domain and have
 * it land in someone's inbox?"
 *
 * 100% passive — only public DNS lookups, nothing touches the
 * customer's servers. Safe to run on any domain.
 *
 * What we check:
 *   - SPF:    which servers may send mail for the domain
 *   - DMARC:  what receivers should do with mail that fails SPF/DKIM
 *   - DKIM:   cryptographic signing keys (probed on common selectors)
 *   - MTA-STS / TLS-RPT: forcing encrypted delivery to the domain
 */

import dns from "node:dns/promises";
import { finding } from "./findings.mjs";

const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2", "k3",
  "s1", "s2", "dkim", "mail", "smtp", "mandrill", "mxvault", "zoho",
  "protonmail", "protonmail2", "fm1", "fm2", "fm3", "sig1", "pm",
  "everlytickey1", "cm", "mailjet",
];

const SPF_LOOKUP_LIMIT = 10;

function makeResolver() {
  const r = new dns.Resolver({ timeout: 5000, tries: 2 });
  return {
    resolveTxt: (name) => r.resolveTxt(name),
    resolveMx: (name) => r.resolveMx(name),
  };
}

async function txtRecords(resolver, name) {
  try {
    const records = await resolver.resolveTxt(name);
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

// ---- SPF ----------------------------------------------------------

export function parseSpf(record) {
  const terms = record.trim().split(/\s+/).slice(1); // drop "v=spf1"
  const lookups = [];
  let allQualifier = null;
  let redirect = null;

  for (const raw of terms) {
    const term = raw.toLowerCase();
    const qualifier = /^[+\-~?]/.test(term) ? term[0] : "+";
    const body = term.replace(/^[+\-~?]/, "");

    if (body === "all") allQualifier = qualifier;
    else if (body.startsWith("include:")) lookups.push({ type: "include", target: body.slice(8) });
    else if (body.startsWith("redirect=")) {
      redirect = body.slice(9);
      lookups.push({ type: "redirect", target: redirect });
    } else if (body === "a" || body.startsWith("a:") || body.startsWith("a/")) lookups.push({ type: "a" });
    else if (body === "mx" || body.startsWith("mx:") || body.startsWith("mx/")) lookups.push({ type: "mx" });
    else if (body === "ptr" || body.startsWith("ptr:")) lookups.push({ type: "ptr" });
    else if (body.startsWith("exists:")) lookups.push({ type: "exists" });
  }

  return { allQualifier, redirect, lookups };
}

// Counts DNS lookups the way receivers do (RFC 7208 §4.6.4),
// following include:/redirect= chains. Stops early past the limit.
async function countSpfLookups(resolver, domain, depth = 0, seen = new Set()) {
  if (depth > 10 || seen.has(domain)) return 0;
  seen.add(domain);

  const spf = (await txtRecords(resolver, domain)).find((r) => /^v=spf1(\s|$)/i.test(r));
  if (!spf) return 0;

  const { lookups } = parseSpf(spf);
  let count = 0;
  for (const l of lookups) {
    count += 1;
    if (count > SPF_LOOKUP_LIMIT) return count;
    if (l.type === "include" || l.type === "redirect") {
      count += await countSpfLookups(resolver, l.target, depth + 1, seen);
    }
  }
  return count;
}

export function analyzeSpf(spfRecords, lookupCount) {
  const out = [];

  if (spfRecords.length === 0) {
    out.push(finding(
      "email:spf-missing", "email", "high",
      "No SPF record",
      "The domain doesn't publish which servers are allowed to send its email.",
      'Add a TXT record starting with "v=spf1" listing your mail providers, ending in "-all" or "~all". If the domain never sends mail, use "v=spf1 -all".'
    ));
    return out;
  }

  if (spfRecords.length > 1) {
    out.push(finding(
      "email:spf-multiple", "email", "medium",
      "Multiple SPF records",
      `Found ${spfRecords.length} SPF records. Receivers treat this as an error and ignore SPF entirely.`,
      "Merge them into a single v=spf1 record."
    ));
  }

  const { allQualifier, redirect } = parseSpf(spfRecords[0]);

  if (allQualifier === "+") {
    out.push(finding(
      "email:spf-pass-all", "email", "critical",
      'SPF allows the entire internet ("+all")',
      "Any server in the world passes SPF for this domain.",
      'Change "+all" to "-all" (or "~all" while testing).'
    ));
  } else if (allQualifier === "?") {
    out.push(finding(
      "email:spf-neutral-all", "email", "medium",
      'SPF ends in "?all" (neutral)',
      "Mail from unlisted servers gets no penalty, so SPF gives almost no protection.",
      'Change "?all" to "~all" or "-all".'
    ));
  } else if (allQualifier === null && !redirect) {
    out.push(finding(
      "email:spf-no-all", "email", "medium",
      "SPF has no catch-all rule",
      'The record never says what to do with unlisted senders, which defaults to neutral.',
      'End the record with "-all" or "~all".'
    ));
  }

  if (lookupCount > SPF_LOOKUP_LIMIT) {
    out.push(finding(
      "email:spf-too-many-lookups", "email", "medium",
      "SPF exceeds the 10-lookup limit",
      `Evaluating the record takes more than ${SPF_LOOKUP_LIMIT} DNS lookups. Receivers return an error and SPF stops protecting you.`,
      "Remove unused include: entries or use a flattening service."
    ));
  }

  return out;
}

// ---- DMARC --------------------------------------------------------

export function parseDmarc(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const [k, ...v] = part.split("=");
    if (k && v.length) tags[k.trim().toLowerCase()] = v.join("=").trim();
  }
  return tags;
}

export function analyzeDmarc(dmarcRecords) {
  const out = [];

  if (dmarcRecords.length === 0) {
    out.push(finding(
      "email:dmarc-missing", "email", "high",
      "No DMARC record",
      "Nothing tells receivers to reject email that fakes this domain. This is the main gap phishers look for.",
      'Add a TXT record at _dmarc.<domain>: "v=DMARC1; p=none; rua=mailto:you@yourdomain" to start monitoring, then move to p=quarantine and p=reject.'
    ));
    return out;
  }

  if (dmarcRecords.length > 1) {
    out.push(finding(
      "email:dmarc-multiple", "email", "medium",
      "Multiple DMARC records",
      "Receivers ignore DMARC when more than one record exists.",
      "Keep a single v=DMARC1 record at _dmarc.<domain>."
    ));
  }

  const tags = parseDmarc(dmarcRecords[0]);
  const policy = (tags.p || "").toLowerCase();

  if (policy === "none" || !policy) {
    out.push(finding(
      "email:dmarc-policy-none", "email", "medium",
      'DMARC is monitor-only ("p=none")',
      "Spoofed mail is reported but still delivered.",
      "Once reports show your real senders pass, change to p=quarantine, then p=reject."
    ));
  } else if (policy === "quarantine") {
    out.push(finding(
      "email:dmarc-policy-quarantine", "email", "info",
      'DMARC set to quarantine',
      "Spoofed mail goes to spam rather than being rejected outright.",
      "Consider p=reject once you're confident in your sending setup."
    ));
  }

  const pct = tags.pct ? Number(tags.pct) : 100;
  if (policy !== "none" && pct < 100) {
    out.push(finding(
      "email:dmarc-partial-pct", "email", "low",
      `DMARC only applies to ${pct}% of mail`,
      "The rest of spoofed mail skips your policy.",
      "Raise pct to 100 (or remove the pct tag)."
    ));
  }

  if (!tags.rua) {
    out.push(finding(
      "email:dmarc-no-reports", "email", "low",
      "DMARC reports aren't being collected",
      "Without rua=, you can't see who is sending mail as your domain.",
      "Add rua=mailto:<address> to the DMARC record."
    ));
  }

  if (tags.sp && tags.sp.toLowerCase() === "none" && policy !== "none") {
    out.push(finding(
      "email:dmarc-subdomain-none", "email", "low",
      "Subdomains are unprotected (sp=none)",
      "Attackers can spoof anything.<domain> even though the main domain is protected.",
      "Remove sp=none or set it to match your main policy."
    ));
  }

  return out;
}

// ---- DKIM ---------------------------------------------------------

export function analyzeDkimKey(selector, record) {
  const tags = parseDmarc(record); // same tag=value; format
  const p = tags.p ?? "";
  if (p === "") {
    return { selector, revoked: true, bits: null };
  }
  // Rough RSA size from the base64 key length (DER-encoded public key).
  const bytes = Buffer.from(p, "base64").length;
  const bits = bytes <= 170 ? 1024 : bytes <= 300 ? 2048 : 4096;
  const type = (tags.k || "rsa").toLowerCase();
  return { selector, revoked: false, bits: type === "rsa" ? bits : null, type };
}

async function findDkimKeys(resolver, domain) {
  const found = [];
  await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      const recs = await txtRecords(resolver, `${sel}._domainkey.${domain}`);
      const rec = recs.find((r) => /v=DKIM1|k=rsa|k=ed25519|p=/i.test(r));
      if (rec) found.push(analyzeDkimKey(sel, rec));
    })
  );
  return found;
}

export function analyzeDkim(keys) {
  const out = [];
  const active = keys.filter((k) => !k.revoked);

  if (active.length === 0) {
    out.push(finding(
      "email:dkim-not-found", "email", "low",
      "No DKIM key found on common selectors",
      "Couldn't find a DKIM signing key. Your provider may use a custom selector name, which is fine.",
      "Confirm DKIM signing is turned on in your email provider's admin panel."
    ));
  }

  for (const k of active) {
    if (k.bits === 1024) {
      out.push(finding(
        `email:dkim-weak-${k.selector}`, "email", "low",
        `DKIM key "${k.selector}" is 1024-bit`,
        "1024-bit RSA is below current recommendations.",
        "Rotate to a 2048-bit key in your email provider's settings."
      ));
    }
  }
  return out;
}

// ---- Main ---------------------------------------------------------

export async function scanEmailSecurity(domain, resolver = makeResolver()) {
  const [rootTxt, dmarcTxt, mxRecords, mtaSts, tlsRpt] = await Promise.all([
    txtRecords(resolver, domain),
    txtRecords(resolver, `_dmarc.${domain}`),
    resolver.resolveMx(domain).catch(() => []),
    txtRecords(resolver, `_mta-sts.${domain}`),
    txtRecords(resolver, `_smtp._tls.${domain}`),
  ]);

  const spfRecords = rootTxt.filter((r) => /^v=spf1(\s|$)/i.test(r));
  const dmarcRecords = dmarcTxt.filter((r) => /^v=DMARC1/i.test(r));
  const lookupCount = spfRecords.length ? await countSpfLookups(resolver, domain) : 0;
  const receivesMail = mxRecords.length > 0;

  const findings = [...analyzeSpf(spfRecords, lookupCount), ...analyzeDmarc(dmarcRecords)];

  if (receivesMail) {
    findings.push(...analyzeDkim(await findDkimKeys(resolver, domain)));

    if (!mtaSts.some((r) => /^v=STSv1/i.test(r))) {
      findings.push(finding(
        "email:mta-sts-missing", "email", "info",
        "MTA-STS not set up",
        "Incoming mail could be downgraded to unencrypted delivery by an attacker on the network path.",
        "Publish an MTA-STS policy (most providers document this)."
      ));
    }
    if (!tlsRpt.some((r) => /^v=TLSRPTv1/i.test(r))) {
      findings.push(finding(
        "email:tls-rpt-missing", "email", "info",
        "TLS-RPT not set up",
        "You won't hear about failed encrypted deliveries.",
        'Add a TXT record at _smtp._tls.<domain>: "v=TLSRPTv1; rua=mailto:you@yourdomain".'
      ));
    }
  }

  return {
    findings,
    summary: {
      receivesMail,
      spf: spfRecords[0] || null,
      dmarc: dmarcRecords[0] || null,
      spfLookups: lookupCount,
    },
  };
}
