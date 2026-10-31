/**
 * findings.mjs
 * -----------------------------------------------------------------
 * Shared shape for every security finding, plus the scoring that
 * turns a list of findings into one 0–100 "attacker's view" score.
 *
 * Every finding looks like:
 *   {
 *     key:      "email:dmarc-missing"   // stable ID, used for alert dedup
 *     category: "email" | "web" | "network" | "exposure"
 *     severity: "critical" | "high" | "medium" | "low" | "info"
 *     title:    one line, plain English
 *     detail:   what we saw
 *     fix:      what to do about it
 *   }
 */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

// How many points each finding knocks off the 100-point score.
const PENALTY = { critical: 25, high: 15, medium: 7, low: 2, info: 0 };

// Severities serious enough to email the customer about.
export const ALERT_SEVERITIES = new Set(["critical", "high", "medium"]);

export function finding(key, category, severity, title, detail, fix) {
  return { key, category, severity, title, detail, fix };
}

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
}

export function scoreFindings(findings) {
  let score = 100;
  for (const f of findings) score -= PENALTY[f.severity] ?? 0;
  return Math.max(0, score);
}

export function gradeForScore(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function cvssToSeverity(cvss) {
  if (cvss == null) return "medium";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
}
