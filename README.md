# CertWatch

A full-stack SSL, domain, and DNS monitoring tool — built solo, end-to-end, as a hands-on learning project covering backend automation, database design, authentication, and frontend development.

**Status:** Functional demo. Built to explore the full lifecycle of a SaaS product — not currently in commercial production.

## What it does

CertWatch watches a website's "vitals" and alerts the owner before something breaks:

- **SSL certificate monitoring** — flags certificates expiring within 30/14/3 days
- **Domain expiration monitoring** — via RDAP (with a WHOIS API fallback for domains RDAP doesn't cover)
- **Certificate Transparency monitoring** — detects new certificates issued for a domain via crt.sh, a signal that can indicate compromise
- **DNS change detection** — snapshots MX/TXT records and flags unexpected changes (a common sign of email hijacking)
- **Uptime monitoring** — checks every ~15 minutes, alerts only on actual state changes (down / back up)
- **Email alerts** — via Resend, with de-duplication logic so the same issue doesn't re-alert every run

## How it's built

- **Monitoring engine** (`check.js`, `uptime.js`): Node.js scripts run on a schedule via **GitHub Actions** — no server to maintain, runs entirely on free-tier infrastructure
- **Database**: **Supabase** (Postgres) with Row Level Security, storing accounts, domains, and per-domain alert state
- **Auth & customer dashboard** (`dashboard.html`): a single-file app using Supabase Auth (signup/login/password reset) and Supabase Storage (avatar uploads) — no build tooling required
- **Alerting**: Resend API for transactional email
- **Landing page** (`certwatch-landing.html` / `index.html`): a from-scratch design built around a "live vitals monitor" concept

## Why these choices

Every piece was chosen to run on a genuinely free tier with minimal ongoing maintenance: GitHub Actions instead of a paid server, RDAP before falling back to a paid WHOIS API, Supabase's free Postgres tier, Resend's free email tier. The goal was proving out a real product end-to-end without any recurring cost.

## What this project demonstrates

- Designing and enforcing a relational schema with Row Level Security policies
- Building real authentication flows (signup, login, password recovery, account deletion) from scratch
- Working with third-party APIs (RDAP, WHOIS, crt.sh, Resend) including handling their real-world quirks — rate limits, outages, and inconsistent documentation
- Scheduling and running background jobs without a dedicated server
- Iterative debugging of a live, deployed system

## Notably *not* built (by design)

- Payment processing / Stripe integration
- SMS alerts, PDF reports, white-label reporting (planned features for a "Pro" tier that were scoped but not built)
- A public production launch

---

*Built by Chad Williamson.*
