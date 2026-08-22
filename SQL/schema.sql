-- CertWatch database schema
-- -----------------------------------------------------------------
-- Paste this whole thing into Supabase's SQL Editor and click Run.
-- It creates three tables: accounts, domains, and alert_state.

-- One row per customer.
create table accounts (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  plan text not null default 'free',       -- 'free', 'starter', 'pro', 'agency'
  created_at timestamptz not null default now()
);

-- One row per domain being watched, linked to whoever owns it.
create table domains (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  hostname text not null,
  created_at timestamptz not null default now(),
  unique (account_id, hostname)  -- same customer can't add the same domain twice
);

-- Replaces alert-state.json. One row per domain, tracking what's
-- already been alerted about so we don't repeat the same warning.
create table alert_state (
  domain_id uuid primary key references domains(id) on delete cascade,
  ssl_tier_alerted integer,          -- last SSL threshold (30/14/3) alerted, or null
  domain_tier_alerted integer,       -- same, for domain expiration
  known_cert_ids jsonb not null default '[]',  -- Certificate Transparency history
  dns_snapshot jsonb,                -- last known MX/TXT records
  last_checked_at timestamptz,
  last_ssl_days_left integer,        -- for a future dashboard health score
  last_domain_days_left integer
);
