-- Adds fields to alert_state for tracking uptime, alongside the
-- existing SSL/domain/CT/DNS fields already there.

alter table alert_state add column uptime_status text;
alter table alert_state add column uptime_down_alerted boolean not null default false;
alter table alert_state add column last_uptime_check_at timestamptz;
