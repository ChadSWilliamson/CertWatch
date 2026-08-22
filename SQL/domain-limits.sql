-- Enforces domain limits per plan. This runs INSIDE the database
-- itself, right before any new domain gets added — so it can't be
-- bypassed, no matter how someone tries to add a domain.

create or replace function enforce_domain_limit()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  account_plan text;
  domain_limit integer;
  current_count integer;
begin
  select plan into account_plan from accounts where id = new.account_id;

  domain_limit := case account_plan
    when 'free' then 1
    when 'starter' then 5
    when 'pro' then 25
    when 'agency' then 100
    else 1
  end;

  select count(*) into current_count from domains where account_id = new.account_id;

  if current_count >= domain_limit then
    raise exception 'Your % plan allows up to % domains. Upgrade to add more.', account_plan, domain_limit;
  end if;

  return new;
end;
$$;

create trigger check_domain_limit
  before insert on domains
  for each row
  execute function enforce_domain_limit();

-- Your own test account shouldn't be limited to 1 domain while
-- you're actively testing — bump it to the starter plan.
update accounts set plan = 'starter' where email = 'zonaazulcrconsulting@gmail.com';
