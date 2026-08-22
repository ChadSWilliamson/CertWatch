-- A single, reliable function that runs on the database itself
-- (with elevated permissions) to either:
--   1. Claim a pre-existing account with a matching email, or
--   2. Return an account you already claimed before, or
--   3. Create a brand new one
-- Doing this as one database function avoids the fragile
-- "read the email off the login token" approach that just failed.

create or replace function claim_account()
returns accounts
language plpgsql
security definer
set search_path = public
as $$
declare
  result accounts;
  user_email text;
begin
  select email into user_email from auth.users where id = auth.uid();

  -- Try to claim an existing unclaimed account with this email.
  update accounts
  set user_id = auth.uid()
  where email = user_email and user_id is null
  returning * into result;

  if result.id is not null then
    return result;
  end if;

  -- Otherwise, see if this login already has an account.
  select * into result from accounts where user_id = auth.uid();
  if result.id is not null then
    return result;
  end if;

  -- Otherwise, brand new — create one.
  insert into accounts (email, user_id, plan)
  values (user_email, auth.uid(), 'free')
  returning * into result;

  return result;
end;
$$;

grant execute on function claim_account() to authenticated;
