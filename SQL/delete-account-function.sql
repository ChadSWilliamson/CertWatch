-- Lets a logged-in person permanently delete their OWN account —
-- their domains, monitoring history, and login — nothing else.
-- Runs with elevated permissions since deleting a login normally
-- requires admin-level access, but it's tightly scoped to only
-- ever affect the person calling it (auth.uid()), never anyone else.

create or replace function delete_own_account()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Deletes the accounts row. Because domains and alert_state were
  -- both set up with "on delete cascade", this automatically removes
  -- every domain and all monitoring history tied to this account too.
  delete from accounts where user_id = auth.uid();

  -- Deletes the actual login itself, so they can't log back in to
  -- find an empty dashboard — the account is genuinely gone.
  delete from auth.users where id = auth.uid();
end;
$$;

grant execute on function delete_own_account() to authenticated;
