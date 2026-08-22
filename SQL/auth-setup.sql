-- Links each account to a real login (Supabase Auth), and adds the
-- security rules that let a logged-in person see and manage ONLY
-- their own data — nobody else's.

-- Connects each account row to a real login.
alter table accounts add column user_id uuid references auth.users(id) unique;

-- Rule: a logged-in person can see their own account row.
create policy "Users can view their own account"
  on accounts for select
  using (auth.uid() = user_id);

-- Rule: allows a pre-existing account (like the one we made by hand
-- with seed.sql) to get "claimed" by a real login the first time
-- someone signs in with that same email — without this, your
-- existing test account would just sit there unconnected.
create policy "Users can claim their pre-existing account"
  on accounts for update
  using (email = auth.jwt() ->> 'email' and user_id is null)
  with check (auth.uid() = user_id);

-- Rule: a logged-in person can create their own account row
-- (this runs once, right after they sign up for the first time).
create policy "Users can create their own account"
  on accounts for insert
  with check (auth.uid() = user_id);

-- Rule: a logged-in person can see domains that belong to THEIR
-- account only.
create policy "Users can view their own domains"
  on domains for select
  using (
    account_id in (select id from accounts where user_id = auth.uid())
  );

-- Rule: a logged-in person can add a domain, but only under
-- their own account.
create policy "Users can add their own domains"
  on domains for insert
  with check (
    account_id in (select id from accounts where user_id = auth.uid())
  );

-- Rule: a logged-in person can remove a domain, but only their own.
create policy "Users can delete their own domains"
  on domains for delete
  using (
    account_id in (select id from accounts where user_id = auth.uid())
  );
