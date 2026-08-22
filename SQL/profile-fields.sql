-- Adds profile fields to accounts, and sets up a storage bucket
-- for avatar images with rules so people can only manage their own.

alter table accounts add column display_name text;
alter table accounts add column phone text;
alter table accounts add column avatar_url text;

-- Lets a logged-in person update their own profile fields (display
-- name, phone, avatar) — separate from the earlier "claim" and
-- "create" rules, which only covered specific first-time actions.
create policy "Users can update their own profile"
  on accounts for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Creates a public storage bucket for avatar images. Public just
-- means anyone with the exact file link can view it (normal for
-- profile pictures) — it does NOT mean anyone can upload or
-- change files; that's controlled by the rules below.
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do nothing;

-- Rule: anyone can view avatar images (needed so they display
-- normally in the dashboard).
create policy "Avatar images are publicly viewable"
  on storage.objects for select
  using (bucket_id = 'avatars');

-- Rule: a logged-in person can only upload a file into a folder
-- named after their own user ID — not anyone else's.
create policy "Users can upload their own avatar"
  on storage.objects for insert
  with check (
    bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text
  );

-- Rule: a logged-in person can only replace or delete their own
-- avatar file, not anyone else's.
create policy "Users can update their own avatar"
  on storage.objects for update
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

create policy "Users can delete their own avatar"
  on storage.objects for delete
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
