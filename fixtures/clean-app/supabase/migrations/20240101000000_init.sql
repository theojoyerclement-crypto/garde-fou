-- Secure Supabase schema: Garde-Fou must report nothing here.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text
);
alter table public.profiles enable row level security;
create policy "Users read own profile" on public.profiles
  for select to authenticated using (auth.uid() = id);
create policy "Users update own profile" on public.profiles
  for update using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

-- RLS enabled in the next migration.
create table public.posts (id serial primary key, author uuid, body text);
create policy "Service role manages posts" on public.posts for all to service_role using (true);
create policy "Restrictive guard" on public.posts as restrictive for all using (true);

-- Not exposed: access revoked from the API roles.
create table public.scratch (id serial primary key);
revoke all on table public.scratch from anon, authenticated;

-- Temporary and private-schema tables are not exposed by the API.
create temp table tmp_import (id int);
create table private.secrets (id int, value text);

-- Opened by mistake, fixed in the next migration.
create table public.legacy (id serial primary key);
create policy "Open legacy" on public.legacy for update using (true);

-- create table public.commented_out (id int);
/* create table public.block_commented (id int); */
create function public.make_table() returns void language plpgsql as $fn$
begin
  execute 'create table public.dynamic_table (id int)';
end;
$fn$;
insert into public.settings (k, v) values ('sql', 'create table public.in_string (id int); x');
