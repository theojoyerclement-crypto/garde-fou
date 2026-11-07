-- Deliberately insecure Supabase schema used to test Garde-Fou. Do not deploy.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text
);
alter table public.profiles enable row level security;

-- No RLS: anyone with the anon key reads and edits every order.
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total numeric
);

CREATE TABLE IF NOT EXISTS "Invoices" (id serial primary key, amount numeric);

create table public.todos (id serial primary key, user_id uuid, title text);
alter table public.todos enable row level security;
create policy "Anyone can update todos" on public.todos for update using (true);
create policy "Anyone can delete todos" on todos for delete to anon, authenticated using ( true );
create policy "Anyone can add todos" on public.todos for insert with check (true);
create policy "Everyone reads todos" on public.todos for select using (true);

create table public.audit_log (id serial primary key, event text);
alter table public.audit_log enable row level security;
