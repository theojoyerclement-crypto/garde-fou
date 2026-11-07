alter table public.posts enable row level security;
create policy "Authors edit their posts" on public.posts
  for update to authenticated using (auth.uid() = author) with check (auth.uid() = author);

drop policy "Open legacy" on public.legacy;
alter table legacy enable row level security;
