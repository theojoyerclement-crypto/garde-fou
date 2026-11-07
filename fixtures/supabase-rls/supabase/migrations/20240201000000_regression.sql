-- A later migration switches RLS off again.
alter table public.audit_log disable row level security;

create function public.handle_new_user() returns trigger
language plpgsql security definer as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;
