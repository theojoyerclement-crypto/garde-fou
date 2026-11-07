-- Plain PostgreSQL schema (no Supabase API in front): RLS is not required.
create table users (id serial primary key, email text);
