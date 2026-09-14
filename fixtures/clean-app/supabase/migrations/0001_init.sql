-- Every table enables row-level security in the migration that creates it, and
-- ships with the policies that make the app work under it.

create table profiles (
  id uuid primary key references auth.users (id),
  email text not null,
  full_name text
);

alter table profiles enable row level security;

create policy "profiles are readable by their owner"
  on profiles for select to authenticated
  using (auth.uid() = id);

create policy "profiles are updatable by their owner"
  on profiles for update to authenticated
  using (auth.uid() = id);

create table notes (
  id bigserial primary key,
  user_id uuid not null references profiles (id),
  body text not null,
  created_at timestamptz default now()
);

alter table notes enable row level security;

create policy "notes are readable by their owner"
  on notes for select to authenticated
  using (auth.uid() = user_id);

create policy "notes are insertable by their owner"
  on notes for insert to authenticated
  with check (auth.uid() = user_id);
