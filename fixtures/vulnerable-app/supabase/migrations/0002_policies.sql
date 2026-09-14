-- "Added security" -- but ENABLE ROW LEVEL SECURITY was never run on messages,
-- so this policy is inert and the table is still world-readable.
create policy "users read their own messages"
  on messages
  for select
  using (auth.uid() = sender_id or auth.uid() = recipient_id);

-- This table was done correctly and must not be reported.
create table waitlist (
  id bigserial primary key,
  email text not null unique
);

alter table waitlist enable row level security;

create policy "nobody reads the waitlist"
  on waitlist
  for select
  using (false);
