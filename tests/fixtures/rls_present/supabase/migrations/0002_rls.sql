-- RLS defined in a DIFFERENT file from the CREATE TABLE (the common real-world layout). The no-RLS
-- correlation aggregates over the whole .sql corpus, so this must suppress the finding on this app.

alter table profiles enable row level security;
alter table documents enable row level security;

create policy "owner can read own documents" on documents
  for select using (owner_id = auth.uid());
create policy "owner can read own profile" on profiles
  for select using (user_id = auth.uid());
