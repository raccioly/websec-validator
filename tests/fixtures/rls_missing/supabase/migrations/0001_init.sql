-- VULNERABLE FIXTURE (P0 missing-rls): owner/tenant-scoped tables shipped with NO Row-Level Security.
-- gen_random_uuid()/timestamptz make the stack read as postgres; there is deliberately zero
-- `enable row level security` / `create policy` anywhere in this repo's committed SQL.

create table profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  email text,
  plan text,
  created_at timestamptz default now()
);

create table documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text,
  body text,
  created_at timestamptz default now()
);
