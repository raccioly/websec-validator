-- CONTROL FIXTURE (rls_present): SAME owner-scoped tables as rls_missing, but RLS is added in a
-- SEPARATE migration (0002_rls.sql) — proves cross-file corpus aggregation suppresses the finding.

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
