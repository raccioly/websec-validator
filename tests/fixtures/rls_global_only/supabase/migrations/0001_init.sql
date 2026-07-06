-- CONTROL FIXTURE (rls_global_only): a Postgres/Supabase app whose only tables are GLOBAL lookups
-- with NO owner/tenant column. RLS is irrelevant here, so the owner-column gate must suppress the
-- finding even though there is committed DDL and no RLS policy.

create table countries (
  code text primary key,
  name text not null
);

create table feature_flags (
  key text primary key,
  enabled boolean default false
);
