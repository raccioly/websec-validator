-- Synthetic Supabase/Postgres schema — license-scoped ownership + RLS.
CREATE TABLE alert_configs (
  id           uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  license_hash text        NOT NULL UNIQUE,
  email        text,
  games        jsonb,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_alert_configs_license ON alert_configs (license_hash);

ALTER TABLE alert_configs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "No direct access" ON alert_configs FOR ALL USING (false);
