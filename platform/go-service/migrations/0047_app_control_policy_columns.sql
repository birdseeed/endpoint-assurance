-- PAT-602: Application Control — per-tenant policy storage columns.
-- Defaults are empty JSON arrays so existing tenants receive no enforcement.

BEGIN;

ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS app_control_approved_admins JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS app_control_app_allowlist   JSONB NOT NULL DEFAULT '[]'::jsonb;

INSERT INTO schema_migrations (version) VALUES ('0047_app_control_policy_columns');

COMMIT;
