-- PAT-601: Application Control — add app_control_enabled flag to tenants.
-- Safe default FALSE: all existing tenants remain read-only inventory/reporting
-- until Application Control is explicitly enabled per-tenant.

BEGIN;

ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS app_control_enabled BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO schema_migrations (version) VALUES ('0046_app_control_enabled');

COMMIT;
