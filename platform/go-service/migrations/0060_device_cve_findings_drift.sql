-- 0060: reconcile device_cve_findings with migration 0025.
-- Prod's table predates 0025's final shape and lacks first_seen_at, which
-- broke the portal findings endpoint and the xlsx export (SQLSTATE 42703).
-- Idempotent: no-op on installs created from 0025 as written.

BEGIN;

ALTER TABLE device_cve_findings
    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ;

UPDATE device_cve_findings SET first_seen_at = last_seen_at WHERE first_seen_at IS NULL;

ALTER TABLE device_cve_findings
    ALTER COLUMN first_seen_at SET NOT NULL,
    ALTER COLUMN first_seen_at SET DEFAULT NOW();

INSERT INTO schema_migrations (version) VALUES ('0060_device_cve_findings_drift')
    ON CONFLICT DO NOTHING;

COMMIT;
