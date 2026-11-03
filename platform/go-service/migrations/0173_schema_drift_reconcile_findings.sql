-- patched.im - 0173_schema_drift_reconcile_findings.sql
-- PAT-2053: the device_cve_findings half of the drift reconcile begun in 0172.
--
-- Prod's device_cve_findings came from a pre-merge draft of 0025_cve_store
-- that lacked idx_dcvef_severity and left app_version nullable with no
-- default. Prod held no NULLs (audited 2026-09-23: 7753 rows, 0 NULLs), and
-- every insert path writes a Go string, so SET NOT NULL is expected to
-- succeed. If a NULL has appeared since, the statement fails, the transaction
-- rolls back and the deploy stops before anything changes.
--
-- Kept apart from 0172 so that no migration transaction locks both
-- cve_feed_entries and device_cve_findings: the extractor's CVE drain
-- (cvepipeline queue -> match) reads cve_feed_entries and writes
-- device_cve_findings inside one transaction, and a migration holding both
-- could deadlock with it. This file touches device_cve_findings only.
--
-- Writers to device_cve_findings: patched-cve-sync (its timer is stopped by
-- deploy.sh while migrations run) and the extractor's CVE drain and Homebrew
-- matcher, which keep running. The index build takes SHARE (blocks those
-- writes, allows reads) and the ALTER then takes ACCESS EXCLUSIVE until
-- COMMIT. lock_timeout bounds the wait behind an in-flight drain; on timeout
-- the deploy stops with nothing applied, and a drain that waited on us simply
-- resumes after COMMIT.
--
-- Every statement is a no-op on a migrations-built database.

BEGIN;

SET LOCAL lock_timeout = '30s';

CREATE INDEX IF NOT EXISTS idx_dcvef_severity ON device_cve_findings (severity);

ALTER TABLE device_cve_findings
    ALTER COLUMN app_version SET DEFAULT '',
    ALTER COLUMN app_version SET NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0173_schema_drift_reconcile_findings')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
