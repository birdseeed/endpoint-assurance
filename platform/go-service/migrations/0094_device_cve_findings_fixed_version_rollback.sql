-- patched.im — 0094_device_cve_findings_fixed_version_rollback.sql
-- Reverses 0094_device_cve_findings_fixed_version.sql: drops
-- device_cve_findings.fixed_version. Data loss on rollback is expected and
-- accepted (same as every other ADD COLUMN rollback in this directory) —
-- the value is re-derived from cve_feed_entries.cpe_ranges by
-- cmd/patched-cve-sync on its next run after a forward migration restores
-- the column.
BEGIN;

ALTER TABLE device_cve_findings
    DROP COLUMN IF EXISTS fixed_version;

DELETE FROM schema_migrations WHERE version = '0094_device_cve_findings_fixed_version';

COMMIT;
