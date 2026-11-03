-- patched.im — 0094_device_cve_findings_fixed_version.sql
-- Adds device_cve_findings.fixed_version — the first version NOT vulnerable
-- (CPERange.VEndExcl) for the CPE range that matched this finding, per
-- cvematch.versionInRange. Lets the free CVE report's remediation plan
-- (PAT-1205) tell the customer what version to upgrade to, not just that
-- an upgrade is needed.
--
-- No backfill: cmd/patched-cve-sync upserts every finding on its next
-- nightly run (see the batched upsert in cmd/patched-cve-sync/main.go),
-- so this column populates naturally as the sync cycles through. Until
-- then it reads as '' (empty), which the report renderer treats as
-- "unknown, use latest vendor release" — a safe/honest default, not
-- wrong data.
--
-- Numbered 0094 because 0090 (the head at brief-writing time) was
-- superseded by 0091-0093 before this ticket landed.
--
-- Apply with:
--   psql -h ... -f migrations/0094_device_cve_findings_fixed_version.sql
--
-- PAT-1205.

BEGIN;

ALTER TABLE device_cve_findings ADD COLUMN fixed_version TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN device_cve_findings.fixed_version IS
    'First version NOT vulnerable for the matched CPE range (CPERange.VEndExcl from cvematch.versionInRange). Empty string when unknown: no range data, or the matched range was open-ended (no VEndExcl). Populated by cmd/patched-cve-sync on upsert; not backfilled.';

INSERT INTO schema_migrations (version) VALUES ('0094_device_cve_findings_fixed_version')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
