-- patched.im - 0172_schema_drift_reconcile.sql
-- PAT-2053: reconcile the schema drift the 2026-09-23 audit found between
-- patched-api-01 and a database built from these migrations.
--
-- The audit fingerprinted prod's live schema read-only
-- (deploy/api-01/schema_fingerprint.sql) and compared it with a fresh
-- migrations-built database. Everything that differed traces to hand-applied
-- pre-merge drafts in the grandfathered range (<= 0055), which never re-run
-- because deploy.sh only considers versions >= 56:
--
--   * 0025_cve_store: prod's cve_feed_entries came from a draft that lacked
--     three of 0025's indexes (including the GIN prefilter on cpe_patterns
--     the matcher relies on) and left description nullable with no default.
--     Prod held no NULLs (audited 2026-09-23: 317213 rows, 0 NULLs), and every
--     code path writes a Go string, so SET NOT NULL is expected to succeed. If
--     a NULL has appeared since, the statement fails, the transaction rolls
--     back and the deploy stops before anything changes.
--   * 0019_windows_cis_l1_rules: its final step drops the 'macos' default on
--     compliance_rules.platform so every rule must name its platform. Prod
--     still carries the default from 0009. Every insert path (the rule-pack
--     importer and the migrations) already names the platform, and CI has
--     always run without the default.
--
-- This file covers cve_feed_entries and compliance_rules only. The
-- device_cve_findings half is 0173, in its own transaction, because the
-- extractor's CVE drain (cvepipeline queue -> match) reads cve_feed_entries and
-- writes device_cve_findings inside one transaction. A migration transaction
-- holding locks on both tables could take them in the opposite order and
-- deadlock with a drain, failing the deploy. No migration transaction here
-- locks both.
--
-- Every statement is a no-op on a migrations-built database: the indexes
-- already exist by these exact names and definitions, the default and
-- NOT NULL are already as set here, and compliance_rules.platform already
-- has no default.
--
-- Index builds come first, under SHARE locks that still allow reads. The
-- ALTER TABLE steps take ACCESS EXCLUSIVE and are last so those locks are held
-- only for the NOT NULL scan and the COMMIT. lock_timeout stops the deploy
-- rather than queueing behind a long reader. patched-cve-sync is the only
-- writer to cve_feed_entries and its timer is stopped by deploy.sh while
-- migrations run; the extractor's CVE drain and the API only read it, and a
-- reader holding ACCESS SHARE makes the ALTER wait at most lock_timeout, then
-- the deploy stops cleanly with nothing applied.
--
-- Deliberately NOT changed here (accepted in
-- deploy/api-01/schema-drift-allowlist.txt, see PAT-2053 for the reasoning):
-- app_cpe_mappings.created_at and schema_migrations.description, which exist
-- only on prod and are harmless extras, and tenant_allowlists_bak_pat728_20260706,
-- a hand-made PAT-728 backup table whose removal is Andy's call.

BEGIN;

SET LOCAL lock_timeout = '30s';

CREATE INDEX IF NOT EXISTS idx_cve_feed_severity ON cve_feed_entries (severity);
CREATE INDEX IF NOT EXISTS idx_cve_feed_modified ON cve_feed_entries (modified_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_feed_cpe_gin  ON cve_feed_entries USING GIN (cpe_patterns);

ALTER TABLE compliance_rules ALTER COLUMN platform DROP DEFAULT;

ALTER TABLE cve_feed_entries
    ALTER COLUMN description SET DEFAULT '',
    ALTER COLUMN description SET NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0172_schema_drift_reconcile')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
