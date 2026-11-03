-- patched.im — 0009_windows_schema_compat.sql
-- Adds the schema_version 3 / Windows-compatibility columns.
--
--   compliance_rules.platform (text NOT NULL DEFAULT 'macos')
--     Identifies which platform a rule applies to. Every existing rule is macOS;
--     future Windows CIS rules will carry platform = 'windows'. The evaluator's
--     LoadRules / LoadRulesForTenant queries filter on this column so a macOS
--     device never evaluates Windows rules and vice versa.
--
--   device_apps.publisher (text NULL)
--     Carries the Windows registry Publisher value. macOS rows leave this NULL.
--     Added to the upsert and ON CONFLICT UPDATE in the extractor.
--
-- ⚠️  DEPLOY ORDERING: apply this migration BEFORE deploying the binary that
-- uses it. The evaluator's platform-filtered query adds `AND platform = $n` which
-- fails against a column that does not yet exist. Apply → restart services.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0009_windows_schema_compat.sql
-- Note: 0008_t2_batch3.sql must have been applied first.

BEGIN;

ALTER TABLE compliance_rules ADD COLUMN platform text NOT NULL DEFAULT 'macos';
ALTER TABLE device_apps      ADD COLUMN publisher text;

INSERT INTO schema_migrations (version) VALUES ('0009_windows_schema_compat');

COMMIT;
