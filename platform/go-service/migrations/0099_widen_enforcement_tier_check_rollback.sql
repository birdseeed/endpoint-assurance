-- patched.im — 0099_widen_enforcement_tier_check_rollback.sql
-- Reverses 0099_widen_enforcement_tier_check.sql.
--
-- Restores the original three-value CHECK constraint (enforcement_tier IN
-- ('report', 'app_management', 'managed')). This is a guard, not a data
-- migration: if any enforcement_tier='report_deploy' or 'patch' row already
-- exists, re-adding the narrower constraint will fail with a
-- check-violation error rather than silently deleting or reclassifying
-- those rows. That failure is intentional — a rollback of the constraint
-- must never destroy data as a side effect, and the only safe path back to
-- the three-value constraint when report_deploy/patch rows exist is an
-- explicit, separate decision (delete or re-tier those rows) taken outside
-- this script.

BEGIN;

ALTER TABLE tenant_app_policies DROP CONSTRAINT tenant_app_policies_enforcement_tier_check;
ALTER TABLE tenant_app_policies ADD CONSTRAINT tenant_app_policies_enforcement_tier_check
    CHECK (enforcement_tier IN ('report', 'app_management', 'managed'));

DELETE FROM schema_migrations WHERE version = '0099_widen_enforcement_tier_check';

COMMIT;
