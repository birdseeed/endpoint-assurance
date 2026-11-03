-- patched.im — 0097_agent_versions_menubar_platform_rollback.sql
-- Reverses 0097_agent_versions_menubar_platform.sql.
--
-- Restores the original two-value CHECK constraint (platform IN ('macos',
-- 'windows')). This is a guard, not a data migration: if any
-- platform='macos-menubar' row already exists, re-adding the narrower
-- constraint will fail with a check-violation error rather than silently
-- deleting or reclassifying those rows. That failure is intentional — a
-- rollback of the constraint must never destroy data as a side effect, and
-- the only safe path back to the two-value constraint when menubar rows
-- exist is an explicit, separate decision (delete or re-platform those
-- rows) taken outside this script.

BEGIN;

ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_platform_check;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_platform_check
    CHECK (platform IN ('macos', 'windows'));

DELETE FROM schema_migrations WHERE version = '0097_agent_versions_menubar_platform';

COMMIT;
