-- Rollback for 0070_allowlist_launch_restricted.
--
-- Note: rolling back while any row has enforcement='launch_restricted' will
-- fail the CHECK constraint re-creation — resolve those rows first.

BEGIN;

ALTER TABLE tenant_allowlists
    DROP CONSTRAINT tenant_allowlists_enforcement_check,
    ADD CONSTRAINT tenant_allowlists_enforcement_check
        CHECK (enforcement IN ('allowed', 'flagged', 'marked_for_uninstall'));

DELETE FROM schema_migrations WHERE version = '0070_allowlist_launch_restricted';

COMMIT;
