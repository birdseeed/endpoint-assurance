-- Rollback for PAT-1992 (0162_local_admin_account_state.sql).
--
-- Drops the account_state column. The values it held are re-collected on the
-- next agent run, so nothing irreplaceable is lost. Deploy the previous
-- binaries first: the extractor from this change writes the column.

BEGIN;

ALTER TABLE local_admin_accounts DROP COLUMN IF EXISTS account_state;

DELETE FROM schema_migrations WHERE version = '0162_local_admin_account_state';

COMMIT;
