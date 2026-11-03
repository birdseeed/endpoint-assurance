-- Rollback for 0181_portal_user_roles (PAT-2007)
--
-- Roll the API binary back first: the PAT-2007 portal write and admin
-- handlers read and write portal_users.role.
--
-- Dropping the column loses every role assignment. Re-applying 0181 after
-- this rollback backfills every then-existing row to 'admin', including
-- users who were 'viewer' before the rollback, so export the roles first if
-- they need to be restored:
--   psql ... -c "\copy (SELECT email, role FROM portal_users) TO 'portal_user_roles.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0181_portal_user_roles_rollback.sql

BEGIN;

ALTER TABLE portal_users DROP COLUMN IF EXISTS role;

DELETE FROM schema_migrations WHERE version = '0181_portal_user_roles';

COMMIT;
