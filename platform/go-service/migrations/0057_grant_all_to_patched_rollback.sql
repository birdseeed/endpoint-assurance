-- Rollback for 0057_grant_all_to_patched.
--
-- WARNING: destructive to the running service. Revoking these grants will make
-- the `patched` app role hit "permission denied" on tables that had no explicit
-- per-table grant — which is exactly the incident 0057 fixes. Only run this on a
-- scratch/throwaway database, never on production.

BEGIN;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM patched;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM patched;

REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM patched;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM patched;

DELETE FROM schema_migrations WHERE version = '0057_grant_all_to_patched';

COMMIT;
