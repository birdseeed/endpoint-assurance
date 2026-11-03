-- Rollback for 0095_owner_catchup_to_patched.
--
-- Restores each reassigned table/sequence to its recorded prior owner, using
-- the exact snapshot 0095 took before transferring ownership -- not a guess.
-- Like the forward migration, this must be run by a role privileged enough
-- to reassign ownership (superuser, or already a member of every prior
-- owner role) -- `patched` itself cannot run this either.
--
-- Requires the prior owner roles to still exist. If any were dropped since
-- 0095 ran, this fails on that row; resolve manually (drop the offending
-- row from _migration_0095_owner_backup, or recreate the role) before
-- re-running.

BEGIN;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT relname, relkind, prior_owner FROM _migration_0095_owner_backup
    LOOP
        IF r.relkind = 'r' THEN
            EXECUTE format('ALTER TABLE public.%I OWNER TO %I', r.relname, r.prior_owner);
        ELSE
            EXECUTE format('ALTER SEQUENCE public.%I OWNER TO %I', r.relname, r.prior_owner);
        END IF;
    END LOOP;
END $$;

DROP TABLE IF EXISTS _migration_0095_owner_backup;

DELETE FROM schema_migrations WHERE version = '0095_owner_catchup_to_patched';

COMMIT;
