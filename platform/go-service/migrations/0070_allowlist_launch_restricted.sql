-- 0070: allow 'launch_restricted' in tenant_allowlists.enforcement (PAT-820).
--
-- The application layer (internal/handlers/allowlist.go) has validated and
-- documented 'launch_restricted' as a valid enforcement value since it was
-- introduced, and the allowlist scan handler already tallies it in the
-- summary — but migration 0023's CHECK constraint never included it, so any
-- POST/PUT that actually set enforcement='launch_restricted' has always
-- failed with a 500 (constraint violation) instead of persisting. This
-- widens the constraint to match the application layer.

BEGIN;

ALTER TABLE tenant_allowlists
    DROP CONSTRAINT tenant_allowlists_enforcement_check,
    ADD CONSTRAINT tenant_allowlists_enforcement_check
        CHECK (enforcement IN ('allowed', 'flagged', 'marked_for_uninstall', 'launch_restricted'));

INSERT INTO schema_migrations (version) VALUES ('0070_allowlist_launch_restricted');

COMMIT;
