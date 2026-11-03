-- 0095: catch-up OWNERSHIP transfer to the `patched` application role (PAT-1209).
--
-- 0057_grant_all_to_patched.sql fixed "permission denied" 500s from missing
-- per-table GRANTs (PAT-579/603) -- but a GRANT only confers DML privileges
-- (SELECT/INSERT/UPDATE/DELETE). Postgres requires table OWNERSHIP (or
-- superuser) for structural ALTER TABLE -- adding/dropping columns,
-- constraints, indexes tied to the table. Migration 0093 (PAT-1169) hit this
-- exact gap: `ALTER TABLE enforcement_audit DROP CONSTRAINT ...` failed with
-- "permission denied for table enforcement_audit" even though `patched` has
-- full DML rights there via 0057. As of 2026-08-06, 36 of 103 public tables
-- are still owned by a role other than `patched` (confirmed via a temporary
-- read-only diagnostic in .github/workflows/deploy-api-01.yml, since removed
-- -- see PAT-1209). Any future migration that structurally ALTERs one of
-- those 36 will hit the identical wall.
--
-- *** THIS MIGRATION CANNOT BE APPLIED BY THE NORMAL DEPLOY PIPELINE. ***
-- deploy.sh runs migrations as `patched` (it sources the app's own
-- /etc/patched-api/env for DATABASE_URL). Postgres requires the CURRENT
-- owner of a table (or a superuser) to run `ALTER TABLE ... OWNER TO`, so
-- `patched` cannot grant itself ownership of tables it doesn't already own
-- -- the same self-referential wall this migration exists to fix. It must be
-- applied directly, once, by a role that already owns these tables (or a
-- superuser), OUTSIDE deploy.sh -- see OPERATIONS.md for the exact command.
-- Once applied, the INSERT below records it in schema_migrations so the
-- normal pipeline sees it as already-applied on every subsequent deploy,
-- exactly like migration 0093 needed a one-off manual apply on 2026-08-06.
--
-- Rollback is exact (not "unsafe in production" like 0057's): every
-- reassigned table/sequence's PRIOR owner is captured in
-- _migration_0095_owner_backup before the transfer, so the rollback restores
-- the true previous owner rather than guessing.
--
-- Scope: pg_tables (base tables) and pg_sequences only -- matches the actual
-- failure mode (structural ALTER TABLE) and every object type this repo's
-- migrations create. Views/foreign tables, if any ever appear, are not
-- covered and would need their own pass.
--
-- Non-author review (PAT-1209, NVIDIA/opencode) flagged the obvious
-- trade-off directly: this is a blanket ownership grant, and DDL rights
-- concentrated on one application role widen what a compromise of that
-- role's credential could do. That risk is real and not eliminated here --
-- it is the same trade-off 0057 already made for DML, extended to DDL,
-- because the alternative (granting ownership reactively, table by table,
-- only when the next migration happens to need it) is the exact pattern
-- that has already caused three separate production incidents
-- (PAT-579/603 for DML grants, PAT-1169/0093 for this). Recorded here for
-- whoever next re-examines `patched`'s privilege model, not resolved by
-- this migration.

BEGIN;

CREATE TABLE IF NOT EXISTS _migration_0095_owner_backup (
    relname     TEXT NOT NULL,
    relkind     TEXT NOT NULL,   -- 'r' = table, 'S' = sequence
    prior_owner TEXT NOT NULL,
    PRIMARY KEY (relname, relkind)
);

GRANT SELECT, INSERT, UPDATE ON _migration_0095_owner_backup TO patched;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT tablename AS relname, tableowner AS owner
        FROM pg_tables
        WHERE schemaname = 'public' AND tableowner <> 'patched'
    LOOP
        INSERT INTO _migration_0095_owner_backup (relname, relkind, prior_owner)
        VALUES (r.relname, 'r', r.owner)
        ON CONFLICT (relname, relkind) DO NOTHING;
        EXECUTE format('ALTER TABLE public.%I OWNER TO patched', r.relname);
    END LOOP;

    FOR r IN
        SELECT sequencename AS relname, sequenceowner AS owner
        FROM pg_sequences
        WHERE schemaname = 'public' AND sequenceowner <> 'patched'
    LOOP
        INSERT INTO _migration_0095_owner_backup (relname, relkind, prior_owner)
        VALUES (r.relname, 'S', r.owner)
        ON CONFLICT (relname, relkind) DO NOTHING;
        EXECUTE format('ALTER SEQUENCE public.%I OWNER TO patched', r.relname);
    END LOOP;
END $$;

INSERT INTO schema_migrations (version) VALUES ('0095_owner_catchup_to_patched')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
