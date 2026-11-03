-- patched.im — 0080_catalogue_target_identity_unique.sql
-- PAT-869: enforce UNIQUE(identity, platform) on catalogue_platform_targets so a
-- pipeline state report can never resolve an identity to more than one target.
--
-- Migration 0078 enforced only UNIQUE(product_id, platform); `identity` carried a
-- plain (non-unique) partial index. That let two targets share the same
-- (identity, platform), which made the POST /admin/catalogue/state lookup
-- ambiguous: the OR-matched row it locked and mutated could belong to a
-- DIFFERENT product than the caller intended, silently writing pipeline state
-- (e.g. 'published') to the wrong product on the PAT-66 supply-chain gate.
--
-- Fail closed on live data: before adding the constraint we ABORT loudly if any
-- duplicate (identity, platform) pair already exists, listing the offenders, so
-- an operator resolves them first rather than the migration silently corrupting
-- or half-applying. NULL identities (unresolved targets) are legitimately
-- non-unique, so both the pre-check and the constraint are scoped to
-- identity IS NOT NULL, matching the partial index 0078 created.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0080_catalogue_target_identity_unique.sql
BEGIN;

-- DEPLOY ORDERING: apply after 0078. The pre-check RAISEs inside this
-- transaction, so a data violation aborts the whole migration and nothing is
-- left half-applied.

DO $$
DECLARE
    dup_list text;
BEGIN
    SELECT string_agg(
             format('(identity=%L, platform=%L, count=%s)', identity, platform, cnt),
             ', ' ORDER BY identity, platform)
      INTO dup_list
      FROM (
            SELECT identity, platform, count(*) AS cnt
              FROM catalogue_platform_targets
             WHERE identity IS NOT NULL
             GROUP BY identity, platform
            HAVING count(*) > 1
           ) d;

    IF dup_list IS NOT NULL THEN
        RAISE EXCEPTION
          'migration 0080 aborted: duplicate (identity, platform) pairs block UNIQUE(identity, platform): %. Resolve these targets before applying.',
          dup_list;
    END IF;
END $$;

-- The unique partial index doubles as the identity lookup index, so it replaces
-- the non-unique one 0078 created (identical columns + predicate).
DROP INDEX IF EXISTS catalogue_platform_targets_identity_idx;
CREATE UNIQUE INDEX catalogue_platform_targets_identity_platform_uq
    ON catalogue_platform_targets (identity, platform)
    WHERE identity IS NOT NULL;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0080_catalogue_target_identity_unique')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
