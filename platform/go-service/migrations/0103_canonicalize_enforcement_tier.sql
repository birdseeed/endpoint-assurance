-- patched.im — 0103_canonicalize_enforcement_tier.sql
-- PAT-1250: step 2 of PAT-1121's three-step tier-vocabulary cutover
-- ("teach the reader before changing the writer" — step 1, the dual-accept
-- reader/constraint widening, shipped as windows-agent-v0.13.15 plus
-- 0099_widen_enforcement_tier_check.sql and is deployed and proven; step 3,
-- dropping legacy acceptance entirely, is a separate future ticket gated on
-- every endpoint in the estate running an agent that emits canonical
-- values).
--
-- This is the writer flip: internal/handlers/app_policies.go's
-- TenantAppPoliciesPutHandler (PUT /admin/tenants/{tenantID}/app-policies)
-- now rewrites a legacy "report"/"app_management" input to canonical
-- "report_deploy"/"patch" before it reaches the INSERT/UPDATE, and its
-- empty-tier default is "report_deploy", not "report". That code change
-- only affects rows written FROM NOW ON. This migration is the matching
-- one-time backfill for every row already sitting in tenant_app_policies
-- with a legacy value — without it, "report"/"app_management" rows persist
-- indefinitely and the two vocabularies never actually converge, which is
-- the exact condition PAT-1121 exists to end. "managed" is the shared name
-- in both vocabularies and is left untouched everywhere in this file.
--
-- Deliberately NOT narrowing tenant_app_policies_enforcement_tier_check
-- (0099): legacy values must still be ACCEPTED on input (dashboards/older
-- clients may still send them for a while), this migration and its writer
-- change only stop the server from STORING/EMITTING them going forward.
--
-- ── Reversibility (read this before running the rollback) ────────────────
--
-- The forward UPDATEs below are, on their own, NOT safely invertible by a
-- blanket reverse mapping (report_deploy → report, patch → app_management)
-- applied to whatever the table looks like at rollback time. Phase 1
-- (0099) already let API callers write "report_deploy"/"patch" explicitly,
-- and TenantAppPoliciesPutHandler did not normalize anything before this
-- ticket (see app_policies_tier_test.go's now-superseded
-- TestAppPoliciesPutAcceptsBothVocabulariesForAllThreeRungs, which asserted
-- exactly that). So by the time this migration runs, some rows may already
-- be genuinely, natively canonical — written that way by a caller, never
-- legacy at all. A blanket reverse mapping cannot tell those apart from the
-- rows THIS migration converts, and would incorrectly relabel them back to
-- a legacy spelling they never had.
--
-- To make the rollback exact rather than a guess, this migration snapshots
-- the primary key and PRIOR value of every row it is about to change into
-- a permanent bookkeeping table, _migration_0103_tier_backup, before
-- touching them — same pattern as
-- 0095_owner_catchup_to_patched.sql/_migration_0095_owner_backup. The
-- rollback restores exactly those rows to exactly their recorded prior
-- value, and only if the row still holds the canonical value this
-- migration wrote (see the rollback file for what happens if a row was
-- edited again in between — e.g. an operator re-saved the same policy
-- through the admin API after this migration ran).
--
-- What IS cleanly recoverable: every row this migration converts, provided
-- it has not been written again since, via the rollback file.
-- What is NOT recoverable by the rollback: distinguishing, after the fact,
-- rows that were natively canonical before this migration from rows this
-- migration converted — moot for the rollback itself (it only ever
-- touches rows recorded in the backup table, i.e. rows THIS migration
-- converted), but worth stating plainly: there is no way, from the data
-- alone, to answer "was this specific report_deploy row always canonical,
-- or did 0103 convert it" once _migration_0103_tier_backup is dropped
-- (which the rollback does on completion, mirroring 0095's rollback).
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0103_canonicalize_enforcement_tier.sql

BEGIN;

CREATE TABLE IF NOT EXISTS _migration_0103_tier_backup (
    id                     BIGINT PRIMARY KEY,
    prior_enforcement_tier TEXT NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE _migration_0103_tier_backup TO patched;

-- Snapshot exactly the rows about to change, and their exact prior value,
-- before either UPDATE below touches them.
INSERT INTO _migration_0103_tier_backup (id, prior_enforcement_tier)
SELECT id, enforcement_tier
FROM tenant_app_policies
WHERE enforcement_tier IN ('report', 'app_management')
ON CONFLICT (id) DO NOTHING;

UPDATE tenant_app_policies
SET enforcement_tier = 'report_deploy'
WHERE enforcement_tier = 'report';

UPDATE tenant_app_policies
SET enforcement_tier = 'patch'
WHERE enforcement_tier = 'app_management';

INSERT INTO schema_migrations (version) VALUES ('0103_canonicalize_enforcement_tier')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
