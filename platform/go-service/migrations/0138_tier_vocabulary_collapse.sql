-- patched.im — 0138_tier_vocabulary_collapse.sql
-- PAT-1599: collapse the commercial subscription tier vocabulary to two
-- values: assurance | managed.
--
-- Ruling (Andy): one tier vocabulary, two values, used identically
-- everywhere. tenants.subscription_tier (migration 0056) previously held
-- three values — report | patch | full_endpoint — mirroring a three-tier
-- buyer ladder that was retired 2026-09-11 (PAT-1566). This migration
-- collapses it to the internal enum: assurance | managed.
--
-- Live production data on patched-api-01, verified 2026-09-16 immediately
-- before writing this migration:
--   SELECT subscription_tier, count(*) FROM tenants GROUP BY subscription_tier;
--     report          | 11
--     patch           | 1
--     full_endpoint   | 1
-- Expected post-migration: assurance = 12 (11 report + 1 patch), managed = 1
-- (1 full_endpoint). The mapping is lossy for the one 'patch' tenant: its
-- distinct "patch-capable but not fully managed" state is not recoverable
-- once collapsed into 'assurance' — this is the deliberate, ticket-sanctioned
-- consequence of retiring the three-tier ladder, not an oversight.
--
-- tenant_tier_changes (also created by 0056) is an append-only audit log —
-- UPDATE, DELETE and TRUNCATE are all rejected by trigger
-- (trg_tenant_tier_changes_append_only, trg_tenant_tier_changes_append_only_truncate,
-- PAT-1133/PAT-1137; see 0101_tenant_purge_audit_anonymisation.sql). Its
-- existing rows (4 in production as of 2026-09-16: full_endpoint=1, patch=2,
-- report=1) record what the tier genuinely was at each historical
-- transition and are deliberately NOT rewritten here — an audit log
-- describes the past, not the current vocabulary. Its to_tier CHECK is
-- updated NOT VALID so existing rows are exempt from re-validation (and
-- stay exactly as written) while every future INSERT is constrained to the
-- new two-value set, matching how the application will only ever write
-- assurance/managed from this point on.
--
-- Out of scope, deliberately untouched by this migration (see PAT-1599 brief):
--   - tenants.tier (SMALLINT 1/2/3, migration 0049) — unrelated CIS
--     collection tier, not a commercial-tier column.
--   - tenant_app_policies.enforcement_tier (migrations 0099/0103) —
--     an unrelated report_deploy/patch/managed vocabulary on a different
--     table.
--
-- Rollback: migrations/0138_tier_vocabulary_collapse_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0138_tier_vocabulary_collapse.sql

BEGIN;

-- Drop the old CHECK before rewriting data: the new values ('assurance',
-- 'managed') are not legal under the old three-value constraint, so the
-- UPDATEs below would fail if it were still in place. ALTER TABLE takes an
-- ACCESS EXCLUSIVE lock on tenants, so no concurrent writer can slip a
-- value in while the table is briefly unconstrained within this
-- transaction.
ALTER TABLE tenants
    DROP CONSTRAINT tenants_subscription_tier_check;

UPDATE tenants
SET subscription_tier = 'assurance'
WHERE subscription_tier IN ('report', 'patch');

UPDATE tenants
SET subscription_tier = 'managed'
WHERE subscription_tier = 'full_endpoint';

-- Sanity check: every row must now be one of the two new values. Fails the
-- migration loudly if anything unexpected slipped through (e.g. a value
-- added between this migration being written and applied).
DO $$
DECLARE
    bad_count BIGINT;
BEGIN
    SELECT count(*) INTO bad_count
    FROM tenants
    WHERE subscription_tier NOT IN ('assurance', 'managed');

    IF bad_count > 0 THEN
        RAISE EXCEPTION 'tier vocabulary collapse: % tenants rows have an unmapped subscription_tier value', bad_count;
    END IF;
END $$;

-- Every row already conforms (checked above), so this validates immediately
-- with no NOT VALID escape hatch needed.
ALTER TABLE tenants
    ADD CONSTRAINT tenants_subscription_tier_check
    CHECK (subscription_tier IN ('assurance', 'managed'));

ALTER TABLE tenants
    ALTER COLUMN subscription_tier SET DEFAULT 'assurance';

COMMENT ON COLUMN tenants.subscription_tier IS
  'Commercial product tier: assurance | managed. Source of truth for billing and feature entitlement. '
  'Distinct from tenants.tier (CIS collection tier) and agent_config.body.tier (agent behavioural mode). '
  'Written only by PUT /admin/tenant-tier/{tenantID} — never by hand. '
  'Collapsed from the retired report/patch/full_endpoint vocabulary by migration 0138 (PAT-1599).';

-- tenant_tier_changes.to_tier: tighten for future inserts only. NOT VALID
-- skips validating the existing historical rows (which legitimately record
-- the old report/patch/full_endpoint values as they were at the time) — see
-- header comment. Postgres still enforces a NOT VALID CHECK on every new
-- row without a separate VALIDATE CONSTRAINT pass.
ALTER TABLE tenant_tier_changes
    DROP CONSTRAINT tenant_tier_changes_to_tier_check;

ALTER TABLE tenant_tier_changes
    ADD CONSTRAINT tenant_tier_changes_to_tier_check
    CHECK (to_tier IN ('assurance', 'managed')) NOT VALID;

COMMENT ON COLUMN tenant_tier_changes.to_tier IS
  'Tier transitioned to. assurance | managed for any row written after migration 0138 (PAT-1599); '
  'historical rows may still read report | patch | full_endpoint, preserved as an accurate record '
  'of what was true at the time — see 0138_tier_vocabulary_collapse.sql.';

INSERT INTO schema_migrations (version) VALUES ('0138_tier_vocabulary_collapse')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
