-- patched.im — 0138_tier_vocabulary_collapse_rollback.sql
-- Rollback for 0138_tier_vocabulary_collapse.sql (PAT-1599).
--
-- Restores the three-value subscription_tier vocabulary (report | patch |
-- full_endpoint) and its original DEFAULT 'report'.
--
-- Data reversal is LOSSY for tenants that were 'patch' before 0138 ran:
-- 'patch' and 'report' both collapsed into 'assurance', and nothing in
-- tenants itself records which one a given tenant used to be, so this
-- rollback maps every 'assurance' row back to 'report' — the value 11 of
-- the 12 collapsed tenants actually had (verified 2026-09-16: 11 report, 1
-- patch, 1 full_endpoint). A tenant that was genuinely 'patch' comes back
-- as 'report' — an entitlement DOWNGRADE, not a lockout — rather than this
-- rollback guessing which tenant it was, or leaving every collapsed tenant
-- with a subscription_tier value the restored CHECK constraint rejects
-- (which would fail every subscription-tier gate closed for all 12
-- tenants, not just the one genuinely ambiguous case).
--
-- 'managed' -> 'full_endpoint' is lossless: 'managed' had exactly one
-- source value ('full_endpoint') going into 0138.
--
-- If the exact pre-0138 per-tenant value is needed, it is recoverable from
-- tenant_tier_changes (append-only, never rewritten by 0138) for any tenant
-- that has a row there, or from a database backup taken before 0138 was
-- applied. This script does not attempt that reconstruction — it is a
-- generic, safe-default rollback, not a targeted data-recovery operation.
--
-- Apply ONLY to undo 0138_tier_vocabulary_collapse.sql.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0138_tier_vocabulary_collapse_rollback.sql

BEGIN;

-- Widen the CHECK first (NOT VALID — the current assurance/managed rows do
-- not need to satisfy the old three-value set yet) so the data rewrite
-- below cannot be blocked by a constraint that hasn't caught up.
ALTER TABLE tenants
    DROP CONSTRAINT tenants_subscription_tier_check;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_subscription_tier_check
    CHECK (subscription_tier IN ('report', 'patch', 'full_endpoint')) NOT VALID;

UPDATE tenants
SET subscription_tier = 'report'
WHERE subscription_tier = 'assurance';

UPDATE tenants
SET subscription_tier = 'full_endpoint'
WHERE subscription_tier = 'managed';

-- Every row is now one of the three restored values; make the constraint
-- authoritative again (this validates the full table, which is cheap here
-- since the UPDATEs above already guarantee conformance).
ALTER TABLE tenants
    VALIDATE CONSTRAINT tenants_subscription_tier_check;

ALTER TABLE tenants
    ALTER COLUMN subscription_tier SET DEFAULT 'report';

COMMENT ON COLUMN tenants.subscription_tier IS
  'Commercial product tier: report | patch | full_endpoint. Source of truth for billing and feature entitlement. '
  'Distinct from tenants.tier (CIS collection tier) and agent_config.body.tier (agent behavioural mode). '
  'Written only by PUT /admin/tenant-tier/{tenantID} — never by hand.';

-- tenant_tier_changes.to_tier: restore the original three-value CHECK for
-- future inserts, the same NOT VALID approach 0138 used going the other
-- way. Existing rows are exempt from re-validation — this table is
-- append-only and its rows (old report/patch/full_endpoint history, plus
-- any assurance/managed rows written while 0138 was live) are never
-- rewritten by either direction of this migration.
ALTER TABLE tenant_tier_changes
    DROP CONSTRAINT tenant_tier_changes_to_tier_check;

ALTER TABLE tenant_tier_changes
    ADD CONSTRAINT tenant_tier_changes_to_tier_check
    CHECK (to_tier IN ('report', 'patch', 'full_endpoint')) NOT VALID;

COMMENT ON COLUMN tenant_tier_changes.to_tier IS
  'Tier transitioned to. report | patch | full_endpoint after rollback of migration 0138 (PAT-1599); '
  'rows written while 0138 was applied may read assurance | managed, preserved as an accurate record '
  'of what was true at the time.';

DELETE FROM schema_migrations WHERE version = '0138_tier_vocabulary_collapse';

COMMIT;
