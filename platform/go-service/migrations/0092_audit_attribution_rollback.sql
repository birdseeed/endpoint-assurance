-- Rollback 0092_audit_attribution
--
-- MIGRATIONS ARE FORWARD-ONLY IN NORMAL OPERATION. deploy/api-01/deploy.sh
-- has no rollback step and never invokes this file; production migrations
-- are applied once, in order, and stay applied. This file exists as a
-- MANUAL EMERGENCY TOOL ONLY, to be run by hand (psql) if 0092 itself turns
-- out to be broken and needs to be backed out before a fix can ship.
--
-- Even run correctly, this rollback is LOSSY:
--   - source_addr is dropped outright for every row (post- and pre-PAT-1135
--     alike) -- there is no pre-migration column to restore it to.
--   - claimed_actor values written by POST-migration requests (a live
--     caller's genuine "actor"/"changed_by" claim on a new row, captured
--     after 0092 shipped) are also dropped outright, with no pre-migration
--     home for them either -- the old schema had nowhere to put them.
--   - Only the BACKFILLED claimed_actor values (rows that existed before
--     0092 ran, whose original actor/changed_by/admin_id got moved into
--     claimed_actor at migration time) are restored below, back into the
--     authoritative column they came from, before the columns are dropped.
--
-- If either of the two lossy categories above matters (an operator wants to
-- keep them), export claimed_actor/source_addr for the affected rows to a
-- separate archive BEFORE running this file. Once COMMIT runs, that data is
-- gone.
BEGIN;

-- Restore backfilled values into the authoritative column BEFORE dropping
-- claimed_actor, so rollback does not lose data that existed before 0092
-- ran. Only rows still carrying the migration's 'legacy_unauthenticated'
-- sentinel are touched -- a row whose authoritative column was subsequently
-- overwritten by anything else (including a live post-migration write of
-- 'admin_shared_token') is left alone, matching the "don't clobber a write
-- that happened after this backfill" rule.
UPDATE device_revocations
    SET admin_id = claimed_actor
    WHERE admin_id = 'legacy_unauthenticated' AND claimed_actor IS NOT NULL;

UPDATE tenant_app_policy_changes
    SET changed_by = claimed_actor
    WHERE changed_by = 'legacy_unauthenticated' AND claimed_actor IS NOT NULL;

UPDATE tenant_rule_changes
    SET changed_by = claimed_actor
    WHERE changed_by = 'legacy_unauthenticated' AND claimed_actor IS NOT NULL;

UPDATE tenant_platform_changes
    SET changed_by = claimed_actor
    WHERE changed_by = 'legacy_unauthenticated' AND claimed_actor IS NOT NULL;

UPDATE tenant_tier_changes
    SET changed_by = claimed_actor
    WHERE changed_by = 'legacy_unauthenticated' AND claimed_actor IS NOT NULL;

-- tenant_decommission_audit is append-only by trigger, not just convention
-- (trg_tenant_decommission_audit_append_only, 0091_agent_decommission.sql)
-- -- see the identical note in 0092_audit_attribution.sql's forward
-- migration. Same exception, same discipline: disable only around this one
-- statement, re-enable before COMMIT.
ALTER TABLE tenant_decommission_audit DISABLE TRIGGER trg_tenant_decommission_audit_append_only;

UPDATE tenant_decommission_audit
    SET actor = claimed_actor
    WHERE actor = 'legacy_unauthenticated' AND claimed_actor IS NOT NULL;

ALTER TABLE tenant_decommission_audit ENABLE TRIGGER trg_tenant_decommission_audit_append_only;

ALTER TABLE device_revocations
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor;

ALTER TABLE tenant_app_policy_changes
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor;

ALTER TABLE tenant_rule_changes
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor;

ALTER TABLE tenant_platform_changes
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor;

ALTER TABLE tenant_tier_changes
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor;

ALTER TABLE tenant_decommission_audit
    DROP COLUMN IF EXISTS source_addr,
    DROP COLUMN IF EXISTS claimed_actor;

DELETE FROM schema_migrations WHERE version = '0092_audit_attribution';

COMMIT;
