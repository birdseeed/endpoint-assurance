-- patched.im — 0135_seed_t2_baseline_rollback.sql
-- Deliberate no-op rollback for 0135_seed_t2_baseline.sql (PAT-1794).
--
-- 0135 seeds tenant_rules rows via INSERT ... ON CONFLICT (tenant_id,
-- rule_id) DO NOTHING, so it never touches or overwrites a pre-existing
-- row — every row it inserts is brand new. But once inserted, a seeded row
-- (enabled = true, no override_severity, no suppression) is byte-for-byte
-- identical in shape to a row an operator could have created by hand.
-- Unlike 0105_seed_patched_agent_policies.sql (which writes a distinctive
-- notes marker to tenant_app_policies and can therefore delete-by-marker in
-- its own rollback), tenant_rules has no marker column recording "written
-- by migration 0135" versus "written by an operator a week later" versus
-- "written by evaluator.SeedT2Baseline for a brand-new tenant created after
-- this migration ran" — the third case uses the exact same INSERT shape on
-- purpose, so the two are indistinguishable by construction.
--
-- Deleting by any of the readily-available signals (a created_at window,
-- rule_id being T2-tier, the absence of an override or suppression) risks
-- discarding a real operator decision made after 0135 ran — for example a
-- suppression applied to a row 0135 created, or a brand-new tenant's own
-- legitimately-seeded baseline. Silently discarding real customer
-- configuration is a worse outcome than leaving a seeded baseline row in
-- place, so this rollback does not attempt to reverse the seeded data.
--
-- It only removes the schema_migrations bookkeeping row, so `migrate down`
-- accounting stays consistent with the rest of this directory's convention.
-- The data effect of 0135 is permanent by design. If a real reversal is
-- ever needed, it has to be a deliberate one-off operation informed by an
-- out-of-band record of exactly which rows 0135 inserted (captured before
-- running this migration), not a generic rollback script.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0135_seed_t2_baseline_rollback.sql

BEGIN;

DELETE FROM schema_migrations WHERE version = '0135_seed_t2_baseline';

COMMIT;
