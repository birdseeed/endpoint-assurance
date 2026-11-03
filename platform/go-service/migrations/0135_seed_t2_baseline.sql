-- patched.im — 0135_seed_t2_baseline.sql
-- PAT-1794: seed a T2 compliance-rule baseline for every existing tenant.
--
-- Decision (Andy, 2026-09-16): every assessed tenant gets the full T2
-- control set on by default, not opt-in. Today compliance_rules has 32
-- enabled T1 rules (always evaluated, no tenant_rules row needed) and 130
-- enabled T2 rules (only evaluated when an enabled tenant_rules row exists
-- for that tenant+rule — see 0005_tenant_rules.sql). Only 39 distinct T2
-- rules have ever been evaluated for any real tenant: roughly 91 enabled T2
-- rules are silently inert, and nothing records which controls an
-- assessment is supposed to include, so a fixed and deployed T2 rule can
-- have zero effect on a real tenant with no signal anywhere that it was
-- skipped.
--
-- This migration inserts one tenant_rules row (enabled = true, no override
-- or suppression) for every (tenant, T2 rule) pair that doesn't already
-- have one — every row in tenants crossed with every row in compliance_rules
-- WHERE collection_tier = 'T2' AND enabled = true. ON CONFLICT (tenant_id,
-- rule_id) DO NOTHING means an existing per-tenant row — an operator's
-- deliberate override, disable or suppression for that (tenant, rule) pair
-- — is never touched, whatever its enabled/override/suppression state.
--
-- Going forward, both tenant-creation code paths call the equivalent
-- single-tenant seed (evaluator.SeedT2Baseline, internal/evaluator/evaluator.go)
-- inside their own transaction, so this migration only needs to cover the
-- gap: tenants that existed before this ticket shipped.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0135_seed_t2_baseline.sql

BEGIN;

INSERT INTO tenant_rules (id, tenant_id, rule_id, enabled, created_at, updated_at)
SELECT gen_random_uuid(), t.id, cr.id, true, now(), now()
FROM tenants t
CROSS JOIN compliance_rules cr
WHERE cr.collection_tier = 'T2'
  AND cr.enabled = true
ON CONFLICT (tenant_id, rule_id) DO NOTHING;

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0135_seed_t2_baseline')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
