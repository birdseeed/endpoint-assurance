-- 0069: per-app minimum-version policy (PAT-723).
--
-- Adds an optional min_version floor to tenant_app_policies. When set on a
-- mandatory app policy, the drift evaluator flags devices whose installed
-- version is below this floor (drift_type=version_below_minimum), extending
-- the policy model from present/absent to present-but-stale.

BEGIN;

ALTER TABLE tenant_app_policies ADD COLUMN IF NOT EXISTS min_version TEXT;

INSERT INTO schema_migrations (version) VALUES ('0069_tenant_app_policies_min_version')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
