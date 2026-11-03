-- patched.im — 0103_canonicalize_enforcement_tier_rollback.sql
-- Reverses 0103_canonicalize_enforcement_tier.sql.
--
-- Restores every row recorded in _migration_0103_tier_backup to its exact
-- prior value — not a blanket reverse mapping — and only if the row still
-- holds the exact canonical value 0103 wrote to it. See 0103's header for
-- why a blanket reverse mapping (report_deploy → report, patch →
-- app_management) applied to the table's current state would be wrong: it
-- cannot distinguish a row 0103 converted from a row that was already
-- natively canonical before 0103 ran.
--
-- LIMITATION, stated plainly rather than silently papered over: if a row
-- 0103 converted was written AGAIN after 0103 ran (e.g. an operator
-- re-saved that app's policy through PUT /admin/tenants/{tenantID}/
-- app-policies, before or after this rollback), its enforcement_tier will
-- no longer match what 0103 wrote, and this rollback deliberately leaves
-- that row alone rather than clobbering a newer, legitimate write with a
-- stale snapshot. Such a row is left in its current (post-0103) state,
-- not reverted. Check for this before relying on a clean rollback:
--
--   SELECT b.id, b.prior_enforcement_tier, t.enforcement_tier AS current_value
--   FROM _migration_0103_tier_backup b
--   JOIN tenant_app_policies t ON t.id = b.id
--   WHERE t.enforcement_tier NOT IN ('report_deploy', 'patch');
--
-- A non-empty result means those rows were edited again since 0103 ran and
-- were left untouched by this rollback.
--
-- The application code (internal/handlers/app_policies.go) that stops
-- storing canonical values is NOT reverted by this file — this is a data
-- rollback only. Revert the Go change separately (or accept that new
-- writes will keep arriving canonical even after this rollback) if a full
-- reversal is intended.

BEGIN;

UPDATE tenant_app_policies tap
SET enforcement_tier = b.prior_enforcement_tier
FROM _migration_0103_tier_backup b
WHERE tap.id = b.id
  AND (
      (b.prior_enforcement_tier = 'report' AND tap.enforcement_tier = 'report_deploy')
      OR (b.prior_enforcement_tier = 'app_management' AND tap.enforcement_tier = 'patch')
  );

DROP TABLE IF EXISTS _migration_0103_tier_backup;

DELETE FROM schema_migrations WHERE version = '0103_canonicalize_enforcement_tier';

COMMIT;
