-- patched.im — 0099_widen_enforcement_tier_check.sql
-- PAT-1121: widen tenant_app_policies.enforcement_tier's CHECK constraint to
-- also accept the canonical agent-config tier vocabulary (report_deploy,
-- patch), alongside the existing admin-API vocabulary (report,
-- app_management, managed).
--
-- Background: agent-config's signed `tier` field already uses
-- report_deploy/patch/managed (see contracts/agent-config.schema.json in the
-- sibling updater repo). The admin-settable enforcement_tier and the posture
-- payload's derived enforcement_tier used a second vocabulary naming the
-- same three rungs: report/app_management/managed. report_deploy≈report and
-- patch≈app_management are the same rung under two names.
-- report_deploy/patch/managed is canonical (it's the signed,
-- already-3-values-post-PAT-1048 vocabulary) — that decision is not
-- re-litigated here.
--
-- This is Phase 1 (reader-side dual-accept) of PAT-1121: it only widens what
-- is *accepted*. It does not change the '' -> 'report' default and does not
-- normalize/rewrite stored values — a row written with 'report' still reads
-- back as 'report'. Mirrors the widening already applied at the Go
-- validation layer (internal/handlers/app_policies.go's validTiers) and in
-- docs/posture.schema.json's two enforcement_tier enums. Storage-layer
-- widening is required here too: without it, the Go layer accepts
-- 'report_deploy'/'patch' but every INSERT/UPDATE using them then fails
-- the old three-value CHECK constraint (SQLSTATE 23514), turning an
-- intended 200 into a 500.
--
-- Deliberately NOT flipping any write/default behavior to canonical yet:
-- Windows agents (updater repo, concurrent ticket) only recognize the legacy
-- "app_management" string as the actuating value in
-- PostureGating.EnforcementActuates. Storing/serving canonical "patch"
-- before that Windows fix ships and the fleet picks it up would silently
-- stop granting Uninstall for patch-tier apps on already-deployed agents.
-- Normalizing stored values to canonical is deferred to a follow-up ticket,
-- gated on the Windows dual-accept fix being released and soaked.
--
-- Additive only: existing 'report'/'app_management'/'managed' rows are
-- untouched, and the constraint is only ever widened, never narrowed, by
-- this forward migration.
--
-- Constraint name follows Postgres's default CHECK-naming convention
-- (<table>_<column>_check), confirmed against 0032_tenant_app_policies.sql,
-- which declared the CHECK inline without an explicit CONSTRAINT name.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0099_widen_enforcement_tier_check.sql

BEGIN;

ALTER TABLE tenant_app_policies DROP CONSTRAINT tenant_app_policies_enforcement_tier_check;
ALTER TABLE tenant_app_policies ADD CONSTRAINT tenant_app_policies_enforcement_tier_check
    CHECK (enforcement_tier IN ('report', 'report_deploy', 'app_management', 'patch', 'managed'));

INSERT INTO schema_migrations (version) VALUES ('0099_widen_enforcement_tier_check')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
