-- patched.im — 0097_agent_versions_menubar_platform.sql
-- PAT-1233: widen agent_versions.platform to also accept 'macos-menubar'.
--
-- The menu-bar apps (PatchedUpdater.app / PatchedSelfService.app, built from
-- the separate `updater` repo's CI release workflow) are different binaries
-- from the macOS endpoint collector/updater daemon that already registers
-- under platform='macos'. They need their own artifact channel so a
-- menu-bar release can never collide with, or overwrite, an endpoint-agent
-- row (or vice versa) — agent_versions' UNIQUE (platform, channel, version)
-- and the lookup in GET /v1/agent/artifact are both keyed on platform, so
-- two binaries sharing one platform value would silently shadow each other.
--
-- This is additive only: existing 'macos' and 'windows' rows are untouched,
-- and the constraint is only ever widened, never narrowed, by this forward
-- migration. Scoped deliberately to this table alone — the unrelated
-- device-platform enum used elsewhere (inventory.go, catalogue_review.go,
-- tenant_rules.go, app_policies.go, discovery_jobs.go, ...) describes
-- endpoint OS platform, not artifact channel, and is out of scope.
--
-- Constraint name follows Postgres's default CHECK-naming convention
-- (<table>_<column>_check), confirmed against 0053_agent_versions.sql,
-- which declared the CHECK inline without an explicit CONSTRAINT name.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0097_agent_versions_menubar_platform.sql

BEGIN;

ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_platform_check;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_platform_check
    CHECK (platform IN ('macos', 'windows', 'macos-menubar'));

INSERT INTO schema_migrations (version) VALUES ('0097_agent_versions_menubar_platform')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
