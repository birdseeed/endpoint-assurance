-- patched.im — 0121_retire_tenant_catalogue.sql
-- PAT-1561 (ADR-0011 §9: "Retire duplicate legacy stores"): drop
-- tenant_catalogue, the per-tenant Self-Service App Catalogue store from
-- 0067 (PAT-659 / PAT-660).
--
-- Live-data survey (patched-api-01, 2026-09-11): 2 rows total, both
-- belonging to Patched.im's own internal tenant (tenant_kind='internal',
-- PAT-1562) — no real customer has ever used this table.
--
-- Both production write paths were already hard-disabled before this
-- migration, independent of table contents:
--   - POST /admin/tenants/{tenantID}/catalogue (TenantCatalogueAddHandler)
--     called tenantCatalogueAddHandler(pool, false) — legacyExecutionEnabled
--     is compiled false in production, so it 503s via
--     legacyExecutionDisabledHandler before touching the database.
--   - GET /v1/allowlist/pending-installs (PendingInstallsHandler) called
--     pendingInstallsHandler(pool, rl, replaySkew, false) — same permanent
--     false, so it always returned {"installs":[]} without reading
--     tenant_catalogue or writing the tenant_allowlists pre-approval
--     side-effect. integration/catalogue_test.go's
--     TestCatalogueAgentPendingInstalls already asserted this fail-closed
--     behaviour even with live rows present.
-- Only the admin GET (list) and DELETE (soft-delete) handlers read/wrote
-- this table unconditionally — read-only inspection and authority-reduction,
-- consistent with this repo's legacy-execution quarantine convention of
-- retaining inspection/reduction paths while gating writes that widen
-- authority (see internal/handlers/ring_rollout.go's
-- legacyExecutionDisabledHandler comment).
--
-- With the table's only remaining live users being an internal tenant and a
-- pair of already-inert write paths, PAT-1561 removes the table, its admin
-- CRUD handlers/routes, and the catalogue_agent.go query/side-effect that
-- depended on it. tenant_allowlists itself is NOT touched — it remains the
-- live, intentional allowlist-violation-reporting store
-- (internal/handlers/allowlist.go / allowlist_agent.go).
--
-- Rollback recreates the exact 0067 schema (table + partial index + grant).

BEGIN;

DROP INDEX IF EXISTS tenant_catalogue_tenant_id;
DROP TABLE IF EXISTS tenant_catalogue;

INSERT INTO schema_migrations (version) VALUES ('0121_retire_tenant_catalogue')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
