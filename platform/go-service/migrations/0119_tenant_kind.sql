-- patched.im — 0119_tenant_kind.sql
-- PAT-1562: distinguish real paying customers from internal/test/staging
-- tenants. Right now every tenant in the table is an internal fixture, and
-- the dashboard's "Work" triage page presents all of them with full
-- production urgency because nothing marks them as non-customer.
--
-- tenant_kind defaults to 'customer' so existing rows (and any row inserted
-- without setting it) keep today's behaviour; internal/test/staging tenants
-- must be explicitly flipped to 'internal' via the new
-- PUT /admin/tenants/{tenantID}/kind endpoint. This is also the root fix for
-- PAT-1541 (a decommissioned test tenant polluting the worst-ingest-lag
-- signal) — health_admin.go's stalest-tenant query filters on
-- tenant_kind = 'customer' rather than a name-matching hack.
--
-- Additive / non-actuating: existing rows are unaffected beyond gaining the
-- default value.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0119_tenant_kind.sql
BEGIN;

ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS tenant_kind TEXT NOT NULL DEFAULT 'customer'
    CHECK (tenant_kind IN ('customer', 'internal'));

INSERT INTO schema_migrations (version) VALUES ('0119_tenant_kind')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
