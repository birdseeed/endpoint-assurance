-- patched.im — 0079_catalogue_vendor_origins.sql
-- PAT-853: validated vendor-owned-origin mirror promotion.
--
-- Adds the curated allowlist that POST /admin/catalogue/promote validates an
-- installer's download origin against before a needs_metadata mirror target
-- may become ready and authorise a live mirror_eula_approvals row. This is
-- the ORIGIN-OWNERSHIP half of the promotion gate (the SIGNER-PRESENCE half
-- reads catalogue_platform_targets.signer_provenance already added by 0078;
-- no schema change needed there).
--
-- Gate-location decision: origin-ownership + signer-presence authorisation
-- lives HERE, in patched.im (this is "will we mirror from this origin at
-- all"). The updater pipeline's downstream CONTENT verification (SHA-256 /
-- Authenticode / notarization) is unchanged and unduplicated — see
-- internal/handlers/catalogue_promotion.go and docs/API.md.
--
-- Model: one row per (product, host, path_prefix) the operator has curated
-- as vendor-owned. A host-only row (path_prefix='') authorises any path on
-- that host UNLESS the host is a known shared/multi-tenant host (github.com,
-- *.s3.amazonaws.com, etc — see isSharedHost in the Go handler), in which
-- case only a NON-EMPTY path_prefix entry can authorise a specific path
-- (e.g. a vendor's own GitHub Releases asset path). Fail closed: no matching
-- row means the origin is rejected.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0079_catalogue_vendor_origins.sql
BEGIN;

-- DEPLOY ORDERING: safe to apply anytime after 0078; additive, nothing
-- existing depends on this table.

CREATE TABLE catalogue_vendor_origins (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id   UUID        NOT NULL REFERENCES catalogue_products(id) ON DELETE CASCADE,
    host         TEXT        NOT NULL,               -- exact lowercased hostname, no scheme/port
    path_prefix  TEXT        NOT NULL DEFAULT '',    -- '' = host-only; non-empty = URL path must start with it
    note         TEXT,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product_id, host, path_prefix)
);
CREATE INDEX catalogue_vendor_origins_product_idx ON catalogue_vendor_origins (product_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_vendor_origins TO patched;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0079_catalogue_vendor_origins')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
