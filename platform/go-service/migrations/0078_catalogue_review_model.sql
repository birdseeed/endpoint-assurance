-- patched.im — 0078_catalogue_review_model.sql
-- PAT-850: app-specific, cross-platform catalogue review model.
--
-- The mirror-approval store (0073_mirror_eula_approvals) is a flat, per-label
-- approval boolean keyed on (label_identity, platform). It answers exactly one
-- question — "is Patched authorised to mirror this label?" — and nothing about
-- the app-level review pipeline: which canonical product a label belongs to,
-- whether the reviewed app is delivered by mirror or vendor-direct, where its
-- installer comes from, how its version is detected, or where in the
-- download → scan → verify → publish pipeline it currently sits.
--
-- This migration adds that richer, app-centric model as FOUR new tables. It is
-- ADDITIVE ONLY: mirror_eula_approvals is deliberately retained during the
-- transition because the live CI mirror pipeline still reads
-- GET /admin/mirror/approved. The new review endpoints (PAT-850) dual-write the
-- mirror approval store so that surface stays correct with no pipeline change.
-- A later change (owned separately) backfills and, once the pipeline is cut
-- over, mirror_eula_approvals can be retired.
--
-- Model:
--   catalogue_products         one canonical product per reviewed app, spanning
--                              platforms (keyed on a platform-neutral product_key).
--   catalogue_platform_targets one row per (product, platform): the app-specific
--                              identity + delivery decision + pipeline state.
--   catalogue_review_audit     append-only decision/revocation/migration trail.
--   catalogue_dismissals       persisted dismissed discoveries (so a dismissed
--                              candidate does not resurface in the review queue).
--
-- The platform-target `state` column is the contract PAT-851/852 consume; the
-- Go handler (internal/handlers/catalogue_review.go) mirrors the CHECK values in
-- a validCatalogueStates map.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0078_catalogue_review_model.sql
BEGIN;

-- DEPLOY ORDERING: safe to apply anytime; additive, nothing existing depends on
-- these tables and mirror_eula_approvals is left untouched.

-- catalogue_products: one canonical product per reviewed app, spanning platforms.
CREATE TABLE catalogue_products (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product_key  TEXT        NOT NULL,   -- app-level key, lowercased, platform-neutral (normalized display name)
    display_name TEXT        NOT NULL,
    homepage     TEXT,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX catalogue_products_product_key_uq ON catalogue_products (product_key);

-- catalogue_platform_targets: per-(product,platform) record; the app-specific identity + pipeline state live here.
CREATE TABLE catalogue_platform_targets (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id        UUID        NOT NULL REFERENCES catalogue_products(id) ON DELETE CASCADE,
    platform          TEXT        NOT NULL CHECK (platform IN ('macos','windows')),
    identity          TEXT,       -- app-specific, platform-qualified: team:/bundle:/pkg:/name:, lowercased; NULL until resolved
    delivery_mode     TEXT        CHECK (delivery_mode IN ('mirror','vendor_direct')),  -- NULL until decided
    installer_source  TEXT,
    version_detection TEXT,
    signer_provenance JSONB       NOT NULL DEFAULT '{}'::jsonb,  -- {team_id, authenticode_publisher, migrated_from, ...}
    state             TEXT        NOT NULL CHECK (state IN (
                        'pending_review','needs_metadata','ready','queued','downloading',
                        'scanning','verifying','published','vendor_direct','failed','revoked')),
    state_error       TEXT,
    state_updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product_id, platform)
);
CREATE INDEX catalogue_platform_targets_state_idx ON catalogue_platform_targets (state);
CREATE INDEX catalogue_platform_targets_identity_idx ON catalogue_platform_targets (identity, platform) WHERE identity IS NOT NULL;

-- catalogue_review_audit: append-only decision/revocation/migration trail.
CREATE TABLE catalogue_review_audit (
    id                 BIGSERIAL   PRIMARY KEY,
    product_id         UUID        REFERENCES catalogue_products(id) ON DELETE SET NULL,
    platform_target_id UUID,
    identity           TEXT,
    platform           TEXT,
    actor              TEXT,
    action             TEXT        NOT NULL,  -- approve|revoke|dismiss|migrate|needs_metadata|update
    delivery_mode      TEXT,
    detail             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX catalogue_review_audit_product_idx ON catalogue_review_audit (product_id);

-- catalogue_dismissals: persisted dismissed discoveries (so they don't reappear).
CREATE TABLE catalogue_dismissals (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity     TEXT        NOT NULL,   -- team:/bundle:/name:, lowercased
    platform     TEXT        NOT NULL CHECK (platform IN ('macos','windows')),
    name         TEXT,
    dismissed_by TEXT,
    reason       TEXT,
    dismissed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX catalogue_dismissals_identity_platform_uq ON catalogue_dismissals (identity, platform);

GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_products TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_platform_targets TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_review_audit TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_dismissals TO patched;
GRANT USAGE, SELECT ON SEQUENCE catalogue_review_audit_id_seq TO patched;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0078_catalogue_review_model')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
