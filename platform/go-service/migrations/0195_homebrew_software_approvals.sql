-- 0195: bring Homebrew formulae and casks into the software approval model
-- (PAT-2058, building on PAT-1786/PAT-2007/PAT-2104/PAT-2013).
--
-- Same resolver, same decision/audit table, same write endpoint
-- (PUT /v1/portal/software-approvals) as applications and browser
-- extensions -- no parallel approval store. Only the policy row itself is
-- new, mirroring tenant_app_policies / tenant_extension_policies:
--
--   tenant_homebrew_policies   one row per (tenant, kind, name, tap) a
--                              customer has decided on. kind is 'formula' or
--                              'cask' (taps are not approvable -- PAT-2013's
--                              identity kind homebrew_tap is namespace
--                              evidence, not a product, and the ticket scope
--                              is formulae and casks only). No FK cascade
--                              hazard here (unlike the audit ledgers): this
--                              is live policy state, not an append-only log,
--                              so it keeps the normal
--                              REFERENCES tenants(id) ON DELETE CASCADE
--                              tenant_app_policies already uses.
--
-- Identity: PAT-2013 already keys a Homebrew observation on (kind, name,
-- tap) -- software_observations.identity_value_normalized /
-- .companion_value_normalized, lower-cased and whitespace-collapsed the same
-- way normalizedIdentityValue does for every other observation kind. This
-- migration follows that scheme rather than inventing a new one: name and
-- tap are stored pre-normalised (lower-cased), and tap '' means "the
-- package's own default tap or unrecorded" -- homebrew/core for a formula,
-- homebrew/cask for a cask -- collapsed at write time (see
-- softwaregov.NormalizeHomebrewTap) so a formula reported with an explicit
-- homebrew/core tap and one reported with no tap at all resolve to the same
-- policy row. Any other tap is kept as its own row, because a same-named
-- formula in a third-party tap is a different package (AGENTS.md "identity
-- is not packaging").
--
-- software_approval_decisions (0182) gains two new product_type values.
-- Homebrew items carry no platform, team_id or browser (they are macOS-only
-- and namespaced by tap instead), so the existing NULL-shape CHECK grows a
-- third branch rather than a new column. identifier holds the bare
-- (normalised) name; the tap, when it disambiguates the product, lives only
-- in product_key ("homebrew:formula:<name>" or, tap-qualified,
-- "homebrew:formula:<tap>/<name>"; casks the same with "cask") -- the same
-- place PAT-2007 already puts every other disambiguating field that doesn't
-- have its own audit column.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0195_homebrew_software_approvals.sql

BEGIN;

CREATE TABLE tenant_homebrew_policies (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        TEXT        NOT NULL CHECK (kind IN ('formula', 'cask')),
    -- Pre-normalised (lower-cased, whitespace-collapsed), matching
    -- software_observations.identity_value_normalized for the same package.
    name        TEXT        NOT NULL CHECK (name = lower(btrim(name)) AND name <> '' AND length(name) <= 256),
    -- '' means the package's own default tap (or unrecorded); see the
    -- header comment. Never NULL, so the uniqueness index below needs no
    -- COALESCE.
    tap         TEXT        NOT NULL DEFAULT '' CHECK (tap = lower(btrim(tap)) AND length(tap) <= 256),
    policy      TEXT        NOT NULL CHECK (policy IN ('approved', 'unapproved', 'unmanaged')),
    notes       TEXT        NOT NULL DEFAULT '' CHECK (length(notes) <= 1000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX tenant_homebrew_policies_identity_uq
    ON tenant_homebrew_policies (tenant_id, kind, name, tap);
CREATE INDEX tenant_homebrew_policies_tenant_idx ON tenant_homebrew_policies (tenant_id);

COMMENT ON TABLE tenant_homebrew_policies IS
    'PAT-2058: customer portal approval decisions for Homebrew formulae and casks, resolved by the same softwaregov resolver as tenant_app_policies/tenant_extension_policies. Written only by PUT /v1/portal/software-approvals.';

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_homebrew_policies TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_homebrew_policies_id_seq TO patched;

-- Extend the audit ledger's product_type vocabulary (0182).
ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_product_type_check;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_product_type_check
    CHECK (product_type IN ('application', 'browser_extension', 'homebrew_formula', 'homebrew_cask'));

-- Extend the per-type NULL shape (0182's unnamed compound CHECK, named
-- software_approval_decisions_check1 by Postgres's default convention).
-- A Homebrew row carries no platform, team_id or browser: it is macOS-only
-- and namespaced by tap in product_key instead of a dedicated column.
ALTER TABLE software_approval_decisions
    DROP CONSTRAINT software_approval_decisions_check1;
ALTER TABLE software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_check1
    CHECK ((product_type = 'application' AND platform IS NOT NULL AND browser IS NULL)
        OR (product_type = 'browser_extension' AND platform IS NULL AND team_id IS NULL AND browser IS NOT NULL)
        OR (product_type IN ('homebrew_formula', 'homebrew_cask')
            AND platform IS NULL AND team_id IS NULL AND browser IS NULL));

INSERT INTO schema_migrations (version) VALUES ('0195_homebrew_software_approvals')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
