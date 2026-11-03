-- patched.im — 0122_catalogue_identity_backfill_prefix_fix.sql
-- PAT-1556 corrective follow-up to 0120_catalogue_identity_backfill.sql.
--
-- 0120 shipped and is already recorded in schema_migrations on production —
-- do not edit it or its rollback; already-applied migrations are never
-- re-run, so editing the file in place would desync it from what actually
-- ran and change nothing on the box.
--
-- Bug: 0120's pat1556_resolvable_identities temp table matched against BARE
-- identity literals (e.g. '{1f01007b-2617-4cc6-bc0a-6a74fc73b132}',
-- 'org.openoffice.script'). Live catalogue_platform_targets.identity values
-- are never bare — every row carries one of the scheme prefixes catalogue
-- review actually writes and reads (catalogueIdentityPrefixes in
-- internal/handlers/catalogue_review.go: "team:", "bundle:", "pkg:",
-- "name:"). All 7 rows this migration targets carry "bundle:". Because 0120
-- joined on exact (platform, identity) equality against bare literals that
-- never occur in the live prefixed column, it matched zero rows and
-- correctly (per its own, wrong, literals) linked nothing — confirmed live
-- on patched-api-01 (read-only queries, 2026-09-12): 0120 applied, 0 of the
-- 7 intended catalogue_products rows linked.
--
-- Fix: same intent, same 7 rows, same identity_kind mapping as 0120, but
-- matched against the real "bundle:"-prefixed values, with the prefix
-- stripped before it is stored as software_product_aliases
-- .identity_value_normalized — that column is compared elsewhere
-- (internal/extractor/software_inventory.go: findSoftwareResolution) against
-- the bare device-reported identifier, which never carries a catalogue
-- scheme prefix, so storing the prefixed form here would silently break
-- future matching.
--
-- Own temp table names (pat1556b_*, not pat1556_*) so this can never collide
-- with 0120's identically-shaped temp tables if a test transaction loads
-- both migration bodies in the same session.
--
-- Idempotent by construction, same style as 0120 and 0112: every INSERT is
-- guarded by ON CONFLICT ... DO NOTHING, and the final UPDATE only ever
-- moves software_product_id from NULL to a resolved id.
BEGIN;

-- The 7 live catalogue_platform_targets rows (platform, identity) that carry
-- a genuine bundle/package identifier, using the real "bundle:"-prefixed
-- form as stored in production. Re-verified against 0120's stated intent
-- (same 7 rows, same identity_kind per row) — only the literal format
-- changes here.
CREATE TEMP TABLE pat1556b_resolvable_identities (
    platform      TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    identity      TEXT NOT NULL,
    identity_kind TEXT NOT NULL
) ON COMMIT DROP;

INSERT INTO pat1556b_resolvable_identities (platform, identity, identity_kind) VALUES
    ('windows', 'bundle:{1f01007b-2617-4cc6-bc0a-6a74fc73b132}', 'windows_native'),
    ('windows', 'bundle:{f4fca927-ceb7-4549-8782-5835bd91078c}', 'windows_native'),
    ('windows', 'bundle:{d57a574c-13dc-48dc-8e8c-8cd75ee45a15}', 'windows_native'),
    ('windows', 'bundle:{a86cf81e-c180-4f13-a14f-63743f285999}', 'windows_native'),
    ('windows', 'bundle:{dfb476c0-49e6-4a74-8cd5-2132dd190a26}', 'windows_native'),
    ('macos',   'bundle:org.openoffice.script',                  'macos_bundle'),
    ('windows', 'bundle:spiceguesttools',                         'windows_native');

-- Every live catalogue_products/catalogue_platform_targets row that matches
-- one of the prefixed identities above, joined to the identity_kind it
-- resolves to. identity_normalized strips the scheme prefix (everything up
-- to and including the first ':') so it matches the bare, unprefixed form
-- software_product_aliases.identity_value_normalized is compared against
-- elsewhere (device-reported identifiers never carry a catalogue scheme
-- prefix). Matched by exact (platform, identity) equality on the full
-- prefixed value — never by product_key alone, so an unrelated product that
-- happens to share a display name cannot be swept in.
CREATE TEMP TABLE pat1556b_targets ON COMMIT DROP AS
SELECT cp.id AS product_id,
       lower(btrim(cp.product_key)) AS canonical_key,
       cp.display_name,
       cpt.id AS target_id,
       cpt.platform,
       lower(btrim(substring(cpt.identity from position(':' in cpt.identity) + 1))) AS identity_normalized,
       r.identity_kind
FROM catalogue_platform_targets cpt
JOIN catalogue_products cp ON cp.id = cpt.product_id
JOIN pat1556b_resolvable_identities r
  ON r.platform = cpt.platform
 AND lower(btrim(r.identity)) = lower(btrim(cpt.identity))
-- Defensive belt-and-braces (non-author review flagged this): every r.identity
-- literal above already contains ':', so a matched cpt.identity is guaranteed
-- to as well -- position() can never return 0 for a joined row. This guard
-- costs nothing and keeps that guarantee explicit rather than implicit, in
-- case this pattern is ever copied with a looser join condition.
WHERE position(':' in cpt.identity) > 0;

-- 1. One software_products row per matched product (canonical_key already
--    lowercased on catalogue_products; canonical_name = display_name;
--    vendor_name left NULL — nothing here evidences a vendor identity).
INSERT INTO software_products (canonical_key, canonical_name, vendor_name, lifecycle_state)
SELECT DISTINCT ON (t.canonical_key)
       t.canonical_key, t.display_name, NULL, 'active'
FROM pat1556b_targets t
ORDER BY t.canonical_key
ON CONFLICT (canonical_key) DO NOTHING;

-- 2. One alias per matched platform target, linking it to the software
--    product it identifies. companion_value_normalized is '' for both
--    identity_kinds used here (macos_bundle, windows_native) per the 0111
--    CHECK constraint. provenance = 'migration' (this is a data migration,
--    not a human review action or a system inference).
INSERT INTO software_product_aliases (
    product_id, platform, identity_kind, identity_value_normalized,
    companion_value_normalized, match_confidence, provenance, evidence
)
SELECT sp.id,
       t.platform,
       t.identity_kind,
       t.identity_normalized,
       '',
       'high',
       'migration',
       jsonb_build_object(
           'ticket', 'PAT-1556',
           'source', 'catalogue_identity_backfill_prefix_fix',
           'catalogue_product_id', t.product_id,
           'catalogue_platform_target_id', t.target_id
       )
FROM pat1556b_targets t
JOIN software_products sp ON sp.canonical_key = t.canonical_key
ON CONFLICT (platform, identity_kind, identity_value_normalized, companion_value_normalized) DO NOTHING;

-- 3. Link catalogue_products to the resolved software_products row. Only
--    ever moves software_product_id from NULL to a value — never overwrites
--    an existing link.
UPDATE catalogue_products cp
SET software_product_id = sp.id,
    updated_at = now()
FROM pat1556b_targets t
JOIN software_products sp ON sp.canonical_key = t.canonical_key
WHERE cp.id = t.product_id
  AND cp.software_product_id IS NULL;

INSERT INTO schema_migrations (version) VALUES ('0122_catalogue_identity_backfill_prefix_fix')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
