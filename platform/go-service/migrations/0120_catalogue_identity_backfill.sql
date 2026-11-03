-- patched.im — 0120_catalogue_identity_backfill.sql
-- PAT-1556 (ADR-0011 §3 / migration plan step 2): "Unify identity. Link
-- retained catalogue_products to software_products, reconcile duplicates and
-- refuse ambiguous backfill rather than guessing."
--
-- Live catalogue_products data (surveyed 2026-09-11) is overwhelmingly a bulk
-- migration artifact from the pre-ADR-0011 mirror_eula_approvals era
-- (migrations/data/0078_backfill_catalogue_from_mirror.sql): most rows carry
-- only a display-name identity in catalogue_platform_targets.identity, with
-- any Team ID demoted to signer_provenance, not identity. There is
-- deliberately NO software_product_aliases.identity_kind for "Team ID known,
-- no bundle known" (see 0111) — every kind requires a real bundle/package
-- identifier. Per ADR-0011 §3, "a display name alone, or a Team ID shared by
-- several applications, cannot authorise catalogue promotion", so the bulk of
-- catalogue_products rows must NOT be auto-linked here, full stop. This is not
-- a confidence threshold — it is a hard identity-purity rule.
--
-- This migration auto-links only the narrow set of catalogue_platform_targets
-- rows that carry a genuine, specific, non-generic bundle/package identifier
-- (a real GUID product code or a real reverse-DNS bundle id) — 7 rows as of
-- the 2026-09-11 survey. Everything else — display-name-only rows, the
-- already-quarantined ambiguous-team-id rows, fake "bundle:<name>" rows that
-- are just a lowercased display name with a prefix, and the one row with a
-- verified Team ID but no bundle (no identity_kind exists for that shape) —
-- keeps catalogue_products.software_product_id NULL. That is a deliberate,
-- reviewed non-decision, not an oversight; see PAT-1556 for the full survey
-- and reasoning, including the Ghostty special case that has evidence but no
-- schema slot.
--
-- Data-driven, not a hardcoded id list: catalogue_products.id and
-- catalogue_platform_targets.id are environment-specific (differ between
-- prod, CI and local fixtures), so this migration matches purely on the
-- (platform, identity value) pairs below — the actual live identity strings —
-- via a temp table, never on a UUID literal.
--
-- Idempotent by construction, same style as 0112: every INSERT below is
-- guarded by ON CONFLICT ... DO NOTHING against an existing UNIQUE constraint
-- (software_products.canonical_key; software_product_aliases' natural key),
-- and the final UPDATE only ever moves software_product_id from NULL to a
-- resolved id, so re-running this file changes nothing further.
BEGIN;

-- The 7 live catalogue_platform_targets rows (platform, identity) that carry
-- a genuine bundle/package identifier, and the identity_kind each resolves
-- to. Every identity value here is copied verbatim from the live survey.
CREATE TEMP TABLE pat1556_resolvable_identities (
    platform      TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    identity      TEXT NOT NULL,
    identity_kind TEXT NOT NULL
) ON COMMIT DROP;

INSERT INTO pat1556_resolvable_identities (platform, identity, identity_kind) VALUES
    ('windows', '{1f01007b-2617-4cc6-bc0a-6a74fc73b132}', 'windows_native'),
    ('windows', '{f4fca927-ceb7-4549-8782-5835bd91078c}', 'windows_native'),
    ('windows', '{d57a574c-13dc-48dc-8e8c-8cd75ee45a15}', 'windows_native'),
    ('windows', '{a86cf81e-c180-4f13-a14f-63743f285999}', 'windows_native'),
    ('windows', '{dfb476c0-49e6-4a74-8cd5-2132dd190a26}', 'windows_native'),
    ('macos',   'org.openoffice.script',                  'macos_bundle'),
    ('windows', 'spiceguesttools',                         'windows_native');

-- Every live catalogue_products/catalogue_platform_targets row that matches
-- one of the identities above, joined to the identity_kind it resolves to.
-- Matched by exact (platform, identity) equality (case-insensitive; both
-- sides are already lowercased by convention, normalised again here
-- defensively) — never by product_key alone, so an unrelated product that
-- happens to share a display name cannot be swept in.
CREATE TEMP TABLE pat1556_targets ON COMMIT DROP AS
SELECT cp.id AS product_id,
       lower(btrim(cp.product_key)) AS canonical_key,
       cp.display_name,
       cpt.id AS target_id,
       cpt.platform,
       lower(btrim(cpt.identity)) AS identity_normalized,
       r.identity_kind
FROM catalogue_platform_targets cpt
JOIN catalogue_products cp ON cp.id = cpt.product_id
JOIN pat1556_resolvable_identities r
  ON r.platform = cpt.platform
 AND lower(btrim(r.identity)) = lower(btrim(cpt.identity));

-- 1. One software_products row per matched product (canonical_key already
--    lowercased on catalogue_products; canonical_name = display_name;
--    vendor_name left NULL — nothing here evidences a vendor identity).
INSERT INTO software_products (canonical_key, canonical_name, vendor_name, lifecycle_state)
SELECT DISTINCT ON (t.canonical_key)
       t.canonical_key, t.display_name, NULL, 'active'
FROM pat1556_targets t
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
           'source', 'catalogue_identity_backfill',
           'catalogue_product_id', t.product_id,
           'catalogue_platform_target_id', t.target_id
       )
FROM pat1556_targets t
JOIN software_products sp ON sp.canonical_key = t.canonical_key
ON CONFLICT (platform, identity_kind, identity_value_normalized, companion_value_normalized) DO NOTHING;

-- 3. Link catalogue_products to the resolved software_products row. Only
--    ever moves software_product_id from NULL to a value — never overwrites
--    an existing link (defensive; nothing should have set one yet, since
--    0115 shipped this column nullable-only and non-actuating).
UPDATE catalogue_products cp
SET software_product_id = sp.id,
    updated_at = now()
FROM pat1556_targets t
JOIN software_products sp ON sp.canonical_key = t.canonical_key
WHERE cp.id = t.product_id
  AND cp.software_product_id IS NULL;

INSERT INTO schema_migrations (version) VALUES ('0120_catalogue_identity_backfill')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
