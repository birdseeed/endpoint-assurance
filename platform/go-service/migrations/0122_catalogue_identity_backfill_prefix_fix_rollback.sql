-- Roll back PAT-1556's prefix-corrected catalogue identity backfill (0122).
--
-- Reverses, in the opposite order, exactly the writes 0122 makes: it
-- re-derives the same (platform, identity) match set from the temp table,
-- then un-links catalogue_products, deletes the aliases this migration
-- created (provenance = 'migration', scoped to the same identities), and
-- deletes the software_products rows this migration created — but only if
-- they have picked up no other alias or reference since, so this fails
-- closed (an FK RESTRICT error) rather than silently deleting state some
-- other process has since built on. Same structure as 0120's rollback; own
-- temp table names (pat1556b_*) so it cannot collide with 0120's rollback if
-- both are ever loaded in the same session.
--
-- This does not touch 0120 or its rollback. 0120 already ran in production
-- and (per its own, incorrect, bare-literal matching) linked zero rows, so
-- there is nothing for 0120's rollback to undo; rolling back 0122 alone
-- fully reverses this ticket's actual effect on the data.
BEGIN;

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

CREATE TEMP TABLE pat1556b_targets ON COMMIT DROP AS
SELECT cp.id AS product_id,
       lower(btrim(cp.product_key)) AS canonical_key,
       cpt.platform,
       lower(btrim(substring(cpt.identity from position(':' in cpt.identity) + 1))) AS identity_normalized,
       r.identity_kind
FROM catalogue_platform_targets cpt
JOIN catalogue_products cp ON cp.id = cpt.product_id
JOIN pat1556b_resolvable_identities r
  ON r.platform = cpt.platform
 AND lower(btrim(r.identity)) = lower(btrim(cpt.identity))
-- Same defensive guard as the forward migration, kept identical so the
-- rollback derives the same identity_normalized set it needs to reverse.
WHERE position(':' in cpt.identity) > 0;

-- 1. Un-link catalogue_products, but only where it points at a
--    software_products row this migration would have created (matched by
--    canonical_key from the target set).
UPDATE catalogue_products cp
SET software_product_id = NULL,
    updated_at = now()
FROM pat1556b_targets t
JOIN software_products sp ON sp.canonical_key = t.canonical_key
WHERE cp.id = t.product_id
  AND cp.software_product_id = sp.id;

-- 2. Delete the aliases 0122 created for these identities.
DELETE FROM software_product_aliases spa
USING pat1556b_targets t
WHERE spa.platform = t.platform
  AND spa.identity_kind = t.identity_kind
  AND spa.identity_value_normalized = t.identity_normalized
  AND spa.companion_value_normalized = ''
  AND spa.provenance = 'migration'
  AND spa.evidence @> jsonb_build_object('ticket', 'PAT-1556', 'source', 'catalogue_identity_backfill_prefix_fix');

-- 3. Delete the software_products rows 0122 created, but only if the two
--    referencing tables this migration itself wrote to (software_product_aliases,
--    catalogue_products) show nothing left pointing at the row. This does
--    not enumerate every table with a software_products FK in the schema —
--    if some other table gained one since, DELETE fails with an FK RESTRICT
--    error rather than silently dropping state that process built on.
DELETE FROM software_products sp
WHERE sp.canonical_key IN (SELECT canonical_key FROM pat1556b_targets)
  AND NOT EXISTS (
      SELECT 1 FROM software_product_aliases spa WHERE spa.product_id = sp.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM catalogue_products cp WHERE cp.software_product_id = sp.id
  );

DELETE FROM schema_migrations
WHERE version = '0122_catalogue_identity_backfill_prefix_fix';

COMMIT;
