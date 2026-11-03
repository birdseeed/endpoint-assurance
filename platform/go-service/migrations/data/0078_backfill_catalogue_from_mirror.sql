-- 0078_backfill_catalogue_from_mirror.sql — PAT-850 Option A data migration.
--
-- Populates the app-specific catalogue review model (migration 0078) from the
-- existing mirror_eula_approvals rows. This is a DATA migration, deliberately
-- kept OUT of migrations/ so the integration harness never auto-runs it and so
-- production applies it as one deliberate, reviewed operation.
--
-- ORDERING: run ONCE against prod AFTER 0078_catalogue_review_model.sql is
-- applied. It reads mirror_eula_approvals (source, left untouched) and
-- device_apps (to classify Team-ID ambiguity). It is safe to dry-run — and you
-- SHOULD — by wrapping the body in BEGIN; ... ROLLBACK; and inspecting the
-- counts before committing for real.
--
-- Option A (decided by Andy, PAT-847, 2026-07-13):
--   * bundle:*  -> migrate as-is (already app-specific).
--   * team:* where the Team ID signs <=1 distinct fleet app in device_apps
--               -> migrate 1:1, keyed to name:<product_key>; Team ID demoted
--                  to signer_provenance (NOT identity). delivery_mode=mirror.
--   * team:* where the Team ID signs >1 distinct fleet app (ambiguous)
--               -> QUARANTINE: create the product but leave the reviewed target
--                  in pending_review with no delivery_mode, for per-app
--                  re-approval. No silent scope-widening.
--
-- Migrated mirror targets are set to needs_metadata (NOT ready): the legacy
-- approval only recorded "authorised to mirror", never an installer source or
-- version-detection strategy, so they are honestly incomplete until an operator
-- resolves that metadata. Current mirroring is unaffected — the CI pipeline
-- still reads the retained mirror_eula_approvals rows, not this new state.
--
-- Idempotent: every INSERT is guarded by ON CONFLICT DO NOTHING on the model's
-- natural keys, so re-running makes no further changes.

BEGIN;

-- ---------------------------------------------------------------------------
-- Classify every live approval row.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE _bf_src ON COMMIT DROP AS
WITH team_ambig AS (
    SELECT lower(team_id) AS teamid
    FROM device_apps
    WHERE team_id IS NOT NULL AND team_id <> '' AND team_id <> 'Unknown'
    GROUP BY lower(team_id)
    HAVING COUNT(DISTINCT name) > 1
)
SELECT
    m.id                                   AS approval_id,
    m.label_identity,
    m.platform,
    m.name,
    m.approved_by,
    m.approved_at,
    split_part(m.label_identity, ':', 1)   AS kind,
    split_part(m.label_identity, ':', 2)   AS keyval,
    lower(btrim(m.name))                   AS product_key,
    CASE
        WHEN split_part(m.label_identity, ':', 1) = 'team'
             AND split_part(m.label_identity, ':', 2) IN (SELECT teamid FROM team_ambig)
            THEN 'quarantine'
        ELSE 'migrate'
    END AS disposition,
    -- app-specific identity for the new model: team rows demote the Team ID to
    -- provenance and key on the reviewed name; bundle/name rows are already
    -- app-specific and carry through unchanged.
    CASE
        WHEN split_part(m.label_identity, ':', 1) = 'team'
            THEN 'name:' || lower(btrim(m.name))
        ELSE m.label_identity
    END AS target_identity
FROM mirror_eula_approvals m
WHERE m.approved = TRUE
  AND m.name IS NOT NULL AND btrim(m.name) <> '';

-- ---------------------------------------------------------------------------
-- 1. One product per distinct product_key. Earliest approval wins the metadata.
-- ---------------------------------------------------------------------------
INSERT INTO catalogue_products (product_key, display_name, created_by, created_at, updated_at)
SELECT DISTINCT ON (product_key)
       product_key, name, approved_by, approved_at, now()
FROM _bf_src
ORDER BY product_key, approved_at
ON CONFLICT (product_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Real platform targets from each approval row.
--    migrate    -> delivery_mode=mirror, state=needs_metadata
--    quarantine -> delivery_mode=NULL,   state=pending_review
--    ON CONFLICT (product_id, platform) DO NOTHING preserves any target already
--    written by a prior row for the same product+platform (e.g. tailscale,
--    which has both a macOS team row and a Windows bundle row -> both real).
-- ---------------------------------------------------------------------------
INSERT INTO catalogue_platform_targets
    (product_id, platform, identity, delivery_mode, signer_provenance, state, state_updated_at, created_at)
SELECT
    p.id,
    s.platform,
    s.target_identity,
    CASE WHEN s.disposition = 'migrate' THEN 'mirror' ELSE NULL END,
    CASE
        WHEN s.kind = 'team' AND s.disposition = 'quarantine'
            THEN jsonb_build_object(
                'team_id', s.keyval,
                'migrated_from', 'mirror_eula_approvals',
                'quarantine_reason', 'ambiguous team-id: signs >1 distinct fleet app; re-review per app',
                'original_approved_by', s.approved_by,
                'original_approved_at', s.approved_at)
        WHEN s.kind = 'team'
            THEN jsonb_build_object(
                'team_id', s.keyval,
                'migrated_from', 'mirror_eula_approvals',
                'original_approved_by', s.approved_by,
                'original_approved_at', s.approved_at)
        ELSE jsonb_build_object(
                'migrated_from', 'mirror_eula_approvals',
                'original_approved_by', s.approved_by,
                'original_approved_at', s.approved_at)
    END,
    CASE WHEN s.disposition = 'migrate' THEN 'needs_metadata' ELSE 'pending_review' END,
    now(), now()
FROM _bf_src s
JOIN catalogue_products p ON p.product_key = s.product_key
ON CONFLICT (product_id, platform) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Ensure every backfilled product has BOTH platform slots — fill the missing
--    one with a needs_metadata / NULL-delivery stub (never fabricates identity).
-- ---------------------------------------------------------------------------
INSERT INTO catalogue_platform_targets (product_id, platform, state, state_updated_at, created_at)
SELECT p.id, plat.platform, 'needs_metadata', now(), now()
FROM catalogue_products p
JOIN (SELECT DISTINCT product_key FROM _bf_src) k ON k.product_key = p.product_key
CROSS JOIN (VALUES ('macos'), ('windows')) AS plat(platform)
ON CONFLICT (product_id, platform) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4. Audit trail: one migrate row per source approval, preserving provenance.
-- ---------------------------------------------------------------------------
INSERT INTO catalogue_review_audit
    (product_id, platform_target_id, identity, platform, actor, action, delivery_mode, detail)
SELECT
    p.id,
    t.id,
    s.target_identity,
    s.platform,
    s.approved_by,
    'migrate',
    CASE WHEN s.disposition = 'migrate' THEN 'mirror' ELSE NULL END,
    jsonb_build_object(
        'disposition', s.disposition,
        'source', 'mirror_eula_approvals',
        'source_label_identity', s.label_identity,
        'original_approved_by', s.approved_by,
        'original_approved_at', s.approved_at)
FROM _bf_src s
JOIN catalogue_products p ON p.product_key = s.product_key
JOIN catalogue_platform_targets t ON t.product_id = p.id AND t.platform = s.platform
WHERE NOT EXISTS (
    SELECT 1 FROM catalogue_review_audit a
    WHERE a.product_id = p.id AND a.platform = s.platform AND a.action = 'migrate'
);

-- ---------------------------------------------------------------------------
-- Dry-run inspection (harmless SELECTs; keep when validating, drop for prod run).
-- ---------------------------------------------------------------------------
SELECT 'products' AS tbl, count(*) FROM catalogue_products
UNION ALL SELECT 'targets_total', count(*) FROM catalogue_platform_targets
UNION ALL SELECT 'targets_mirror_needs_metadata', count(*) FROM catalogue_platform_targets WHERE delivery_mode='mirror' AND state='needs_metadata'
UNION ALL SELECT 'targets_pending_review', count(*) FROM catalogue_platform_targets WHERE state='pending_review'
UNION ALL SELECT 'targets_stub_needs_metadata', count(*) FROM catalogue_platform_targets WHERE delivery_mode IS NULL AND state='needs_metadata'
UNION ALL SELECT 'audit_migrate', count(*) FROM catalogue_review_audit WHERE action='migrate';

COMMIT;
