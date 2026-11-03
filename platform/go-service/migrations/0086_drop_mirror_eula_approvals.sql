-- patched.im — 0086_drop_mirror_eula_approvals.sql
-- PAT-847: retire the legacy PAT-794 mirror-approval store.
--
-- The app-specific catalogue review model (0078/0079/0080, PAT-850/851/853)
-- has been the CI mirror pipeline's sole source of truth since PAT-851 shipped
-- GET /admin/catalogue/pipeline-ready — the updater repo's ci/mirror_pipeline.py
-- reads that endpoint exclusively (see its _label_identity / pipeline-ready
-- fetch) and no longer reads GET /admin/mirror/approved. The Go handlers for
-- the legacy surface (mirror.go: MirrorCandidatesHandler, MirrorApprovedHandler,
-- MirrorApprovalCreateHandler, MirrorApprovalDeleteHandler) and their
-- mirror_eula_approvals dual-writes in catalogue_review.go / catalogue_promotion.go
-- were removed in the same change that adds this migration. This migration
-- drops the now-unread table.
--
-- FAIL LOUD: before dropping, verify every currently-approved legacy row's APP
-- is represented in the catalogue model. "Represented" means a
-- catalogue_products row with product_key = lower(btrim(name)) that has a
-- catalogue_platform_targets row for the approval's platform — the same
-- (product, platform) grain migrations/data/0078_backfill_catalogue_from_mirror.sql
-- (the PAT-850 Option A data migration, run once by hand — see its header)
-- creates for every row it processes, in BOTH its 'migrate' and 'quarantine'
-- dispositions (a quarantined row still gets a product + target, just parked
-- at state='pending_review'). The guard deliberately checks product+platform
-- existence rather than re-deriving per-row identities, because Option A
-- collapses same-name rows: when two approved rows share (lower(name),
-- platform) under different identities, the backfill's ON CONFLICT DO NOTHING
-- keeps only the first target identity — the "losing" row's app is still
-- represented by that product, and an identity-exact guard would abort on it
-- forever with no possible remediation.
--
-- Two scope notes, both by-design Option A behavior this guard mirrors
-- rather than fights:
--   * Approved rows with a NULL/blank name were SKIPPED by the backfill (its
--     WHERE clause excludes them — they are unmappable to a product). They can
--     never become represented, so they are exempt from the abort and instead
--     reported via RAISE WARNING below, then dropped with the table. These are
--     precisely the name-less team-wide approvals whose over-broad grant
--     PAT-847 exists to retire.
--   * The guard guarantees each approved APP survives as a (product, platform)
--     target — it does NOT guarantee every row's individual provenance
--     (approved_by/approved_at/team_id) survived; Option A's name-collapse
--     keeps first-writer provenance only, and the audit-trail dedup in the
--     backfill matches. That loss already happened at backfill time; the drop
--     changes nothing about it.
-- A row failing this check means the data backfill was never run against this
-- database (or a live approval was created after it ran, with no matching
-- review since) — dropping now would lose a live approval with no record in
-- the new model, so abort instead.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0086_drop_mirror_eula_approvals.sql
BEGIN;

-- DEPLOY ORDERING: apply after 0078 (catalogue model) and, on any box that
-- ever had live mirror approvals, after migrations/data/0078_backfill_catalogue_from_mirror.sql
-- has been run for real (not just dry-run) against that box. The guard below
-- enforces this at apply time rather than trusting operational memory.

DO $$
DECLARE
    unrepresented_list text;
    nameless_list      text;
BEGIN
    -- By-design discards: approved rows the backfill could never map (no name).
    -- Surface them in the apply output so the operator sees exactly what is
    -- being retired with the table, then let the drop proceed.
    SELECT string_agg(
             format('(label_identity=%L, platform=%L)', m.label_identity, m.platform),
             ', ' ORDER BY m.label_identity, m.platform)
      INTO nameless_list
      FROM mirror_eula_approvals m
      WHERE m.approved = TRUE
        AND (m.name IS NULL OR btrim(m.name) = '');

    IF nameless_list IS NOT NULL THEN
        RAISE WARNING
          'migration 0086: dropping approved name-less legacy approval(s) the 0078 backfill skipped by design (unmappable to a product): %. These over-broad identity-only grants are retired with the table.',
          nameless_list;
    END IF;

    -- Abort condition: a nameable approved row whose (product, platform) never
    -- made it into the catalogue model — the backfill was not run, or a later
    -- approval was never re-reviewed.
    SELECT string_agg(
             format('(label_identity=%L, name=%L, platform=%L)', u.label_identity, u.name, u.platform),
             ', ' ORDER BY u.label_identity, u.platform)
      INTO unrepresented_list
      FROM (
            SELECT m.label_identity, m.name, m.platform
              FROM mirror_eula_approvals m
              WHERE m.approved = TRUE
                AND m.name IS NOT NULL AND btrim(m.name) <> ''
                AND NOT EXISTS (
                      SELECT 1
                        FROM catalogue_products p
                        JOIN catalogue_platform_targets t ON t.product_id = p.id
                       WHERE p.product_key = lower(btrim(m.name))
                         AND t.platform = m.platform
                    )
           ) u;

    IF unrepresented_list IS NOT NULL THEN
        RAISE EXCEPTION
          'migration 0086 aborted: approved mirror_eula_approvals row(s) not represented in the catalogue model: %. Run migrations/data/0078_backfill_catalogue_from_mirror.sql against this database first (see that file''s header), then re-apply 0086.',
          unrepresented_list;
    END IF;
END $$;

DROP TABLE mirror_eula_approvals;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0086_drop_mirror_eula_approvals')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
