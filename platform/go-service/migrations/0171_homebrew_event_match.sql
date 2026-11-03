-- 0171: Homebrew mappings on the event-driven CVE match paths (PAT-2045)
--
-- PAT-2024 detects a published, changed or removed CPE mapping by diffing
-- app_cpe_mappings against cve_mapping_snapshot, and queues one 'mapping'
-- job per affected match_name. Both only knew application mappings. PAT-2023
-- added Homebrew mappings to app_cpe_mappings (source_type homebrew_formula
-- or homebrew_cask), which match by exact formula name or cask token, and
-- only when review_state is 'curated'.
--
--   cve_mapping_snapshot.source_type   which matcher a snapshot row belongs
--                                      to, so a removed Homebrew mapping is
--                                      still routed to the Homebrew matcher.
--   cve_mapping_snapshot.review_state  so a mapping moving into or out of
--                                      'curated' reads as a change.
--   cve_match_queue.mapping_source_type
--                                      which matcher a 'mapping' job expands
--                                      through. Always 'app_name' on an
--                                      'observation' row.
--
-- Existing rows keep their meaning through the defaults: every snapshot row
-- and every queued mapping job so far is an application mapping. The
-- Homebrew mappings already in app_cpe_mappings are seeded into the
-- snapshot, as 0161 seeded application mappings, so they do not all read as
-- newly published on the first cycle; the nightly full match covers them.
--
-- Derived, rebuildable state only. No evidence lives here.
BEGIN;

ALTER TABLE cve_mapping_snapshot
    ADD COLUMN source_type TEXT NOT NULL DEFAULT 'app_name'
        CONSTRAINT cve_mapping_snapshot_source_type_check
        CHECK (source_type IN ('app_name', 'homebrew_formula', 'homebrew_cask')),
    ADD COLUMN review_state TEXT NOT NULL DEFAULT 'curated';

ALTER TABLE cve_match_queue
    ADD COLUMN mapping_source_type TEXT NOT NULL DEFAULT 'app_name'
        CONSTRAINT cve_match_queue_mapping_source_type_check
        CHECK (mapping_source_type IN ('app_name', 'homebrew_formula', 'homebrew_cask')),
    ADD CONSTRAINT cve_match_queue_mapping_source_shape
        CHECK (kind = 'mapping' OR mapping_source_type = 'app_name');

INSERT INTO cve_mapping_snapshot (mapping_id, match_name, cpe_vendor, cpe_product, source_type, review_state)
SELECT id, match_name, cpe_vendor, cpe_product, source_type, review_state
FROM app_cpe_mappings
WHERE source_type <> 'app_name'
ON CONFLICT (mapping_id) DO NOTHING;

INSERT INTO schema_migrations (version) VALUES ('0171_homebrew_event_match')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
