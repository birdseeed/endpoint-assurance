-- Rollback for 0168_homebrew_cve_match (PAT-2023).
--
-- Roll the binaries back first: a PAT-2023 extractor or patched-cve-sync
-- reads these columns and the review queue.
--
-- Homebrew findings, Homebrew mappings and the review queue are derived or
-- curated-from-public data: findings are rebuilt by one full match, and the
-- seed mappings are re-created by re-applying 0168. Auto-seeded mappings and
-- review decisions recorded in the queue are lost; they are re-derived on the
-- next match after re-apply, except any queue row a person had dismissed.

BEGIN;

DELETE FROM device_cve_findings WHERE package_source IS NOT NULL;

-- Homebrew observations queued for the drain; a pre-0168 binary would route
-- them down the application path.
DELETE FROM cve_match_queue
WHERE kind = 'observation'
  AND (app_name LIKE '% (Homebrew formula)' OR app_name LIKE '% (Homebrew cask)');

ALTER TABLE device_cve_findings
    DROP COLUMN IF EXISTS confidence_tier,
    DROP COLUMN IF EXISTS mapping_basis,
    DROP COLUMN IF EXISTS required_by,
    DROP COLUMN IF EXISTS install_reason,
    DROP COLUMN IF EXISTS package_name,
    DROP COLUMN IF EXISTS package_source;

DROP TABLE IF EXISTS homebrew_cpe_review_queue;

-- The PAT-2051 reconciliation at the top of 0168 (platform, notes, no
-- UNIQUE(match_name)) is deliberately not undone: it is the migrations' own
-- shape, not part of this feature.
DELETE FROM app_cpe_mappings WHERE source_type <> 'app_name';
DROP INDEX IF EXISTS app_cpe_mappings_homebrew_uq;
ALTER TABLE app_cpe_mappings
    DROP COLUMN IF EXISTS review_state,
    DROP COLUMN IF EXISTS source_type;

DELETE FROM schema_migrations WHERE version = '0168_homebrew_cve_match';

COMMIT;
