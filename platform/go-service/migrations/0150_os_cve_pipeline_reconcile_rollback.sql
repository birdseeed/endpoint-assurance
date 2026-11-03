-- PAT-1918 rollback deliberately preserves vendor advisory evidence.
--
-- The base advisory rows are retained because they can explain a
-- customer-visible finding. PAT-1918-only metadata is removed so a later
-- forward apply starts from the exact historical-0050-compatible shape.

BEGIN;

DROP TABLE IF EXISTS os_cve_source_documents;

DROP INDEX IF EXISTS idx_os_cve_source_document;

ALTER TABLE os_cve_advisories
    DROP CONSTRAINT IF EXISTS os_cve_advisories_platform_valid,
    DROP CONSTRAINT IF EXISTS os_cve_advisories_source_valid,
    DROP COLUMN IF EXISTS source_document_id,
    DROP COLUMN IF EXISTS vendor_reference;

REVOKE DELETE ON os_cve_advisories FROM patched;

DELETE FROM schema_migrations
WHERE version = '0150_os_cve_pipeline_reconcile';

COMMIT;
