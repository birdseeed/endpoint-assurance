-- Reverses 0151_vendor_advisory_titles.sql. Do not discard live vendor
-- provenance: this rollback fails closed while vendor-sourced descriptions or
-- titles exist. Export/remediate those rows first, then rerun the rollback.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM cve_feed_entries
        WHERE description_source IN ('msrc', 'apple')
    ) OR EXISTS (
        SELECT 1
        FROM os_cve_advisories
        WHERE BTRIM(vendor_title) <> ''
    ) THEN
        RAISE EXCEPTION
            'cannot roll back 0151_vendor_advisory_titles while vendor provenance exists; export cve_feed_entries rows with description_source msrc/apple and os_cve_advisories rows with vendor_title, remediate them, then rerun the rollback';
    END IF;
END
$$;

ALTER TABLE cve_feed_entries
    DROP CONSTRAINT IF EXISTS cve_feed_entries_description_source_presence,
    DROP CONSTRAINT IF EXISTS cve_feed_entries_description_source_valid,
    DROP COLUMN IF EXISTS description_source;

ALTER TABLE os_cve_advisories
    DROP COLUMN IF EXISTS vendor_title;

DELETE FROM schema_migrations WHERE version = '0151_vendor_advisory_titles';

COMMIT;
