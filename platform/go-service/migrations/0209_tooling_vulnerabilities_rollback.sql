-- Roll the API/extractor/sync binaries back first. Advisory, assessment,
-- finding and queue rows are derived and can be recreated. Curated mappings
-- are repository-owned seeds, not tenant decisions or evidence.
BEGIN;
DROP TRIGGER IF EXISTS trg_tooling_vulnerability_device_state ON tooling_device_state;
DROP TRIGGER IF EXISTS trg_tooling_vulnerability_current_entry ON tooling_current_entries;
DROP FUNCTION IF EXISTS tooling_vulnerability_enqueue_device();
DROP TABLE IF EXISTS tooling_vulnerability_refresh_queue;
DROP TABLE IF EXISTS tooling_vulnerability_findings;
DROP TABLE IF EXISTS tooling_vulnerability_assessments;
DROP TABLE IF EXISTS tooling_vulnerability_mappings;
DROP TABLE IF EXISTS tooling_advisory_packages;
DROP TABLE IF EXISTS tooling_advisories;
DELETE FROM schema_migrations WHERE version='0209_tooling_vulnerabilities';
COMMIT;
