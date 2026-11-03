-- Rollback for 0050_os_cve_store (PAT-409).

BEGIN;

DROP TABLE IF EXISTS os_cve_advisories;

DELETE FROM schema_migrations WHERE version = '0050_os_cve_store';

COMMIT;
