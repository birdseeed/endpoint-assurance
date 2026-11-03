-- Rollback for 0196 (PAT-2147). Drops the lifecycle store, the reviewed
-- mappings and their audit. The cycle data is re-fetchable; the mappings and
-- audit are not, so export lifecycle_mappings and lifecycle_mapping_audit
-- first if any staff review has happened since the seed.
BEGIN;

DROP TABLE lifecycle_mapping_audit;
DROP FUNCTION reject_lifecycle_mapping_audit_mutation();
DROP TABLE lifecycle_mappings;
DROP TABLE lifecycle_cycles;
DROP TABLE lifecycle_products;

DELETE FROM schema_migrations WHERE version = '0196_software_lifecycle';

COMMIT;
