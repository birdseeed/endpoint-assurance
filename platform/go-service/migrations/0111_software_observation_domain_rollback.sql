BEGIN;

DROP TRIGGER IF EXISTS trg_software_observations_reject_truncate ON software_observations;
DROP FUNCTION IF EXISTS reject_software_observation_truncate();
DROP TRIGGER IF EXISTS trg_software_observations_reject_update ON software_observations;
DROP FUNCTION IF EXISTS reject_software_observation_update();
DROP TABLE IF EXISTS software_installations;
DROP TABLE IF EXISTS software_observation_resolutions;
DROP TABLE IF EXISTS software_observations;
DROP TABLE IF EXISTS software_inventory_runs;
DROP TABLE IF EXISTS software_product_aliases;
DROP TABLE IF EXISTS software_products;
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_id_tenant_uq;
DELETE FROM schema_migrations WHERE version = '0111_software_observation_domain';

COMMIT;
