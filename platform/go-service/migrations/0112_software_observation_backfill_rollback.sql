BEGIN;

-- Reverse order of the forward migration's inserts. Deleting
-- software_observations rows cascades to software_observation_resolutions
-- (FK ON DELETE CASCADE, 0111); software_installations.latest_observation_id
-- only SETs NULL on delete, so installations must be removed explicitly.
DELETE FROM software_installations WHERE provenance = 'backfill_current_snapshot';
DELETE FROM software_observations
WHERE inventory_run_id IN (
    SELECT id FROM software_inventory_runs WHERE provenance = 'backfill_current_snapshot'
);
DELETE FROM software_inventory_runs WHERE provenance = 'backfill_current_snapshot';

DELETE FROM schema_migrations WHERE version = '0112_software_observation_backfill';

COMMIT;
