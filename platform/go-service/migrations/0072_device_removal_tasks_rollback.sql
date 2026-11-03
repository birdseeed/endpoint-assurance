-- Rollback for 0072_device_removal_tasks (PAT-781 / PAT-462).

BEGIN;

DROP INDEX IF EXISTS device_removal_tasks_active_uq;
DROP INDEX IF EXISTS device_removal_tasks_device;
DROP TABLE IF EXISTS device_removal_tasks;

DELETE FROM schema_migrations WHERE version = '0072_device_removal_tasks';

COMMIT;
