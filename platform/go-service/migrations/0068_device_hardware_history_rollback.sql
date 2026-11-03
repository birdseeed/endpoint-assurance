-- Rollback for 0068_device_hardware_history (PAT-686).

BEGIN;

DROP TABLE IF EXISTS device_hardware_history;

DELETE FROM schema_migrations WHERE version = '0068_device_hardware_history';

COMMIT;
