-- patched.im — rollback for 0144_device_os_update.sql

BEGIN;

DROP TABLE IF EXISTS device_os_update;

DELETE FROM schema_migrations WHERE version = '0144_device_os_update';

COMMIT;
