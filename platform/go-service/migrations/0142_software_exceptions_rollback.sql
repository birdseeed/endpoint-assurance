-- patched.im — rollback for 0142_software_exceptions.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_tenant_software_exception_changes_append_only_truncate ON tenant_software_exception_changes;
DROP TRIGGER IF EXISTS trg_tenant_software_exception_changes_append_only ON tenant_software_exception_changes;
DROP FUNCTION IF EXISTS reject_tenant_software_exception_changes_truncate();
DROP FUNCTION IF EXISTS reject_tenant_software_exception_changes_mutation();
DROP TABLE IF EXISTS tenant_software_exception_changes;
DROP TABLE IF EXISTS tenant_software_exception_devices;
DROP TABLE IF EXISTS tenant_software_exceptions;

DELETE FROM schema_migrations WHERE version = '0142_software_exceptions';

COMMIT;
