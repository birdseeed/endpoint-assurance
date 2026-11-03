-- patched.im - 0081_healthsignals_rotation_rollback.sql
-- Reverses 0081_healthsignals_rotation.sql.
BEGIN;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS health_signals_last_rotated_at;

DELETE FROM schema_migrations WHERE version = '0081_healthsignals_rotation';

COMMIT;
