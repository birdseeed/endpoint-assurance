-- patched.im — 0080_catalogue_target_identity_unique_rollback.sql
-- Reverses 0080_catalogue_target_identity_unique.sql: drops the
-- UNIQUE(identity, platform) index and restores the non-unique partial identity
-- index 0078 originally created, returning the schema to its pre-0080 shape.
BEGIN;

DROP INDEX IF EXISTS catalogue_platform_targets_identity_platform_uq;
CREATE INDEX IF NOT EXISTS catalogue_platform_targets_identity_idx
    ON catalogue_platform_targets (identity, platform)
    WHERE identity IS NOT NULL;

DELETE FROM schema_migrations WHERE version = '0080_catalogue_target_identity_unique';

COMMIT;
