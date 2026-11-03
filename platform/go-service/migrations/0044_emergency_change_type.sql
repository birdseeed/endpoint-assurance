-- PAT-593: Add rollout_emergency_deploy to ring_config_changes.change_type CHECK constraint.
-- Postgres does not support ALTER TABLE ... ALTER CONSTRAINT directly; we must drop and re-add
-- the CHECK constraint with the expanded value list.

BEGIN;

ALTER TABLE ring_config_changes DROP CONSTRAINT IF EXISTS ring_config_changes_change_type_check;

ALTER TABLE ring_config_changes
    ADD CONSTRAINT ring_config_changes_change_type_check
    CHECK (change_type IN (
        'config_updated',
        'device_override_set',
        'device_override_cleared',
        'rollout_paused',
        'rollout_resumed',
        'rollout_skipped',
        'rollout_advanced',
        'rollout_auto_paused',
        'rollout_completed',
        'rollout_superseded',
        'rollout_emergency_deploy'
    ));

INSERT INTO schema_migrations (version) VALUES ('0044_emergency_change_type');

COMMIT;
