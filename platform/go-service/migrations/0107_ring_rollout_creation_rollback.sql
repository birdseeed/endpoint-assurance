BEGIN;
DROP TRIGGER IF EXISTS trg_ring_rollout_evidence_immutable ON ring_version_approvals;
DROP FUNCTION IF EXISTS reject_ring_rollout_evidence_mutation();
DROP INDEX IF EXISTS ring_rollout_creation_idempotency_idx;
ALTER TABLE ring_version_approvals
    DROP CONSTRAINT IF EXISTS ring_rollout_creation_impact_check,
    DROP CONSTRAINT IF EXISTS ring_rollout_creation_evidence_complete_check,
    DROP CONSTRAINT IF EXISTS ring_rollout_creation_hash_check,
    DROP CONSTRAINT IF EXISTS ring_rollout_creation_mode_check,
    DROP COLUMN IF EXISTS impact_snapshot,
    DROP COLUMN IF EXISTS request_fingerprint,
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS reason,
    DROP COLUMN IF EXISTS rollout_mode,
    DROP COLUMN IF EXISTS verified_at,
    DROP COLUMN IF EXISTS verified_signer,
    DROP COLUMN IF EXISTS verified_sha256,
    DROP COLUMN IF EXISTS catalogue_generated_at,
    DROP COLUMN IF EXISTS catalogue_content_hash,
    DROP COLUMN IF EXISTS catalogue_target_id,
    DROP COLUMN IF EXISTS catalogue_product_id;
ALTER TABLE ring_config_changes DROP CONSTRAINT IF EXISTS ring_config_changes_change_type_check;
-- Existing rollout_created audit rows are intentionally retained. Rollback
-- removes the creation API/schema, not its append-only historical evidence,
-- so the restored vocabulary continues to admit that now-dormant event type.
ALTER TABLE ring_config_changes ADD CONSTRAINT ring_config_changes_change_type_check CHECK (change_type IN (
    'config_updated', 'device_override_set', 'device_override_cleared',
    'rollout_paused', 'rollout_resumed', 'rollout_skipped',
    'rollout_advanced', 'rollout_auto_paused', 'rollout_completed',
    'rollout_superseded', 'rollout_emergency_deploy', 'rollout_created'
));
-- Preserve source_addr and claimed_actor: exercised rollout_created audit
-- evidence retains its honest attribution after the creation API is removed.
DELETE FROM schema_migrations WHERE version = '0107_ring_rollout_creation';
COMMIT;
