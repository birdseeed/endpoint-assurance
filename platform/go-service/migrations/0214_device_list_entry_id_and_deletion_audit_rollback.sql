-- Reverses 0214_device_list_entry_id_and_deletion_audit.sql (PAT-2271).
BEGIN;

REVOKE UPDATE (entry_count) ON TABLE device_list_uploads FROM patched;
REVOKE DELETE ON TABLE device_list_entries FROM patched;

DROP TRIGGER IF EXISTS trg_device_list_entry_deletions_append_only_truncate ON device_list_entry_deletions;
DROP TRIGGER IF EXISTS trg_device_list_entry_deletions_append_only ON device_list_entry_deletions;
DROP FUNCTION IF EXISTS reject_device_list_entry_deletions_truncate();
DROP FUNCTION IF EXISTS reject_device_list_entry_deletions_mutation();
DROP TABLE IF EXISTS device_list_entry_deletions;

ALTER TABLE device_list_entries DROP CONSTRAINT IF EXISTS device_list_entries_id_key;
ALTER TABLE device_list_entries DROP COLUMN IF EXISTS id;

DELETE FROM schema_migrations WHERE version = '0214_device_list_entry_id_and_deletion_audit';

COMMIT;
