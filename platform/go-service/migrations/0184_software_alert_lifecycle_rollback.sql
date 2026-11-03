-- Rollback for 0184_software_alert_lifecycle (PAT-2097)
--
-- Roll the API and extractor binaries back first: both write these columns
-- and the transitions table.
--
-- Dropping them loses every acknowledgement, resolution, re-open and the
-- whole transition history, which cannot be rebuilt. The 0183 alerts, their
-- ledger rows and their email and webhook state are untouched. Export first
-- if the history matters:
--   psql ... -c "\copy software_unapproved_alert_transitions TO 'software_unapproved_alert_transitions.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0184_software_alert_lifecycle_rollback.sql

BEGIN;

DROP TABLE IF EXISTS software_unapproved_alert_transitions;
DROP FUNCTION IF EXISTS reject_software_unapproved_alert_transitions_mutation();
DROP FUNCTION IF EXISTS reject_software_unapproved_alert_transitions_truncate();

DROP INDEX IF EXISTS software_unapproved_alerted_devices_tenant_status_idx;
DROP INDEX IF EXISTS software_unapproved_alerted_devices_device_idx;
DROP INDEX IF EXISTS software_unapproved_alerted_devices_active_idx;
DROP INDEX IF EXISTS software_unapproved_alerted_devices_reopen_digest_idx;

ALTER TABLE software_unapproved_alerted_devices
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_id_key,
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_status_valid,
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_reason_valid,
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_resolved_shape,
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_ack_shape,
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_reopen_shape,
    DROP CONSTRAINT IF EXISTS software_unapproved_alerted_devices_product_shape,
    DROP COLUMN IF EXISTS product,
    DROP COLUMN IF EXISTS reopen_digest_pending,
    DROP COLUMN IF EXISTS reopen_digest_attempts,
    DROP COLUMN IF EXISTS reopen_digest_next_attempt_at,
    DROP COLUMN IF EXISTS last_reopened_at,
    DROP COLUMN IF EXISTS reopened_count,
    DROP COLUMN IF EXISTS resolved_reason,
    DROP COLUMN IF EXISTS resolved_at,
    DROP COLUMN IF EXISTS acknowledged_by_kind,
    DROP COLUMN IF EXISTS acknowledged_by,
    DROP COLUMN IF EXISTS acknowledged_at,
    DROP COLUMN IF EXISTS status_changed_at,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS id;

DELETE FROM schema_migrations WHERE version = '0184_software_alert_lifecycle';

COMMIT;
