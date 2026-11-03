-- patched.im — 0157_notification_channels_rollback.sql
-- Reverses 0157_notification_channels.sql (PAT-1888).
--
-- This is the schema-level reversal, used only when the feature is being
-- removed from the platform entirely. It is destructive: it discards every
-- configured channel and the whole delivery audit trail.
--
-- The product-level rollback is NOT this file. To stop one tenant receiving
-- notifications, disable the channel and keep the history:
--
--   UPDATE notification_channels SET enabled = false, updated_at = now()
--   WHERE tenant_id = '<uuid>';
--
-- That path retains audit and retry state, which is what the ticket requires.

BEGIN;

DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_channels;

DELETE FROM schema_migrations WHERE version = '0157_notification_channels';

COMMIT;
