-- Rollback for PAT-1974 (0159_local_admin_accounts.sql).
--
-- local_admin_accounts is derived, re-extractable data (from the immutable
-- raw_payloads archive), same as device_certificates/device_storage_volume:
-- dropping it loses nothing re-extraction can't rebuild once a PAT-1974
-- agent has reported again. No append-only ledger is involved, so this
-- rollback carries no destructive-data guard.
--
-- The "local_admins" key merged into devices.collection_status (PAT-1732)
-- by upsertCollectionStatus is left in place deliberately: it lives in a
-- pre-existing JSONB column this migration did not create, and stripping one
-- key out of every device's stored snapshot is more destructive than simply
-- leaving a now-unused key that a rolled-back extractor will stop writing.

BEGIN;

DROP TABLE IF EXISTS local_admin_accounts;

DELETE FROM schema_migrations WHERE version = '0159_local_admin_accounts';

COMMIT;
