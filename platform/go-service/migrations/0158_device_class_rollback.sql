-- Rollback for PAT-1960 (0158_device_class.sql).
--
-- Both new devices columns and the compliance_rules backfill are derived
-- data: devices.device_class/installation_type/os_caption are re-derivable
-- by re-extraction from the immutable raw_payloads archive once a
-- device-class-reporting agent (PAT-1959) has sent a payload again, and the
-- compliance_rules.device_class backfill is reproducible by re-running the
-- same UPDATE in 0158. No append-only ledger is involved, so this rollback
-- carries no destructive-data guard.

BEGIN;

ALTER TABLE compliance_rules DROP COLUMN IF EXISTS device_class;

ALTER TABLE devices DROP COLUMN IF EXISTS os_caption;
ALTER TABLE devices DROP COLUMN IF EXISTS installation_type;
ALTER TABLE devices DROP COLUMN IF EXISTS device_class;

DELETE FROM schema_migrations WHERE version = '0158_device_class';

COMMIT;
