-- Rollback for 0199_jamf_webhook_coverage (PAT-2145)
--
-- Roll the API binary back first: the Jamf webhook endpoint and the
-- /v1/portal/mdm/jamf/* routes read and write these tables.
--
-- Dropping jamf_devices loses every Mac Jamf has reported since setup. It
-- cannot be rebuilt: Jamf Pro does not resend past webhooks and the raw
-- bodies were never stored. Dropping jamf_webhook_connectors invalidates
-- every tenant's webhook URL and token (Jamf would then get 401s until the
-- customer sets up again). Dropping jamf_webhook_audit loses who created,
-- rotated and revoked each token. Export first:
--   psql ... -c "\copy jamf_devices TO 'jamf_devices.csv' CSV HEADER"
--   psql ... -c "\copy jamf_webhook_audit TO 'jamf_webhook_audit.csv' CSV HEADER"
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0199_jamf_webhook_coverage_rollback.sql

BEGIN;

DROP TABLE IF EXISTS jamf_devices;
DROP TABLE IF EXISTS jamf_webhook_audit;
DROP TABLE IF EXISTS jamf_webhook_connectors;
DROP FUNCTION IF EXISTS reject_jamf_webhook_audit_mutation();
DROP FUNCTION IF EXISTS reject_jamf_webhook_audit_truncate();

DELETE FROM schema_migrations WHERE version = '0199_jamf_webhook_coverage';

COMMIT;
