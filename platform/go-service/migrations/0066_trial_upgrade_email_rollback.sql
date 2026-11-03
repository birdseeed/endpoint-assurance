-- Rollback for 0066_trial_upgrade_email (PAT-670).

BEGIN;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS upgrade_email_sent_at;

DELETE FROM schema_migrations WHERE version = '0066_trial_upgrade_email';

COMMIT;
