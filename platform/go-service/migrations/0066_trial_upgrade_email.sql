-- 0066: trial upgrade email idempotency column (PAT-670).
--
--   upgrade_email_sent_at — timestamp when the upgrade/expiry email was sent
--                            to a trial tenant. NULL = email not yet sent.
--                            Set once per trial; ensures the email is sent at
--                            most once (idempotency guard for the scheduler /
--                            admin trigger endpoint).
--
-- Only meaningful on rows where is_trial = true; non-trial (full-paid) tenants
-- will always have NULL in this column.

BEGIN;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS upgrade_email_sent_at TIMESTAMPTZ;

COMMENT ON COLUMN tenants.upgrade_email_sent_at IS
    'Timestamp when the trial-expiry upgrade email was sent (PAT-670). NULL = not yet sent. Written once; never cleared.';

INSERT INTO schema_migrations (version) VALUES ('0066_trial_upgrade_email')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
