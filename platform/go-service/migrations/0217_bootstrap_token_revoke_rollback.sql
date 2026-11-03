-- Reverses 0217_bootstrap_token_revoke.sql (PAT-2287).
--
-- Roll the API binary back first: the 0217 binary writes action/actor and
-- reads revoked_at. Refuses while any token is revoked or any revoke audit row
-- exists, because dropping those columns would silently re-enable a revoked
-- token (it would read as live again until its expiry) and erase who revoked
-- it. Let the revoked tokens expire first; the audit rows cannot be deleted
-- (append-only, 0101), so a table that has ever recorded a revoke keeps 0217.
BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM bootstrap_tokens WHERE revoked_at IS NOT NULL AND consumed_at IS NULL AND expires_at > now()) THEN
        RAISE EXCEPTION 'cannot roll back 0217 while a revoked bootstrap token is unexpired: dropping revoked_at would make it redeemable again';
    END IF;
    IF EXISTS (SELECT 1 FROM enrollment_token_audit WHERE action = 'revoke') THEN
        RAISE EXCEPTION 'cannot roll back 0217: enrollment_token_audit holds revoke rows, and it is append-only';
    END IF;
END $$;

ALTER TABLE enrollment_token_audit DROP CONSTRAINT IF EXISTS enrollment_token_audit_revoke_actor_check;
ALTER TABLE enrollment_token_audit DROP CONSTRAINT IF EXISTS enrollment_token_audit_action_check;
ALTER TABLE enrollment_token_audit DROP COLUMN IF EXISTS actor;
ALTER TABLE enrollment_token_audit DROP COLUMN IF EXISTS action;
ALTER TABLE bootstrap_tokens DROP COLUMN IF EXISTS revoked_at;

DELETE FROM schema_migrations WHERE version = '0217_bootstrap_token_revoke';

COMMIT;
