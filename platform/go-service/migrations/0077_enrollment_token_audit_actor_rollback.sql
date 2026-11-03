-- Rollback for 0077_enrollment_token_audit_actor (PAT-453).

BEGIN;

ALTER TABLE enrollment_token_audit DROP COLUMN IF EXISTS actor_email;

DELETE FROM schema_migrations WHERE version = '0077_enrollment_token_audit_actor';

COMMIT;
