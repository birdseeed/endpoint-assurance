-- Rollback for 0229_portal_owner_role (PAT-1883)
--
-- The ordinary rollback of self-service sign-up is not this file. It is
-- SELF_SERVICE_SIGNUP_ENABLED=false (the default): every sign-up and access
-- route then answers 404 and nothing is deleted.
--
-- Run 0230's rollback first, and roll the API binary back before this:
-- the handlers read portal_users.role 'owner'.
--
-- This refuses to run while it would lose or contradict stored data:
--   * a portal_users row with role 'owner' (narrowing the check would fail,
--     and demoting an owner here would be a silent access change);
--   * a feedback row recorded for an owner;
--   * a tenant created by self-service sign-up (dropping created_via loses
--     which tenants those were, and it cannot be reconstructed).
-- Resolve those by hand first, deliberately, if a schema rollback is really
-- what is wanted.
--
-- portal_users.disabled_by is dropped without a check. A member an owner
-- disabled then reads as any disabled row did before 0229: disabled, with
-- nothing saying by whom. If 0229 is applied again that row counts as the
-- operator's, so the owner can no longer enable it. That is the restrictive
-- direction and loses no access decision, so it is not a reason to refuse.
--
-- Locks. This takes ACCESS EXCLUSIVE on portal_users, feedback and tenants
-- at once and holds them to COMMIT, so the checks below and the changes see
-- the same rows. As in the forward migration the wait is bounded:
-- lock_timeout cancels it after 30 seconds, nothing is rolled back, and the
-- sign-ins and ingest requests that queued behind the request carry on. Run
-- it again once the long transaction it met has ended.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0229_portal_owner_role_rollback.sql

BEGIN;

SET LOCAL lock_timeout = '30s';

LOCK TABLE portal_users, feedback, tenants IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM portal_users WHERE role = 'owner') THEN
        RAISE EXCEPTION 'cannot roll back 0229: portal_users rows with role owner exist';
    END IF;
    IF EXISTS (SELECT 1 FROM feedback WHERE reporter_role = 'owner') THEN
        RAISE EXCEPTION 'cannot roll back 0229: feedback recorded for an owner exists';
    END IF;
    IF EXISTS (SELECT 1 FROM tenants WHERE created_via = 'self_service') THEN
        RAISE EXCEPTION 'cannot roll back 0229: tenants created by self-service sign-up exist';
    END IF;
END $$;

ALTER TABLE tenants DROP COLUMN created_via;

ALTER TABLE feedback
    DROP CONSTRAINT feedback_reporter_role_values_check,
    ADD CONSTRAINT feedback_reporter_role_check CHECK (reporter_role IN ('viewer', 'admin'));

ALTER TABLE portal_users
    DROP CONSTRAINT portal_users_disabled_by_check,
    DROP COLUMN disabled_by;

ALTER TABLE portal_users
    DROP CONSTRAINT portal_users_role_check,
    ADD CONSTRAINT portal_users_role_check CHECK (role IN ('admin', 'viewer'));

COMMENT ON COLUMN portal_users.role IS
    'Customer portal role (PAT-2007): admin may write software approval state, viewer is read-only. Default viewer; rows existing at 0181 were backfilled to admin.';

DELETE FROM schema_migrations WHERE version = '0229_portal_owner_role';

COMMIT;
