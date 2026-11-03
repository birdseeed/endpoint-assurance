-- Rollback for 0230_portal_invitations_and_access_audit (PAT-1883)
--
-- The ordinary rollback of self-service sign-up is not this file. It is
-- SELF_SERVICE_SIGNUP_ENABLED=false (the default): every sign-up and access
-- route then answers 404, and every tenant, membership, invitation and audit
-- row is kept.
--
-- Roll the API binary back, or disable the flag, before running this: the
-- /v1/portal/signup and /v1/portal/access routes read and write these tables.
--
-- Invitations and the access audit cannot be reconstructed, so this fails
-- closed once either table holds a row (the 0224 rule); prefer leaving the
-- additive objects in place.
--
-- Locks. This takes ACCESS EXCLUSIVE on portal_invitations and
-- portal_access_audit, and then on tenants (dropping the purge trigger and
-- the foreign key), which every ingest request reads. The wait for each is
-- bounded: lock_timeout cancels it after 30 seconds, nothing is dropped, and
-- whatever queued behind the request carries on. Run it again once the long
-- transaction it met has ended.
--
-- Usage:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0230_portal_invitations_and_access_audit_rollback.sql

BEGIN;

SET LOCAL lock_timeout = '30s';

LOCK TABLE portal_invitations, portal_access_audit IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM portal_invitations) OR EXISTS (SELECT 1 FROM portal_access_audit) THEN
        RAISE EXCEPTION 'cannot roll back 0230: portal invitations or access audit rows exist';
    END IF;
END $$;

DROP TRIGGER trg_tenants_redact_portal_access_audit_before_purge ON public.tenants;
DROP FUNCTION public.redact_portal_access_audit_before_tenant_purge();

DROP TABLE portal_access_audit;
DROP FUNCTION public.reject_portal_access_audit_mutation();
DROP FUNCTION public.reject_portal_access_audit_truncate();
DROP FUNCTION public.reject_portal_access_audit_marker_on_insert();

DROP TABLE portal_invitations;

DELETE FROM schema_migrations WHERE version = '0230_portal_invitations_and_access_audit';

COMMIT;
