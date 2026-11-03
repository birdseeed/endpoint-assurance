-- patched.im - 0230_portal_invitations_and_access_audit.sql
-- PAT-1883: self-service organisation sign-up. Two new tables.
--
-- 1. portal_invitations: one row per invitation an owner sends. Mutable
--    tenant state (pending, then accepted or revoked), so it follows the
--    tenant_enrolment_keys (0211) pattern: FK to tenants ON DELETE CASCADE,
--    and a tenant purge deletes it with the tenant. The invited address is
--    stored lower case. An invitation is single use: accepting it creates the
--    invitee's portal_users row and marks it accepted in one transaction.
--    Expiry is not a stored state. expires_at is compared with now() when the
--    row is read, so there is no background job and no row to sweep. At most
--    one pending invitation per (tenant, email), by partial unique index.
--    Nothing here sends email.
--
-- 2. portal_access_audit: append-only record of who was given access to a
--    tenant, by whom, and every later change: organisation_created,
--    invitation_created, invitation_accepted, invitation_revoked,
--    role_changed, member_disabled, member_enabled. Each row is written in
--    the same transaction as the change it records. Same shape and rules as
--    jamf_webhook_audit (0199) and the 0228 ledgers:
--      * no FK to tenants (a cascade DELETE would hit the append-only
--        trigger and break tenant purge, 0091/0096), so rows outlive a purge;
--      * UPDATE, DELETE and TRUNCATE are rejected by trigger. That stops an
--        accidental write, not the owning role `patched` (AGENTS.md). Do not
--        describe it as tamper-proof;
--      * on DELETE FROM tenants, a BEFORE DELETE trigger nulls actor_email
--        and subject_email for that tenant's rows only and stamps
--        tenant_purge_anonymized_at (the 0225 / 0228 pattern). The action,
--        the roles, the invitation id and the time are kept. The guard
--        admits exactly that one UPDATE: nested inside the tenants trigger
--        (pg_trigger_depth() = 2), the transaction-local purge scope naming
--        the row's own tenant, the row not already marked, the marker equal
--        to the transaction timestamp, both addresses NULL and every other
--        column unchanged. If the redaction fails, the DELETE fails with it.
--    Its own trigger, function and purge scope setting, so the 0101, 0109,
--    0225 and 0228 purge paths are untouched and this migration rolls back
--    without restoring any of them.
--
-- Additive only: no change to any existing table. A new BEFORE DELETE
-- trigger is added to tenants. Replay is not supported (CREATE TABLE); the
-- migration is transactional, so a failed apply leaves nothing behind.
--
-- Locks. Both tables are new, so the only existing table this waits for is
-- tenants: the foreign key from portal_invitations and the new BEFORE DELETE
-- trigger each take SHARE ROW EXCLUSIVE on it, held until COMMIT. That does
-- not wait for readers, but it does wait for any open transaction that has
-- written to tenants, and while it waits every later write to tenants queues
-- behind it. lock_timeout stops the deploy rather than queueing behind a long
-- writer: after 30 seconds the waiting statement is cancelled, the
-- transaction rolls back with nothing created, and the deploy can be retried
-- (the same reasoning as 0172 and 0173).
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0230_portal_invitations_and_access_audit.sql

BEGIN;

SET LOCAL lock_timeout = '30s';

-- ============================================================================
-- portal_invitations
-- ============================================================================

CREATE TABLE portal_invitations (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The invited address, lower case. Only a caller whose verified Cloudflare
    -- Access email equals it can accept.
    email            TEXT        NOT NULL CHECK (email = lower(email) AND btrim(email) <> '' AND char_length(email) <= 320),
    -- The role acceptance grants. Never owner: ownership is not invitable.
    role             TEXT        NOT NULL CHECK (role IN ('admin', 'viewer')),
    status           TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked')),
    -- Verified portal email of the owner who created / revoked it.
    invited_by_email TEXT        NOT NULL CHECK (char_length(invited_by_email) BETWEEN 1 AND 320),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    accepted_at      TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    revoked_by_email TEXT        CHECK (revoked_by_email IS NULL OR char_length(revoked_by_email) BETWEEN 1 AND 320),
    CONSTRAINT portal_invitations_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT portal_invitations_status_shape CHECK (
        (status = 'pending'  AND accepted_at IS NULL     AND revoked_at IS NULL     AND revoked_by_email IS NULL)
     OR (status = 'accepted' AND accepted_at IS NOT NULL AND revoked_at IS NULL     AND revoked_by_email IS NULL)
     OR (status = 'revoked'  AND accepted_at IS NULL     AND revoked_at IS NOT NULL AND revoked_by_email IS NOT NULL))
);

CREATE UNIQUE INDEX uq_portal_invitations_pending
    ON portal_invitations (tenant_id, email) WHERE status = 'pending';
CREATE INDEX idx_portal_invitations_tenant
    ON portal_invitations (tenant_id, created_at DESC);
-- The invitee's own lookup (GET /v1/portal/signup/state) is by address.
CREATE INDEX idx_portal_invitations_email_pending
    ON portal_invitations (email) WHERE status = 'pending';

COMMENT ON TABLE portal_invitations IS
    'PAT-1883: invitations an owner sends to join a tenant as admin or viewer. Single use. Expiry is read from expires_at, never stored as a status. FK to tenants ON DELETE CASCADE: a tenant purge deletes them.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE portal_invitations TO patched;

-- ============================================================================
-- portal_access_audit
-- ============================================================================

CREATE TABLE portal_access_audit (
    id            BIGSERIAL   PRIMARY KEY,
    tenant_id     UUID        NOT NULL,
    -- Verified portal email of whoever did it. NULL only on a row redacted by
    -- a tenant purge.
    actor_email   TEXT        CHECK (actor_email IS NULL OR char_length(actor_email) BETWEEN 1 AND 320),
    action        TEXT        NOT NULL CHECK (action IN
                      ('organisation_created', 'invitation_created', 'invitation_accepted', 'invitation_revoked',
                       'role_changed', 'member_disabled', 'member_enabled')),
    -- The address the action was about: the new owner, the invitee, the
    -- member. NULL only on a row redacted by a tenant purge.
    subject_email TEXT        CHECK (subject_email IS NULL OR char_length(subject_email) BETWEEN 1 AND 320),
    old_role      TEXT        CHECK (old_role IS NULL OR old_role IN ('owner', 'admin', 'viewer')),
    new_role      TEXT        CHECK (new_role IS NULL OR new_role IN ('owner', 'admin', 'viewer')),
    -- portal_invitations.id for the three invitation actions. No FK: the
    -- invitation is deleted with the tenant and this row is not.
    invitation_id UUID,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    tenant_purge_anonymized_at TIMESTAMPTZ,
    CONSTRAINT portal_access_audit_invitation_shape CHECK (
        (action IN ('invitation_created', 'invitation_accepted', 'invitation_revoked')) = (invitation_id IS NOT NULL)),
    CONSTRAINT portal_access_audit_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND actor_email IS NOT NULL AND subject_email IS NOT NULL)
        OR (tenant_purge_anonymized_at IS NOT NULL AND actor_email IS NULL AND subject_email IS NULL))
);

CREATE INDEX idx_portal_access_audit_tenant ON portal_access_audit (tenant_id, id DESC);

CREATE FUNCTION public.reject_portal_access_audit_marker_on_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.tenant_purge_anonymized_at IS NOT NULL THEN
        RAISE EXCEPTION 'portal_access_audit: the tenant purge marker is not permitted on INSERT';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_portal_access_audit_purge_marker_insert BEFORE INSERT
    ON public.portal_access_audit
    FOR EACH ROW EXECUTE FUNCTION public.reject_portal_access_audit_marker_on_insert();

CREATE FUNCTION public.reject_portal_access_audit_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.portal_access_audit_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor_email IS NULL AND NEW.subject_email IS NULL
       AND (to_jsonb(NEW) - ARRAY['actor_email', 'subject_email', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor_email', 'subject_email', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'portal_access_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$;

CREATE TRIGGER trg_portal_access_audit_append_only
    BEFORE UPDATE OR DELETE ON public.portal_access_audit
    FOR EACH ROW EXECUTE FUNCTION public.reject_portal_access_audit_mutation();

CREATE FUNCTION public.reject_portal_access_audit_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'portal_access_audit is append-only: TRUNCATE is not permitted';
END;
$$;

CREATE TRIGGER trg_portal_access_audit_append_only_truncate
    BEFORE TRUNCATE ON public.portal_access_audit
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_portal_access_audit_truncate();

COMMENT ON TABLE portal_access_audit IS
    'PAT-1883: append-only audit of organisation creation, invitations, role changes and member disable/enable. UPDATE, DELETE and TRUNCATE rejected by trigger (not tamper-proof: the owning role can disable it). No FK to tenants on purpose; a tenant purge redacts actor_email and subject_email and keeps the rest.';
COMMENT ON COLUMN portal_access_audit.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-1883, 0228 pattern); actor_email and subject_email redacted, all other event fields retained. No automatic retention sweep.';

GRANT SELECT, INSERT ON TABLE portal_access_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE portal_access_audit_id_seq TO patched;

-- ============================================================================
-- The tenant purge trigger. Definer privileges let a role that holds only
-- SELECT and INSERT on the ledger purge a tenant without being granted UPDATE.
-- ============================================================================

CREATE FUNCTION public.redact_portal_access_audit_before_tenant_purge() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE previous_scope text := current_setting('patched.portal_access_audit_purge_tenant', true);
BEGIN
    IF TG_OP <> 'DELETE' OR TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'tenants'
       OR pg_trigger_depth() <> 1 THEN
        RAISE EXCEPTION 'portal access audit redaction requires the tenant DELETE trigger';
    END IF;
    PERFORM set_config('patched.portal_access_audit_purge_tenant', OLD.id::text, true);

    UPDATE public.portal_access_audit
       SET actor_email = NULL, subject_email = NULL, tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    PERFORM set_config('patched.portal_access_audit_purge_tenant', coalesce(previous_scope, ''), true);
    RETURN OLD;
END;
$$;
REVOKE ALL ON FUNCTION public.redact_portal_access_audit_before_tenant_purge() FROM PUBLIC;

CREATE TRIGGER trg_tenants_redact_portal_access_audit_before_purge BEFORE DELETE ON public.tenants
    FOR EACH ROW EXECUTE FUNCTION public.redact_portal_access_audit_before_tenant_purge();

COMMENT ON TRIGGER trg_tenants_redact_portal_access_audit_before_purge ON public.tenants IS
    'PAT-1883: before a tenant row is deleted, redact actor_email and subject_email on that tenant''s portal_access_audit rows. A failure aborts the DELETE.';

-- ============================================================================
-- Fail the migration, not a later purge, if a guard is not attached as
-- expected.
-- ============================================================================

DO $$
BEGIN
    -- tgtype bits: 1 row, 2 before, 8 delete, 16 update, 32 truncate.
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'public.portal_access_audit'::regclass
           AND tgname = 'trg_portal_access_audit_append_only'
           AND tgfoid = 'public.reject_portal_access_audit_mutation()'::regprocedure
           AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 8) = 8 AND (tgtype & 16) = 16
           AND tgenabled = 'O' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'append-only row trigger on portal_access_audit is absent, disabled or wrong';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'public.portal_access_audit'::regclass
           AND tgname = 'trg_portal_access_audit_append_only_truncate'
           AND tgfoid = 'public.reject_portal_access_audit_truncate()'::regprocedure
           AND (tgtype & 1) = 0 AND (tgtype & 2) = 2 AND (tgtype & 32) = 32
           AND tgenabled = 'O' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'append-only truncate trigger on portal_access_audit is absent, disabled or wrong';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'public.tenants'::regclass
           AND tgname = 'trg_tenants_redact_portal_access_audit_before_purge'
           AND tgfoid = 'public.redact_portal_access_audit_before_tenant_purge()'::regprocedure
           AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 8) = 8
           AND tgenabled = 'O' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'tenant purge portal access audit redaction trigger is absent, disabled or wrong';
    END IF;
END;
$$;

INSERT INTO schema_migrations (version) VALUES ('0230_portal_invitations_and_access_audit')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
