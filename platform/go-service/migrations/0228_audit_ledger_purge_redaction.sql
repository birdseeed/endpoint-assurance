-- patched.im - 0228_audit_ledger_purge_redaction.sql
-- PAT-2403: seven audit ledgers have no cascading tenant foreign key, so
-- their rows outlive a tenant purge and kept the actor's email and identifying
-- free text. This applies the PAT-2380 / 0225 pattern to each of them: the six
-- the ticket names, and tenant_shadow_it_policy_changes, which the ticket's
-- survey found with the same defect and the same shape.
--
--   software_approval_decisions      (0182)  actor_email, reason
--   device_retirement_decisions      (0193)  actor_email, reason
--   jamf_webhook_audit               (0199)  actor_email
--   device_list_entry_deletions      (0214)  actor_email, hostname, serial
--   agent_release_audit              (0204)  actor, details
--   software_declaration_decisions   (0224)  actor_email, justification,
--                                            declaration snapshot
--   tenant_shadow_it_policy_changes  (0104)  claimed_actor, source_addr, reason
--
-- On DELETE FROM tenants, one BEFORE DELETE trigger redacts the purged
-- tenant's rows in all seven ledgers and stamps tenant_purge_anonymized_at.
-- Every other event field is retained. If any redaction fails, the DELETE
-- fails with it, so a purge is never partial.
--
-- Each ledger keeps its own append-only guard. The guard admits exactly one
-- UPDATE: the redaction above, recognised by all of
--   * running nested inside the tenants trigger (pg_trigger_depth() = 2),
--   * the transaction-local purge scope naming this row's own tenant,
--   * the row not being marked already, the marker being this transaction's
--     timestamp, the identifying columns holding their redacted values, and
--   * every other column being unchanged.
-- Anything else (an ordinary UPDATE, a DELETE, a TRUNCATE, a second redaction,
-- un-marking a row, an INSERT that arrives already marked) is refused exactly
-- as before. As AGENTS.md records, these guards stop accidents; they do not
-- stop the owning role. Do not describe these tables as tamper-proof.
--
-- No existing row is rewritten by this migration. The actor columns lose
-- NOT NULL only so that the redaction can null them; a table CHECK keeps the
-- old rule (actor required) for every row that is not marked.
--
-- Replay-safe. Rollback is refused once any row has been redacted.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0228_audit_ledger_purge_redaction.sql

BEGIN;

-- ============================================================================
-- Shared: a row may never be INSERTed already carrying the purge marker.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.reject_tenant_purge_marker_on_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.tenant_purge_anonymized_at IS NOT NULL THEN
        RAISE EXCEPTION '%: the tenant purge marker is not permitted on INSERT', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END;
$$;

-- ============================================================================
-- software_approval_decisions (0182)
-- ============================================================================

ALTER TABLE public.software_approval_decisions
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.software_approval_decisions
    ALTER COLUMN actor_email DROP NOT NULL;
ALTER TABLE public.software_approval_decisions
    DROP CONSTRAINT IF EXISTS software_approval_decisions_purge_shape;
ALTER TABLE public.software_approval_decisions
    ADD CONSTRAINT software_approval_decisions_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND actor_email IS NOT NULL)
        OR (tenant_purge_anonymized_at IS NOT NULL AND actor_email IS NULL AND reason IS NULL));

DROP TRIGGER IF EXISTS trg_software_approval_decisions_purge_marker_insert ON public.software_approval_decisions;
CREATE TRIGGER trg_software_approval_decisions_purge_marker_insert BEFORE INSERT
    ON public.software_approval_decisions
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_software_approval_decisions_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor_email IS NULL AND NEW.reason IS NULL
       AND (to_jsonb(NEW) - ARRAY['actor_email', 'reason', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor_email', 'reason', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'software_approval_decisions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$;

-- ============================================================================
-- device_retirement_decisions (0193)
-- ============================================================================

ALTER TABLE public.device_retirement_decisions
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.device_retirement_decisions
    ALTER COLUMN actor_email DROP NOT NULL;
ALTER TABLE public.device_retirement_decisions
    DROP CONSTRAINT IF EXISTS device_retirement_decisions_purge_shape;
ALTER TABLE public.device_retirement_decisions
    ADD CONSTRAINT device_retirement_decisions_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND actor_email IS NOT NULL)
        OR (tenant_purge_anonymized_at IS NOT NULL AND actor_email IS NULL AND reason IS NULL));

DROP TRIGGER IF EXISTS trg_device_retirement_decisions_purge_marker_insert ON public.device_retirement_decisions;
CREATE TRIGGER trg_device_retirement_decisions_purge_marker_insert BEFORE INSERT
    ON public.device_retirement_decisions
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_device_retirement_decisions_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor_email IS NULL AND NEW.reason IS NULL
       AND (to_jsonb(NEW) - ARRAY['actor_email', 'reason', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor_email', 'reason', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'device_retirement_decisions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$;

-- ============================================================================
-- jamf_webhook_audit (0199)
-- ============================================================================

ALTER TABLE public.jamf_webhook_audit
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.jamf_webhook_audit
    ALTER COLUMN actor_email DROP NOT NULL;
ALTER TABLE public.jamf_webhook_audit
    DROP CONSTRAINT IF EXISTS jamf_webhook_audit_purge_shape;
ALTER TABLE public.jamf_webhook_audit
    ADD CONSTRAINT jamf_webhook_audit_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL) = (actor_email IS NOT NULL));

DROP TRIGGER IF EXISTS trg_jamf_webhook_audit_purge_marker_insert ON public.jamf_webhook_audit;
CREATE TRIGGER trg_jamf_webhook_audit_purge_marker_insert BEFORE INSERT
    ON public.jamf_webhook_audit
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_jamf_webhook_audit_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor_email IS NULL
       AND (to_jsonb(NEW) - ARRAY['actor_email', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor_email', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'jamf_webhook_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$;

-- ============================================================================
-- device_list_entry_deletions (0214)
-- ============================================================================

ALTER TABLE public.device_list_entry_deletions
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.device_list_entry_deletions
    ALTER COLUMN actor_email DROP NOT NULL;
ALTER TABLE public.device_list_entry_deletions
    DROP CONSTRAINT IF EXISTS device_list_entry_deletions_purge_shape;
ALTER TABLE public.device_list_entry_deletions
    ADD CONSTRAINT device_list_entry_deletions_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND actor_email IS NOT NULL)
        OR (tenant_purge_anonymized_at IS NOT NULL AND actor_email IS NULL
            AND hostname IS NULL AND serial IS NULL));

DROP TRIGGER IF EXISTS trg_device_list_entry_deletions_purge_marker_insert ON public.device_list_entry_deletions;
CREATE TRIGGER trg_device_list_entry_deletions_purge_marker_insert BEFORE INSERT
    ON public.device_list_entry_deletions
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_device_list_entry_deletions_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor_email IS NULL AND NEW.hostname IS NULL AND NEW.serial IS NULL
       AND (to_jsonb(NEW) - ARRAY['actor_email', 'hostname', 'serial', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor_email', 'hostname', 'serial', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'device_list_entry_deletions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$;

-- ============================================================================
-- agent_release_audit (0204)
--
-- details is free-form JSON written by several handlers (request bodies,
-- operator banners, provenance text), so it cannot be redacted key by key:
-- it is replaced with the empty object. source, action and recorded_at keep
-- the event shape. Rows with no tenant (global promotions and registrations)
-- are never touched: the redaction and its exemption both key on tenant_id.
--
-- 0204 shares one guard function between five agent_release_* tables. Only
-- this table's row trigger moves to its own function; the other four tables
-- and this table's TRUNCATE trigger keep reject_agent_release_mutation().
-- ============================================================================

ALTER TABLE public.agent_release_audit
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.agent_release_audit
    ALTER COLUMN actor DROP NOT NULL;
ALTER TABLE public.agent_release_audit
    DROP CONSTRAINT IF EXISTS agent_release_audit_purge_shape;
ALTER TABLE public.agent_release_audit
    ADD CONSTRAINT agent_release_audit_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND actor IS NOT NULL)
        OR (tenant_purge_anonymized_at IS NOT NULL AND tenant_id IS NOT NULL
            AND actor IS NULL AND details = '{}'::jsonb));

DROP TRIGGER IF EXISTS agent_release_audit_purge_marker_insert ON public.agent_release_audit;
CREATE TRIGGER agent_release_audit_purge_marker_insert BEFORE INSERT
    ON public.agent_release_audit
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_agent_release_audit_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor IS NULL AND NEW.details = '{}'::jsonb
       AND (to_jsonb(NEW) - ARRAY['actor', 'details', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor', 'details', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only: % forbidden', TG_TABLE_NAME, TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS agent_release_audit_immutable ON public.agent_release_audit;
CREATE TRIGGER agent_release_audit_immutable BEFORE UPDATE OR DELETE
    ON public.agent_release_audit
    FOR EACH ROW EXECUTE FUNCTION public.reject_agent_release_audit_mutation();

-- ============================================================================
-- software_declaration_decisions (0224)
--
-- declaration is to_jsonb() of the tenant_software_declarations row at the
-- time of the decision, so it repeats created_by (an email) and justification
-- (free text). The redaction keeps only a reviewed list of non-identifying
-- keys: an allowlist, so a column added to tenant_software_declarations later
-- is dropped from retained snapshots until someone reviews it and adds it
-- here. name and publisher are kept: they are the software the decision was
-- about, the same as identifier on software_approval_decisions.
--
-- 0224 guards this table with one STATEMENT-level trigger, which cannot see
-- rows. It stays (so a statement matching no rows is still refused) and now
-- lets through only an UPDATE nested in the tenant purge; a new ROW-level
-- trigger then holds each row to the exact redaction.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.software_declaration_purge_snapshot(snapshot jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT coalesce(jsonb_object_agg(e.key, e.value), '{}'::jsonb)
      FROM jsonb_each(CASE WHEN jsonb_typeof(snapshot) = 'object' THEN snapshot ELSE '{}'::jsonb END) AS e
     WHERE e.key = ANY (ARRAY[
        'id', 'tenant_id', 'name', 'publisher', 'platform', 'min_version', 'review_date',
        'selected_alias_id', 'resolved_alias_id', 'policy_id', 'resolved_identifier',
        'resolved_kind', 'resolved_companion', 'resolved_publisher_key', 'created_at', 'resolved_at'])
$$;

ALTER TABLE public.software_declaration_decisions
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.software_declaration_decisions
    ALTER COLUMN actor_email DROP NOT NULL,
    ALTER COLUMN justification DROP NOT NULL;
ALTER TABLE public.software_declaration_decisions
    DROP CONSTRAINT IF EXISTS software_declaration_decisions_purge_shape;
ALTER TABLE public.software_declaration_decisions
    ADD CONSTRAINT software_declaration_decisions_purge_shape CHECK (
        (tenant_purge_anonymized_at IS NULL AND actor_email IS NOT NULL AND justification IS NOT NULL)
        OR (tenant_purge_anonymized_at IS NOT NULL AND actor_email IS NULL AND justification IS NULL
            AND NOT (declaration ?| ARRAY['created_by', 'justification'])));

DROP TRIGGER IF EXISTS software_declaration_decisions_purge_marker_insert ON public.software_declaration_decisions;
CREATE TRIGGER software_declaration_decisions_purge_marker_insert BEFORE INSERT
    ON public.software_declaration_decisions
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_software_declaration_decision_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND coalesce(current_setting('patched.audit_ledger_purge_tenant', true), '') <> '' THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'software_declaration_decisions is append-only';
END;
$$;

CREATE OR REPLACE FUNCTION public.reject_software_declaration_decision_row_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.actor_email IS NULL AND NEW.justification IS NULL
       AND NEW.declaration IS NOT DISTINCT FROM public.software_declaration_purge_snapshot(OLD.declaration)
       AND (to_jsonb(NEW) - ARRAY['actor_email', 'justification', 'declaration', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['actor_email', 'justification', 'declaration', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'software_declaration_decisions is append-only';
END;
$$;

DROP TRIGGER IF EXISTS software_declaration_decisions_append_only_row ON public.software_declaration_decisions;
CREATE TRIGGER software_declaration_decisions_append_only_row BEFORE UPDATE OR DELETE
    ON public.software_declaration_decisions
    FOR EACH ROW EXECUTE FUNCTION public.reject_software_declaration_decision_row_mutation();

-- ============================================================================
-- tenant_shadow_it_policy_changes (0104)
--
-- actor is kept: since 0092 the admin audit writers store a fixed sentinel
-- there (admin_shared_token), never an identity, exactly as 0101 reasoned for
-- its tables. What identifies someone is the caller-supplied claimed_actor,
-- the observed source_addr and the free-text reason. All three are already
-- nullable, so no NOT NULL changes.
-- ============================================================================

ALTER TABLE public.tenant_shadow_it_policy_changes
    ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ;
ALTER TABLE public.tenant_shadow_it_policy_changes
    DROP CONSTRAINT IF EXISTS tenant_shadow_it_policy_changes_purge_shape;
ALTER TABLE public.tenant_shadow_it_policy_changes
    ADD CONSTRAINT tenant_shadow_it_policy_changes_purge_shape CHECK (
        tenant_purge_anonymized_at IS NULL
        OR (claimed_actor IS NULL AND source_addr IS NULL AND reason IS NULL));

DROP TRIGGER IF EXISTS trg_tenant_shadow_it_policy_changes_purge_marker_insert ON public.tenant_shadow_it_policy_changes;
CREATE TRIGGER trg_tenant_shadow_it_policy_changes_purge_marker_insert BEFORE INSERT
    ON public.tenant_shadow_it_policy_changes
    FOR EACH ROW EXECUTE FUNCTION public.reject_tenant_purge_marker_on_insert();

CREATE OR REPLACE FUNCTION public.reject_tenant_shadow_it_policy_changes_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND pg_trigger_depth() = 2
       AND current_setting('patched.audit_ledger_purge_tenant', true) = OLD.tenant_id::text
       AND OLD.tenant_purge_anonymized_at IS NULL
       AND NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()
       AND NEW.claimed_actor IS NULL AND NEW.source_addr IS NULL AND NEW.reason IS NULL
       AND (to_jsonb(NEW) - ARRAY['claimed_actor', 'source_addr', 'reason', 'tenant_purge_anonymized_at'])
           IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY['claimed_actor', 'source_addr', 'reason', 'tenant_purge_anonymized_at']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'tenant_shadow_it_policy_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$;

-- ============================================================================
-- The tenant purge trigger. Its own trigger and function, so the older 0101,
-- 0109 and 0225 purge paths are untouched. Definer privileges let a role that
-- holds only SELECT and INSERT on the ledgers purge a tenant without being
-- granted UPDATE on them.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.redact_audit_ledgers_before_tenant_purge() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE previous_scope text := current_setting('patched.audit_ledger_purge_tenant', true);
BEGIN
    IF TG_OP <> 'DELETE' OR TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'tenants'
       OR pg_trigger_depth() <> 1 THEN
        RAISE EXCEPTION 'audit ledger redaction requires the tenant DELETE trigger';
    END IF;
    PERFORM set_config('patched.audit_ledger_purge_tenant', OLD.id::text, true);

    UPDATE public.software_approval_decisions
       SET actor_email = NULL, reason = NULL, tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    UPDATE public.device_retirement_decisions
       SET actor_email = NULL, reason = NULL, tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    UPDATE public.jamf_webhook_audit
       SET actor_email = NULL, tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    UPDATE public.device_list_entry_deletions
       SET actor_email = NULL, hostname = NULL, serial = NULL,
           tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    UPDATE public.agent_release_audit
       SET actor = NULL, details = '{}'::jsonb, tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    UPDATE public.software_declaration_decisions
       SET actor_email = NULL, justification = NULL,
           declaration = public.software_declaration_purge_snapshot(declaration),
           tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    UPDATE public.tenant_shadow_it_policy_changes
       SET claimed_actor = NULL, source_addr = NULL, reason = NULL,
           tenant_purge_anonymized_at = transaction_timestamp()
     WHERE tenant_id = OLD.id AND tenant_purge_anonymized_at IS NULL;

    PERFORM set_config('patched.audit_ledger_purge_tenant', coalesce(previous_scope, ''), true);
    RETURN OLD;
END;
$$;
REVOKE ALL ON FUNCTION public.redact_audit_ledgers_before_tenant_purge() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_tenants_redact_audit_ledgers_before_purge ON public.tenants;
CREATE TRIGGER trg_tenants_redact_audit_ledgers_before_purge BEFORE DELETE ON public.tenants
    FOR EACH ROW EXECUTE FUNCTION public.redact_audit_ledgers_before_tenant_purge();

-- ============================================================================
-- Fail the migration, not a later purge, if any guard is not attached as
-- expected: an enabled BEFORE row trigger for UPDATE and DELETE on each
-- ledger, and the purge trigger on tenants.
-- ============================================================================

DO $$
DECLARE
    expected record;
BEGIN
    FOR expected IN
        SELECT * FROM (VALUES
            ('public.software_approval_decisions',    'trg_software_approval_decisions_append_only',    'public.reject_software_approval_decisions_mutation()'),
            ('public.device_retirement_decisions',    'trg_device_retirement_decisions_append_only',    'public.reject_device_retirement_decisions_mutation()'),
            ('public.jamf_webhook_audit',             'trg_jamf_webhook_audit_append_only',             'public.reject_jamf_webhook_audit_mutation()'),
            ('public.device_list_entry_deletions',    'trg_device_list_entry_deletions_append_only',    'public.reject_device_list_entry_deletions_mutation()'),
            ('public.agent_release_audit',            'agent_release_audit_immutable',                  'public.reject_agent_release_audit_mutation()'),
            ('public.software_declaration_decisions', 'software_declaration_decisions_append_only_row', 'public.reject_software_declaration_decision_row_mutation()'),
            ('public.tenant_shadow_it_policy_changes', 'trg_tenant_shadow_it_policy_changes_append_only', 'public.reject_tenant_shadow_it_policy_changes_mutation()')
        ) AS v(tbl, trg, fn)
    LOOP
        -- tgtype bits: 1 row, 2 before, 8 delete, 16 update.
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
             WHERE tgrelid = expected.tbl::regclass AND tgname = expected.trg
               AND tgfoid = expected.fn::regprocedure
               AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 8) = 8 AND (tgtype & 16) = 16
               AND tgenabled = 'O' AND NOT tgisinternal
        ) THEN
            RAISE EXCEPTION 'append-only row trigger % on % is absent, disabled or wrong', expected.trg, expected.tbl;
        END IF;
    END LOOP;
    -- 0224's statement-level guard: before (2), delete (8), update (16), truncate (32), not row (1).
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'public.software_declaration_decisions'::regclass
           AND tgname = 'software_declaration_decisions_append_only'
           AND tgfoid = 'public.reject_software_declaration_decision_mutation()'::regprocedure
           AND (tgtype & 1) = 0 AND (tgtype & 2) = 2 AND (tgtype & 8) = 8
           AND (tgtype & 16) = 16 AND (tgtype & 32) = 32
           AND tgenabled = 'O' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION '0224 statement-level append-only trigger on software_declaration_decisions is absent, disabled or wrong';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'public.tenants'::regclass
           AND tgname = 'trg_tenants_redact_audit_ledgers_before_purge'
           AND tgfoid = 'public.redact_audit_ledgers_before_tenant_purge()'::regprocedure
           AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 8) = 8
           AND tgenabled = 'O' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'tenant purge audit ledger redaction trigger is absent, disabled or wrong';
    END IF;
END;
$$;

COMMENT ON COLUMN public.software_approval_decisions.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); actor_email and reason redacted, all other event fields retained. No automatic retention sweep.';
COMMENT ON COLUMN public.device_retirement_decisions.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); actor_email and reason redacted, all other event fields retained. No automatic retention sweep.';
COMMENT ON COLUMN public.jamf_webhook_audit.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); actor_email redacted, all other event fields retained. No automatic retention sweep.';
COMMENT ON COLUMN public.device_list_entry_deletions.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); actor_email, hostname and serial redacted, all other event fields retained. No automatic retention sweep.';
COMMENT ON COLUMN public.agent_release_audit.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); actor redacted and details replaced with {}, source, action and recorded_at retained. Never set on a row with no tenant. No automatic retention sweep.';
COMMENT ON COLUMN public.software_declaration_decisions.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); actor_email and justification redacted, declaration reduced to the reviewed non-identifying keys of software_declaration_purge_snapshot(). No automatic retention sweep.';
COMMENT ON COLUMN public.tenant_shadow_it_policy_changes.tenant_purge_anonymized_at IS
    'Irreversible tenant-purge marker (PAT-2403); claimed_actor, source_addr and reason redacted, all other event fields retained. No automatic retention sweep.';
COMMENT ON TRIGGER trg_tenants_redact_audit_ledgers_before_purge ON public.tenants IS
    'PAT-2403: before a tenant row is deleted, redact that tenant''s rows in software_approval_decisions, device_retirement_decisions, jamf_webhook_audit, device_list_entry_deletions, agent_release_audit, software_declaration_decisions and tenant_shadow_it_policy_changes. A failure aborts the DELETE.';

INSERT INTO schema_migrations (version) VALUES ('0228_audit_ledger_purge_redaction')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
