-- patched.im - 0101_tenant_purge_audit_anonymisation.sql
-- PAT-1137: resolve the retention/compliance decision 0096 explicitly
-- deferred - anonymise, don't delete, the governance audit trail on tenant
-- purge.
--
-- 0096_audit_append_only_guards.sql enumerated four tables where
-- PurgeTenantHandler's `DELETE FROM tenants` (internal/handlers/admin.go)
-- cascades into a real DELETE against rows that table's own comment called
-- "append-only": tenant_tier_changes (0056), device_revocations (0040),
-- provenance_records (0011), and enrollment_token_audit
-- (0040_enrollment_audit_log). It deliberately did not guard any of them,
-- and did not choose between "the trail must survive purge" (drop the
-- cascade) and "purge must be able to erase it" (leave the cascade, stop
-- calling it append-only) - flagged as a data-retention/compliance
-- decision for follow-up.
--
-- This migration is that follow-up. The ticket's title is the ruling:
-- ANONYMISE. Three of the four tables above are "who authorised what, to
-- which tenant, when" governance records - a tier change, a device
-- revocation, an enrolment-token mint - that are most needed AFTER the
-- tenant is gone, exactly when a cascade would previously have destroyed
-- them. tenant_decommission_audit (0091) already survives purge (it was
-- deliberately built with no FK to tenants at all - see 0091's header) but
-- still held identifying free text; it gets the same anonymisation
-- treatment here for consistency, without any FK change since it never had
-- one.
--
-- provenance_records is the deliberate EXCEPTION and keeps cascading
-- unchanged: it is high-volume per-device install/update telemetry, not a
-- governance record, and has no evidentiary value once stripped of tenant
-- and device identity. Its ON DELETE CASCADE is untouched by this
-- migration; this paragraph is here so the next reader does not mistake
-- the omission for an oversight.
--
-- catalogue_review_audit (0078) - the fifth table PAT-1137's brief named as
-- a survivor candidate - turns out not to need anything here. It has NO
-- tenant_id column and NO FK, direct or indirect, to tenants: it is a
-- global, cross-tenant record of catalogue (software-title) review
-- decisions, not tenant-owned data. 0096 flagged it as "not guarded" for
-- an entirely different reason (its product_id FK ON DELETE SET NULL
-- against catalogue_products, unrelated to any tenant). A tenant purge
-- cannot reach it today, so it already "survives" trivially and is left
-- untouched - noted here, and in the implementing commit's summary, as a
-- correction to the brief rather than a silent scope change.
--
-- ── What "anonymise" means here ─────────────────────────────────────────
--
-- Keep the shape (something happened, when, of what kind, to how many
-- devices); null the identity. Two eras of identity-bearing columns exist
-- on these tables:
--
-- * The pre-PAT-1135 "authoritative" actor columns (tenant_tier_changes.
-- changed_by, device_revocations.admin_id, tenant_decommission_audit.
-- actor) are, since 0092_audit_attribution.sql, ALREADY non-identifying
-- - every row holds one of exactly two fixed sentinels
-- ('admin_shared_token' or 'legacy_unauthenticated'), never a real
-- caller-supplied value. Redacting them further would remove nothing.
-- They are left untouched.
-- * The genuinely identifying columns are claimed_actor (untrusted
-- caller-supplied string) and source_addr (observed client IP) added
-- by 0092 to tenant_tier_changes, device_revocations, and
-- tenant_decommission_audit; enrollment_token_audit's actor_email
-- (0077, a real verified identity on the customer-portal mint path)
-- and admin_note (free text); device_revocations.device_id and
-- enrollment_token_audit.token_id (device/token identifiers, per the
-- ticket's list); and tenant_decommission_audit.reason (operator free
-- text, called out explicitly in the ticket). These are what get
-- nulled.
--
-- tenant_id itself is KEPT, not nulled, on every anonymised row. It is an
-- opaque UUID that, after this migration drops the FK below, no longer
-- resolves to any tenants row once the tenant is purged - there is nothing
-- left to join it back to, so it carries no identity on its own. Keeping
-- it lets an operator answer "did THIS purged tenant have a tier change on
-- this date" (distinguishing one purged tenant's history from another's)
-- without exposing anything the tenant's own (now-deleted) row would have
-- supplied. This mirrors tenant_decommission_audit's existing design
-- exactly (see 0091: "deliberately no FK").
--
-- ── The append-only-guard interaction (the trickiest part) ──────────────
--
-- tenant_decommission_audit already has a BEFORE UPDATE OR DELETE trigger
-- (trg_tenant_decommission_audit_append_only, 0091) that RAISEs
-- unconditionally. This migration's anonymisation UPDATE against that
-- table would be rejected by its own guard. tenant_tier_changes and
-- enrollment_token_audit have NO guard yet (0096 deliberately withheld one
-- because of the very cascade conflict this migration now resolves) - but
-- once their tenant_id cascade is gone, nothing but this migration's own
-- anonymisation path has any legitimate reason to UPDATE or DELETE them
-- (grepped internal/, non-test: both are INSERT-only from application
-- code), so they get the append-only guard added here, matching the 0096
-- pattern exactly (row-level BEFORE UPDATE OR DELETE + statement-level
-- BEFORE TRUNCATE).
--
-- The exception mechanism is a single, transaction-local session flag:
-- patched.tenant_purge_anonymizing. It is set, via set_config(..., true)
-- (is_local = true), ONLY inside anonymize_tenant_audit_before_purge()
-- below, which is itself reachable only via the new BEFORE DELETE trigger
-- on `tenants`. is_local means the flag cannot leak to another session and
-- cannot outlive the current transaction - it is unset again the instant
-- this DELETE FROM tenants commits or rolls back. Each guard function
-- checks it, and ONLY for TG_OP = 'UPDATE': a DELETE against any of these
-- tables is REJECTED unconditionally, always, with no exception, because
-- anonymisation only ever redacts columns - it never removes a row. This
-- is a narrow, named, single-purpose bypass of one specific trusted
-- caller, not a loosening of the guard for anyone who can start a
-- transaction and set a GUC of their choosing - an ordinary UPDATE from
-- any other code path does not run inside anonymize_tenant_audit_before_
-- purge() and so never sets the flag, and is rejected exactly as before.
--
-- device_revocations is deliberately NOT given an append-only guard here,
-- even though it is one of the four tables from 0096's list and one of the
-- ticket's five survivors. DeleteDeviceHandler (internal/handlers/
-- admin_overview.go) legitimately issues `DELETE FROM devices WHERE id =
-- $1` for a single device, completely independent of any tenant purge,
-- and device_revocations.device_id is (and remains) ON DELETE CASCADE
-- against devices(id). Guarding this table would reject that existing,
-- legitimate deletion path the moment a removed device had any revocation
-- history, exactly the class of conflict 0096 already resolved for
-- compliance_signals and raw_payloads by correcting the comment instead of
-- adding a trigger (see 0096's header). The same treatment applies here:
-- no trigger, and this comment (plus the implementing commit's summary) is
-- the record that the omission is deliberate, not missed. Tenant-purge
-- anonymisation of device_revocations still happens - see the trigger
-- function below - it is simply not additionally guarded against a
-- non-purge UPDATE/DELETE, because a real one already legitimately exists.
--
-- ── Retention ─────────────────────────────────────────────────────────
--
-- Anonymised rows are kept, not swept. Documented default retention: 6
-- years, matching standard UK / Isle of Man business-record retention.
-- This figure is a placeholder pending PAT-112 (customer agreement + DPA
-- templates), which is where the real figure gets settled with actual
-- legal input - treat 6 years as "the safe assumption until PAT-112 says
-- otherwise", not as a considered legal conclusion. No deletion job is
-- built by this migration; only the period is documented, per the ticket.
--
-- ── Schema changes ───────────────────────────────────────────────────────
--
-- tenant_tier_changes, device_revocations, enrollment_token_audit:
-- DROP the tenant_id -> tenants(id) FK (was ON DELETE CASCADE). tenant_id
-- stays as a plain, unconstrained UUID column - see "tenant_id itself"
-- above.
-- device_revocations.device_id, enrollment_token_audit.token_id:
-- DROP NOT NULL, so the anonymisation UPDATE below can null them.
-- Their FKs to devices(id) / bootstrap_tokens(id) are UNCHANGED
-- (still ON DELETE CASCADE) - safe, because this migration's tenants
-- BEFORE DELETE trigger nulls these columns before Postgres processes
-- the devices/bootstrap_tokens cascades that a tenant purge triggers,
-- so by the time those cascades run there is nothing left on the
-- already-anonymised rows for them to match.
-- tenant_tier_changes, enrollment_token_audit: new append-only guard
-- triggers (see above).
-- tenant_decommission_audit: existing append-only guard function
-- (0091) is CREATE OR REPLACEd to add the anonymisation exception;
-- the trigger itself (already present) is untouched.
-- tenants: new BEFORE DELETE ROW trigger that performs the
-- anonymisation UPDATEs against all four tables above, scoped to
-- WHERE tenant_id = OLD.id, before the row (and its cascades) are
-- processed. No other BEFORE DELETE trigger exists on tenants today
-- (grepped migrations/) so there is no ordering conflict to reason
-- about.
--
-- Safe to run against a database that already has rows: every ALTER is
-- schema-only (no rewrite requiring data to already satisfy a new
-- constraint), and the new triggers only change behaviour for writes that
-- happen after this migration applies - no existing row is touched by this
-- migration itself.
--
-- Apply with:
-- psql -h patched-api-01 -U patched -d patched -f migrations/0101_tenant_purge_audit_anonymisation.sql

BEGIN;

-- ============================================================================
-- tenant_tier_changes - drop the tenant cascade, add the append-only guard
-- ============================================================================

ALTER TABLE tenant_tier_changes
    DROP CONSTRAINT IF EXISTS tenant_tier_changes_tenant_id_fkey;

CREATE FUNCTION reject_tenant_tier_changes_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND current_setting('patched.tenant_purge_anonymizing', true) = 'on' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'tenant_tier_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_tier_changes_append_only
    BEFORE UPDATE OR DELETE ON tenant_tier_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_tier_changes_mutation();

CREATE FUNCTION reject_tenant_tier_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_tier_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_tier_changes_append_only_truncate
    BEFORE TRUNCATE ON tenant_tier_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_tier_changes_truncate();

COMMENT ON TABLE tenant_tier_changes IS
    'Append-only audit log of every subscription_tier transition. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_tier_changes_append_only, trg_tenant_tier_changes_append_only_truncate - PAT-1133/PAT-1137), except the single named anonymisation UPDATE tenant purge performs (see 0101_tenant_purge_audit_anonymisation.sql). Rows SURVIVE a tenant purge with claimed_actor/source_addr nulled (PAT-1137) - tenant_id is no longer FK-constrained and may be dangling after a purge. Retention: 6 years by default, pending PAT-112. Written atomically by PUT /admin/tenant-tier/{tenantID} alongside the tenants UPDATE.';
COMMENT ON COLUMN tenant_tier_changes.tenant_id IS
    'No longer FK-constrained to tenants(id) as of PAT-1137 - a purged tenant leaves this dangling on purpose, so the row still exists and is still groupable by (now-gone) tenant without any longer resolving to a real tenants row.';

-- ============================================================================
-- device_revocations - drop the tenant cascade; deliberately NOT guarded
-- (see header: DeleteDeviceHandler's legitimate device_id cascade delete)
-- ============================================================================

ALTER TABLE device_revocations
    DROP CONSTRAINT IF EXISTS device_revocations_tenant_id_fkey;

ALTER TABLE device_revocations
    ALTER COLUMN device_id DROP NOT NULL;

COMMENT ON TABLE device_revocations IS
    'Audit trail of every device revocation (PAT-549). Rows SURVIVE a tenant purge with claimed_actor/source_addr/device_id nulled (PAT-1137) - tenant_id is no longer FK-constrained and may be dangling after a purge. Deliberately has NO append-only DB trigger, unlike its four sibling tables: DeleteDeviceHandler (internal/handlers/admin_overview.go) legitimately DELETEs a single device independent of any tenant purge, and device_id remains ON DELETE CASCADE against devices(id) - guarding this table would reject that existing deletion path, the same conflict 0096 resolved for compliance_signals by leaving it unguarded. Never UPDATE or DELETE rows here from application code. Retention: 6 years by default, pending PAT-112.';
COMMENT ON COLUMN device_revocations.tenant_id IS
    'No longer FK-constrained to tenants(id) as of PAT-1137 - a purged tenant leaves this dangling on purpose; see tenant_tier_changes.tenant_id for the identical rationale.';
COMMENT ON COLUMN device_revocations.device_id IS
    'Nullable as of PAT-1137: tenant-purge anonymisation nulls this (a device identifier) on every row belonging to the purged tenant, before the devices row itself cascade-deletes. Still ON DELETE CASCADE for any other device deletion (e.g. DeleteDeviceHandler), which continues to remove the row entirely, as before.';

-- ============================================================================
-- enrollment_token_audit - drop the tenant cascade, add the append-only guard
-- ============================================================================

ALTER TABLE enrollment_token_audit
    DROP CONSTRAINT IF EXISTS enrollment_token_audit_tenant_id_fkey;

ALTER TABLE enrollment_token_audit
    ALTER COLUMN token_id DROP NOT NULL;

CREATE FUNCTION reject_enrollment_token_audit_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND current_setting('patched.tenant_purge_anonymizing', true) = 'on' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'enrollment_token_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enrollment_token_audit_append_only
    BEFORE UPDATE OR DELETE ON enrollment_token_audit
    FOR EACH ROW
    EXECUTE FUNCTION reject_enrollment_token_audit_mutation();

CREATE FUNCTION reject_enrollment_token_audit_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'enrollment_token_audit is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enrollment_token_audit_append_only_truncate
    BEFORE TRUNCATE ON enrollment_token_audit
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_enrollment_token_audit_truncate();

COMMENT ON TABLE enrollment_token_audit IS
    'Append-only audit log of every admin/portal enrolment-token mint (PAT-453). UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_enrollment_token_audit_append_only, trg_enrollment_token_audit_append_only_truncate - PAT-1137), except the single named anonymisation UPDATE tenant purge performs (see 0101_tenant_purge_audit_anonymisation.sql). Rows SURVIVE a tenant purge with token_id/actor_email/admin_note nulled (PAT-1137) - tenant_id is no longer FK-constrained and may be dangling after a purge. Retention: 6 years by default, pending PAT-112.';
COMMENT ON COLUMN enrollment_token_audit.tenant_id IS
    'No longer FK-constrained to tenants(id) as of PAT-1137 - a purged tenant leaves this dangling on purpose; see tenant_tier_changes.tenant_id for the identical rationale.';
COMMENT ON COLUMN enrollment_token_audit.token_id IS
    'Nullable as of PAT-1137: tenant-purge anonymisation nulls this (a token identifier) on every row belonging to the purged tenant, before the bootstrap_tokens row itself cascade-deletes. Still ON DELETE CASCADE against bootstrap_tokens(id) - bootstrap_tokens rows are never deleted except via this same tenant-purge cascade (grepped internal/, non-test), so no other path is affected.';

-- ============================================================================
-- tenant_decommission_audit - no FK to change; extend the EXISTING guard
-- (0091) with the same anonymisation exception, and anonymise on purge
-- ============================================================================

CREATE OR REPLACE FUNCTION reject_tenant_decommission_audit_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND current_setting('patched.tenant_purge_anonymizing', true) = 'on' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'tenant_decommission_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE tenant_decommission_audit IS
    'Append-only audit trail of every write to tenant_decommission (PAT-1108), mirroring tenant_platform_changes (0010). One row per PUT /admin/tenants/{tenantID}/decommission call, whether or not the resulting directive differs from the previous one. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_decommission_audit_append_only for UPDATE/DELETE, trg_tenant_decommission_audit_append_only_truncate for TRUNCATE -- PAT-1108/PAT-1137), except the single named anonymisation UPDATE tenant purge performs (see 0101_tenant_purge_audit_anonymisation.sql) -- this holds even for the owning role. Already survives a tenant purge (deliberately no FK to tenants - see 0091); PAT-1137 additionally nulls claimed_actor/source_addr/reason on purge. Retention: 6 years by default, pending PAT-112.';
COMMENT ON COLUMN tenant_decommission_audit.reason IS
    'Operator-supplied free text, recorded and surfaced for audit/operator visibility only. Must NEVER be evaluated as a control-flow input, here or on the agent. Nulled by tenant-purge anonymisation (PAT-1137).';

-- ============================================================================
-- The anonymisation trigger itself: fires BEFORE the tenants row is
-- deleted, redacts identifying columns on all four surviving audit tables
-- for that tenant, and sets the transaction-local flag that is the only
-- thing the four guard functions above will accept as permission to do so.
-- ============================================================================

CREATE FUNCTION anonymize_tenant_audit_before_purge() RETURNS trigger AS $$
BEGIN
    -- Transaction-local (is_local = true): reverts automatically at COMMIT
    -- or ROLLBACK of the current transaction, cannot leak to another
    -- session. This is the entire trust boundary the four append-only
    -- guards above rely on - see this file's header comment.
    PERFORM set_config('patched.tenant_purge_anonymizing', 'on', true);

    UPDATE tenant_tier_changes
       SET claimed_actor = NULL,
           source_addr = NULL
     WHERE tenant_id = OLD.id;

    UPDATE device_revocations
       SET claimed_actor = NULL,
           source_addr = NULL,
           device_id = NULL
     WHERE tenant_id = OLD.id;

    UPDATE enrollment_token_audit
       SET token_id = NULL,
           actor_email = NULL,
           admin_note = NULL
     WHERE tenant_id = OLD.id;

    UPDATE tenant_decommission_audit
       SET claimed_actor = NULL,
           source_addr = NULL,
           reason = NULL
     WHERE tenant_id = OLD.id;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_anonymize_audit_before_purge
    BEFORE DELETE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION anonymize_tenant_audit_before_purge();

COMMENT ON TRIGGER trg_tenants_anonymize_audit_before_purge ON tenants IS
    'PAT-1137: before a tenant row is deleted (PurgeTenantHandler''s DELETE FROM tenants, or any other DELETE against this table), redact the identifying columns on that tenant''s tenant_tier_changes / device_revocations / enrollment_token_audit / tenant_decommission_audit rows in place, so they survive the purge instead of cascading away. Runs BEFORE the devices/bootstrap_tokens cascades a tenant purge also triggers, so device_id/token_id are already NULL on these rows by the time those cascades look for children to remove.';

-- ============================================================================
-- provenance_records - deliberately unchanged; comment reinforced so this
-- exclusion reads as a decision, not an oversight (see header).
-- ============================================================================

COMMENT ON TABLE provenance_records IS
    'Immutable audit trail of third-party app updates from the Patched Updater. One row per app action. body JSONB is the source of truth - never UPDATE or DELETE rows here. Still fully CASCADE-DELETEd on tenant purge (PAT-1137 deliberately excluded this table from anonymisation: high-volume per-device telemetry with no governance value once stripped of identity - see 0101_tenant_purge_audit_anonymisation.sql header).';

-- ============================================================================
-- catalogue_review_audit - no schema change. Not tenant-scoped: no
-- tenant_id column, no FK to tenants, direct or indirect. A tenant purge
-- cannot reach it, so it already survives trivially. See this file's
-- header for why the ticket's original five-table list named it in error.
-- ============================================================================

COMMENT ON TABLE catalogue_review_audit IS
    'Append-only decision/revocation/migration trail for the app catalogue review pipeline (PAT-850). Global and cross-tenant: no tenant_id column, no FK to tenants, so a tenant purge cannot reach it (checked for PAT-1137). product_id REFERENCES catalogue_products(id) ON DELETE SET NULL - unrelated to any tenant lifecycle; see 0096_audit_append_only_guards.sql for why that FK path is not DB-guarded.';

INSERT INTO schema_migrations (version) VALUES ('0101_tenant_purge_audit_anonymisation')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
