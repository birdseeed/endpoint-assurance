-- patched.im — 0096_audit_append_only_guards.sql
-- PAT-1133: enforce "append-only" on the audit-log tables that already
-- document that property in a COMMENT ON TABLE, instead of only documenting
-- it.
--
-- Every migration in this repo runs as role `patched` (see each file's
-- "Apply with" header), which makes `patched` the OWNER of every table it
-- creates — and, since 0095_owner_catchup_to_patched, the owner of every
-- table in the database, full stop. Table ownership is not something
-- GRANT/REVOKE can take away: an owner always retains implicit UPDATE/
-- DELETE/TRUNCATE regardless of what privileges are explicitly granted or
-- withheld. Several tables are commented "append-only" / "immutable audit
-- trail" and granted only SELECT+INSERT, but that GRANT documents intent
-- and enforces nothing against the very role making every write in
-- production. This migration follows the pattern 0091_agent_decommission.sql
-- established for tenant_decommission_audit: a row-level BEFORE UPDATE OR
-- DELETE trigger that RAISEs (chosen over a rule, and over a silent no-op,
-- for the same reasons given in 0091's header — triggers fire for the
-- owning role too, and a bug that tries to "correct" an audit row must fail
-- loudly, not vanish), plus a SEPARATE statement-level BEFORE TRUNCATE
-- trigger, because Postgres never fires row-level triggers for TRUNCATE —
-- without it the owning role could still erase an entire audit trail in one
-- statement (0091's fifth-round finding P1-C).
--
-- ── Inventory (PAT-1133's enumerate-first requirement) ──────────────────
--
-- Every migrations/*.sql file was grepped for "append-only", "immutable",
-- "audit trail", and "audit log". The full candidate list, and what was
-- done with each:
--
-- GUARDED here (genuinely append-only-by-design; grepped internal/ for
-- UPDATE/DELETE against each table name — app code only ever INSERTs, and
-- no FK on any of these five cascades a write into them from elsewhere):
--   tenant_platform_changes    (0010) — no FK on tenant_id.
--   tenant_rule_changes        (0005) — no FK on tenant_id/rule_id.
--   tenant_app_policy_changes  (0021) — no FK on tenant_id.
--   ring_config_changes        (0042) — no FK on tenant_id/device_id.
--   enforcement_audit          (0048) — tenant_id REFERENCES tenants(id)
--     with NO ON DELETE clause (default NO ACTION), so a tenant purge with
--     enforcement_audit rows already fails on the FK today, independent of
--     this migration — adding the trigger changes nothing about that.
--
-- ALREADY GUARDED (PAT-1108/0091 — confirmed present, not re-added):
--   tenant_decommission_audit  (0091)
--
-- NOT guarded — a real cascading write from elsewhere in the schema would
-- be rejected by the trigger, breaking a legitimate, existing code path.
-- Verified empirically (BEGIN; add a throwaway trigger; exercise the
-- cascade; ROLLBACK) before excluding each of these, not assumed:
--   tenant_tier_changes        (0056) — tenant_id ... ON DELETE CASCADE.
--   device_revocations         (0040) — tenant_id AND device_id both
--     ON DELETE CASCADE.
--   provenance_records         (0011) — tenant_id ... ON DELETE CASCADE.
--   enrollment_token_audit     (0040_enrollment_audit_log) — tenant_id AND
--     token_id (REFERENCES bootstrap_tokens) both ON DELETE CASCADE.
--   All four: PurgeTenantHandler (internal/handlers/admin.go) does exactly
--   one `DELETE FROM tenants WHERE id = $1`, documented as hard-deleting
--   "a tenant and all child rows via ON DELETE CASCADE". For any tenant
--   that ever had a tier change, device revocation, provenance record, or
--   enrolment token, that cascade reaches into these tables and performs a
--   real DELETE against rows there — confirmed by reproducing it directly
--   against a throwaway BEFORE DELETE trigger, which fired and raised. Note
--   tenant_decommission_audit (0091) deliberately has NO FK to tenants at
--   all, specifically so it survives tenant purge instead of racing this
--   exact conflict — these four tables predate that pattern and were never
--   brought in line with it. This ticket does not silently guess which of
--   "audit trail must survive purge" (drop the cascade, matching
--   tenant_decommission_audit) or "purge must be able to erase the trail"
--   (leave as-is, and stop calling these tables append-only) is correct —
--   that is a data-retention/compliance decision, not an append-only-
--   enforcement one, and is flagged for follow-up rather than decided here.
--   catalogue_review_audit    (0078) — product_id REFERENCES
--     catalogue_products(id) ON DELETE SET NULL. No production code path
--     deletes catalogue_products today (grepped internal/, non-test) — only
--     test cleanup does — but the same reproduction method above confirms
--     the SET NULL fires a real UPDATE against catalogue_review_audit rows
--     referencing the deleted product, which a BEFORE UPDATE guard would
--     reject. Also already granted UPDATE+DELETE (0078, likely copy-paste
--     from its sibling tables in the same migration, since app code only
--     ever INSERTs into it) rather than the SELECT+INSERT-only pattern the
--     other append-only tables use. Left unguarded and flagged rather than
--     also silently dropping its FK's ON DELETE SET NULL.
--   portal_access_log          (0059) — comment calls it an "audit trail"
--     but never claims append-only/immutable, and it was granted full
--     SELECT/INSERT/UPDATE/DELETE deliberately (not a copy-paste artifact —
--     every other table in this same migration, portal_users, gets the
--     identical grant for an unrelated reason). No misleading comment to
--     fix; excluded as not documented as append-only in the first place.
--
-- COMMENT CORRECTED, not guarded — the table's own comment claimed
-- append-only/immutable, but internal/ has a real, legitimate UPDATE or
-- DELETE against it outside any audit-mutation scenario:
--   compliance_signals (0001) — "(Append-only; the auditor-ready report is
--     built from this table.)" but DeleteDeviceHandler
--     (internal/handlers/admin_overview.go) legitimately DELETEs a device's
--     compliance_signals rows as part of removing the device entirely. Not
--     an audit-tampering path; a device-deletion cascade this repo
--     implements in application code rather than an FK.
--   raw_payloads (0001) — "immutable archive of every inbound POST" but the
--     extractor (internal/extractor/extractor.go, upsert.go) legitimately
--     UPDATEs three bookkeeping columns (extraction_attempts, extracted_at,
--     extraction_error, device_id) as it claims and processes rows. The
--     `body` column — the actual archived payload — is never written after
--     insert; only bookkeeping is. Comment corrected to say so precisely
--     instead of claiming the whole row is immutable.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0096_audit_append_only_guards.sql

BEGIN;

-- ============================================================================
-- tenant_platform_changes
-- ============================================================================

CREATE FUNCTION reject_tenant_platform_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_platform_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_platform_changes_append_only
    BEFORE UPDATE OR DELETE ON tenant_platform_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_platform_changes_mutation();

CREATE FUNCTION reject_tenant_platform_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_platform_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_platform_changes_append_only_truncate
    BEFORE TRUNCATE ON tenant_platform_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_platform_changes_truncate();

COMMENT ON TABLE tenant_platform_changes IS
    'Append-only audit trail of every tenants.macos_enabled / windows_enabled flip. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_platform_changes_append_only, trg_tenant_platform_changes_append_only_truncate — PAT-1133), not merely documented against — this holds even for the owning role. Use INSERT to record each change.';

-- ============================================================================
-- tenant_rule_changes
-- ============================================================================

CREATE FUNCTION reject_tenant_rule_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_rule_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_rule_changes_append_only
    BEFORE UPDATE OR DELETE ON tenant_rule_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_rule_changes_mutation();

CREATE FUNCTION reject_tenant_rule_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_rule_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_rule_changes_append_only_truncate
    BEFORE TRUNCATE ON tenant_rule_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_rule_changes_truncate();

COMMENT ON TABLE tenant_rule_changes IS
    'Append-only audit trail of every tenant_rules mutation. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_rule_changes_append_only, trg_tenant_rule_changes_append_only_truncate — PAT-1133), not merely documented against — this holds even for the owning role. Use INSERT to record each change.';

-- ============================================================================
-- tenant_app_policy_changes
-- ============================================================================

CREATE FUNCTION reject_tenant_app_policy_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_app_policy_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_app_policy_changes_append_only
    BEFORE UPDATE OR DELETE ON tenant_app_policy_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_app_policy_changes_mutation();

CREATE FUNCTION reject_tenant_app_policy_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_app_policy_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_app_policy_changes_append_only_truncate
    BEFORE TRUNCATE ON tenant_app_policy_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_app_policy_changes_truncate();

COMMENT ON TABLE tenant_app_policy_changes IS
    'Append-only audit trail of every app-update-policy mutation: per-app toggles (app_enabled/app_disabled/app_removed) and fleet-default flips (default_changed). UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_app_policy_changes_append_only, trg_tenant_app_policy_changes_append_only_truncate — PAT-1133), not merely documented against — this holds even for the owning role. Use INSERT to record each change.';

-- ============================================================================
-- ring_config_changes
-- ============================================================================

CREATE FUNCTION reject_ring_config_changes_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ring_config_changes is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ring_config_changes_append_only
    BEFORE UPDATE OR DELETE ON ring_config_changes
    FOR EACH ROW
    EXECUTE FUNCTION reject_ring_config_changes_mutation();

CREATE FUNCTION reject_ring_config_changes_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ring_config_changes is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ring_config_changes_append_only_truncate
    BEFORE TRUNCATE ON ring_config_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_ring_config_changes_truncate();

COMMENT ON TABLE ring_config_changes IS
    'Append-only audit log for patching ring configuration and rollout state transitions. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_ring_config_changes_append_only, trg_ring_config_changes_append_only_truncate — PAT-1133), not merely documented against — this holds even for the owning role. Use INSERT to record each change.';

-- ============================================================================
-- enforcement_audit
-- ============================================================================

CREATE FUNCTION reject_enforcement_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'enforcement_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforcement_audit_append_only
    BEFORE UPDATE OR DELETE ON enforcement_audit
    FOR EACH ROW
    EXECUTE FUNCTION reject_enforcement_audit_mutation();

CREATE FUNCTION reject_enforcement_audit_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'enforcement_audit is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforcement_audit_append_only_truncate
    BEFORE TRUNCATE ON enforcement_audit
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_enforcement_audit_truncate();

COMMENT ON TABLE enforcement_audit IS
    'Append-only audit log: SELECT (dashboard) + INSERT (agent ingestion) only. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_enforcement_audit_append_only, trg_enforcement_audit_append_only_truncate — PAT-1133), not merely documented against via GRANT — this holds even for the owning role.';

-- ============================================================================
-- Comment corrections — tables where a real, legitimate UPDATE/DELETE path
-- exists in application code, so no trigger is added here (see header).
-- ============================================================================

COMMENT ON TABLE compliance_signals IS
    'Time-series of per-device compliance state; the auditor-ready report is built from this table. Append-only from the evaluator''s perspective (new observations are always INSERTed, never revised), but NOT append-only overall: DeleteDeviceHandler (internal/handlers/admin_overview.go) legitimately DELETEs a device''s rows here as part of deleting the device. PAT-1133: no append-only trigger was added — it would reject that legitimate deletion.';

COMMENT ON TABLE raw_payloads IS
    'Archive of every inbound POST, partitioned monthly on received_at. The `body` column is immutable — never written after insert. The row as a whole is NOT immutable: the extractor (internal/extractor/extractor.go, upsert.go) legitimately UPDATEs extraction_attempts, extracted_at, extraction_error, and device_id as it claims and processes each row (see AGENTS.md: re-extraction is always possible by resetting extracted_at = NULL, extraction_attempts = 0). PAT-1133: no append-only trigger was added — it would reject that legitimate bookkeeping.';

INSERT INTO schema_migrations (version) VALUES ('0096_audit_append_only_guards')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
