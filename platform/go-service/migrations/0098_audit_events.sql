-- patched.im — 0098_audit_events.sql
-- PAT-1022: durable storage for POST /v1/events, the SIEM-style security
-- audit event endpoint both agents already implement and ship to today
-- (macOS emit_audit_event()/drain_events_queue() in
-- updater/endpoint/patched-update.sh; Windows AuditEventShipper.cs) but
-- which this server has never had a handler for — every event currently
-- 404s, retries into each agent's local ring-buffer (cap 1000), and is
-- ultimately lost. See updater/docs/audit-events-contract.md for the wire
-- contract this table stores.
--
-- ── Shape decision: typed columns, not a raw-JSONB archive ─────────────────
-- provenance_records (0011) stores the agent's JSON body verbatim in a
-- JSONB `body` column, because that payload shape has evolved repeatedly
-- (see fetchProvenancePatchHistory's COALESCE pairs in internal/report/
-- report.go bridging several historical field-name variants across macOS
-- and Windows). The audit-events envelope is different: it is a single,
-- closed contract (docs/audit-events-contract.md's "Event envelope" table,
-- six fixed event_type values, two fixed platform values) that both agents
-- already implement identically, and the reason this table exists at all is
-- to serve a tenant-wide, date-range-bounded query (PAT-1022 item 4,
-- internal/report/audit_events.go) that needs to filter and sort on several
-- of those fields economically. Typed columns + a small number of targeted
-- indexes serve that far better than a GIN index over opaque JSONB, at the
-- cost of a migration if the contract ever grows a field — an acceptable
-- trade given how narrow and already-stable the envelope is. This mirrors
-- enforcement_audit (0048), the closest existing precedent: a typed
-- security-audit-log table fed by agent ingestion, not a raw-body archive.
--
-- ── Append-only ──────────────────────────────────────────────────────────
-- docs/audit-events-contract.md is explicit: "the platform MUST NOT expose
-- a delete or update API for event records" — this is the tamper-evidence
-- guarantee an attacker with root on the endpoint cannot retract. Per the
-- reasoning 0096_audit_append_only_guards.sql established (and its
-- inventory of exactly which append-only tables it could and could not
-- guard): a BEFORE UPDATE OR DELETE ROW trigger plus a separate BEFORE
-- TRUNCATE STATEMENT trigger, because table ownership (every table here is
-- owned by `patched` since 0095_owner_catchup_to_patched) grants implicit
-- UPDATE/DELETE/TRUNCATE that no GRANT/REVOKE can withdraw — only a trigger
-- actually enforces it, for the owning role too.
--
-- Unlike provenance_records (deliberately NOT guarded by 0096, because its
-- tenant_id has ON DELETE CASCADE and tenant purge must be able to cascade
-- into it), audit_events' tenant_id below has NO explicit ON DELETE clause
-- (default NO ACTION) — the same choice enforcement_audit (0048) already
-- made, and 0096's header records that enforcement_audit "already fails on
-- the FK today, independent of this migration" for exactly this reason. So
-- guarding audit_events with the trigger here does not conflict with any
-- cascade: a tenant purge (PurgeTenantHandler, internal/handlers/admin.go)
-- against a tenant with audit_events rows already fails on the FK before
-- the trigger would ever fire, same pre-existing limitation as
-- enforcement_audit, tenant_tier_changes-adjacent tables, and friends. Not
-- decided here — flagged the same way 0096 flagged it for the other four
-- ON-DELETE-CASCADE tables.
--
-- ── Retention ────────────────────────────────────────────────────────────
-- Contract requires retention >= 90 days (SOC 2 CC7 evidence window). No
-- deletion path exists in this migration at all (forward-only, matches this
-- table's append-only guarantee) — a retention-enforcement job, if ever
-- needed, is a deliberate follow-up (PAT-1022 ticket scope explicitly
-- excludes it: "retention enforcement itself can be a follow-up ... just
-- make sure nothing here actively deletes early"). Nothing here deletes at
-- all, early or otherwise.
--
-- Apply BEFORE deploying the binary that serves POST /v1/events.
--   psql -h patched-api-01 -U patched -d patched -f migrations/0098_audit_events.sql

BEGIN;

CREATE TABLE audit_events (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id),
    device_id        TEXT        NOT NULL,
    event_type       TEXT        NOT NULL CHECK (event_type IN (
                          'verification_passed',
                          'verification_failed',
                          'install_completed',
                          'install_failed',
                          'posture_warning',
                          'allowlist_tamper_detected'
                      )),
    label            TEXT,
    version          TEXT,
    verified_signer  TEXT,
    reason           TEXT,
    expected         TEXT,
    actual           TEXT,
    platform         TEXT        NOT NULL CHECK (platform IN ('macos', 'windows')),
    source_ip        INET,
    -- occurred_at: the AGENT's own event timestamp (envelope `timestamp`
    -- field), not server receipt time — mirrors fetchProvenancePatchHistory's
    -- documented reasoning in internal/report/report.go for why agent-side
    -- event time, not ingestion time, is the correct ordering/query key: a
    -- queued, retried event can be POSTed well after it actually occurred.
    occurred_at      TIMESTAMPTZ NOT NULL,
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tenant-wide, date-range report (internal/report/audit_events.go,
-- FetchTenantAuditEvents) — the primary access path this table exists to
-- serve.
CREATE INDEX idx_audit_events_tenant_occurred ON audit_events (tenant_id, occurred_at DESC);

-- Per-device lookups (e.g. device-detail drill-down), same shape as
-- enforcement_audit_device (0048).
CREATE INDEX idx_audit_events_tenant_device_occurred ON audit_events (tenant_id, device_id, occurred_at DESC);

-- The app connects as the unprivileged `patched` role; without this grant
-- the handler 500s with "permission denied for table" (cf. PAT-579 for
-- tenant_new_apps, and 0048's identical note for enforcement_audit).
-- SELECT + INSERT only — no UPDATE/DELETE granted, matching the trigger
-- guard below (belt and braces, same as every other 0096-guarded table).
GRANT SELECT, INSERT ON TABLE audit_events TO patched;

CREATE FUNCTION reject_audit_events_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_events_mutation();

CREATE FUNCTION reject_audit_events_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_events_append_only_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_audit_events_truncate();

COMMENT ON TABLE audit_events IS
    'Durable, append-only store for POST /v1/events (PAT-1022) — the SIEM-style security audit trail both agents ship (updater/docs/audit-events-contract.md). UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_audit_events_append_only, trg_audit_events_append_only_truncate), not merely documented against via GRANT — this holds even for the owning role. Retain >= 90 days (SOC 2 CC7); no deletion path exists yet, forward-only by design. Use INSERT to record each event.';

INSERT INTO schema_migrations (version) VALUES ('0098_audit_events')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
