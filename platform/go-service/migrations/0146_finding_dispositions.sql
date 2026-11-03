-- patched.im — 0146_finding_dispositions.sql
-- PAT-1829: findings disposition tracking (acknowledged / risk_accepted /
-- closed) — platform half only. Dashboard UI (a state filter/badge on the
-- console findings screens) is a separate follow-up ticket.
--
-- ── Two finding identity shapes, one table ─────────────────────────────────
-- There are two finding types today, with genuinely different identity:
--
--   CIS findings (internal/handlers/admin_overview.go's TenantFindingsHandler,
--   backed by report.FetchTenantFindings) — one row per (device, compliance
--   rule), sourced from compliance_evaluations. Identity is
--   (tenant_id, device_id, rule_key).
--
--   CVE findings (internal/handlers/cve.go's TenantCVEFindingsHandler) — one
--   row per CVE, aggregated across every affected device on the tenant (see
--   that handler's own comment), sourced from device_cve_findings grouped by
--   cve_id. Identity is (tenant_id, cve_id) — there is no meaningful
--   per-device CVE disposition in the current findings view; a specialist
--   disposes of "this CVE, for this tenant", not "this CVE, on this one
--   device".
--
-- Rather than two tables (which would give the admin API and any future
-- console UI two shapes to poll and reconcile) or one table with a JSONB
-- identity blob (which would give up the partial-unique-index enforcement
-- below), this is one table with a finding_kind discriminator and
-- kind-appropriate nullable identity columns, enforced by a CHECK constraint:
-- finding_kind='cis' requires device_id+rule_key set and cve_id null;
-- finding_kind='cve' requires the reverse.
--
-- ── Shape: append-only-with-supersede ───────────────────────────────────────
-- Same shape and same reasoning as migrations/0143_device_dispositions.sql:
-- a disposition can be corrected ("actually this is risk_accepted, not just
-- acknowledged") and the ticket requires the OLD row's substantive fields to
-- survive byte-for-byte next to the correction, not be folded into a
-- separate log. Every row is either the live tip (superseded_at IS NULL) or
-- a superseded predecessor, chained by supersedes_id. The guard trigger
-- below enforces that superseding a row may only ever touch
-- superseded_at/superseded_reason — every other column is fixed for the
-- life of the row. DELETE and TRUNCATE are never permitted.
--
-- At most one ACTIVE disposition per (tenant, finding identity): two partial
-- unique indexes below, one per finding_kind, since the uniqueness key
-- differs by kind (device_id+rule_key for cis, cve_id for cve). A second
-- INSERT for an already-disposed finding without first superseding the
-- existing row is a unique-violation, not a silently ambiguous state.
--
-- ── Explicitly out of scope (see ticket) ────────────────────────────────────
-- Auto-superseding a disposition when the underlying finding resolves itself
-- (e.g. a CVE finding disappearing because the device patched) is a real
-- future feature but not this ticket. A disposition can outlive its finding
-- for now — that is an acceptable, documented gap, not a bug to fix here.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0146_finding_dispositions.sql

BEGIN;

CREATE TABLE finding_dispositions (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_kind        TEXT         NOT NULL CHECK (finding_kind IN ('cis', 'cve')),
    -- CIS identity: (tenant_id, device_id, rule_key). NULL for finding_kind='cve'.
    device_id           UUID         REFERENCES devices(id) ON DELETE CASCADE,
    rule_key            TEXT,
    -- CVE identity: (tenant_id, cve_id), aggregated across the tenant's
    -- affected devices — see TenantCVEFindingsHandler. NULL for finding_kind='cis'.
    cve_id              TEXT         REFERENCES cve_feed_entries(cve_id) ON DELETE CASCADE,
    status              TEXT         NOT NULL CHECK (status IN ('acknowledged', 'risk_accepted', 'closed')),
    recorded_by         TEXT         NOT NULL DEFAULT '',
    reason              TEXT         NOT NULL DEFAULT '',
    recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    supersedes_id       UUID         REFERENCES finding_dispositions(id),
    superseded_at       TIMESTAMPTZ,
    superseded_reason   TEXT,
    CONSTRAINT finding_dispositions_supersede_fields CHECK (
        (superseded_at IS NULL AND superseded_reason IS NULL) OR
        (superseded_at IS NOT NULL AND superseded_reason IS NOT NULL)
    ),
    CONSTRAINT finding_dispositions_kind_shape CHECK (
        (finding_kind = 'cis' AND device_id IS NOT NULL AND rule_key IS NOT NULL AND cve_id IS NULL) OR
        (finding_kind = 'cve' AND device_id IS NULL AND rule_key IS NULL AND cve_id IS NOT NULL)
    )
);

CREATE INDEX idx_finding_dispositions_tenant
    ON finding_dispositions (tenant_id, recorded_at DESC);

-- "Does this CIS/CVE finding have a live disposition right now" is the
-- common lookup for both the admin list and a future console badge.
-- Partial indexes on the common case, split by kind since the identity
-- columns differ.
CREATE INDEX idx_finding_dispositions_active_cis
    ON finding_dispositions (tenant_id, device_id, rule_key)
    WHERE superseded_at IS NULL AND finding_kind = 'cis';
CREATE INDEX idx_finding_dispositions_active_cve
    ON finding_dispositions (tenant_id, cve_id)
    WHERE superseded_at IS NULL AND finding_kind = 'cve';

-- Enforces "at most one active disposition per finding identity" — a second
-- INSERT for an already-disposed finding without first superseding the
-- existing row is a unique-violation, not a silently ambiguous state. Two
-- indexes because the uniqueness key differs by finding_kind; each is
-- naturally scoped to its own kind by the WHERE clause (the kind-shape CHECK
-- above guarantees a cis row's cve_id is NULL and a cve row's device_id/
-- rule_key are NULL, so neither index sees rows of the other kind).
CREATE UNIQUE INDEX uq_finding_dispositions_active_cis
    ON finding_dispositions (tenant_id, device_id, rule_key)
    WHERE superseded_at IS NULL AND finding_kind = 'cis';
CREATE UNIQUE INDEX uq_finding_dispositions_active_cve
    ON finding_dispositions (tenant_id, cve_id)
    WHERE superseded_at IS NULL AND finding_kind = 'cve';

-- Same anti-fork protection as device_dispositions (0143) and
-- remediation_artefacts (0141): two concurrent writers superseding the same
-- row could otherwise both insert a successor, forking the chain. This
-- makes the second one a unique-violation at INSERT time.
CREATE UNIQUE INDEX idx_finding_dispositions_supersedes_unique
    ON finding_dispositions (supersedes_id) WHERE supersedes_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON TABLE finding_dispositions TO patched;

COMMENT ON TABLE finding_dispositions IS
    'PAT-1829: append-only-with-supersede disposition records (acknowledged/risk_accepted/closed) for CIS and CVE findings. finding_kind selects which identity columns are populated — see migration header for the two identity shapes. A correction writes a NEW row with supersedes_id pointing at the prior one and sets the prior row''s superseded_at/superseded_reason; the guard trigger below forbids any other change to an existing row.';
COMMENT ON COLUMN finding_dispositions.superseded_reason IS
    'Free text, but the admin handler''s correction path uses the fixed value "correction" (a specialist recorded a new disposition for a finding that already had a live one).';

-- ── Append-only-with-supersede guard ────────────────────────────────────
-- Same shape as guard_device_dispositions_mutation (0143): exactly one
-- narrow UPDATE shape is allowed (an active row transitioning to
-- superseded); every other column must be byte-identical to the row as
-- first written, and the transition may only ever happen once per row.
-- DELETE is never permitted.
CREATE FUNCTION guard_finding_dispositions_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'finding_dispositions is append-only: DELETE is not permitted on row id=%', OLD.id;
    END IF;

    IF NEW.id                IS DISTINCT FROM OLD.id
        OR NEW.tenant_id         IS DISTINCT FROM OLD.tenant_id
        OR NEW.finding_kind      IS DISTINCT FROM OLD.finding_kind
        OR NEW.device_id         IS DISTINCT FROM OLD.device_id
        OR NEW.rule_key          IS DISTINCT FROM OLD.rule_key
        OR NEW.cve_id            IS DISTINCT FROM OLD.cve_id
        OR NEW.status            IS DISTINCT FROM OLD.status
        OR NEW.recorded_by       IS DISTINCT FROM OLD.recorded_by
        OR NEW.reason            IS DISTINCT FROM OLD.reason
        OR NEW.recorded_at       IS DISTINCT FROM OLD.recorded_at
        OR NEW.supersedes_id     IS DISTINCT FROM OLD.supersedes_id
    THEN
        RAISE EXCEPTION 'finding_dispositions is append-only: only superseded_at/superseded_reason may change on row id=%', OLD.id;
    END IF;

    IF OLD.superseded_at IS NOT NULL THEN
        RAISE EXCEPTION 'finding_dispositions row id=% is already superseded', OLD.id;
    END IF;
    IF NEW.superseded_at IS NULL OR NEW.superseded_reason IS NULL THEN
        RAISE EXCEPTION 'finding_dispositions update must set both superseded_at and superseded_reason, id=%', OLD.id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_dispositions_append_only
    BEFORE UPDATE OR DELETE ON finding_dispositions
    FOR EACH ROW
    EXECUTE FUNCTION guard_finding_dispositions_mutation();

CREATE FUNCTION reject_finding_dispositions_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'finding_dispositions is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_dispositions_append_only_truncate
    BEFORE TRUNCATE ON finding_dispositions
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_finding_dispositions_truncate();

INSERT INTO schema_migrations (version) VALUES ('0146_finding_dispositions')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
