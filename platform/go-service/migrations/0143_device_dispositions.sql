-- patched.im — 0143_device_dispositions.sql
-- PAT-1825: device disposition records (decommissioned/on-leave/lost/
-- unaccounted) and the automatic reappearance finding — the follow-up
-- PAT-1595 deferred (see 0140_device_lifecycle.sql item 4/5, and
-- internal/devicelifecycle.ClassifyState's activeDisposition parameter and
-- ReappearedSince, both already shaped for this table).
--
-- Shape decision (append-only-with-supersede, not a mutable "current" row
-- plus a separate audit log): PAT-1824's tenant_software_exceptions /
-- tenant_software_exception_changes split works because status there is a
-- one-way ratchet (unaccepted -> accepted) with no correction path. A
-- disposition can be corrected ("actually it's lost, not decommissioned")
-- or auto-reversed by a live check-in, and the ticket requires the OLD row's
-- substantive fields to survive byte-for-byte next to the correction, not
-- be folded into a separate log keyed by exception_id. So device_dispositions
-- carries its own history: every row is either the live tip (superseded_at
-- IS NULL) or a superseded predecessor, chained by supersedes_id, and the
-- guard trigger below enforces that superseding a row may only ever touch
-- superseded_at/superseded_reason — every other column is fixed for the
-- life of the row, same principle as remediation_artefacts' supersession
-- chain (0141) but enforced at the database level rather than left to
-- application discipline, because this table's writers include an
-- unattended extractor path (the reappearance rule) as well as an admin
-- handler.
--
-- device_id is NOT NULL, not nullable-for-cohort: a cohort disposition
-- ("these 12 devices are all decommissioned") writes one row per device,
-- all sharing one cohort_id, rather than inventing a separate cohort
-- concept — there is no query this ticket needs that a cohort_id grouping
-- column doesn't already answer, and a separate cohort entity would be a
-- second source of truth for "which devices" that the per-row list already
-- carries.
--
-- At most one ACTIVE disposition per device (partial unique index below):
-- a correction or a reappearance must go through the supersede path, never
-- create a second live disposition alongside an existing one — "the active
-- disposition for this device" must always be an unambiguous single row for
-- internal/devicelifecycle.ClassifyState's activeDisposition lookup to mean
-- anything.
--
-- Findings surface decision (documented per the implementer brief): a
-- reappearance is NOT written into compliance_evaluations. That table's
-- rule_id is a hard FK to compliance_rules (0003) and is populated only by
-- the rule engine evaluating a compliance_signals key on every ingest
-- (internal/evaluator) — a reappearance is a lifecycle event derived from
-- device_dispositions + devices.last_seen, not a signal-vs-expected-value
-- comparison, and remediation_artefacts (0141) already establishes the
-- precedent that a finding family which doesn't fit the compliance_rules
-- shape gets its own table rather than a fabricated rule row (that
-- migration's own comment: "CVE findings live entirely in
-- device_cve_findings ... structurally cannot be the subject of a
-- remediation_artefacts row"). device_lifecycle_findings below follows the
-- same reasoning for this third finding family. It is deliberately narrow
-- (one kind so far) rather than a generic findings table — PAT-1609 (the
-- console side) is the ticket that will decide whether this grows into a
-- shared cross-finding-type surface; inventing that shape now, unread by
-- anything, would be speculative.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0143_device_dispositions.sql

BEGIN;

CREATE TABLE device_dispositions (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id           UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    category            TEXT         NOT NULL
                             CHECK (category IN ('decommissioned', 'on-leave', 'lost', 'unaccounted')),
    reported_by         TEXT         NOT NULL DEFAULT '',
    reported_by_role    TEXT         NOT NULL DEFAULT '',
    channel             TEXT         NOT NULL DEFAULT '',
    note                TEXT         NOT NULL DEFAULT '',
    recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Shared across every row written from one cohort decision. NULL for a
    -- single-device disposition — there is nothing to group it with.
    cohort_id           UUID,
    supersedes_id       UUID         REFERENCES device_dispositions(id),
    superseded_at       TIMESTAMPTZ,
    superseded_reason   TEXT,
    CONSTRAINT device_dispositions_supersede_fields CHECK (
        (superseded_at IS NULL AND superseded_reason IS NULL) OR
        (superseded_at IS NOT NULL AND superseded_reason IS NOT NULL)
    )
);

CREATE INDEX idx_device_dispositions_tenant
    ON device_dispositions (tenant_id, recorded_at DESC);
CREATE INDEX idx_device_dispositions_cohort
    ON device_dispositions (cohort_id) WHERE cohort_id IS NOT NULL;

-- The lookup internal/handlers/device_lifecycle.go and the reappearance
-- check in internal/extractor both run: "does this device have a live
-- disposition right now". Partial index on the common case.
CREATE INDEX idx_device_dispositions_active
    ON device_dispositions (device_id) WHERE superseded_at IS NULL;

-- Enforces "at most one active disposition per device" — a second INSERT
-- for an already-disposed device without first superseding the existing row
-- is a unique-violation, not a silently ambiguous state.
CREATE UNIQUE INDEX uq_device_dispositions_one_active_per_device
    ON device_dispositions (device_id) WHERE superseded_at IS NULL;

-- Same anti-fork protection as remediation_artefacts (0141): two concurrent
-- writers superseding the same row could otherwise both insert a successor,
-- forking the chain. This makes the second one a unique-violation at INSERT
-- time.
CREATE UNIQUE INDEX idx_device_dispositions_supersedes_unique
    ON device_dispositions (supersedes_id) WHERE supersedes_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON TABLE device_dispositions TO patched;

COMMENT ON TABLE device_dispositions IS
    'PAT-1825: append-only-with-supersede disposition records (decommissioned/on-leave/lost/unaccounted). A correction or an automatic reappearance writes a NEW row with supersedes_id pointing at the prior one and sets the prior row''s superseded_at/superseded_reason; the guard trigger below forbids any other change to an existing row. See migration header for why this is not folded into compliance_evaluations.';
COMMENT ON COLUMN device_dispositions.superseded_reason IS
    'Free text, but the two paths that write it use fixed values: "correction" (a human recorded a new disposition for a device that already had a live one) and "reappeared" (internal/extractor auto-superseded on a live check-in — see device_lifecycle_findings).';

-- ── Append-only-with-supersede guard ────────────────────────────────────
-- Unlike tenant_software_exception_changes (0142), which is purely
-- append-only, this table must allow exactly one narrow UPDATE shape: an
-- active row transitioning to superseded. Every other column must be
-- byte-identical to the row as first written, and the transition may only
-- ever happen once per row (superseded_at NULL -> NOT NULL, never touched
-- again). DELETE is never permitted.
CREATE FUNCTION guard_device_dispositions_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'device_dispositions is append-only: DELETE is not permitted on row id=%', OLD.id;
    END IF;

    IF NEW.id                IS DISTINCT FROM OLD.id
        OR NEW.tenant_id         IS DISTINCT FROM OLD.tenant_id
        OR NEW.device_id         IS DISTINCT FROM OLD.device_id
        OR NEW.category          IS DISTINCT FROM OLD.category
        OR NEW.reported_by       IS DISTINCT FROM OLD.reported_by
        OR NEW.reported_by_role  IS DISTINCT FROM OLD.reported_by_role
        OR NEW.channel           IS DISTINCT FROM OLD.channel
        OR NEW.note              IS DISTINCT FROM OLD.note
        OR NEW.recorded_at       IS DISTINCT FROM OLD.recorded_at
        OR NEW.cohort_id         IS DISTINCT FROM OLD.cohort_id
        OR NEW.supersedes_id     IS DISTINCT FROM OLD.supersedes_id
    THEN
        RAISE EXCEPTION 'device_dispositions is append-only: only superseded_at/superseded_reason may change on row id=%', OLD.id;
    END IF;

    IF OLD.superseded_at IS NOT NULL THEN
        RAISE EXCEPTION 'device_dispositions row id=% is already superseded', OLD.id;
    END IF;
    IF NEW.superseded_at IS NULL OR NEW.superseded_reason IS NULL THEN
        RAISE EXCEPTION 'device_dispositions update must set both superseded_at and superseded_reason, id=%', OLD.id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_dispositions_append_only
    BEFORE UPDATE OR DELETE ON device_dispositions
    FOR EACH ROW
    EXECUTE FUNCTION guard_device_dispositions_mutation();

CREATE FUNCTION reject_device_dispositions_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_dispositions is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_dispositions_append_only_truncate
    BEFORE TRUNCATE ON device_dispositions
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_device_dispositions_truncate();

-- ── Reappearance findings ───────────────────────────────────────────────
-- One row per auto-supersede-on-reappearance event. Genuinely append-only
-- (no supersede shape of its own) — a finding is a historical fact about
-- what the extractor observed and did, never itself corrected in place.
CREATE TABLE device_lifecycle_findings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id       UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    disposition_id  UUID        NOT NULL REFERENCES device_dispositions(id),
    kind            TEXT        NOT NULL CHECK (kind IN ('reappeared_after_disposition')),
    detail          TEXT        NOT NULL DEFAULT '',
    raised_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_device_lifecycle_findings_tenant
    ON device_lifecycle_findings (tenant_id, raised_at DESC);
CREATE INDEX idx_device_lifecycle_findings_device
    ON device_lifecycle_findings (device_id, raised_at DESC);

COMMENT ON TABLE device_lifecycle_findings IS
    'PAT-1825: append-only findings raised by internal/extractor''s automatic reappearance rule — a device with a live disposition (decommissioned/on-leave/lost/unaccounted) reporting inventory again. kind is deliberately a narrow enum of one value; a future finding family is a new CHECK value plus migration, not a schema-free text field.';

CREATE FUNCTION reject_device_lifecycle_findings_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_lifecycle_findings is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_lifecycle_findings_append_only
    BEFORE UPDATE OR DELETE ON device_lifecycle_findings
    FOR EACH ROW
    EXECUTE FUNCTION reject_device_lifecycle_findings_mutation();

CREATE FUNCTION reject_device_lifecycle_findings_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_lifecycle_findings is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_lifecycle_findings_append_only_truncate
    BEFORE TRUNCATE ON device_lifecycle_findings
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_device_lifecycle_findings_truncate();

GRANT SELECT, INSERT ON TABLE device_lifecycle_findings TO patched;

INSERT INTO schema_migrations (version) VALUES ('0143_device_dispositions')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
