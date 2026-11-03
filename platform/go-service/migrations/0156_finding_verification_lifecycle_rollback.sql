-- Rollback for PAT-1878.  Lifecycle history is non-reconstructible and must
-- never be discarded.  A rollback is therefore permitted only before any
-- event exists; production (where 0146 history is backfilled) fails closed.
BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM finding_lifecycle_events LIMIT 1) THEN
        RAISE EXCEPTION '0156 rollback refused: finding lifecycle history exists';
    END IF;
END;
$$;

DROP VIEW IF EXISTS finding_lifecycle_current;
DROP TRIGGER IF EXISTS trg_finding_lifecycle_events_append_only_truncate ON finding_lifecycle_events;
DROP TRIGGER IF EXISTS trg_finding_lifecycle_events_append_only ON finding_lifecycle_events;
DROP FUNCTION IF EXISTS reject_finding_lifecycle_events_truncate();
DROP FUNCTION IF EXISTS reject_finding_lifecycle_event_mutation();
DROP TABLE IF EXISTS finding_lifecycle_events;

DROP INDEX IF EXISTS uq_finding_dispositions_active_software;
DROP INDEX IF EXISTS idx_finding_dispositions_active_software;
ALTER TABLE finding_dispositions DROP CONSTRAINT finding_dispositions_kind_shape;
ALTER TABLE finding_dispositions DROP CONSTRAINT finding_dispositions_finding_kind_check;
ALTER TABLE finding_dispositions DROP CONSTRAINT finding_dispositions_status_check;
CREATE OR REPLACE FUNCTION guard_finding_dispositions_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'finding_dispositions is append-only: DELETE is not permitted on row id=%', OLD.id;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.finding_kind IS DISTINCT FROM OLD.finding_kind
        OR NEW.device_id IS DISTINCT FROM OLD.device_id
        OR NEW.rule_key IS DISTINCT FROM OLD.rule_key
        OR NEW.cve_id IS DISTINCT FROM OLD.cve_id
        OR NEW.status IS DISTINCT FROM OLD.status
        OR NEW.recorded_by IS DISTINCT FROM OLD.recorded_by
        OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.recorded_at IS DISTINCT FROM OLD.recorded_at
        OR NEW.supersedes_id IS DISTINCT FROM OLD.supersedes_id
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
ALTER TABLE finding_dispositions DROP COLUMN software_key;
ALTER TABLE finding_dispositions
    ADD CONSTRAINT finding_dispositions_finding_kind_check
        CHECK (finding_kind IN ('cis', 'cve')),
    ADD CONSTRAINT finding_dispositions_status_check
        CHECK (status IN ('acknowledged', 'risk_accepted', 'closed')),
    ADD CONSTRAINT finding_dispositions_kind_shape CHECK (
        (finding_kind = 'cis' AND device_id IS NOT NULL AND rule_key IS NOT NULL AND cve_id IS NULL) OR
        (finding_kind = 'cve' AND device_id IS NULL AND rule_key IS NULL AND cve_id IS NOT NULL)
    );

DELETE FROM schema_migrations WHERE version = '0156_finding_verification_lifecycle';
COMMIT;
