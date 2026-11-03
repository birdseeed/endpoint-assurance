-- patched.im - 0156_finding_verification_lifecycle.sql
-- PAT-1878: preserve the complete finding/remediation verification lifecycle.
--
-- finding_dispositions (0146) remains the compatibility/action projection.
-- This migration adds the durable evidence ledger beneath it.  The ledger is
-- deliberately neutral across CIS, CVE and software-policy findings: every
-- identity is (tenant, kind, optional device, finding_key), and every change
-- is an immutable event.  Human actions and endpoint observations are kept
-- distinct so an operator can request verification but cannot manufacture a
-- verified closure.
BEGIN;

ALTER TABLE finding_dispositions
    ADD COLUMN software_key TEXT;

ALTER TABLE finding_dispositions
    DROP CONSTRAINT finding_dispositions_kind_shape;
ALTER TABLE finding_dispositions
    DROP CONSTRAINT finding_dispositions_finding_kind_check;
ALTER TABLE finding_dispositions
    DROP CONSTRAINT finding_dispositions_status_check;

ALTER TABLE finding_dispositions
    ADD CONSTRAINT finding_dispositions_finding_kind_check
        CHECK (finding_kind IN ('cis', 'cve', 'software')),
    ADD CONSTRAINT finding_dispositions_status_check
        CHECK (status IN (
            'acknowledged', 'risk_accepted', 'closed',
            'guidance_issued', 'customer_applied', 'pending_verification'
        )),
    ADD CONSTRAINT finding_dispositions_kind_shape CHECK (
        (finding_kind = 'cis'
            AND device_id IS NOT NULL AND rule_key IS NOT NULL
            AND cve_id IS NULL AND software_key IS NULL) OR
        (finding_kind = 'cve'
            AND device_id IS NULL AND rule_key IS NULL
            AND cve_id IS NOT NULL AND software_key IS NULL) OR
        (finding_kind = 'software'
            AND device_id IS NOT NULL AND rule_key IS NULL
            AND cve_id IS NULL AND software_key IS NOT NULL)
    );

-- 0146's mutation guard predates software_key. Replace it so the new identity
-- column is just as immutable as the original CIS/CVE identity columns.
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
        OR NEW.software_key IS DISTINCT FROM OLD.software_key
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

CREATE INDEX idx_finding_dispositions_active_software
    ON finding_dispositions (tenant_id, device_id, software_key)
    WHERE superseded_at IS NULL AND finding_kind = 'software';
CREATE UNIQUE INDEX uq_finding_dispositions_active_software
    ON finding_dispositions (tenant_id, device_id, software_key)
    WHERE superseded_at IS NULL AND finding_kind = 'software';

CREATE TABLE finding_lifecycle_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_kind    TEXT NOT NULL CHECK (finding_kind IN ('cis', 'cve', 'software')),
    device_id       UUID,
    finding_key     TEXT NOT NULL CHECK (btrim(finding_key) <> ''),
    event_type      TEXT NOT NULL CHECK (event_type IN (
        'first_observed', 'currently_observed', 'acknowledged',
        'risk_accepted', 'guidance_issued', 'customer_applied',
        'pending_verification', 'verification_unknown', 'verified_fixed',
        'still_failing', 'recurred'
    )),
    source_type     TEXT NOT NULL CHECK (source_type IN (
        'endpoint_observation', 'operator_action', 'migration'
    )),
    actor           TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    observed_at     TIMESTAMPTZ,
    authoritative   BOOLEAN NOT NULL DEFAULT false,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id)
        REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT finding_lifecycle_identity_shape CHECK (
        (finding_kind = 'cve' AND device_id IS NULL) OR
        (finding_kind IN ('cis', 'software') AND device_id IS NOT NULL)
    ),
    CONSTRAINT finding_lifecycle_source_shape CHECK (
        (source_type = 'endpoint_observation'
            AND event_type IN (
                'first_observed', 'currently_observed', 'verification_unknown',
                'verified_fixed', 'still_failing', 'recurred'
            )
            AND observed_at IS NOT NULL) OR
        (source_type IN ('operator_action', 'migration')
            AND event_type IN (
                'acknowledged', 'risk_accepted', 'guidance_issued',
                'customer_applied', 'pending_verification'
            ))
    ),
    CONSTRAINT finding_lifecycle_authority_shape CHECK (
        authoritative = (source_type = 'endpoint_observation'
            AND event_type <> 'verification_unknown')
    )
);

CREATE INDEX idx_finding_lifecycle_identity
    ON finding_lifecycle_events
        (tenant_id, finding_kind, device_id, finding_key, id);
CREATE INDEX idx_finding_lifecycle_tenant_recorded
    ON finding_lifecycle_events (tenant_id, recorded_at DESC, id DESC);

GRANT SELECT, INSERT ON TABLE finding_lifecycle_events TO patched;
GRANT USAGE, SELECT ON SEQUENCE finding_lifecycle_events_id_seq TO patched;

CREATE FUNCTION reject_finding_lifecycle_event_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'finding_lifecycle_events is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_lifecycle_events_append_only
    BEFORE UPDATE OR DELETE ON finding_lifecycle_events
    FOR EACH ROW EXECUTE FUNCTION reject_finding_lifecycle_event_mutation();

CREATE FUNCTION reject_finding_lifecycle_events_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'finding_lifecycle_events is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_finding_lifecycle_events_append_only_truncate
    BEFORE TRUNCATE ON finding_lifecycle_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_finding_lifecycle_events_truncate();

-- Seed reconstructible current endpoint observations before importing human
-- actions, so the latest projection remains the later action while true
-- first-seen evidence survives the migration.
WITH latest AS (
    SELECT DISTINCT ON (ce.device_id, ce.rule_id)
        ce.device_id, ce.rule_id, ce.status, ce.observed_value
    FROM compliance_evaluations ce
    ORDER BY ce.device_id, ce.rule_id, ce.evaluated_at DESC
), current_failures AS (
    SELECT d.tenant_id, l.device_id, l.rule_id, cr.rule_key,
           MIN(ce.evaluated_at) FILTER (
               WHERE ce.status IN ('error', 'fail') AND ce.observed_value IS NOT NULL
           ) AS first_observed_at
    FROM latest l
    JOIN devices d ON d.id = l.device_id
    JOIN compliance_rules cr ON cr.id = l.rule_id
    JOIN compliance_evaluations ce
      ON ce.device_id = l.device_id AND ce.rule_id = l.rule_id
    WHERE l.status IN ('error', 'fail') AND l.observed_value IS NOT NULL
    GROUP BY d.tenant_id, l.device_id, l.rule_id, cr.rule_key
)
INSERT INTO finding_lifecycle_events (
    tenant_id, finding_kind, device_id, finding_key, event_type,
    source_type, actor, reason, observed_at, authoritative, evidence
)
SELECT tenant_id, 'cis', device_id, rule_key, 'first_observed',
       'endpoint_observation', 'endpoint',
       'backfilled from append-only compliance evaluation evidence',
       first_observed_at, true,
       jsonb_build_object('migration', '0156', 'rule_id', rule_id)
FROM current_failures
WHERE first_observed_at IS NOT NULL;

WITH affected AS (
    SELECT d.tenant_id, f.cve_id, f.device_id, f.app_name, f.app_version,
           f.match_confidence, f.fixed_version,
           MIN(f.first_seen_at) AS first_seen_at,
           CASE
		     WHEN f.app_name IN ('macOS', 'Windows') THEN 'os'
             WHEN lower(d.os) LIKE 'windows%'
              AND bool_and(COALESCE(da.identifier_kind, '') = 'winget')
               THEN 'windows_winget'
             WHEN lower(d.os) LIKE 'windows%' THEN 'unsupported'
             ELSE 'all_software'
           END AS required_scope
    FROM device_cve_findings f
    JOIN devices d ON d.id = f.device_id
    LEFT JOIN device_apps da
      ON da.device_id = f.device_id AND lower(da.name) = lower(f.app_name)
    GROUP BY d.tenant_id, f.cve_id, f.device_id, d.os, f.app_name,
             f.app_version, f.match_confidence, f.fixed_version
), current_cves AS (
    SELECT tenant_id, cve_id, MIN(first_seen_at) AS first_seen_at,
           jsonb_agg(jsonb_build_object(
               'device_id', device_id,
               'required_scope', required_scope,
               'app_name', app_name,
               'app_version', app_version,
               'match_confidence', match_confidence,
               'fixed_version', fixed_version
           ) ORDER BY device_id, app_name) AS affected_devices
    FROM affected
    GROUP BY tenant_id, cve_id
)
INSERT INTO finding_lifecycle_events (
    tenant_id, finding_kind, device_id, finding_key, event_type,
    source_type, actor, reason, observed_at, authoritative, evidence
)
SELECT tenant_id, 'cve', NULL, cve_id, 'first_observed',
       'endpoint_observation', 'endpoint',
       'backfilled from current CVE match evidence',
       first_seen_at, true,
       jsonb_build_object('migration', '0156', 'affected_devices', affected_devices)
FROM current_cves
WHERE first_seen_at IS NOT NULL;

-- Preserve every PAT-1829 decision.  A legacy human "closed" assertion is
-- intentionally backfilled as pending_verification, not verified_fixed.
INSERT INTO finding_lifecycle_events (
    tenant_id, finding_kind, device_id, finding_key, event_type,
    source_type, actor, reason, authoritative, evidence, recorded_at
)
SELECT
    fd.tenant_id,
    fd.finding_kind,
    fd.device_id,
    CASE fd.finding_kind WHEN 'cis' THEN fd.rule_key ELSE fd.cve_id END,
    CASE fd.status WHEN 'closed' THEN 'pending_verification' ELSE fd.status END,
    'migration',
    fd.recorded_by,
    fd.reason,
    false,
    jsonb_build_object(
        'source_table', 'finding_dispositions',
        'source_id', fd.id,
        'legacy_status', fd.status,
        'superseded_at', fd.superseded_at
    ),
    fd.recorded_at
FROM finding_dispositions fd
WHERE fd.finding_kind IN ('cis', 'cve')
ORDER BY fd.recorded_at, fd.id
ON CONFLICT DO NOTHING;

-- Read model.  Closure evidence is retained even after recurrence: callers
-- get the current state plus first/last observation, last verified closure,
-- recurrence count and all commercial action milestones.  The immutable
-- event endpoint remains the complete audit history.
CREATE VIEW finding_lifecycle_current AS
WITH ranked AS (
    SELECT e.*,
           row_number() OVER (
               PARTITION BY tenant_id, finding_kind, device_id, finding_key
               ORDER BY id DESC
           ) AS latest_rank
    FROM finding_lifecycle_events e
), grouped AS (
    SELECT
        tenant_id, finding_kind, device_id, finding_key,
        MIN(observed_at) FILTER (WHERE event_type = 'first_observed') AS first_observed_at,
        MAX(observed_at) FILTER (WHERE event_type IN (
            'first_observed', 'currently_observed', 'still_failing', 'recurred'
        )) AS currently_observed_at,
        MAX(recorded_at) FILTER (WHERE event_type = 'acknowledged') AS acknowledged_at,
        MAX(recorded_at) FILTER (WHERE event_type = 'risk_accepted') AS risk_accepted_at,
        MAX(recorded_at) FILTER (WHERE event_type = 'guidance_issued') AS guidance_issued_at,
        MAX(recorded_at) FILTER (WHERE event_type = 'customer_applied') AS customer_applied_at,
        MAX(recorded_at) FILTER (WHERE event_type = 'pending_verification') AS pending_verification_at,
        MAX(observed_at) FILTER (WHERE event_type = 'verified_fixed') AS verified_fixed_at,
        MAX(observed_at) FILTER (WHERE event_type = 'still_failing') AS still_failing_at,
        MAX(recorded_at) FILTER (WHERE event_type = 'verification_unknown') AS verification_unknown_at,
        MAX(observed_at) FILTER (WHERE event_type = 'recurred') AS recurred_at,
        COUNT(*) FILTER (WHERE event_type = 'recurred')::int AS recurrence_count,
        COUNT(*)::int AS event_count
    FROM finding_lifecycle_events
    GROUP BY tenant_id, finding_kind, device_id, finding_key
)
SELECT
    g.*,
    r.event_type AS status,
    r.recorded_at AS status_recorded_at,
    r.observed_at AS status_observed_at,
    r.authoritative AS status_authoritative
FROM grouped g
JOIN ranked r
  ON r.tenant_id = g.tenant_id
 AND r.finding_kind = g.finding_kind
 AND r.device_id IS NOT DISTINCT FROM g.device_id
 AND r.finding_key = g.finding_key
 AND r.latest_rank = 1;

GRANT SELECT ON finding_lifecycle_current TO patched;

COMMENT ON TABLE finding_lifecycle_events IS
    'PAT-1878 immutable lifecycle ledger. Operator actions can request verification; only authoritative endpoint_observation events can record verified_fixed, still_failing or recurrence.';
COMMENT ON VIEW finding_lifecycle_current IS
    'PAT-1878 current finding state with retained closure and recurrence milestones. Complete history remains in finding_lifecycle_events.';

INSERT INTO schema_migrations (version) VALUES ('0156_finding_verification_lifecycle')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
