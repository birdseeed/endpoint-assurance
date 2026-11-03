-- patched.im — 0141_remediation_artefacts.sql
-- PAT-1549: remediation artefact generation for advisory CIS/config findings.
--
-- Scope: CIS/config-finding remediation only. compliance_rules never carries
-- a CVE row — CVE findings live entirely in device_cve_findings /
-- cve_feed_entries (0025), a table with no rule_id / compliance_rules FK at
-- all. rule_id here is a real FK to compliance_rules, so a CVE finding
-- structurally cannot be the subject of a remediation_artefacts row; there is
-- no separate "rule type" flag to check because the two finding families
-- were never unified into one table.
--
-- Application is observed, never asked (ruling 2, ticket): there is no
-- confirmation workflow and no tenant-write path from this table. A row only
-- ever starts 'issued' and is flipped to 'applied' by the extractor pipeline
-- when a later posture ingestion shows the same (device, rule) now passing —
-- see internal/extractor/upsert.go markArtefactsApplied. Where no later
-- ingest ever shows a pass, the row simply stays 'issued' forever — absence
-- of a later pass is never treated as evidence of application.
--
-- Provenance (ticket "Artefact provenance (settled)"): id, rule_pack_version,
-- the (rule, device) finding it answers, observed_prior_value captured at
-- generation time, generated_at, content_hash. Same immutability shape as an
-- issued report — a regenerated artefact is a NEW row with supersedes_id
-- pointing at the old one, never an UPDATE of payload/content_hash on an
-- existing row. observed_prior_value is captured now for PAT-1665 (a future
-- rollback-artefact generator) to consume later; nothing reads it yet.
--
-- Scope column: device_id, NOT NULL. compliance_evaluations (0003) has no
-- tenant-wide finding shape — device_id is NOT NULL there and every rule is
-- evaluated per device — so there is no "tenant-wide" scope to support here;
-- following that existing shape rather than inventing one.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0141_remediation_artefacts.sql

BEGIN;

CREATE TABLE remediation_artefacts (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id             UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id               UUID        NOT NULL REFERENCES compliance_rules(id),
    platform              TEXT        NOT NULL CHECK (platform IN ('macos', 'windows')),
    rule_pack_version     TEXT        NOT NULL,
    -- observed_value read at generation time from the most recent FAILING
    -- compliance_evaluations row for (device_id, rule_id) — nullable only
    -- because compliance_evaluations.observed_value itself is nullable (an
    -- unreadable signal has no observed value; see evaluator.go).
    observed_prior_value  TEXT,
    -- The generated artefact body: a plist-XML .mobileconfig document for
    -- macOS, or an Intune settings-catalogue JSON payload for Windows.
    -- Stored as the exact bytes content_hash is computed over.
    payload               TEXT        NOT NULL,
    content_hash          TEXT        NOT NULL,          -- sha256 hex of payload
    generated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    generated_by          TEXT        NOT NULL DEFAULT '',
    status                TEXT        NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'applied')),
    applied_observed_at   TIMESTAMPTZ,
    supersedes_id         UUID        REFERENCES remediation_artefacts(id)
);

CREATE INDEX idx_remediation_artefacts_tenant ON remediation_artefacts (tenant_id, generated_at DESC);
CREATE INDEX idx_remediation_artefacts_device ON remediation_artefacts (device_id, generated_at DESC);
-- The auto-apply-detection hook (extractor) looks up issued artefacts for a
-- (device, rule) pair on every ingest that produces a passing evaluation —
-- this is that lookup's index.
CREATE INDEX idx_remediation_artefacts_apply_lookup
    ON remediation_artefacts (device_id, rule_id)
    WHERE status = 'issued';

-- Two concurrent regenerations for the same (device, rule) could otherwise
-- both read the same "current" artefact as their supersedes target and both
-- insert, forking the supersession chain (markArtefactsApplied's NOT EXISTS
-- check would then never mark one branch applied). This constraint makes a
-- fork a unique-violation at INSERT time instead of a silent possibility —
-- the handler catches 23505 and returns 409 for the loser to retry.
CREATE UNIQUE INDEX idx_remediation_artefacts_supersedes_unique
    ON remediation_artefacts (supersedes_id)
    WHERE supersedes_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON TABLE remediation_artefacts TO patched;

COMMENT ON TABLE remediation_artefacts IS
    'PAT-1549: generated per-platform remediation artefacts (signed .mobileconfig / Intune settings-catalogue JSON) for advisory CIS/config findings. Immutable once issued except for the applied/applied_observed_at transition written by the extractor''s auto-detection hook; a regeneration is a new row with supersedes_id set, never an edit.';
COMMENT ON COLUMN remediation_artefacts.observed_prior_value IS
    'Captured at generation time for PAT-1665 (future rollback-artefact generation) to consume. Not read by anything in this migration''s scope.';
COMMENT ON COLUMN remediation_artefacts.status IS
    'issued = generated, not yet observed applied. applied = a later posture ingestion showed the rule passing for this device while this artefact was still the latest issued one for it. Never set by a tenant-facing endpoint — see internal/extractor/upsert.go.';

INSERT INTO schema_migrations (version) VALUES ('0141_remediation_artefacts')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
