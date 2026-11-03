-- 0209: exact vulnerability assessment for AI tooling (PAT-2109).
--
-- OSV advisory identifiers are not CVE identifiers. They therefore live in
-- tooling_advisories with their source and aliases instead of being inserted
-- into cve_feed_entries. NVD-backed IDE/runtime matches use the same
-- assessment/finding seam but retain source='nvd' and a real CVE identifier.
-- Assessment rows are derived from the authority-aware PAT-2021 current-entry
-- projection and can be rebuilt by patched-cve-sync --mode=tooling-sync.
-- Extractor writes only enqueue a local device refresh; no extractor request
-- performs network I/O.
BEGIN;

CREATE TABLE tooling_advisories (
    source          TEXT NOT NULL CHECK (source IN ('osv','nvd')),
    advisory_id     TEXT NOT NULL CHECK (btrim(advisory_id) <> ''),
    canonical_cve_id TEXT CHECK (canonical_cve_id IS NULL OR canonical_cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    summary         TEXT NOT NULL DEFAULT '',
    details         TEXT NOT NULL DEFAULT '',
    severity        TEXT CHECK (severity IS NULL OR severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
    score           NUMERIC(4,1),
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,
    withdrawn_at    TIMESTAMPTZ,
    raw_document    JSONB NOT NULL,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, advisory_id)
);
CREATE INDEX tooling_advisories_modified_idx ON tooling_advisories (modified_at DESC);

CREATE TABLE tooling_advisory_packages (
    source          TEXT NOT NULL,
    advisory_id     TEXT NOT NULL,
    ecosystem       TEXT NOT NULL CHECK (ecosystem IN ('npm','PyPI')),
    package_name    TEXT NOT NULL CHECK (btrim(package_name) <> ''),
    affected_ranges JSONB NOT NULL DEFAULT '[]',
    affected_versions TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (source, advisory_id, ecosystem, package_name),
    FOREIGN KEY (source, advisory_id) REFERENCES tooling_advisories(source, advisory_id) ON DELETE CASCADE
);
CREATE INDEX tooling_advisory_packages_lookup_idx
    ON tooling_advisory_packages (ecosystem, package_name);

CREATE TABLE tooling_vulnerability_mappings (
    id              BIGSERIAL PRIMARY KEY,
    identity_kind   TEXT NOT NULL CHECK (identity_kind IN ('ide_extension','local_model_runtime')),
    identity_value  TEXT NOT NULL CHECK (identity_value = lower(btrim(identity_value)) AND identity_value <> ''),
    companion       TEXT NOT NULL CHECK (companion = lower(btrim(companion)) AND companion <> ''),
    cpe_vendor      TEXT NOT NULL CHECK (btrim(cpe_vendor) <> ''),
    cpe_product     TEXT NOT NULL CHECK (btrim(cpe_product) <> ''),
    review_state    TEXT NOT NULL DEFAULT 'pending' CHECK (review_state IN ('pending','published','rejected')),
    provenance      TEXT NOT NULL CHECK (btrim(provenance) <> ''),
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (identity_kind, identity_value, companion, cpe_vendor, cpe_product),
    CHECK ((review_state = 'published' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)
        OR review_state <> 'published')
);
CREATE INDEX tooling_vulnerability_mappings_lookup_idx
    ON tooling_vulnerability_mappings (identity_kind, identity_value, companion)
    WHERE review_state = 'published';

-- Only reviewed global mappings are seeded. Tenant observations never write
-- this table. LM Studio deliberately has no row because no vetted CPE was
-- established. llama.cpp build-tag versions are rejected by the matcher and
-- remain not_assessed rather than being treated as clean.
INSERT INTO tooling_vulnerability_mappings
    (identity_kind, identity_value, companion, cpe_vendor, cpe_product, review_state, provenance, reviewed_by, reviewed_at)
VALUES
    ('local_model_runtime','ollama','ollama','ollama','ollama','published','PAT-2109 curated NVD CPE review','PAT-2109',now()),
    ('local_model_runtime','llama_cpp','llama_cpp','ggml','llama.cpp','published','PAT-2109 curated NVD CPE review','PAT-2109',now()),
    ('local_model_runtime','llama_cpp','llama_cpp','ggerganov','llama.cpp','published','PAT-2109 curated NVD CPE review','PAT-2109',now());

CREATE TABLE tooling_vulnerability_assessments (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    device_id       UUID NOT NULL,
    subject_kind    TEXT NOT NULL CHECK (subject_kind IN ('package','ide_extension','local_runtime','mcp_server')),
    ecosystem       TEXT CHECK (ecosystem IS NULL OR ecosystem IN ('npm','PyPI')),
    package_name    TEXT,
    identity_value  TEXT NOT NULL CHECK (btrim(identity_value) <> ''),
    companion       TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL CHECK (btrim(version) <> ''),
    state           TEXT NOT NULL CHECK (state IN ('assessed','pending','not_assessed')),
    reason          TEXT,
    finding_count   INT CHECK (finding_count IS NULL OR finding_count >= 0),
    highest_severity TEXT CHECK (highest_severity IS NULL OR highest_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
    observations    JSONB NOT NULL DEFAULT '[]',
    input_observed_at TIMESTAMPTZ NOT NULL,
    assessed_at     TIMESTAMPTZ,
    active          BOOLEAN NOT NULL DEFAULT true,
    last_error      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    UNIQUE (device_id, subject_kind, identity_value, companion, version),
    CHECK ((state = 'assessed' AND finding_count IS NOT NULL AND assessed_at IS NOT NULL)
        OR (state <> 'assessed' AND finding_count IS NULL AND highest_severity IS NULL)),
    CHECK ((subject_kind = 'package' AND ecosystem IS NOT NULL AND package_name IS NOT NULL AND companion = ecosystem)
        OR (subject_kind <> 'package' AND ecosystem IS NULL AND package_name IS NULL))
);
CREATE INDEX tooling_vulnerability_assessments_tenant_idx
    ON tooling_vulnerability_assessments (tenant_id, active, state);
CREATE INDEX tooling_vulnerability_assessments_device_idx
    ON tooling_vulnerability_assessments (device_id, active);

CREATE TABLE tooling_vulnerability_findings (
    assessment_id   BIGINT NOT NULL REFERENCES tooling_vulnerability_assessments(id) ON DELETE CASCADE,
    source          TEXT NOT NULL CHECK (source IN ('osv','nvd')),
    advisory_id     TEXT NOT NULL,
    canonical_cve_id TEXT CHECK (canonical_cve_id IS NULL OR canonical_cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    severity        TEXT CHECK (severity IS NULL OR severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
    score           NUMERIC(4,1),
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (assessment_id, source, advisory_id),
    FOREIGN KEY (source, advisory_id) REFERENCES tooling_advisories(source, advisory_id) ON DELETE RESTRICT
);
CREATE INDEX tooling_vulnerability_findings_advisory_idx
    ON tooling_vulnerability_findings (source, advisory_id);

CREATE TABLE tooling_vulnerability_refresh_queue (
    device_id       UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);

CREATE FUNCTION tooling_vulnerability_enqueue_device() RETURNS trigger AS $$
DECLARE d UUID; t UUID;
BEGIN
    d := COALESCE(NEW.device_id, OLD.device_id);
    t := COALESCE(NEW.tenant_id, OLD.tenant_id);
    INSERT INTO tooling_vulnerability_refresh_queue(device_id, tenant_id, requested_at)
    VALUES (d, t, now())
    ON CONFLICT (device_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, requested_at=EXCLUDED.requested_at;
    -- Create a local-only pending row for a newly observed exact direct
    -- identity/version. An existing assessed row for the same exact version
    -- stays assessed: a repeated unchanged inventory must not cause chronic
    -- false pending between prompt timer runs.
    IF TG_TABLE_NAME = 'tooling_current_entries' AND TG_OP <> 'DELETE' THEN
        INSERT INTO tooling_vulnerability_assessments
            (tenant_id,device_id,subject_kind,ecosystem,package_name,identity_value,companion,version,
             state,reason,observations,input_observed_at)
        SELECT NEW.tenant_id,NEW.device_id,
               CASE WHEN so.identity_kind IN ('npm_package','pip_package') THEN 'package'
                    WHEN so.identity_kind='ide_extension' THEN 'ide_extension'
                    ELSE 'local_runtime' END,
               CASE WHEN so.identity_kind='npm_package' THEN 'npm'
                    WHEN so.identity_kind='pip_package' THEN 'PyPI' END,
               CASE WHEN so.identity_kind IN ('npm_package','pip_package') THEN so.identity_value_normalized END,
               so.identity_value_normalized,
               CASE WHEN so.identity_kind='npm_package' THEN 'npm'
                    WHEN so.identity_kind='pip_package' THEN 'PyPI'
                    ELSE so.companion_value_normalized END,
               COALESCE(NULLIF(d.attributes->>'version',''),NULLIF(si.current_version,''),'unknown'),
               'pending','inventory_changed',
               jsonb_build_array(jsonb_build_object('Block',NEW.block,'Unit',NEW.unit,'Kind',NEW.entry_kind)),
               NEW.observed_at
        FROM software_observations so
        JOIN tooling_observation_details d ON d.observation_id=so.id AND d.tenant_id=so.tenant_id
        LEFT JOIN software_installations si ON si.device_id=NEW.device_id
          AND si.tenant_id=NEW.tenant_id AND si.identity_fingerprint=so.identity_fingerprint AND si.removed_at IS NULL
        WHERE so.id=NEW.observation_id AND so.tenant_id=NEW.tenant_id
          AND so.identity_kind IN ('npm_package','pip_package','ide_extension','local_model_runtime')
        ON CONFLICT(device_id,subject_kind,identity_value,companion,version) DO UPDATE SET
          active=true, observations=EXCLUDED.observations,
          input_observed_at=GREATEST(tooling_vulnerability_assessments.input_observed_at,EXCLUDED.input_observed_at),
          updated_at=now();
    END IF;
    -- Once the authority-aware current projection removes or replaces an
    -- exact observation, retire its derived assessment locally. This closes
    -- the old version immediately without guessing that a newly inserted
    -- version is the only installed version: another current entry for the
    -- old exact version keeps it active.
    IF TG_TABLE_NAME = 'tooling_current_entries' AND TG_OP IN ('UPDATE','DELETE') THEN
        UPDATE tooling_vulnerability_assessments a SET active=false, updated_at=now()
        FROM software_observations old_so
        JOIN tooling_observation_details old_d
          ON old_d.observation_id=old_so.id AND old_d.tenant_id=old_so.tenant_id
        WHERE old_so.id=OLD.observation_id AND old_so.tenant_id=OLD.tenant_id
          AND a.device_id=OLD.device_id AND a.tenant_id=OLD.tenant_id
          AND a.identity_value=old_so.identity_value_normalized
          AND a.version=COALESCE(NULLIF(old_d.attributes->>'version',''),'unknown')
          AND NOT EXISTS (
              SELECT 1 FROM tooling_current_entries still
              JOIN software_observations still_so
                ON still_so.id=still.observation_id AND still_so.tenant_id=still.tenant_id
              JOIN tooling_observation_details still_d
                ON still_d.observation_id=still_so.id AND still_d.tenant_id=still_so.tenant_id
              WHERE still.device_id=OLD.device_id
                AND still_so.identity_value_normalized=old_so.identity_value_normalized
                AND COALESCE(NULLIF(still_d.attributes->>'version',''),'unknown')=
                    COALESCE(NULLIF(old_d.attributes->>'version',''),'unknown'));
    END IF;
    -- A failed read makes retained input pending but never closes it. Partial
    -- and unchanged complete reports do not invalidate an exact successful
    -- advisory assessment.
    IF TG_TABLE_NAME = 'tooling_device_state' AND TG_OP <> 'DELETE'
       AND EXISTS (SELECT 1 FROM tooling_device_state s
                    WHERE s.device_id=d AND s.tenant_id=t AND s.block=NEW.block
                      AND (s.collection_status='failed'
                           OR EXISTS (SELECT 1 FROM jsonb_each_text(s.unit_statuses) x WHERE x.value='failed'))) THEN
        UPDATE tooling_vulnerability_assessments
           SET state='pending', finding_count=NULL, highest_severity=NULL,
               assessed_at=NULL, reason='inventory_unavailable', updated_at=now()
         WHERE device_id=d AND tenant_id=t AND active
           AND EXISTS (
             SELECT 1 FROM jsonb_array_elements(observations) o
             JOIN tooling_device_state s ON s.device_id=d AND s.tenant_id=t AND s.block=NEW.block
             WHERE o->>'Block'=NEW.block
               AND (s.collection_status='failed'
                    OR o->>'Unit' IN (SELECT x.key FROM jsonb_each_text(s.unit_statuses) x WHERE x.value='failed')));
        DELETE FROM tooling_vulnerability_findings f USING tooling_vulnerability_assessments a
         WHERE f.assessment_id=a.id AND a.device_id=d AND a.tenant_id=t AND a.active
           AND a.state='pending' AND a.reason='inventory_unavailable'
           AND EXISTS (
             SELECT 1 FROM jsonb_array_elements(a.observations) o
             JOIN tooling_device_state s ON s.device_id=d AND s.tenant_id=t AND s.block=NEW.block
             WHERE o->>'Block'=NEW.block
               AND (s.collection_status='failed'
                    OR o->>'Unit' IN (SELECT x.key FROM jsonb_each_text(s.unit_statuses) x WHERE x.value='failed')));
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_tooling_vulnerability_current_entry
    AFTER INSERT OR UPDATE OR DELETE ON tooling_current_entries
    FOR EACH ROW EXECUTE FUNCTION tooling_vulnerability_enqueue_device();
CREATE TRIGGER trg_tooling_vulnerability_device_state
    AFTER INSERT OR DELETE OR UPDATE OF collection_status, truncated, unit_statuses, authority
    ON tooling_device_state FOR EACH ROW EXECUTE FUNCTION tooling_vulnerability_enqueue_device();

COMMENT ON TABLE tooling_advisories IS 'PAT-2109 authoritative OSV/NVD tooling advisory records. Source IDs are never relabelled as CVEs.';
COMMENT ON TABLE tooling_vulnerability_assessments IS 'PAT-2109 exact current identity and version assessment. Null counts outside assessed are enforced.';
COMMENT ON TABLE tooling_vulnerability_mappings IS 'PAT-2109 globally curated exact IDE/runtime to CPE mappings. Tenant observations cannot publish mappings.';

GRANT SELECT, INSERT, UPDATE, DELETE ON tooling_advisories, tooling_advisory_packages,
    tooling_vulnerability_assessments, tooling_vulnerability_findings,
    tooling_vulnerability_refresh_queue TO patched;
GRANT SELECT, INSERT, UPDATE ON tooling_vulnerability_mappings TO patched;
GRANT USAGE, SELECT ON SEQUENCE tooling_vulnerability_assessments_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE tooling_vulnerability_mappings_id_seq TO patched;

INSERT INTO schema_migrations(version) VALUES ('0209_tooling_vulnerabilities')
ON CONFLICT (version) DO NOTHING;
COMMIT;
