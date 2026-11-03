-- 0210: tenant-safe AI tooling portal, evidence and notification contract (PAT-2205).
BEGIN;

-- A vulnerability assessment can inherit identity/version from another
-- current row (notably MCP -> exact package). The opaque entry hashes are the
-- stable, local join back to every current row whose evidence it assesses.
ALTER TABLE tooling_vulnerability_assessments
    ADD COLUMN current_entry_keys TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE tooling_vulnerability_assessments
    ADD CONSTRAINT tooling_vulnerability_assessments_current_entry_keys_check
    CHECK (array_position(current_entry_keys, NULL) IS NULL
       AND (cardinality(current_entry_keys) = 0
            OR array_to_string(current_entry_keys, ',') ~ '^([0-9a-f]{64})(,[0-9a-f]{64})*$')) NOT VALID;

UPDATE tooling_vulnerability_assessments a
SET current_entry_keys = x.keys
FROM (
    SELECT a2.id, array_agg(DISTINCT c.entry_key ORDER BY c.entry_key) AS keys
    FROM tooling_vulnerability_assessments a2
    JOIN tooling_current_entries c
      ON c.tenant_id = a2.tenant_id AND c.device_id = a2.device_id
    JOIN software_observations so
      ON so.id = c.observation_id AND so.tenant_id = c.tenant_id
    JOIN tooling_observation_details d
      ON d.observation_id = c.observation_id AND d.tenant_id = c.tenant_id
    WHERE EXISTS (
        SELECT 1 FROM jsonb_array_elements(a2.observations) o
        WHERE o->>'Block' = c.block AND o->>'Unit' = c.unit AND o->>'Kind' = c.entry_kind
    )
      AND (
        (a2.subject_kind = 'package'
         AND a2.identity_value = so.identity_value_normalized
         AND a2.version = COALESCE(NULLIF(d.attributes->>'version',''), NULLIF(so.observed_version,''), 'unknown'))
        OR (a2.subject_kind = 'mcp_server'
            AND so.identity_kind = 'mcp_server'
            AND a2.identity_value = so.identity_value_normalized)
        OR (a2.subject_kind = 'ide_extension' AND so.identity_kind = 'ide_extension'
            AND a2.identity_value = so.identity_value_normalized)
        OR (a2.subject_kind = 'local_runtime' AND so.identity_kind = 'local_model_runtime'
            AND a2.identity_value = so.identity_value_normalized)
      )
    GROUP BY a2.id
) x
WHERE x.id = a.id;
ALTER TABLE tooling_vulnerability_assessments
    VALIDATE CONSTRAINT tooling_vulnerability_assessments_current_entry_keys_check;

-- Extend 0209's existing row-trigger work instead of adding another row
-- trigger or a 27,000-row transition-table join. Its direct pending
-- assessment INSERT already has the exact NEW row, so it can attach the key
-- at constant additional cost. The scheduled matcher replaces the complete
-- key set and remains authoritative for unresolved MCP and inherited
-- MCP-to-package evidence.
CREATE OR REPLACE FUNCTION tooling_vulnerability_enqueue_device() RETURNS trigger AS $$
DECLARE d UUID; t UUID;
BEGIN
    d := COALESCE(NEW.device_id, OLD.device_id);
    t := COALESCE(NEW.tenant_id, OLD.tenant_id);
    INSERT INTO tooling_vulnerability_refresh_queue(device_id, tenant_id, requested_at)
    VALUES (d, t, now())
    ON CONFLICT (device_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, requested_at=EXCLUDED.requested_at;
    IF TG_TABLE_NAME = 'tooling_current_entries' AND TG_OP <> 'DELETE' THEN
        INSERT INTO tooling_vulnerability_assessments
            (tenant_id,device_id,subject_kind,ecosystem,package_name,identity_value,companion,version,
             state,reason,observations,current_entry_keys,input_observed_at)
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
               ARRAY[NEW.entry_key],NEW.observed_at
        FROM software_observations so
        JOIN tooling_observation_details d ON d.observation_id=so.id AND d.tenant_id=so.tenant_id
        LEFT JOIN software_installations si ON si.device_id=NEW.device_id
          AND si.tenant_id=NEW.tenant_id AND si.identity_fingerprint=so.identity_fingerprint AND si.removed_at IS NULL
        WHERE so.id=NEW.observation_id AND so.tenant_id=NEW.tenant_id
          AND so.identity_kind IN ('npm_package','pip_package','ide_extension','local_model_runtime')
        ON CONFLICT(device_id,subject_kind,identity_value,companion,version) DO UPDATE SET
          active=true, observations=EXCLUDED.observations,
          current_entry_keys=(SELECT array_agg(DISTINCT k ORDER BY k)
                              FROM unnest(tooling_vulnerability_assessments.current_entry_keys ||
                                          EXCLUDED.current_entry_keys) k),
          input_observed_at=GREATEST(tooling_vulnerability_assessments.input_observed_at,EXCLUDED.input_observed_at),
          updated_at=now();
    END IF;
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

CREATE FUNCTION tooling_vulnerability_unlink_current_entries() RETURNS trigger AS $$
BEGIN
    WITH gone AS MATERIALIZED (
        SELECT DISTINCT o.tenant_id,o.device_id,o.entry_key
        FROM unlinked_entries o
        WHERE NOT EXISTS (
            SELECT 1 FROM tooling_current_entries c
            WHERE c.tenant_id=o.tenant_id AND c.device_id=o.device_id
              AND c.entry_key=o.entry_key
        )
    )
    UPDATE tooling_vulnerability_assessments a
       SET current_entry_keys=ARRAY(
               SELECT k FROM unnest(a.current_entry_keys) k
               WHERE NOT EXISTS (
                   SELECT 1 FROM gone g
                   WHERE g.tenant_id=a.tenant_id AND g.device_id=a.device_id AND g.entry_key=k
               ) ORDER BY k),
           updated_at=now()
     WHERE EXISTS (
         SELECT 1 FROM gone g
         WHERE g.tenant_id=a.tenant_id AND g.device_id=a.device_id
           AND g.entry_key=ANY(a.current_entry_keys)
     );
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER zzz_trg_tooling_vulnerability_unlink_current_entries_update
    AFTER UPDATE ON tooling_current_entries
    REFERENCING OLD TABLE AS unlinked_entries
    FOR EACH STATEMENT EXECUTE FUNCTION tooling_vulnerability_unlink_current_entries();
CREATE TRIGGER zzz_trg_tooling_vulnerability_unlink_current_entries_delete
    AFTER DELETE ON tooling_current_entries
    REFERENCING OLD TABLE AS unlinked_entries
    FOR EACH STATEMENT EXECUTE FUNCTION tooling_vulnerability_unlink_current_entries();

-- Independent, opt-in AI first-seen delivery. Cursor-only runner writes do
-- not alter preference audit attribution.
ALTER TABLE tenant_software_notification_settings
    ADD COLUMN ai_tooling_notifications_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN ai_tooling_notified_through TIMESTAMPTZ;

CREATE TABLE ai_tooling_notification_changes (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    old_enabled BOOLEAN NOT NULL,
    new_enabled BOOLEAN NOT NULL,
    changed_by  TEXT NOT NULL CHECK (btrim(changed_by) <> '' AND length(changed_by) <= 320),
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (old_enabled <> new_enabled)
);
CREATE INDEX ai_tooling_notification_changes_tenant_idx
    ON ai_tooling_notification_changes(tenant_id, changed_at DESC, id DESC);

CREATE FUNCTION reject_ai_tooling_notification_change_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ai_tooling_notification_changes is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_ai_tooling_notification_changes_append_only
    BEFORE UPDATE OR DELETE ON ai_tooling_notification_changes
    FOR EACH ROW EXECUTE FUNCTION reject_ai_tooling_notification_change_mutation();
CREATE TRIGGER trg_ai_tooling_notification_changes_no_truncate
    BEFORE TRUNCATE ON ai_tooling_notification_changes
    FOR EACH STATEMENT EXECUTE FUNCTION reject_ai_tooling_notification_change_mutation();

ALTER TABLE report_records DROP CONSTRAINT IF EXISTS report_records_report_type_valid;
ALTER TABLE report_records ADD CONSTRAINT report_records_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'software-inventory','app-policy-drift','browser-extensions','edr-coverage','device-health',
    'encryption-posture','local-admin','device-compliance','new-software','software-drift',
    'approved-software','ai-tooling-evidence'
));
ALTER TABLE portal_report_schedules DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'edr-coverage','encryption-posture','local-admin','new-software','software-drift','approved-software',
    'ai-tooling-evidence'
));

GRANT SELECT, INSERT ON ai_tooling_notification_changes TO patched;
GRANT USAGE, SELECT ON SEQUENCE ai_tooling_notification_changes_id_seq TO patched;

INSERT INTO schema_migrations(version) VALUES ('0210_ai_tooling_portal_contract')
ON CONFLICT(version) DO NOTHING;
COMMIT;
