-- Roll the API and CVE sync binaries back first. Export the append-only
-- preference audit if it must be retained. Issued evidence reports and
-- schedules are refused because the restored constraints cannot represent them.
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM report_records WHERE report_type='ai-tooling-evidence') THEN
        RAISE EXCEPTION 'cannot roll back 0210 while AI tooling evidence reports exist';
    END IF;
    IF EXISTS (SELECT 1 FROM portal_report_schedules WHERE report_type='ai-tooling-evidence') THEN
        RAISE EXCEPTION 'cannot roll back 0210 while AI tooling evidence schedules exist';
    END IF;
END $$;

ALTER TABLE report_records DROP CONSTRAINT IF EXISTS report_records_report_type_valid;
ALTER TABLE report_records ADD CONSTRAINT report_records_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'software-inventory','app-policy-drift','browser-extensions','edr-coverage','device-health',
    'encryption-posture','local-admin','device-compliance','new-software','software-drift','approved-software'
));
ALTER TABLE portal_report_schedules DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
    'executive-summary','cis-compliance','cve-report','patch-status','stale-endpoints','cert-expiry',
    'edr-coverage','encryption-posture','local-admin','new-software','software-drift','approved-software'
));

DROP TRIGGER IF EXISTS trg_ai_tooling_notification_changes_no_truncate ON ai_tooling_notification_changes;
DROP TRIGGER IF EXISTS trg_ai_tooling_notification_changes_append_only ON ai_tooling_notification_changes;
DROP FUNCTION IF EXISTS reject_ai_tooling_notification_change_mutation();
DROP TABLE IF EXISTS ai_tooling_notification_changes;
ALTER TABLE tenant_software_notification_settings
    DROP COLUMN ai_tooling_notified_through,
    DROP COLUMN ai_tooling_notifications_enabled;
DROP TRIGGER IF EXISTS zzz_trg_tooling_vulnerability_link_current_entry ON tooling_current_entries;
DROP TRIGGER IF EXISTS zzz_trg_tooling_vulnerability_link_current_entries_insert ON tooling_current_entries;
DROP TRIGGER IF EXISTS zzz_trg_tooling_vulnerability_link_current_entries_update ON tooling_current_entries;
DROP TRIGGER IF EXISTS zzz_trg_tooling_vulnerability_unlink_current_entries_update ON tooling_current_entries;
DROP TRIGGER IF EXISTS zzz_trg_tooling_vulnerability_unlink_current_entries_delete ON tooling_current_entries;
DROP FUNCTION IF EXISTS tooling_vulnerability_link_current_entry();
DROP FUNCTION IF EXISTS tooling_vulnerability_link_current_entries();
DROP FUNCTION IF EXISTS tooling_vulnerability_unlink_current_entries();
ALTER TABLE tooling_vulnerability_assessments
    DROP CONSTRAINT tooling_vulnerability_assessments_current_entry_keys_check,
    DROP COLUMN current_entry_keys;

-- Restore 0209's exact trigger function, without the 0210 column.
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

DELETE FROM schema_migrations WHERE version='0210_ai_tooling_portal_contract';
COMMIT;
