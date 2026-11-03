-- patched.im — 0130_macos_2_10_1_screensaver_inactivity_rollback.sql
-- Reverses 0130_macos_2_10_1_screensaver_inactivity.sql (PAT-1753).
--
-- Fails closed if the new rule has already accumulated compliance_evaluations:
-- deleting it would orphan those evaluation rows' rule_id foreign key and
-- silently drop them out of every report/PDF join that assumes the referenced
-- rule still exists. Roll back only before the new rule has ever evaluated a
-- device, or delete the dependent compliance_evaluations rows first as a
-- deliberate, separate decision.
BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM compliance_evaluations e
        JOIN compliance_rules r ON r.id = e.rule_id
        WHERE r.rule_key = 'cis_macos_2_10_1_screensaver_inactivity'
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0130: compliance_evaluations reference cis_macos_2_10_1_screensaver_inactivity';
    END IF;
END;
$$;

DELETE FROM compliance_rules
WHERE rule_key = 'cis_macos_2_10_1_screensaver_inactivity'
  AND benchmark = 'CIS Apple macOS'
  AND benchmark_version = 'v3.0.0';

DELETE FROM schema_migrations WHERE version = '0130_macos_2_10_1_screensaver_inactivity';

COMMIT;
