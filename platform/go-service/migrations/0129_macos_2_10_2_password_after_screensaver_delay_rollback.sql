-- patched.im — 0129_macos_2_10_2_password_after_screensaver_delay_rollback.sql
-- Reverses 0129_macos_2_10_2_password_after_screensaver_delay.sql (PAT-1746).
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
        WHERE r.rule_key = 'cis_macos_2_10_2_password_after_screensaver_delay'
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0129: compliance_evaluations reference cis_macos_2_10_2_password_after_screensaver_delay';
    END IF;
END;
$$;

DELETE FROM compliance_rules
WHERE rule_key = 'cis_macos_2_10_2_password_after_screensaver_delay'
  AND benchmark = 'CIS Apple macOS'
  AND benchmark_version = 'v3.0.0';

UPDATE compliance_rules
SET enabled = true
WHERE rule_key = 'cis_macos_2_10_1_screensaver_timeout'
  AND benchmark = 'CIS Apple macOS'
  AND benchmark_version = 'v2.1.0';

DELETE FROM schema_migrations WHERE version = '0129_macos_2_10_2_password_after_screensaver_delay';

COMMIT;
