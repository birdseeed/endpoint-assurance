-- Reverses 0149_neutral_macos_mdm_enrolment.sql. The rule row is derived
-- configuration and carries no unrecoverable evidence.

BEGIN;

UPDATE compliance_rules
SET signal_key = 'mdm_enrolment',
    comparator = 'contains',
    expected_values = ARRAY['mdm=Yes']
WHERE rule_key = 'patched_mdm_enrolment'
  AND platform = 'macos'
  AND signal_key = 'mdm_enrolled'
  AND comparator = 'eq'
  AND expected_values = ARRAY['Yes']
  AND treat_unknown_as = 'fail';

DELETE FROM schema_migrations WHERE version = '0149_neutral_macos_mdm_enrolment';

COMMIT;
