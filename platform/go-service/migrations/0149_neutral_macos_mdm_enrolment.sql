-- patched.im — 0149_neutral_macos_mdm_enrolment.sql
-- PAT-1752: move the macOS baseline MDM rule onto the same neutral
-- mdm_enrolled = Yes|No|Unknown contract as Windows.
--
-- The Go evaluator temporarily converts the legacy macOS mdm_enrolment value
-- only when the new key is absent. That compatibility path is deliberately
-- bounded to this exact macOS rule and has an explicit removal seam after one
-- updater release. Unknown or missing evidence continues to fail closed.

BEGIN;

UPDATE compliance_rules
SET signal_key = 'mdm_enrolled',
    comparator = 'eq',
    expected_values = ARRAY['Yes']
WHERE rule_key = 'patched_mdm_enrolment'
  AND platform = 'macos'
  AND signal_key = 'mdm_enrolment'
  AND comparator = 'contains'
  AND expected_values = ARRAY['mdm=Yes']
  AND treat_unknown_as = 'fail';

INSERT INTO schema_migrations (version) VALUES ('0149_neutral_macos_mdm_enrolment')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
