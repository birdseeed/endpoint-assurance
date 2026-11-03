-- Roll back PAT-1858 control identifiers and restore the three historical
-- benchmark labels. The identifiers are reproducible migration-owned metadata.

BEGIN;

UPDATE compliance_rules
SET benchmark = 'CIS Apple macOS',
    benchmark_version = 'v3.0.0'
WHERE benchmark = 'patched.im baseline'
  AND benchmark_version = 'v1'
  AND rule_key IN (
      'cis_macos_5_8_local_admin_count',
      'cis_macos_5_x_password_policy_non_default',
      'cis_macos_5_x_secure_boot_arm64'
  );

ALTER TABLE compliance_rules
    DROP COLUMN control_identifier;

DELETE FROM schema_migrations WHERE version = '0152_cis_control_identifiers';

COMMIT;
