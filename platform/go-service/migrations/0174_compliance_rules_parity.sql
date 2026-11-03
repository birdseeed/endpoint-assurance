-- 0174: Backfill the four PAT-300/PAT-481 findings-based compliance rules
-- that migration 0033 defines but patched-api-01 never received (PAT-2059).
--
-- 0033_compliance_findings_rules.sql sits below MIGRATION_FLOOR=56
-- (deploy/api-01/deploy.sh) and was never recorded as applied on
-- patched-api-01, so `compliance_rules` on that box is missing:
--   patched_macos_disk_encryption_off
--   patched_win_disk_encryption_off
--   patched_macos_removable_storage_unencrypted
--   patched_win_removable_storage_unencrypted
-- A device reporting FileVault or BitLocker disabled, or unencrypted
-- removable storage, never gets a finding on that box: the rule its signal
-- would evaluate against simply does not exist.
--
-- 0083_critical_findings_fail_unknown.sql *is* recorded as applied on prod:
-- it is a plain UPDATE with no INSERT, so it ran cleanly, matched zero rows
-- (nothing to update, since 0033 never seeded them) and its bookkeeping
-- INSERT into schema_migrations succeeded regardless. This migration will
-- not cause 0083 to run again. It therefore seeds the four rows with
-- treat_unknown_as = 'fail' directly -- the end state 0033 followed by 0083
-- produces on every database that ran both -- rather than 'pass' as 0033
-- alone would leave them, so this backfill never reintroduces the fail-open
-- gap PAT-913 closed.
--
-- Every column is named explicitly; none is left to a schema default. Per
-- PAT-2051/PAT-2053, prod's compliance_rules.platform still carries 0019's
-- un-dropped DEFAULT 'macos', so relying on defaults here risks silently
-- seeding a Windows row as macos if a value were ever left out.
--
-- Idempotent on (benchmark, benchmark_version, rule_key) -- the table's
-- existing UNIQUE constraint from 0003. A database where 0033 already ran
-- (every CI, test and fresh-install database) inserts nothing here. Each
-- inserted row's `description` carries a trailing marker so the rollback can
-- tell a row this migration inserted apart from a pre-existing 0033 row with
-- the same rule_key; compliance_rules has no dedicated provenance/notes
-- column, so this reuses the same description-marker pattern 0169 used on
-- app_cpe_mappings.notes for the identical problem.

BEGIN;

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version, title, description, severity,
    signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent, platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings,
    enabled, device_class, control_identifier, treat_not_configured_as
) VALUES
(
    'patched_macos_disk_encryption_off',
    'patched.im baseline', 'v1',
    'Full-disk encryption enabled (macOS)',
    'Disk encryption protects data at rest. Finding reported by the agent when FileVault is disabled or not fully encrypted. [PAT-2059/0174 backfill]',
    'critical',
    'disk_encryption_off', 'eq', ARRAY['Pass'], NULL, 'fail',
    'T1', 'none', false, 'macos',
    ARRAY['SC-28', 'SC-28(1)'], ARRAY['A.8.24', 'A.10.1.1'], ARRAY['secure-configuration'],
    true, NULL, NULL, NULL
),
(
    'patched_win_disk_encryption_off',
    'patched.im baseline', 'v1',
    'Full-disk encryption enabled (Windows)',
    'BitLocker full-disk encryption protects data at rest. Finding reported by the agent when the OS drive is unencrypted. [PAT-2059/0174 backfill]',
    'critical',
    'disk_encryption_off', 'eq', ARRAY['Pass'], NULL, 'fail',
    'T1', 'none', false, 'windows',
    ARRAY['SC-28', 'SC-28(1)'], ARRAY['A.8.24', 'A.10.1.1'], ARRAY['secure-configuration'],
    true, NULL, NULL, NULL
),
(
    'patched_macos_removable_storage_unencrypted',
    'patched.im baseline', 'v1',
    'Unencrypted removable storage detected (macOS)',
    'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed. [PAT-2059/0174 backfill]',
    'medium',
    'removable_storage_unencrypted', 'eq', ARRAY['Pass'], NULL, 'fail',
    'T1', 'none', false, 'macos',
    NULL, NULL, NULL,
    true, NULL, NULL, NULL
),
(
    'patched_win_removable_storage_unencrypted',
    'patched.im baseline', 'v1',
    'Unencrypted removable storage detected (Windows)',
    'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed. [PAT-2059/0174 backfill]',
    'medium',
    'removable_storage_unencrypted', 'eq', ARRAY['Pass'], NULL, 'fail',
    'T1', 'none', false, 'windows',
    NULL, NULL, NULL,
    true, NULL, NULL, NULL
)
ON CONFLICT (benchmark, benchmark_version, rule_key) DO NOTHING;

INSERT INTO schema_migrations (version) VALUES ('0174_compliance_rules_parity')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
