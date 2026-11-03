-- patched.im — 0033_compliance_findings_rules.sql
-- Adds rule definitions for agent-reported compliance findings (PAT-300, PAT-481).
-- These rules use the 'eq' comparator against an expected 'Pass' value, with
-- 'pass' as the unknown state — since the agent only emits these finding keys
-- when a violation is detected.

BEGIN;

-- PAT-300: disk_encryption_off (macOS)
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version, title, description, severity,
    signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent, platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES (
    'patched_macos_disk_encryption_off',
    'patched.im baseline', 'v1',
    'Full-disk encryption enabled (macOS)',
    'Disk encryption protects data at rest. Finding reported by the agent when FileVault is disabled or not fully encrypted.',
    'critical',
    'disk_encryption_off', 'eq', ARRAY['Pass'], NULL, 'pass',
    'T1', 'none', false, 'macos',
    ARRAY['SC-28', 'SC-28(1)'], ARRAY['A.8.24', 'A.10.1.1'], ARRAY['secure-configuration']
);

-- PAT-300: disk_encryption_off (Windows)
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version, title, description, severity,
    signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent, platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES (
    'patched_win_disk_encryption_off',
    'patched.im baseline', 'v1',
    'Full-disk encryption enabled (Windows)',
    'BitLocker full-disk encryption protects data at rest. Finding reported by the agent when the OS drive is unencrypted.',
    'critical',
    'disk_encryption_off', 'eq', ARRAY['Pass'], NULL, 'pass',
    'T1', 'none', false, 'windows',
    ARRAY['SC-28', 'SC-28(1)'], ARRAY['A.8.24', 'A.10.1.1'], ARRAY['secure-configuration']
);

-- PAT-481: removable_storage_unencrypted (macOS)
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version, title, description, severity,
    signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent, platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES (
    'patched_macos_removable_storage_unencrypted',
    'patched.im baseline', 'v1',
    'Unencrypted removable storage detected (macOS)',
    'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed.',
    'medium',
    'removable_storage_unencrypted', 'eq', ARRAY['Pass'], NULL, 'pass',
    'T1', 'none', false, 'macos',
    NULL, NULL, NULL
);

-- PAT-481: removable_storage_unencrypted (Windows)
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version, title, description, severity,
    signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent, platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES (
    'patched_win_removable_storage_unencrypted',
    'patched.im baseline', 'v1',
    'Unencrypted removable storage detected (Windows)',
    'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed.',
    'medium',
    'removable_storage_unencrypted', 'eq', ARRAY['Pass'], NULL, 'pass',
    'T1', 'none', false, 'windows',
    NULL, NULL, NULL
);

INSERT INTO schema_migrations (version) VALUES ('0033_compliance_findings_rules');

COMMIT;
