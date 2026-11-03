-- patched.im — 0025_windows_t2_audit_policy.sql
-- PAT-405 (parity epic PAT-404, ADR-0007): Windows CIS L1 T2 — batch 2.
--
-- CIS Microsoft Windows 11 Benchmark v2.0.0, §17 Advanced Audit Policy
-- Configuration. The Windows analog of the macOS §3.5 audit T2 pack
-- (migration 0008). 10 rules, all T2, platform='windows'.
--
-- COLLECTOR CONTRACT (this migration DEFINES it; collector implements it in
-- PAT-423): signals are emitted by ComplianceCollector.AddAuditPolicy() from
-- `auditpol /get /category:* /r`, each carrying the subcategory's verbatim
-- Inclusion Setting string: 'No Auditing' | 'Success' | 'Failure' |
-- 'Success and Failure'.
--
--   auditpol subcategory          -> signal_key
--   Credential Validation         -> audit_credential_validation
--   User Account Management       -> audit_user_account_management
--   Security Group Management     -> audit_security_group_management
--   Process Creation              -> audit_process_creation
--   Logon                         -> audit_logon
--   Account Lockout               -> audit_account_lockout
--   Audit Policy Change           -> audit_policy_change
--   Sensitive Privilege Use       -> audit_sensitive_privilege_use
--   System Integrity              -> audit_system_integrity
--   Security State Change         -> audit_security_state_change
--
-- Comparator design (relies on evaluator semantics, evaluator.go:140):
--   * "include Success" controls  -> comparator 'contains', expected ['Success']
--     ('contains' substring-matches, so it passes "Success" AND "Success and
--      Failure" but not "Failure"/"No Auditing").
--   * "include Failure" controls  -> 'contains', expected ['Failure'].
--   * "Success and Failure" req'd -> 'eq', expected ['Success and Failure']
--     (exact; 'eq' is set-membership over expected_values).
--
-- Until the collector emits these, signals are null -> treat_unknown_as='fail'.
-- pii_observed: audit-policy configuration metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0025_windows_t2_audit_policy.sql
-- Note: 0019_windows_cis_l1_rules.sql must have been applied first (platform column).

BEGIN;

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES

-- §17.1.1 — Audit Credential Validation (Success and Failure)
(
    'cis_win_17_1_1_audit_credential_validation',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Credential Validation (Success and Failure)',
    'CIS §17.1.1. Credential Validation auditing records authentication of account credentials — the primary signal for password-guessing and pass-the-hash. Must be set to Success and Failure.',
    'medium',
    'audit_credential_validation', 'eq', ARRAY['Success and Failure'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.2.3 — Audit User Account Management (Success and Failure)
(
    'cis_win_17_2_3_audit_user_account_management',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit User Account Management (Success and Failure)',
    'CIS §17.2.3. Records creation/deletion/modification of user accounts and password resets — essential for detecting persistence and privilege abuse. Must be Success and Failure.',
    'medium',
    'audit_user_account_management', 'eq', ARRAY['Success and Failure'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.2.2 — Audit Security Group Management (include Success)
(
    'cis_win_17_2_2_audit_security_group_management',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Security Group Management (Success)',
    'CIS §17.2.2. Records changes to security groups (e.g. adds to Administrators/Domain Admins) — a key lateral-movement and privilege-escalation signal. Must at minimum include Success.',
    'medium',
    'audit_security_group_management', 'contains', ARRAY['Success'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.3.2 — Audit Process Creation (include Success)
(
    'cis_win_17_3_2_audit_process_creation',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Process Creation (Success)',
    'CIS §17.3.2. Records new-process events (4688) — foundational for EDR/IR to reconstruct attacker activity and malware execution. Must at minimum include Success.',
    'medium',
    'audit_process_creation', 'contains', ARRAY['Success'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.5.4 — Audit Logon (Success and Failure)
(
    'cis_win_17_5_4_audit_logon',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Logon (Success and Failure)',
    'CIS §17.5.4. Records interactive/network logon attempts — the core record for intrusion and brute-force detection. Must be Success and Failure.',
    'medium',
    'audit_logon', 'eq', ARRAY['Success and Failure'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.5.1 — Audit Account Lockout (include Failure)
(
    'cis_win_17_5_1_audit_account_lockout',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Account Lockout (Failure)',
    'CIS §17.5.1. Records failed logon attempts that trip account lockout — a direct indicator of password-guessing campaigns. Must at minimum include Failure.',
    'medium',
    'audit_account_lockout', 'contains', ARRAY['Failure'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.7.1 — Audit Audit Policy Change (include Success)
(
    'cis_win_17_7_1_audit_policy_change',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Audit Policy Change (Success)',
    'CIS §17.7.1. Records changes to the audit policy itself — attackers disable auditing to cover tracks, so this is a critical tamper signal. Must at minimum include Success.',
    'medium',
    'audit_policy_change', 'contains', ARRAY['Success'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.8.1 — Audit Sensitive Privilege Use (Success and Failure)
(
    'cis_win_17_8_1_audit_sensitive_privilege_use',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Sensitive Privilege Use (Success and Failure)',
    'CIS §17.8.1. Records use of sensitive privileges (e.g. SeDebugPrivilege, act-as-OS) commonly abused in privilege escalation. Must be Success and Failure.',
    'medium',
    'audit_sensitive_privilege_use', 'eq', ARRAY['Success and Failure'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.9.5 — Audit System Integrity (Success and Failure)
(
    'cis_win_17_9_5_audit_system_integrity',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit System Integrity (Success and Failure)',
    'CIS §17.9.5. Records violations of system integrity (audit subsystem failures, driver/integrity issues). Must be Success and Failure.',
    'medium',
    'audit_system_integrity', 'eq', ARRAY['Success and Failure'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §17.9.3 — Audit Security State Change (include Success)
(
    'cis_win_17_9_3_audit_security_state_change',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Audit Security State Change (Success)',
    'CIS §17.9.3. Records system startup/shutdown and system-time changes — anchors the timeline of other events and flags anti-forensic clock tampering. Must at minimum include Success.',
    'medium',
    'audit_security_state_change', 'contains', ARRAY['Success'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0025_windows_t2_audit_policy');

COMMIT;
