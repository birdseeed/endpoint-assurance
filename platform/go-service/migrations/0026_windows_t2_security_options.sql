-- patched.im — 0026_windows_t2_security_options.sql
-- PAT-405 (parity epic PAT-404, ADR-0007): Windows CIS L1 T2 — batch 3.
--
-- CIS Microsoft Windows 11 Benchmark v2.0.0, §2.3 Security Options (Local
-- Policies). The Windows analog of the macOS §5.4/5.5 sudo + §5 access-control
-- T2 controls. 8 rules, all T2, platform='windows'.
--
-- Excludes §2.3.17.1 (UAC EnableLUA) and §2.3.8.1 (SMB client signing) — those
-- already ship as T1 rules in migration 0019.
--
-- COLLECTOR CONTRACT (defined here; implemented in PAT-425): signals are read
-- from the registry by ComplianceCollector.AddSecurityOptions(); the pure
-- normalization is Patched.Shared.Compliance.SecurityOptionsParser.Evaluate().
-- Binary controls emit 'Yes'/'No' (Yes = compliant, matching the T1 uac_enabled
-- style); two emit raw numerics.
--
--   registry value             -> signal_key                       -> emit
--   NoConnectedUser            -> block_microsoft_accounts          -> Yes if 3
--   SCENoApplyLegacyAuditPolicy-> audit_force_subcategory_policy    -> Yes if 1
--   DontDisplayLastUserName    -> dont_display_last_username        -> Yes if 1
--   InactivityTimeoutSecs      -> machine_inactivity_limit_seconds  -> int* (lte 900)
--   RestrictAnonymousSAM       -> restrict_anonymous_sam            -> Yes if 1
--   NoLMHash                   -> no_lm_hash                        -> Yes if 1
--   LmCompatibilityLevel       -> lan_manager_auth_level            -> int (gte 5)
--   FilterAdministratorToken   -> uac_admin_approval_builtin        -> Yes if 1
--
--   * InactivityTimeoutSecs: 0 = "no limit" = fail. Collector CLAMPS 0 -> 99999
--     so the `lte 900` rule fails correctly.
--
-- Until the collector emits these, signals are null -> treat_unknown_as='fail'.
-- pii_observed: security-policy configuration metadata — no PII.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0026_windows_t2_security_options.sql
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

-- §2.3.1.1 — Accounts: Block Microsoft accounts
(
    'cis_win_2_3_1_1_block_microsoft_accounts',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Block Microsoft accounts',
    'CIS §2.3.1.1. NoConnectedUser must be 3 (users cannot add or log on with Microsoft accounts), keeping authentication under the organisation''s control rather than consumer identities.',
    'medium',
    'block_microsoft_accounts', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-2','CM-7'], ARRAY['A.5.16'], ARRAY['user-access-control']
),

-- §2.3.2.1 — Audit: Force audit policy subcategory settings
(
    'cis_win_2_3_2_1_force_audit_subcategory',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Force audit policy subcategory settings',
    'CIS §2.3.2.1. SCENoApplyLegacyAuditPolicy must be 1 so the advanced (subcategory) audit policy is honoured — otherwise the §17 audit settings are silently overridden by legacy policy.',
    'medium',
    'audit_force_subcategory_policy', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AU-2','AU-12'], ARRAY['A.8.15'], ARRAY['secure-configuration']
),

-- §2.3.7.2 — Interactive logon: Don't display last signed-in user
(
    'cis_win_2_3_7_2_no_last_username',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Do not display last signed-in user',
    'CIS §2.3.7.2. DontDisplayLastUserName must be 1 so the previous user''s name is not shown at logon — halving the credential an attacker with physical access needs to guess.',
    'medium',
    'dont_display_last_username', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-23'], ARRAY['A.8.2'], ARRAY['secure-configuration']
),

-- §2.3.7.3 — Interactive logon: Machine inactivity limit
(
    'cis_win_2_3_7_3_inactivity_limit',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Machine inactivity limit ≤ 900 seconds',
    'CIS §2.3.7.3. InactivityTimeoutSecs must lock the session after at most 900 seconds (15 min) of inactivity. A value of 0 means "no limit" — the collector clamps 0 to 99999 so this control fails.',
    'medium',
    'machine_inactivity_limit_seconds', 'lte', ARRAY['900'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-11'], ARRAY['A.8.1'], ARRAY['secure-configuration']
),

-- §2.3.10.2 — Network access: No anonymous enumeration of SAM accounts
(
    'cis_win_2_3_10_2_restrict_anonymous_sam',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Do not allow anonymous enumeration of SAM accounts',
    'CIS §2.3.10.2. RestrictAnonymousSAM must be 1 to stop unauthenticated callers enumerating local account names — a common reconnaissance step before password attacks.',
    'high',
    'restrict_anonymous_sam', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-3','AC-6'], ARRAY['A.8.3'], ARRAY['secure-configuration']
),

-- §2.3.11.1 — Network security: Do not store LAN Manager hash
(
    'cis_win_2_3_11_1_no_lm_hash',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Do not store LAN Manager hash on next password change',
    'CIS §2.3.11.1. NoLMHash must be 1. The LM hash is trivially crackable; storing it lets an attacker with the SAM recover passwords almost instantly.',
    'high',
    'no_lm_hash', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','SC-28'], ARRAY['A.8.24'], ARRAY['secure-configuration']
),

-- §2.3.11.7 — Network security: LAN Manager authentication level
(
    'cis_win_2_3_11_7_lm_auth_level',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'LAN Manager authentication level (NTLMv2 only)',
    'CIS §2.3.11.7. LmCompatibilityLevel must be ≥ 5 (send NTLMv2 only; refuse LM & NTLM). Lower levels allow downgrade and relay attacks against legacy authentication.',
    'high',
    'lan_manager_auth_level', 'gte', ARRAY['5'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['IA-5','SC-8'], ARRAY['A.8.24'], ARRAY['secure-configuration']
),

-- §2.3.17.4 — UAC: Admin Approval Mode for the built-in Administrator
(
    'cis_win_2_3_17_4_uac_admin_approval_builtin',
    'CIS Microsoft Windows 11', 'v2.0.0',
    'Admin Approval Mode for the built-in Administrator',
    'CIS §2.3.17.4. FilterAdministratorToken must be 1 so the built-in Administrator also runs under UAC — otherwise that account elevates silently, bypassing the primary privilege-separation control.',
    'high',
    'uac_admin_approval_builtin', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'windows',
    ARRAY['AC-6','CM-7'], ARRAY['A.8.2'], ARRAY['user-access-control']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0026_windows_t2_security_options');

COMMIT;
