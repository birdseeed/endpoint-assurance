-- patched.im — 0040_macos_cis_l1_expansion.sql
-- PAT-586: macOS CIS L1 full coverage — 38 gap controls.
--
-- All 38 rules are T2 (per-tenant toggle), platform='macos'.
-- Collector v0.11.0 required for non-null signal values.
--
-- Groups:
--   §1.7    — Software update deferral (1 rule)
--   §2.2.2  — Firewall stealth mode (1 rule)
--   §2.3.1  — AirDrop + AirPlay Receiver disabled (2 rules)
--   §2.3.2  — Time server configured + enforced + timed running (3 rules)
--   §2.3.3  — Bluetooth Sharing disabled (1 rule; user-context)
--   §2.3.4  — Time Machine encrypted (1 rule)
--   §2.4    — Wi-Fi + Bluetooth menu visible (2 rules)
--   §2.5.1  — Siri disabled (1 rule)
--   §2.6.4  — Personalised advertising disabled (1 rule)
--   §2.6.8  — System-wide preferences require admin (1 rule)
--   §2.10.3–5 — Login window text/fullname/hints (3 rules)
--   §2.11.1 — Password hints absent (1 rule)
--   §2.12.1–2 — Guest account + SMB guest disabled (2 rules)
--   §2.18.1 — On-device dictation (1 rule)
--   §3.3    — install.log retention ≥ 365 days (1 rule)
--   §3.4    — Audit log retention ≥ 60 days (1 rule)
--   §3.6    — Firewall logging (1 rule)
--   §5.1.1  — Home folder permissions (1 rule)
--   §5.1.5–6 — No world-writable apps or system files (2 rules)
--   §5.7    — Screensaver unlock requires session owner only (1 rule)
--   §5.9    — Guest home folder absent (1 rule)
--   §5.10   — XProtect services running (1 rule)
--   §6.1.1  — Show filename extensions (1 rule; user-context)
--   §6.3.1,3,4,6,7,10 — Safari MDM profile controls (6 rules)
--   §6.4.1  — Terminal secure keyboard entry (1 rule; user-context)
--
-- mSCP severity gaps: several controls have no severity in mSCP sonoma_rev5.
-- These are marked '-- mSCP severity gap' and defaulted to 'medium' or 'low'
-- per CIS_L1_GAP.md. Revisit against the CIS PDF before enabling for customers.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0040_macos_cis_l1_expansion.sql
-- Note: 0039_nullable_os.sql must have been applied first.

BEGIN;

-- ============================================================================
-- §1.7 — Software update deferral
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_1_7_update_deferral_days',
    'CIS Apple macOS', 'v2.1.0',
    'Limit Software Update Deferral to 30 Days or Fewer',
    'CIS §1.7. MDM-managed devices may defer software updates via enforcedSoftwareUpdateDelay. CIS L1 ODV requires deferral ≤ 30 days. Null (no MDM deferral configured) means updates install immediately — treat as pass. Collector reads com.apple.applicationaccess enforcedSoftwareUpdateDelay via JXA. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'update_deferral_days', 'lte', ARRAY['30'],
    NULL, 'pass',
    'T2', 'none', false,
    'macos',
    ARRAY['SI-2'], ARRAY['A.8.8'], ARRAY['patch-management']
);

-- ============================================================================
-- §2.2.2 — Firewall stealth mode
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_2_2_firewall_stealth_mode',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Firewall Stealth Mode',
    'CIS §2.2.2. Firewall stealth mode causes the Mac to drop unrequested incoming packets silently instead of returning ICMP/RST responses. Reduces active reconnaissance exposure. Collector reads com.apple.security.firewall EnableStealthMode via JXA.',
    'medium',
    'firewall_stealth_mode', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SC-7'], ARRAY['A.8.20'], ARRAY['firewalls']
);

-- ============================================================================
-- §2.3.1 — AirDrop and AirPlay Receiver
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_3_1_1_airdrop_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable AirDrop',
    'CIS §2.3.1.1. AirDrop allows file sharing with nearby devices over Wi-Fi/Bluetooth. On unmanaged devices it defaults to accepting from Everyone. MDM sets com.apple.applicationaccess allowAirDrop=false to block it.',
    'medium',
    'airdrop_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_3_1_2_airplay_receiver_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable AirPlay Receiver',
    'CIS §2.3.1.2. AirPlay Receiver allows the Mac to accept screen or audio streams from other devices. MDM sets com.apple.applicationaccess allowAirPlayIncomingRequests=false to disable.',
    'medium',
    'airplay_receiver_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.3.2 — Time synchronisation
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_3_2_1a_time_server_host',
    'CIS Apple macOS', 'v2.1.0',
    'Configure Authorised Time Server',
    'CIS §2.3.2.1. An organisation-approved NTP server must be configured via MDM (com.apple.MCX timeServer). Accurate time is required for authentication protocols, log correlation, and certificate validation. Signal is Yes if any host is configured, No/null if absent.',
    'medium',
    'time_server_host', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AU-8'], ARRAY['A.8.17'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_3_2_1b_time_server_enforced',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce Automatic Time Synchronisation',
    'CIS §2.3.2.1. macOS must enforce automatic time-only sync (com.apple.timed TMAutomaticTimeOnlyEnabled=true) to prevent manual clock manipulation.',
    'medium',
    'time_server_enforced', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AU-8'], ARRAY['A.8.17'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_3_2_2_timed_running',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Time Synchronisation Daemon (timed)',
    'CIS §2.3.2.2. The com.apple.timed LaunchDaemon must be running. Detected via launchctl list.',
    'medium',
    'timed_running', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AU-8'], ARRAY['A.8.17'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.3.3.10 — Bluetooth Sharing (per-user signal)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_3_3_10_bluetooth_sharing_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Bluetooth Sharing',
    'CIS §2.3.3.10. Bluetooth Sharing allows other devices to browse files on this Mac. Collector reads com.apple.Bluetooth PrefKeyServicesEnabled from the console user ByHost defaults; value 0 means disabled (pass). Null if no interactive user is logged in.',
    'medium',
    'bluetooth_sharing_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.3.4.2 — Time Machine encryption
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_3_4_2_time_machine_encrypted',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure Time Machine Volumes Are Encrypted',
    'CIS §2.3.4.2. When Time Machine is configured, all backup destinations must be encrypted. Collector checks com.apple.TimeMachine.plist for NotEncrypted keys. Null if Time Machine is not configured (treat as pass — no backup = not applicable). Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'time_machine_encrypted', 'eq', ARRAY['Yes'],
    NULL, 'pass',
    'T2', 'none', false,
    'macos',
    ARRAY['SC-28'], ARRAY['A.8.24'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.4 — Connectivity menus
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_4_1_wifi_menu_visible',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Wi-Fi Menu in Menu Bar',
    'CIS §2.4.1. The Wi-Fi menu must be visible so users can see which network they are connected to and take action if connected to an untrusted network. MDM sets com.apple.controlcenter WiFi=18 to show it. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'wifi_menu_visible', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-6'], ARRAY['A.8.1'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_4_2_bluetooth_menu_visible',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Bluetooth Menu in Menu Bar',
    'CIS §2.4.2. The Bluetooth menu must be visible so users can see Bluetooth state and disable it when not in use. MDM sets com.apple.controlcenter Bluetooth=18 to show it. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'bluetooth_menu_visible', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-6'], ARRAY['A.8.1'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.5.1 — Siri
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_5_1_siri_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Siri',
    'CIS §2.5.1. Siri sends voice queries and context to Apple servers. MDM sets com.apple.applicationaccess allowAssistant=false to block Siri. On unmanaged devices Siri defaults to enabled.',
    'medium',
    'siri_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.6.4 — Personalised advertising
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_6_4_personalized_ads_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Personalised Advertising',
    'CIS §2.6.4. Apple Personalised Advertising sends device and usage data to Apple for ad targeting. MDM sets com.apple.applicationaccess allowApplePersonalizedAdvertising=false to disable it.',
    'medium',
    'personalized_ads_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §2.6.8 — System-wide preferences require admin
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_6_8_system_prefs_admin_lock',
    'CIS Apple macOS', 'v2.1.0',
    'Require Admin Password to Change System-Wide Preferences',
    'CIS §2.6.8. Eight authorisation database rights (system.preferences.*) must have shared=false (absent or explicit <false/>) so that admin credentials are required to modify system-wide settings. Collector checks all 8 rights via security authorizationdb read and emits Yes only if all pass.',
    'high',
    'system_prefs_admin_lock', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-6', 'AC-3'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- §2.10.3–5 — Login window
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_10_3_loginwindow_text_set',
    'CIS Apple macOS', 'v2.1.0',
    'Display Custom Legal/Acceptable-Use Banner at Login Window',
    'CIS §2.10.3. A custom text banner at the login window notifies users of acceptable-use policy and may constitute legal notice. MDM sets com.apple.loginwindow LoginwindowText to any non-empty string. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'loginwindow_text_set', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-8'], ARRAY['A.8.1'], ARRAY['secure-configuration']
),
(
    'cis_macos_2_10_4_loginwindow_fullname_prompt',
    'CIS Apple macOS', 'v2.1.0',
    'Set Login Window to Show Username and Password Fields',
    'CIS §2.10.4. The login window must prompt for both username and password (not show a list of user accounts). Prevents users from seeing account names and reduces targeted attack surface. MDM sets com.apple.loginwindow SHOWFULLNAME=true.',
    'medium',
    'loginwindow_fullname_prompt', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-14', 'IA-2'], ARRAY['A.8.5'], ARRAY['access-control']
),
(
    'cis_macos_2_10_5_loginwindow_password_hints',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Password Hints at Login Window',
    'CIS §2.10.5. Password hints at the login window can disclose partial password information. MDM sets com.apple.loginwindow RetriesUntilHint=0 so hints are never shown. Collector emits Yes when value is 0.',
    'medium',
    'loginwindow_password_hints', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['IA-5', 'AC-14'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- §2.11.1 — Password hints on user accounts
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_11_1_password_hints_absent',
    'CIS Apple macOS', 'v2.1.0',
    'Remove Password Hints from All User Accounts',
    'CIS §2.11.1. Password hints stored on user accounts can be displayed at the login window and aid guessing. Collector checks dscl . -list /Users hint for any non-empty hint text; emits Yes only when all accounts have no hint set. Hint content is NOT collected — only existence.',
    'medium',
    'password_hints_absent', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['IA-5'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- §2.12.1–2 — Guest access
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_12_1_guest_account_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable the Guest Account',
    'CIS §2.12.1. The guest account permits unauthenticated login. MDM sets com.apple.MCX DisableGuestAccount=true to disable it.',
    'medium',
    'guest_account_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-2', 'IA-2'], ARRAY['A.8.2'], ARRAY['access-control']
),
(
    'cis_macos_2_12_2_smb_guest_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Guest Access to SMB Shares',
    'CIS §2.12.2. Guest access to SMB shares allows unauthenticated file access. Collector reads com.apple.smb.server AllowGuestAccess; value 0 means disabled. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'smb_guest_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-2', 'CM-7'], ARRAY['A.8.9'], ARRAY['access-control']
);

-- ============================================================================
-- §2.18.1 — Dictation
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_2_18_1_dictation_on_device',
    'CIS Apple macOS', 'v2.1.0',
    'Enforce On-Device Dictation',
    'CIS §2.18.1. Without on-device dictation enforced, macOS may upload voice input to Apple servers for processing. MDM sets com.apple.applicationaccess forceOnDeviceOnlyDictation=true to keep audio processing local.',
    'medium',
    'dictation_on_device', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7', 'SC-8'], ARRAY['A.8.9'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §3.3 — install.log retention
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_3_3_install_log_retention',
    'CIS Apple macOS', 'v2.1.0',
    'Configure install.log Retention to 365 Days or More',
    'CIS §3.3. install.log records all software installation events. CIS L1 ODV requires at least 365 days retention. Collector reads TTL from /etc/asl/com.apple.install; null if the config file is absent (default macOS install does not set this — treat as fail).',
    'medium',
    'install_log_retention_days', 'gte', ARRAY['365'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AU-11'], ARRAY['A.8.15'], ARRAY['logging']
);

-- ============================================================================
-- §3.4 — Audit log retention
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_3_4_audit_retention_expire',
    'CIS Apple macOS', 'v2.1.0',
    'Configure Audit Log Retention to 60 Days or More',
    'CIS §3.4. The expire-after field in /etc/security/audit_control must require at least 60 days of retention. Collector parses the value (supports d/y units) and emits Yes when ≥ 60 days.',
    'low',
    'audit_retention_expire', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AU-11'], ARRAY['A.8.15'], ARRAY['logging']
);

-- ============================================================================
-- §3.6 — Firewall logging
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_3_6_firewall_logging',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Application Firewall Logging',
    'CIS §3.6. Firewall logging must be enabled (com.apple.security.firewall EnableLogging=true) and a logging option must be configured (LoggingOption non-empty). Collector checks both via JXA; emits Yes only when both are set. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'firewall_logging', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AU-2', 'SC-7'], ARRAY['A.8.15'], ARRAY['logging', 'firewalls']
);

-- ============================================================================
-- §5.1.1 — Home folder permissions
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_5_1_1_home_folders_mode',
    'CIS Apple macOS', 'v2.1.0',
    'Secure User Home Folder Permissions (700 or 711)',
    'CIS §5.1.1. Home folders in /System/Volumes/Data/Users must be mode 700 or 711. More permissive modes allow other users to read files. Collector counts directories with non-compliant mode (excluding Shared and Guest); emits Yes when count is 0.',
    'medium',
    'home_folders_mode', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-3', 'MP-4'], ARRAY['A.8.3'], ARRAY['access-control']
);

-- ============================================================================
-- §5.1.5–6 — World-writable files
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_5_1_5_system_apps_world_writable',
    'CIS Apple macOS', 'v2.1.0',
    'No World-Writable .app Bundles in /Applications',
    'CIS §5.1.5. Application bundles in /Applications must not be world-writable. World-writable apps allow any local user to replace binaries. Collector counts world-writable .app directories; emits Yes when count is 0. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'system_apps_world_writable', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7', 'SI-7'], ARRAY['A.8.6'], ARRAY['secure-configuration']
),
(
    'cis_macos_5_1_6_system_folder_world_writable',
    'CIS Apple macOS', 'v2.1.0',
    'No World-Writable Directories in System Folder',
    'CIS §5.1.6. /System/Volumes/Data/System must contain no world-writable directories (excluding known-legitimate Apple paths: downloadDir, locks). Collector counts violations; emits Yes when count is 0. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'system_folder_world_writable', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['CM-7', 'SI-7'], ARRAY['A.8.6'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §5.7 — Screensaver unlock authorisation
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_5_7_screensaver_unlock_group',
    'CIS Apple macOS', 'v2.1.0',
    'Restrict Screensaver Unlock to Session Owner Only',
    'CIS §5.7. The system.login.screensaver authorisation right must require only the session owner to authenticate (authenticate-session-owner). The default Apple value (authenticate-session-owner-or-admin) allows admins to unlock any screensaver session, violating least privilege. Collector extracts the group value from authorizationdb.',
    'medium',
    'screensaver_unlock_group', 'eq', ARRAY['authenticate-session-owner'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-11', 'AC-6'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- §5.9–5.10 — Guest folder and antivirus
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_5_9_guest_folder_absent',
    'CIS Apple macOS', 'v2.1.0',
    'Remove Guest Home Folder',
    'CIS §5.9. /Users/Guest is an Apple-managed folder that should be absent when the guest account is disabled. Its presence may indicate the guest account is partially active. Collector checks for existence of /Users/Guest. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'guest_folder_absent', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AC-2'], ARRAY['A.8.2'], ARRAY['access-control']
),
(
    'cis_macos_5_10_xprotect_running',
    'CIS Apple macOS', 'v2.1.0',
    'Ensure XProtect Antivirus Services Are Running',
    'CIS §5.10. Apple XProtect must be actively running (not just installed). Two LaunchDaemons must appear in launchctl list: com.apple.XprotectFramework.PluginService and com.apple.XProtect.daemon.scan. Collector counts matching entries; emits Yes when ≥ 2 found.',
    'high',
    'xprotect_running', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SI-3'], ARRAY['A.8.7'], ARRAY['malware-protection']
);

-- ============================================================================
-- §6.1.1 — Filename extensions (per-user signal)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_6_1_1_show_file_extensions',
    'CIS Apple macOS', 'v2.1.0',
    'Show All Filename Extensions',
    'CIS §6.1.1. macOS hides filename extensions by default, which aids social engineering (e.g. a PDF icon that is actually an .app). Collector reads AppleShowAllExtensions from the console user GlobalPreferences; emits Yes when set to 1. Null if no interactive user. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'show_file_extensions', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SI-3', 'AT-2'], ARRAY['A.8.22'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §6.3 — Safari MDM profile controls
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_6_3_1_safari_auto_open_downloads_disabled',
    'CIS Apple macOS', 'v2.1.0',
    'Disable Safari Auto-Open of Safe Downloads',
    'CIS §6.3.1. Safari auto-opening "safe" downloads can execute malicious files without user interaction. MDM profile must set AutoOpenSafeDownloads=0. Collector reads profiles -P -o stdout. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'safari_auto_open_downloads_disabled', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SI-3', 'CM-7'], ARRAY['A.8.22'], ARRAY['malware-protection']
),
(
    'cis_macos_6_3_3_safari_fraudulent_warning',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Safari Fraudulent Website Warning',
    'CIS §6.3.3. Safari must warn users when visiting sites identified as fraudulent. MDM profile must set WarnAboutFraudulentWebsites=1. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'safari_fraudulent_warning', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SI-3', 'SC-18'], ARRAY['A.8.22'], ARRAY['malware-protection']
),
(
    'cis_macos_6_3_4_safari_cross_site_tracking_blocked',
    'CIS Apple macOS', 'v2.1.0',
    'Prevent Cross-Site Tracking in Safari',
    'CIS §6.3.4. Cross-site tracking allows advertisers to build profiles across sites. MDM profile must configure storage blocking policy (storageBlockingPolicy=1, WebKitStorageBlockingPolicy=1, or BlockStoragePolicy=2). Collector checks all known key variants. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'safari_cross_site_tracking_blocked', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SC-18', 'CM-7'], ARRAY['A.8.22'], ARRAY['secure-configuration']
),
(
    'cis_macos_6_3_6_safari_private_measurement',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Safari Private Click Measurement',
    'CIS §6.3.6. Private Click Measurement (PCM) provides privacy-preserving ad attribution without sending individual user data to advertisers. MDM profile must set WebKitPreferences.privateClickMeasurementEnabled=1. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'safari_private_measurement', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SC-18'], ARRAY['A.8.22'], ARRAY['secure-configuration']
),
(
    'cis_macos_6_3_7_safari_full_url_shown',
    'CIS Apple macOS', 'v2.1.0',
    'Show Full URL in Safari Smart Search Field',
    'CIS §6.3.7. Showing the complete URL in the address bar helps users detect homograph and subdomain phishing attacks. MDM profile must set ShowFullURLInSmartSearchField=1. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'safari_full_url_shown', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AT-2', 'SC-18'], ARRAY['A.8.22'], ARRAY['secure-configuration']
),
(
    'cis_macos_6_3_10_safari_status_bar_shown',
    'CIS Apple macOS', 'v2.1.0',
    'Show Status Bar in Safari',
    'CIS §6.3.10. The Safari status bar shows link destinations before navigation, helping users detect link-redirect attacks. MDM profile must set ShowOverlayStatusBar=1. Severity defaulted to low — mSCP severity gap.',
    'low', -- mSCP severity gap
    'safari_status_bar_shown', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['AT-2', 'SC-18'], ARRAY['A.8.22'], ARRAY['secure-configuration']
);

-- ============================================================================
-- §6.4.1 — Terminal secure keyboard entry (per-user signal)
-- ============================================================================

INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version,
    title, description, severity,
    signal_key, comparator, expected_values,
    applicable_arch, treat_unknown_as,
    collection_tier, pii_observed, requires_user_consent,
    platform,
    nist_mappings, iso_mappings, cyber_essentials_mappings
) VALUES
(
    'cis_macos_6_4_1_terminal_secure_keyboard',
    'CIS Apple macOS', 'v2.1.0',
    'Enable Secure Keyboard Entry in Terminal',
    'CIS §6.4.1. Secure keyboard entry prevents other processes from intercepting keystrokes typed in Terminal. Collector reads com.apple.Terminal SecureKeyboardEntry from the console user defaults; emits Yes when set to 1. Null if no interactive user. Severity defaulted to medium — mSCP severity gap.',
    'medium', -- mSCP severity gap
    'terminal_secure_keyboard', 'eq', ARRAY['Yes'],
    NULL, 'fail',
    'T2', 'none', false,
    'macos',
    ARRAY['SC-28', 'AC-3'], ARRAY['A.8.5'], ARRAY['access-control']
);

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0040_macos_cis_l1_expansion');

COMMIT;
