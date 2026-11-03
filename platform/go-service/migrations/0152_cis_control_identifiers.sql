-- PAT-1858: store an authoritative control identifier on each benchmark-
-- versioned compliance rule. NULL is deliberate: it means this rule has no
-- evidenced identifier for its stated benchmark version, or is not a CIS
-- control at all. Identifiers must never be inferred from rule_key.

BEGIN;

ALTER TABLE compliance_rules
    ADD COLUMN control_identifier TEXT;

ALTER TABLE compliance_rules
    ADD CONSTRAINT compliance_rules_control_identifier_nonblank
    CHECK (control_identifier IS NULL OR btrim(control_identifier) <> '');

COMMENT ON COLUMN compliance_rules.control_identifier IS
    'Authoritative control identifier for this exact benchmark and benchmark_version. NULL means explicitly unmapped or not a CIS control; never infer it from rule_key. Windows remains NULL because its current rules are NIST-mapped, not evidenced CIS controls.';

-- These 73 mappings are literal transcriptions of the CIS Apple macOS 14.0
-- Sonoma v2.1.0 references recorded from the pinned mSCP sonoma_rev5 source in
-- docs/CIS_L1_GAP.md. The prerequisite rows are seeded unconditionally by
-- migrations 0006, 0007, 0008 and 0040 (10 + 8 + 17 + 38 = 73). They are
-- intentionally constrained to v2.1.0 rows, and the exact-count guard below
-- fails closed if that migration history is incomplete or has drifted.
-- The older v3.0.0 rows remain NULL: this repository has no authoritative v3
-- mapping, and a v2.1.0 number must not be presented as a v3.0.0 identifier.
UPDATE compliance_rules AS cr
SET control_identifier = mappings.control_identifier
FROM (VALUES
    ('cis_macos_1_2_update_check_auto', '1.2'),
    ('cis_macos_1_3_update_download_auto', '1.3'),
    ('cis_macos_1_5_app_updates_auto', '1.5'),
    ('cis_macos_1_6a_xprotect_data_auto', '1.6'),
    ('cis_macos_1_6b_critical_updates_auto', '1.6'),
    ('cis_macos_1_7_update_deferral_days', '1.7'),
    ('cis_macos_2_10_1_screensaver_timeout', '2.10.1'),
    ('cis_macos_2_10_3_loginwindow_text_set', '2.10.3'),
    ('cis_macos_2_10_4_loginwindow_fullname_prompt', '2.10.4'),
    ('cis_macos_2_10_5_loginwindow_password_hints', '2.10.5'),
    ('cis_macos_2_11_1_password_hints_absent', '2.11.1'),
    ('cis_macos_2_12_1_guest_account_disabled', '2.12.1'),
    ('cis_macos_2_12_2_smb_guest_disabled', '2.12.2'),
    ('cis_macos_2_18_1_dictation_on_device', '2.18.1'),
    ('cis_macos_2_2_2_firewall_stealth_mode', '2.2.2'),
    ('cis_macos_2_3_1_1_airdrop_disabled', '2.3.1.1'),
    ('cis_macos_2_3_1_2_airplay_receiver_disabled', '2.3.1.2'),
    ('cis_macos_2_3_2_1a_time_server_host', '2.3.2.1'),
    ('cis_macos_2_3_2_1b_time_server_enforced', '2.3.2.1'),
    ('cis_macos_2_3_2_2_timed_running', '2.3.2.2'),
    ('cis_macos_2_3_3_10_bluetooth_sharing_disabled', '2.3.3.10'),
    ('cis_macos_2_3_3_2_smbd_disabled', '2.3.3.2'),
    ('cis_macos_2_3_3_3_printer_sharing_disabled', '2.3.3.3'),
    ('cis_macos_2_3_3_5_remote_management_disabled', '2.3.3.5'),
    ('cis_macos_2_3_3_7_internet_sharing_disabled', '2.3.3.7'),
    ('cis_macos_2_3_4_2_time_machine_encrypted', '2.3.4.2'),
    ('cis_macos_2_4_1_wifi_menu_visible', '2.4.1'),
    ('cis_macos_2_4_2_bluetooth_menu_visible', '2.4.2'),
    ('cis_macos_2_5_1_siri_disabled', '2.5.1'),
    ('cis_macos_2_6_4_personalized_ads_disabled', '2.6.4'),
    ('cis_macos_2_6_8_system_prefs_admin_lock', '2.6.8'),
    ('cis_macos_2_9_2_power_nap_disabled', '2.9.2'),
    ('cis_macos_2_9_3_wake_on_network_disabled', '2.9.3'),
    ('cis_macos_3_3_install_log_retention', '3.3'),
    ('cis_macos_3_4_audit_retention_expire', '3.4'),
    ('cis_macos_3_5_audit_control_group', '3.5'),
    ('cis_macos_3_5_audit_control_mode', '3.5'),
    ('cis_macos_3_5_audit_control_no_acl', '3.5'),
    ('cis_macos_3_5_audit_control_owner', '3.5'),
    ('cis_macos_3_5_audit_folder_group', '3.5'),
    ('cis_macos_3_5_audit_folder_mode', '3.5'),
    ('cis_macos_3_5_audit_folder_no_acl', '3.5'),
    ('cis_macos_3_5_audit_folder_owner', '3.5'),
    ('cis_macos_3_5_audit_logs_group', '3.5'),
    ('cis_macos_3_5_audit_logs_mode', '3.5'),
    ('cis_macos_3_5_audit_logs_no_acl', '3.5'),
    ('cis_macos_3_5_audit_logs_owner', '3.5'),
    ('cis_macos_3_6_firewall_logging', '3.6'),
    ('cis_macos_4_2_httpd_disabled', '4.2'),
    ('cis_macos_4_3_nfsd_disabled', '4.3'),
    ('cis_macos_5_1_1_home_folders_mode', '5.1.1'),
    ('cis_macos_5_1_3_amfi_enabled', '5.1.3'),
    ('cis_macos_5_1_5_system_apps_world_writable', '5.1.5'),
    ('cis_macos_5_1_6_system_folder_world_writable', '5.1.6'),
    ('cis_macos_5_10_xprotect_running', '5.10'),
    ('cis_macos_5_2_1a_lockout_threshold', '5.2.1'),
    ('cis_macos_5_2_1b_lockout_reset_minutes', '5.2.1'),
    ('cis_macos_5_2_2_min_length', '5.2.2'),
    ('cis_macos_5_2_7_max_age_days', '5.2.7'),
    ('cis_macos_5_2_8_history_depth', '5.2.8'),
    ('cis_macos_5_4_sudo_timeout', '5.4'),
    ('cis_macos_5_5_sudo_timestamp_type', '5.5'),
    ('cis_macos_5_6_root_disabled', '5.6'),
    ('cis_macos_5_7_screensaver_unlock_group', '5.7'),
    ('cis_macos_5_9_guest_folder_absent', '5.9'),
    ('cis_macos_6_1_1_show_file_extensions', '6.1.1'),
    ('cis_macos_6_3_1_safari_auto_open_downloads_disabled', '6.3.1'),
    ('cis_macos_6_3_10_safari_status_bar_shown', '6.3.10'),
    ('cis_macos_6_3_3_safari_fraudulent_warning', '6.3.3'),
    ('cis_macos_6_3_4_safari_cross_site_tracking_blocked', '6.3.4'),
    ('cis_macos_6_3_6_safari_private_measurement', '6.3.6'),
    ('cis_macos_6_3_7_safari_full_url_shown', '6.3.7'),
    ('cis_macos_6_4_1_terminal_secure_keyboard', '6.4.1')
) AS mappings(rule_key, control_identifier)
WHERE cr.benchmark = 'CIS Apple macOS'
  AND cr.benchmark_version = 'v2.1.0'
  AND cr.rule_key = mappings.rule_key;

-- These are Patched assurance checks, not CIS controls. Their original rows
-- were labelled as CIS despite the source inventory explicitly identifying
-- them as Patched-specific. Correct the benchmark label without changing the
-- stable rule key or UUID referenced by evaluations and tenant policy.
UPDATE compliance_rules
SET benchmark = 'patched.im baseline',
    benchmark_version = 'v1'
WHERE benchmark = 'CIS Apple macOS'
  AND benchmark_version = 'v3.0.0'
  AND rule_key IN (
      'cis_macos_5_8_local_admin_count',
      'cis_macos_5_x_password_policy_non_default',
      'cis_macos_5_x_secure_boot_arm64'
  );

-- Fail the migration rather than silently shipping a partial or over-broad
-- backfill if the seeded v2.1.0 pack differs from the reviewed 73-row source.
DO $$
DECLARE
    mapped_count INTEGER;
    own_check_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO mapped_count
    FROM compliance_rules
    WHERE benchmark = 'CIS Apple macOS'
      AND benchmark_version = 'v2.1.0'
      AND control_identifier IS NOT NULL;

    IF mapped_count <> 73 THEN
        RAISE EXCEPTION 'expected 73 evidenced CIS macOS v2.1.0 identifiers, found %', mapped_count;
    END IF;

    SELECT COUNT(*) INTO own_check_count
    FROM compliance_rules
    WHERE benchmark = 'patched.im baseline'
      AND benchmark_version = 'v1'
      AND control_identifier IS NULL
      AND rule_key IN (
          'cis_macos_5_8_local_admin_count',
          'cis_macos_5_x_password_policy_non_default',
          'cis_macos_5_x_secure_boot_arm64'
      );

    IF own_check_count <> 3 THEN
        RAISE EXCEPTION 'expected 3 relabelled Patched-specific checks, found %', own_check_count;
    END IF;
END;
$$;

INSERT INTO schema_migrations (version) VALUES ('0152_cis_control_identifiers')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
