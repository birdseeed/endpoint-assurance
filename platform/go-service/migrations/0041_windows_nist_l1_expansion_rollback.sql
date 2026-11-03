-- patched.im — 0041_windows_nist_l1_expansion_rollback.sql
-- Rolls back 0041: removes the 19 Windows NIST SP 800-53 Rev 5 rules.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0041_windows_nist_l1_expansion_rollback.sql

BEGIN;

DELETE FROM compliance_rules WHERE rule_key IN (
    'nist_win_ia7_fips_mode_enabled',
    'nist_win_sc13_tls10_client_disabled',
    'nist_win_sc13_tls10_server_disabled',
    'nist_win_sc13_tls11_client_disabled',
    'nist_win_sc13_tls11_server_disabled',
    'nist_win_sc13_tls12_client_enabled',
    'nist_win_sc13_tls12_server_enabled',
    'nist_win_sc28_bitlocker_cipher_256bit',
    'nist_win_si7_secure_boot_enabled',
    'nist_win_si7_tpm_ready',
    'nist_win_sc39_vbs_enabled',
    'nist_win_si16_hvci_enabled',
    'nist_win_sc41_kernel_dma_protection',
    'nist_win_si16_mandatory_aslr',
    'nist_win_ac2_laps_enrolled',
    'nist_win_au11_security_log_max_size',
    'nist_win_si3_defender_definition_age',
    'nist_win_si3_asr_ransomware',
    'nist_win_cm7_asr_psexec_wmi_block'
);

DELETE FROM schema_migrations WHERE version = '0041_windows_nist_l1_expansion';

COMMIT;
