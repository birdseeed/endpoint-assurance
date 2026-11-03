-- 0220: Remove internal references from shipped compliance descriptions (PAT-2318).
-- Exact descriptions and rule identities protect custom text. Private migration
-- provenance retains rollback ownership without exposing markers to customers.
BEGIN;

-- No foreign key: this record must survive a rule's deletion without changing
-- the rule table, and rollback must never claim a replacement UUID.
CREATE TABLE IF NOT EXISTS _migration_0220_compliance_copy_backup (
    rule_id UUID PRIMARY KEY,
    rule_key TEXT NOT NULL,
    benchmark TEXT NOT NULL,
    benchmark_version TEXT NOT NULL,
    original_description TEXT NOT NULL,
    customer_description TEXT NOT NULL
);
GRANT SELECT, INSERT ON TABLE _migration_0220_compliance_copy_backup TO patched;

INSERT INTO _migration_0220_compliance_copy_backup
    (rule_id, rule_key, benchmark, benchmark_version,
     original_description, customer_description)
SELECT rule.id, rule.rule_key, rule.benchmark, rule.benchmark_version,
       copy.original_description, copy.customer_description
FROM compliance_rules AS rule
JOIN (VALUES
    ('cis_macos_2_10_2_password_after_screensaver_delay', 'CIS Apple macOS', 'v3.0.0', 'CIS §2.10.2 (PAT-1746). Signal is screensaver_delay_seconds: the delay after the screen saver starts or the display sleeps before the session requires a password to unlock, read via sysadminctl -screenLock status on macOS 13+ and via the legacy askForPasswordDelay plist key on earlier macOS. This is distinct from cis_macos_2_10_1_screensaver_timeout''s idle-to-activation interval (now retired — it does not measure this control). A missing signal is treated as fail; CIS requires 5 seconds or immediate.', 'CIS §2.10.2. Signal is screensaver_delay_seconds: the delay after the screen saver starts or the display sleeps before the session requires a password to unlock, read via sysadminctl -screenLock status on macOS 13+ and via the legacy askForPasswordDelay plist key on earlier macOS. This is distinct from cis_macos_2_10_1_screensaver_timeout''s idle-to-activation interval (now retired — it does not measure this control). A missing signal is treated as fail; CIS requires 5 seconds or immediate.'),
    ('cis_macos_2_10_1_screensaver_inactivity', 'CIS Apple macOS', 'v3.0.0', 'CIS §2.10.1 (PAT-1753). Signal is screensaver_idle_seconds: com.apple.screensaver idleTime, read through NSUserDefaults as the console user, so an MDM-profile-forced value wins over a local default. idleTime 0 ("never") is sent as the sentinel 99999, the same sentinel Windows uses for machine_inactivity_limit_seconds, which fails this check the same as any other over-limit value. A missing signal (the read failed, or the key is not set) is treated as fail; the macOS default is not verified. This is distinct from cis_macos_2_10_2_password_after_screensaver_delay, which checks the password grace period after the screen saver starts, not the idle interval before it starts. CIS requires 20 minutes (1200 seconds) or less.', 'CIS §2.10.1. Signal is screensaver_idle_seconds: com.apple.screensaver idleTime, read through NSUserDefaults as the console user, so an MDM-profile-forced value wins over a local default. idleTime 0 ("never") is sent as the sentinel 99999, the same sentinel Windows uses for machine_inactivity_limit_seconds, which fails this check the same as any other over-limit value. A missing signal (the read failed, or the key is not set) is treated as fail; the macOS default is not verified. This is distinct from cis_macos_2_10_2_password_after_screensaver_delay, which checks the password grace period after the screen saver starts, not the idle interval before it starts. CIS requires 20 minutes (1200 seconds) or less.'),
    ('cis_win_18_9_102_auto_updates', 'CIS Microsoft Windows 11', 'v2.0.0', 'CIS §18.9.102. The agent reads, in order, the Group Policy NoAutoUpdate and AUOptions values, the Intune/MDM Update/AllowAutoUpdate value under PolicyManager (PAT-1780), then the local AUOptions value. Not configured passes: Windows 10/11 enable automatic updates by default, so a device with no policy set relies on that OS default rather than failing for want of an explicit setting. A failed read is Unknown and still fails. Unpatched Windows devices are the primary vector for ransomware lateral movement in SME estates.', 'CIS §18.9.102. The agent reads, in order, the Group Policy NoAutoUpdate and AUOptions values, the Intune/MDM Update/AllowAutoUpdate value under PolicyManager, then the local AUOptions value. Not configured passes: Windows 10/11 enable automatic updates by default, so a device with no policy set relies on that OS default rather than failing for want of an explicit setting. A failed read is Unknown and still fails. Unpatched Windows devices are the primary vector for ransomware lateral movement in SME estates.'),
    ('nist_win_si16_mandatory_aslr', 'NIST SP 800-53 Rev 5', 'Rev 5 (2020)', 'NIST SI-16. Mandatory ASLR relocates every image at load, including images built without the /DYNAMICBASE linker flag. The agent reads the system Exploit Protection setting ForceRelocateImages from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions (PAT-1770). Passes only when the setting is on. Not configured fails: mandatory ASLR is off by default, so an unset value means images are not force-relocated. A failed or undecodable read is Unknown and fails.', 'NIST SI-16. Mandatory ASLR relocates every image at load, including images built without the /DYNAMICBASE linker flag. The agent reads the system Exploit Protection setting ForceRelocateImages from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions. Passes only when the setting is on. Not configured fails: mandatory ASLR is off by default, so an unset value means images are not force-relocated. A failed or undecodable read is Unknown and fails.'),
    ('patched_macos_disk_encryption_off', 'patched.im baseline', 'v1', 'Disk encryption protects data at rest. Finding reported by the agent when FileVault is disabled or not fully encrypted. [PAT-2059/0174 backfill]', 'Disk encryption protects data at rest. Finding reported by the agent when FileVault is disabled or not fully encrypted.'),
    ('patched_win_disk_encryption_off', 'patched.im baseline', 'v1', 'BitLocker full-disk encryption protects data at rest. Finding reported by the agent when the OS drive is unencrypted. [PAT-2059/0174 backfill]', 'BitLocker full-disk encryption protects data at rest. Finding reported by the agent when the OS drive is unencrypted.'),
    ('patched_macos_removable_storage_unencrypted', 'patched.im baseline', 'v1', 'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed. [PAT-2059/0174 backfill]', 'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed.'),
    ('patched_win_removable_storage_unencrypted', 'patched.im baseline', 'v1', 'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed. [PAT-2059/0174 backfill]', 'Removable storage (USB/Thunderbolt) should be encrypted. Finding reported by the agent when unencrypted volumes are detected. Note: placeholders used for CIS control refs until confirmed.')
) AS copy(rule_key, benchmark, benchmark_version, original_description, customer_description)
ON rule.rule_key = copy.rule_key
  AND rule.benchmark = copy.benchmark
  AND rule.benchmark_version = copy.benchmark_version
WHERE rule.description = copy.original_description
-- Lock the selected rows until their guarded update below has completed.
FOR UPDATE OF rule
ON CONFLICT (rule_id) DO NOTHING;

UPDATE compliance_rules AS rule
SET description = backup.customer_description
FROM _migration_0220_compliance_copy_backup AS backup
WHERE rule.id = backup.rule_id
  AND rule.rule_key = backup.rule_key
  AND rule.benchmark = backup.benchmark
  AND rule.benchmark_version = backup.benchmark_version
  AND rule.description = backup.original_description;

INSERT INTO schema_migrations (version) VALUES ('0220_compliance_customer_copy')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
