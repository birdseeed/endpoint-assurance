# CIS macOS Sonoma 14 L1 gap inventory

**Sources:**
- mSCP (macOS Security Compliance Project) — `usnistgov/macos_security` tag `sonoma_rev5` commit `c87541e6faa93086e7c91d0b07193848bc45bad6` (dated 2025-09-11). Benchmark: CIS Apple macOS 14.0 Sonoma v2.1.0 Benchmark (Level 1).
- Current implemented controls — `go-service/docs/CIS_RULES.md` + `migrations/0003_compliance_rules.sql`

**ADR:** `go-service/docs/adr/0001-cis-collection-scope.md` (action item 1)

---

## Headline

| Metric | Count |
|---|---|
| CIS L1 controls in mSCP Sonoma 14 baseline | 90 |
| — automated (non-supplemental) | 87 |
| — supplemental / documentation only | 3 |
| T1-implemented today (direct mSCP match) | 13 |
| patched.im baseline with a partial mSCP analogue | 1 (`patched_mdm_enrolment`; less strict than CIS §1.8) |
| Custom T1 controls (patched.im, no mSCP equivalent) | 3 |
| T2-gap (automated, not yet collected) | 73 |
| T3 (explicitly out of scope) | All CIS L2 + manual L1 audit items |

---

## Methodology

**Source:** mSCP `baselines/cis_lvl1.yaml` at `sonoma_rev5` lists 90 rules. Each references a YAML file in `rules/` with a `check` field (the shell/osascript command used to verify compliance), a `title`, `severity`, and CIS section under `references.cis.benchmark`.

**Matching approach:** The 17 implemented controls were matched to mSCP rules by comparing what system state each checks (not by rule_key string). 13 map directly. `patched_mdm_enrolment` has a partial analogue in CIS §1.8, but the Patched check is less strict because it does not establish User Approved MDM enrolment, so it remains a Patched baseline check without a CIS identifier. The other 3 (`local_admin_count`, `secure_boot`, `password_policy_is_default`) are patched.im-specific controls with no direct mSCP L1 equivalent. They remain T1 but are not in the mSCP L1 count.

**Benchmark version note:** Our existing `rule_key` slugs encode section numbers from an older CIS version (e.g., `cis_macos_2_5_1_1_filevault` uses §2.5.1.1). mSCP sonoma_rev5 targets CIS Apple macOS 14.0 Sonoma v2.1.0, where FileVault is §2.6.6. All CIS section references in this document use the mSCP v2.1.0 numbering. This creates no functional gap — the signals being checked are the same — but new rule_keys added in a future migration should use the v2.1.0 numbering.

**ODV (Organisation-Defined Value) rules:** mSCP uses `$ODV` as a placeholder where CIS allows organisations to set their own threshold. CIS L1 recommended values are noted in the collection method column. The evaluator `expected_values` policy comes in ADR action item 3 — this doc only inventories collection feasibility.

**Supplemental rules** (`supplemental_*`) are documentation or guidance for manual checks. They are not automated and do not require new collector signals. They are listed briefly in a separate section.

**Already-collected signals:** The collector already emits `screensaver_delay_seconds` and `password_policy_raw` (among others) but these have no corresponding `compliance_rules` row yet. Several T2 gaps can be satisfied by parsing existing collected data — flagged as `// existing-signal`.

---

## How to read this table

| Column | Meaning |
|---|---|
| **CIS ref** | Section from CIS Apple macOS Sonoma 14 v2.1.0 (mSCP `references.cis.benchmark`) |
| **mSCP rule** | mSCP rule id (filename under `rules/`) |
| **Status** | `T1-implemented` — already in production. `T2-gap` — target for collection expansion. |
| **Title** | mSCP `title` (abbreviated) |
| **Sev** | mSCP `severity` field (`high`/`medium`/`low`). `—` = not set in mSCP. |
| **Proposed `signal_key`** | Slug following `<area>_<topic>` convention. `// TBD` if uncertain. |
| **Collection method** | Key command or reference. `// existing-signal` = already collected by the agent. `// new-collector` = new capability needed. |
| **PII observation** | One sentence on what observing this signal reveals about the device user. |
| **Notes** | Version conditionality, adaptation needed, edge cases. |

---

## Gap table by CIS section

### CIS § 1 — Software Updates, Patches and Additional Security Software

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 1.1 | `system_settings_softwareupdate_current` | **T1-implemented** | Software Update Is Current | medium | `pending_updates_count` | existing signal | None — system state only | Already evaluated by `cis_macos_1_1_pending_security_updates` |
| 1.2 | `system_settings_software_update_enforce` | **T2-gap** | Enforce Software Update Automatically | — | `update_check_auto` | `defaults read com.apple.SoftwareUpdate AutomaticCheckEnabled` | None — system state only | // new-collector; MDM-settable; most managed devices will be `true` |
| 1.3 | `system_settings_software_update_download_enforce` | **T2-gap** | Enforce Auto-Download of Updates | — | `update_download_auto` | `defaults read com.apple.SoftwareUpdate AutomaticDownload` | None — system state only | // new-collector |
| 1.4 | `system_settings_install_macos_updates_enforce` | **T1-implemented** | Enforce macOS Updates Automatically Installed | — | `auto_security_updates` | existing signal | None — system state only | Already evaluated by `cis_macos_1_4_auto_security_updates` |
| 1.5 | `system_settings_software_update_app_update_enforce` | **T2-gap** | Enforce App Store Update Auto-Install | — | `app_updates_auto_install` | `defaults read com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates` | None — system state only | // new-collector |
| 1.6 | `os_config_data_install_enforce` | **T2-gap** | Enforce XProtect/Gatekeeper Data Auto-Update | medium | `xprotect_data_auto_update` | `osascript JXA: NSUserDefaults com.apple.SoftwareUpdate ConfigDataInstall` | None — system state only | // new-collector; checks the `ConfigDataInstall` key; same CIS §1.6 as next row (two sub-checks) |
| 1.6 | `system_settings_critical_update_install_enforce` | **T2-gap** | Enforce Critical Security Update Auto-Install | — | `critical_updates_auto_install` | `osascript JXA: NSUserDefaults com.apple.SoftwareUpdate CriticalUpdateInstall` | None — system state only | // new-collector; checks `CriticalUpdateInstall`; both 1.6 sub-checks can be emitted as separate signals |
| 1.7 | `os_software_update_deferral` | **T2-gap** | Software Update Deferral ≤ ODV Days | — | `update_deferral_days` | `osascript JXA: NSUserDefaults com.apple.applicationaccess enforcedSoftwareUpdateDelay` | None — system state only | // new-collector; CIS L1 ODV = 30 days; MDM-set; `null` if not enforced (treat as 0 = pass) |
| 1.8 | `os_mdm_require` | **patched.im baseline (partial match)** | Enforce MDM Enrollment | medium | `mdm_enrolled` | existing signal | None — enrollment status only | The neutral `Yes` fact does not establish the stricter User Approved MDM state required here. `patched_mdm_enrolment` must not carry the CIS §1.8 identifier. |

**Section 1 subtotals:** 9 rules — 2 T1-implemented, 7 T2-gap.

---

### CIS § 2 — System Preferences

#### § 2.2 — Firewall

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.2.1 | `system_settings_firewall_enable` | **T1-implemented** | Enable macOS Application Firewall | medium | `firewall` | existing signal | None — system state only | Already evaluated by `cis_macos_2_5_2_2_firewall` |
| 2.2.2 | `system_settings_firewall_stealth_mode_enable` | **T2-gap** | Enable Firewall Stealth Mode | medium | `firewall_stealth_mode` | `osascript JXA: NSUserDefaults com.apple.security.firewall EnableStealthMode` (+ fallback: `defaults read /Library/Preferences/com.apple.alf stealthenabled`) | None — system state only | // new-collector; stealth = drops unrequested incoming packets silently |

#### § 2.3 — Sharing and Network Services

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.3.1.1 | `os_airdrop_disable` | **T2-gap** | Disable AirDrop | medium | `airdrop_disabled` | `osascript JXA: NSUserDefaults com.apple.applicationaccess allowAirDrop` → expect `false` | None — system state only | // new-collector; MDM-enforced; unmanaged devices default to allowing Everyone |
| 2.3.1.2 | `system_settings_airplay_receiver_disable` | **T2-gap** | Disable AirPlay Receiver | medium | `airplay_receiver_disabled` | `osascript JXA: NSUserDefaults com.apple.applicationaccess allowAirPlayIncomingRequests` → expect `false` | None — system state only | // new-collector |
| 2.3.2.1 | `system_settings_time_server_configure` | **T2-gap** | Configure Authorized Time Server | medium | `time_server_host` | `osascript JXA: NSUserDefaults com.apple.MCX timeServer` | None — system configuration only | // new-collector; MDM-set; CIS ODV = any authorised NTP server |
| 2.3.2.1 | `system_settings_time_server_enforce` | **T2-gap** | Enforce macOS Time Synchronisation | medium | `time_server_enforced` | `osascript JXA: NSUserDefaults com.apple.timed TMAutomaticTimeOnlyEnabled` → expect `true` | None — system state only | // new-collector; same CIS section as `time_server_host` (two sub-checks) |
| 2.3.2.2 | `os_time_server_enabled` | **T2-gap** | Enable Time Synchronisation Daemon | medium | `timed_running` | `launchctl list \| grep -c com.apple.timed` → expect 1 | None — system state only | // new-collector; checks `com.apple.timed` is running; should always be true on managed devices |
| 2.3.3.1 | `system_settings_screen_sharing_disable` | **T1-implemented** | Disable Screen Sharing and Apple Remote Desktop | medium | `screen_sharing` | existing signal | None — system state only | Already evaluated by `cis_macos_2_4_10_screen_sharing` |
| 2.3.3.2 | `system_settings_smbd_disable` | **T2-gap** | Disable SMB File Sharing | medium | `smbd_disabled` | `launchctl print-disabled system \| grep -c '"com.apple.smbd" => disabled'` → expect 1 | None — system state only | // new-collector |
| 2.3.3.3 | `system_settings_printer_sharing_disable` | **T2-gap** | Disable Printer Sharing | medium | `printer_sharing_disabled` | `cupsctl \| grep -c '_share_printers=0'` | None — system state only | // new-collector |
| 2.3.3.4 | `system_settings_ssh_disable` | **T1-implemented** | Disable Remote Login (SSH) | high | `remote_login` | existing signal | None — system state only | Already evaluated by `cis_macos_2_4_4_remote_login` |
| 2.3.3.5 | `system_settings_remote_management_disable` | **T2-gap** | Disable Remote Management | medium | `remote_management_disabled` | `mdmclient QuerySecurityInfo \| grep -c 'RemoteDesktopEnabled = 0'` → expect 1 | None — system state only | // new-collector; disables Apple Remote Desktop (ARD) agent |
| 2.3.3.6 | `system_settings_rae_disable` | **T1-implemented** | Disable Remote Apple Events | medium | `remote_apple_events` | existing signal | None — system state only | Already evaluated by `cis_macos_2_4_1_remote_apple_events` |
| 2.3.3.7 | `system_settings_internet_sharing_disable` | **T2-gap** | Disable Internet Sharing | medium | `internet_sharing_disabled` | `osascript JXA: NSUserDefaults com.apple.MCX forceInternetSharingOff` → expect `true` | None — system state only | // new-collector; MDM-set; sharing is disabled but MDM enforcement of the lock is what's checked |
| 2.3.3.10 | `system_settings_bluetooth_sharing_disable` | **T2-gap** | Disable Bluetooth Sharing | medium | `bluetooth_sharing_disabled` | `sudo -u $CURRENT_USER defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled` → expect 0 | None — reveals Bluetooth sharing preference, no user content | // new-collector; // needs-user-context (per-user currentHost pref); CURRENT_USER detection needed in collector |
| 2.3.4.2 | `system_settings_time_machine_encrypted_configure` | **T2-gap** | Ensure Time Machine Volumes Are Encrypted | — | `time_machine_encrypted` | `defaults read /Library/Preferences/com.apple.TimeMachine.plist \| grep -c NotEncrypted` → expect 0 | None — backup configuration state only | // new-collector; only meaningful if Time Machine is configured; emit signal only when TM backup exists |

#### § 2.4 — Connectivity Menus

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.4.1 | `system_settings_wifi_menu_enable` | **T2-gap** | Enable Wi-Fi Menu | — | `wifi_menu_visible` | `osascript JXA: NSUserDefaults com.apple.controlcenter WiFi` → expect 18 | None — UI configuration only | // new-collector; CIS rationale: visible so user knows current network state |
| 2.4.2 | `system_settings_bluetooth_menu_enable` | **T2-gap** | Enable Bluetooth Menu | — | `bluetooth_menu_visible` | `osascript JXA: NSUserDefaults com.apple.controlcenter Bluetooth` → expect 18 | None — UI configuration only | // new-collector |

#### § 2.5 — Siri

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.5.1 | `system_settings_siri_disable` | **T2-gap** | Disable Siri | medium | `siri_disabled` | `osascript JXA: NSUserDefaults com.apple.applicationaccess allowAssistant` → expect `false` | None — system state only; whether Siri is enabled does not reveal query content | // new-collector; MDM-enforceable |

#### § 2.6 — Privacy and Security

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.6.4 | `system_settings_personalized_advertising_disable` | **T2-gap** | Disable Personalized Advertising | medium | `personalized_ads_disabled` | `osascript JXA: NSUserDefaults com.apple.applicationaccess allowApplePersonalizedAdvertising` → expect `false` | None — system state only | // new-collector; MDM-enforceable |
| 2.6.5 | `os_gatekeeper_enable` | **T1-implemented** | Enable Gatekeeper | high | `gatekeeper` | existing signal | None — system state only | Already evaluated by `cis_macos_2_5_2_1_gatekeeper` |
| 2.6.6 | `system_settings_filevault_enforce` | **T1-implemented** | Enforce FileVault | high | `filevault` | existing signal | None — disk encryption state only | Already evaluated by `cis_macos_2_5_1_1_filevault` |
| 2.6.8 | `system_settings_system_wide_preferences_configure` | **T2-gap** | Require Admin to Modify System-Wide Preferences | high | `system_prefs_admin_lock` | `security authorizationdb read system.preferences \| xmllint --xpath ...` (checks 8 auth DB sections for `shared=false, group=admin`) | None — system authorisation policy only | // new-collector; complex: checks 8 auth DB entries; collector can emit pass/fail composite |

#### § 2.9 — Energy Saver

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.9.2 | `os_power_nap_disable` | **T2-gap** | Disable Power Nap | — | `power_nap_disabled` | `pmset -g custom \| awk '/powernap/ { sum+=$2 } END {print sum}'` → expect 0 | None — power management state only | // new-collector; Intel + Apple Silicon both checked; AC and battery modes |
| 2.9.3 | `system_settings_wake_network_access_disable` | **T2-gap** | Disable Wake for Network Access | — | `wake_on_network_disabled` | `pmset -g custom \| awk '/womp/ { sum+=$2 } END {print sum}'` → expect 0 | None — power management state only | // new-collector |

#### § 2.10 — Screen Saver / Login Window

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.10.1 | `system_settings_screensaver_timeout_enforce` | **T2-gap** | Enforce Screen Saver Timeout | medium | `screensaver_timeout_seconds` | `osascript JXA: NSUserDefaults com.apple.screensaver idleTime` → expect ≤ 1200 | None — UI timeout policy only | // existing-signal: `screensaver_delay_seconds` is already collected. Rename or alias the existing key. CIS L1 ODV = 1200s (20 min). |
| 2.10.2 | `system_settings_screensaver_ask_for_password_delay_enforce` | **T1-implemented** | Enforce Password After Screen Saver | medium | `screensaver_password` | existing signal | None — system state only | Already evaluated by `cis_macos_2_10_screensaver_password` |
| 2.10.3 | `system_settings_loginwindow_loginwindowtext_enable` | **T2-gap** | Show Custom Login Window Text | — | `loginwindow_text_set` | `osascript JXA: NSUserDefaults com.apple.loginwindow LoginwindowText` (base64 check — any non-empty value = pass) | None — reveals whether a banner is configured; no banner content needed in signal | // new-collector; CIS rationale = legal notice / acceptable-use banner; signal should be bool (configured yes/no) |
| 2.10.4 | `system_settings_loginwindow_prompt_username_password_enforce` | **T2-gap** | Login Window Prompts for Username + Password | medium | `loginwindow_fullname_prompt` | `osascript JXA: NSUserDefaults com.apple.loginwindow SHOWFULLNAME` → expect `true` | None — UI configuration only | // new-collector; prevents list-of-users at login screen |
| 2.10.5 | `system_settings_password_hints_disable` | **T2-gap** | Disable Password Hints at Login Window | medium | `loginwindow_password_hints` | `osascript JXA: NSUserDefaults com.apple.loginwindow RetriesUntilHint` → expect 0 | None — login UI policy; no user content | // new-collector |

#### § 2.11 — Password Hints

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.11.1 | `os_password_hint_remove` | **T2-gap** | Remove Password Hints from User Accounts | medium | `password_hints_absent` | `dscl . -list /Users hint \| awk '{ print $2 }'` → expect empty | Hint existence revealed (not content); reveals whether any user has set a password hint | // new-collector; hint content should NOT be collected — only whether any hint exists (bool) |

#### § 2.12 — Guest Access

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.12.1 | `system_settings_guest_account_disable` | **T2-gap** | Disable the Guest Account | medium | `guest_account_disabled` | `osascript JXA: NSUserDefaults com.apple.MCX DisableGuestAccount+EnableGuestAccount` (composite: both must align) | None — OS-managed guest account state | // new-collector |
| 2.12.2 | `system_settings_guest_access_smb_disable` | **T2-gap** | Disable Guest Access to SMB Shares | — | `smb_guest_disabled` | `defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess` → expect 0 | None — file sharing configuration | // new-collector |
| 2.12.3 | `system_settings_automatic_login_disable` | **T1-implemented** | Disable Automatic Login | medium | `auto_login_user` | existing signal | None — login state only | Already evaluated by `cis_macos_5_1_auto_login_disabled` |

#### § 2.18 — Siri / Dictation

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.18.1 | `os_on_device_dictation_enforce` | **T2-gap** | Enforce On-Device Dictation | medium | `dictation_on_device` | `osascript JXA: NSUserDefaults com.apple.applicationaccess forceOnDeviceOnlyDictation` → expect `true` | None — MDM policy state; does not reveal dictation content | // new-collector; prevents audio from being sent to Apple servers for processing |

**Section 2 subtotals:** 35 rules — 6 T1-implemented (§2.2.1, §2.3.3.1, §2.3.3.4, §2.3.3.6, §2.6.5, §2.6.6, §2.12.3), 29 T2-gap.

---

### CIS § 3 — Logging and Auditing

#### § 3.1 — Enable Security Auditing

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 3.1 | `audit_auditd_enabled` | **T1-implemented** | Enable Security Auditing (auditd) | medium | `audit_logging` | existing signal | None — auditd daemon state only | Already evaluated by `cis_macos_3_x_audit_logging` |

#### § 3.3 — Install Log Retention

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 3.3 | `os_install_log_retention_configure` | **T2-gap** | Configure install.log Retention | medium | `install_log_retention_days` | `aslmanager -dd 2>&1 \| awk '/install.log/ ... TTL'` — extracts TTL from aslmanager output | None — log configuration; no log content collected | // new-collector; CIS L1 ODV = 365 days TTL; check is complex (aslmanager output parsing) |

#### § 3.4 — Audit Log Retention

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 3.4 | `audit_retention_configure` | **T2-gap** | Configure Audit Retention | low | `audit_retention_expire` | `awk -F: '/expire-after/{print $2}' /etc/security/audit_control` | None — log retention policy; no log content | // new-collector; CIS L1 ODV = `60d` (60 days minimum) |

#### § 3.5 — Audit File Permissions (11 controls)

All 11 controls under §3.5 check permissions/ownership of auditd files and directories. They share a common pattern: read a file attribute, compare to expected value. No user identifiers are involved.

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 3.5 | `audit_acls_files_configure` | **T2-gap** | Audit Log Files Have No ACLs | medium | `audit_log_files_acl` | `ls -le $(grep '^dir' /etc/security/audit_control \| awk -F: '{print $2}') \| awk '{print $1}' \| grep -c ":"` → expect 0 | None — filesystem metadata | // new-collector; composite: could be a single signal counting ACL violations |
| 3.5 | `audit_acls_folders_configure` | **T2-gap** | Audit Log Folder Has No ACLs | medium | `audit_log_folder_acl` | `ls -lde /var/audit \| awk '{print $1}' \| grep -c ":"` → expect 0 | None — filesystem metadata | // new-collector |
| 3.5 | `audit_control_acls_configure` | **T2-gap** | audit_control Has No ACLs | medium | `audit_control_acl` | `ls -le /etc/security/audit_control \| awk '{print $1}' \| grep -c ":"` → expect 0 | None — filesystem metadata | // new-collector |
| 3.5 | `audit_control_group_configure` | **T2-gap** | audit_control Group Is wheel | medium | `audit_control_group` | `ls -dn /etc/security/audit_control \| awk '{print $4}'` → expect 0 (GID of wheel) | None — filesystem metadata | // new-collector |
| 3.5 | `audit_control_mode_configure` | **T2-gap** | audit_control Mode ≤ 440 | medium | `audit_control_mode` | `ls -l /etc/security/audit_control \| awk '!/-r--[r-]-----|current|total/{print $1}' \| wc -l` → expect 0 | None — filesystem metadata | // new-collector |
| 3.5 | `audit_control_owner_configure` | **T2-gap** | audit_control Owner Is root | medium | `audit_control_owner` | `ls -dn /etc/security/audit_control \| awk '{print $3}'` → expect 0 (UID of root) | None — filesystem metadata | // new-collector |
| 3.5 | `audit_files_group_configure` | **T2-gap** | Audit Log Files Group Is wheel | medium | `audit_log_files_group` | `ls -n $(audit_dir) \| awk '{s+=$4} END {print s}'` → expect 0 (sum of GIDs = all wheel) | None — filesystem metadata | // new-collector |
| 3.5 | `audit_files_mode_configure` | **T2-gap** | Audit Log Files Mode ≤ 440 | medium | `audit_log_files_mode` | `ls -l $(audit_dir) \| awk '!/-r--r-----|current|total/{print $1}' \| wc -l` → expect 0 | None — filesystem metadata | // new-collector |
| 3.5 | `audit_files_owner_configure` | **T2-gap** | Audit Log Files Owner Is root | medium | `audit_log_files_owner` | `ls -n $(audit_dir) \| awk '{s+=$3} END {print s}'` → expect 0 (sum UIDs = all root) | None — filesystem metadata | // new-collector |
| 3.5 | `audit_folder_group_configure` | **T2-gap** | Audit Log Folder Group Is wheel | medium | `audit_log_folder_group` | `ls -dn $(audit_dir) \| awk '{print $4}'` → expect 0 | None — filesystem metadata | // new-collector |
| 3.5 | `audit_folder_owner_configure` | **T2-gap** | Audit Log Folder Owner Is root | medium | `audit_log_folder_owner` | `ls -dn $(audit_dir) \| awk '{print $3}'` → expect 0 | None — filesystem metadata | // new-collector |
| 3.5 | `audit_folders_mode_configure` | **T2-gap** | Audit Log Folder Mode ≤ 700 | medium | `audit_log_folder_mode` | `stat -f %A $(audit_dir)` → expect 700 | None — filesystem metadata | // new-collector |

Note on §3.5 collection strategy: All 11 controls check the same audit directory (from `grep '^dir' /etc/security/audit_control`). A single collector function can emit all 11 signals in one pass, minimising shell forks.

#### § 3.6 — Firewall Logging

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 3.6 | `os_firewall_log_enable` | **T2-gap** | Enable Firewall Logging | — | `firewall_logging` | `osascript JXA: NSUserDefaults com.apple.security.firewall EnableLogging + LoggingOption` (composite: both must be set) | None — system log configuration | // new-collector; two sub-keys: `EnableLogging=true` AND `LoggingOption` not empty |

**Section 3 subtotals:** 16 rules — 1 T1-implemented, 15 T2-gap.

---

### CIS § 4 — Network Configurations

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 4.2 | `os_httpd_disable` | **T2-gap** | Disable Built-in Web Server (httpd) | medium | `httpd_disabled` | `launchctl print-disabled system \| grep -c '"org.apache.httpd" => disabled'` → expect 1 | None — system state only | // new-collector |
| 4.3 | `os_nfsd_disable` | **T2-gap** | Disable Network File System Service | medium | `nfsd_disabled` | `launchctl print-disabled system \| grep -c '"com.apple.nfsd" => disabled'` → expect 1 | None — system state only | // new-collector |

**Section 4 subtotals:** 2 rules — 0 T1-implemented, 2 T2-gap.

---

### CIS § 5 — System Access, Authentication and Authorization

#### § 5.1 — File System Integrity

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 5.1.1 | `os_home_folders_secure` | **T2-gap** | Secure User Home Folders (mode 700 or 711) | medium | `home_folders_mode` | `find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) \| grep -vE "Shared\|Guest" \| wc -l` → expect 0 | User account presence revealed (count of incorrectly-permissioned home dirs) | // new-collector; reveals number of user accounts with wrong home dir perms; no usernames |
| 5.1.2 | `os_sip_enable` | **T1-implemented** | Enable System Integrity Protection (SIP) | high | `sip` | existing signal | None — system state only | Already evaluated by `cis_macos_2_5_3_sip` |
| 5.1.3 | `os_mobile_file_integrity_enable` | **T2-gap** | Enable Apple Mobile File Integrity (AMFI) | — | `amfi_enabled` | `nvram -p \| grep -c "amfi_get_out_of_my_way=1"` → expect 0 | None — kernel parameter state | // new-collector; AMFI is separate from SIP; checks nvram boot-args; should always be 0 on stock devices |
| 5.1.4 | `os_authenticated_root_enable` | **T1-implemented** | Enable Authenticated Root | medium | `sealed_system_volume` | existing signal | None — system state only | Already covered by `cis_macos_2_5_5_sealed_system_volume` via `csrutil authenticated-root` |
| 5.1.5 | `os_system_wide_applications_configure` | **T2-gap** | No World-Writable System Applications | — | `system_apps_world_writable` | `find /Applications -iname "*.app" -type d -perm -2 -ls \| wc -l` → expect 0 | None — filesystem metadata | // new-collector; count of world-writable .app bundles in /Applications |
| 5.1.6 | `os_world_writable_system_folder_configure` | **T2-gap** | No World-Writable Files in System Folder | — | `system_folder_world_writable` | `find /System/Volumes/Data/System -type d -perm -2 -ls \| grep -vE "downloadDir\|locks" \| wc -l` → expect 0 | None — filesystem metadata | // new-collector |

#### § 5.2 — Password Policy

All `pwpolicy_*` rules use `pwpolicy -getaccountpolicies` which reads MDM-configured account policy XML. The collector already emits `password_policy_raw` (raw XML from this command). These 5 signals can be derived by parsing the existing raw value — no new shell commands needed.

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 5.2.1 | `pwpolicy_account_lockout_enforce` | **T2-gap** | Limit Failed Login Attempts | medium | `pwpolicy_lockout_threshold` | Parse `policyAttributeMaximumFailedAuthentications` from `password_policy_raw` | None — policy metadata only; no passwords | // existing-signal: parse from `password_policy_raw`; CIS L1 ODV = ≤ 5 attempts |
| 5.2.1 | `pwpolicy_account_lockout_timeout_enforce` | **T2-gap** | Set Account Lockout Duration | medium | `pwpolicy_lockout_reset_minutes` | Parse `autoEnableInSeconds` (÷60) from `password_policy_raw` | None — policy metadata only | // existing-signal: parse from `password_policy_raw`; CIS L1 ODV = ≥ 15 minutes |
| 5.2.2 | `pwpolicy_minimum_length_enforce` | **T2-gap** | Require Minimum Password Length | medium | `pwpolicy_min_length` | Parse `policyAttributeMinimumLength` from `password_policy_raw` | None — policy metadata only | // existing-signal: parse from `password_policy_raw`; CIS L1 ODV = ≥ 15 characters; related to but distinct from existing `password_policy_is_default` check |
| 5.2.7 | `pwpolicy_max_lifetime_enforce` | **T2-gap** | Restrict Maximum Password Lifetime | medium | `pwpolicy_max_age_days` | Parse `policyAttributeExpiresEveryNDays` from `password_policy_raw` | None — policy metadata only | // existing-signal: parse from `password_policy_raw`; CIS L1 ODV = ≤ 365 days |
| 5.2.8 | `pwpolicy_history_enforce` | **T2-gap** | Prohibit Password Reuse | medium | `pwpolicy_history_depth` | Parse `policyAttributePasswordHistoryDepth` from `password_policy_raw` | None — policy metadata only | // existing-signal: parse from `password_policy_raw`; CIS L1 ODV = ≥ 15 generations |

#### § 5.4–5.7 — Sudo and Session Control

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 5.4 | `os_sudo_timeout_configure` | **T2-gap** | Configure Sudo Timeout | medium | `sudo_timeout_minutes` | `sudo -V \| grep -c "Authentication timestamp timeout: 0.0 minutes"` → expect 1 (CIS L1 ODV = 0 minutes — no cached credentials) | None — system policy state | // new-collector; 0-minute timeout forces re-auth per sudo invocation |
| 5.5 | `os_sudoers_timestamp_type_configure` | **T2-gap** | Configure Sudoers Timestamp Type | medium | `sudo_timestamp_type` | `sudo -V \| awk -F': ' '/Type of authentication timestamp record/{print $2}'` → expect `tty` | None — system policy state | // new-collector; tty-scoped timestamp prevents cross-terminal privilege escalation |
| 5.6 | `os_root_disable` | **T2-gap** | Disable Root Login | medium | `root_disabled` | `dscl . -read /Users/root UserShell 2>&1 \| grep -c "/usr/bin/false"` → expect 1 | None — system account state | // new-collector; root shell should be /usr/bin/false on all managed devices |
| 5.7 | `os_unlock_active_user_session_disable` | **T2-gap** | Disable Unlock of Another User's Session | medium | `screensaver_unlock_group` | `security authorizationdb read system.login.screensaver 2>&1 \| grep -c '<string>authenticate-session-owner-or-admin</string>'` | None — authorisation policy only; no user identifiers | // new-collector; checks the screensaver unlock auth group; emit the actual group name rather than a bool for richer evaluation |

#### § 5.9–5.10 — Guest and Antivirus

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 5.9 | `os_guest_folder_removed` | **T2-gap** | Remove Guest Home Folder | — | `guest_folder_absent` | `ls /Users/ \| grep -c "Guest"` → expect 0 | None — OS-managed folder presence | // new-collector; `/Users/Guest` is an Apple-managed folder; should be absent when Guest account is disabled |
| 5.10 | `os_anti_virus_installed` | **T2-gap** | Approved Antivirus Must Be Running | high | `xprotect_running` | `launchctl list \| grep -cE "(com.apple.XprotectFramework.PluginService$\|com.apple.XProtect.daemon.scan$)"` → expect 2 | None — system service state | // new-collector; checks XProtect launchd services are running (not just installed). Collector already emits `xprotect_version` — that's version not daemon state; // existing-signal: `xprotect_version` is a close proxy but not identical |

**Section 5 subtotals:** 17 rules — 2 T1-implemented (§5.1.2, §5.1.4), 15 T2-gap.

---

### CIS § 6 — User Accounts and Environment

| CIS ref | mSCP rule | Status | Title | Sev | Proposed `signal_key` | Collection method | PII observation | Notes |
|---|---|---|---|---|---|---|---|---|
| 6.1.1 | `os_show_filename_extensions_enable` | **T2-gap** | Show All Filename Extensions | — | `show_file_extensions` | `sudo -u $CURRENT_USER defaults read .GlobalPreferences AppleShowAllExtensions 2>/dev/null` → expect 1 | None — per-user Finder preference; reveals nothing about file content | // new-collector; // needs-user-context (per-user pref); CURRENT_USER detection needed; macOS hides extensions by default which aids social engineering |
| 6.3.1 | `os_safari_open_safe_downloads_disable` | **T2-gap** | Disable Auto-Open of Safe Downloads in Safari | — | `safari_auto_open_downloads_disabled` | `profiles -P -o stdout \| grep -c 'AutoOpenSafeDownloads = 0'` → expect ≥ 1 | None — Safari profile policy; no browsing data | // new-collector; MDM profile required; checks deployed profile output |
| 6.3.3 | `os_safari_warn_fraudulent_website_enable` | **T2-gap** | Warn When Visiting Fraudulent Website in Safari | — | `safari_fraudulent_warning` | `profiles -P -o stdout \| grep -c 'WarnAboutFraudulentWebsites = 1'` → expect ≥ 1 | None — Safari profile policy; no browsing data | // new-collector; MDM profile required |
| 6.3.4 | `os_safari_prevent_cross-site_tracking_enable` | **T2-gap** | Prevent Cross-Site Tracking in Safari | — | `safari_cross_site_tracking_blocked` | `profiles -P -o stdout \| grep -cE 'WebKitPreferences.storageBlockingPolicy = 1\|WebKitStorageBlockingPolicy = 1\|BlockStoragePolicy = 2'` → expect ≥ 1 | None — Safari profile policy; no browsing data | // new-collector; MDM profile required |
| 6.3.6 | `os_safari_advertising_privacy_protection_enable` | **T2-gap** | Enable Safari Advertising Privacy Protection | — | `safari_private_measurement` | `profiles -P -o stdout \| grep -c 'WebKitPreferences.privateClickMeasurementEnabled = 1'` → expect ≥ 1 | None — Safari profile policy; no browsing data | // new-collector; MDM profile required |
| 6.3.7 | `os_safari_show_full_website_address_enable` | **T2-gap** | Show Full Website Address in Safari | — | `safari_full_url_shown` | `profiles -P -o stdout \| grep -c 'ShowFullURLInSmartSearchField = 1'` → expect ≥ 1 | None — Safari profile policy; no browsing data | // new-collector; MDM profile required |
| 6.3.10 | `os_safari_show_status_bar_enabled` | **T2-gap** | Show Status Bar in Safari | — | `safari_status_bar_shown` | `profiles -P -o stdout \| grep -c 'ShowOverlayStatusBar = 1'` → expect ≥ 1 | None — Safari profile policy; no browsing data | // new-collector; MDM profile required |
| 6.4.1 | `os_terminal_secure_keyboard_enable` | **T2-gap** | Enable Secure Keyboard Entry in Terminal | — | `terminal_secure_keyboard` | `sudo -u $CURRENT_USER defaults read com.apple.Terminal SecureKeyboardEntry` → expect 1 | None — per-user Terminal preference; no session content | // new-collector; // needs-user-context; prevents other apps reading keystrokes in Terminal |

**Section 6 subtotals:** 8 rules — 0 T1-implemented, 8 T2-gap.

---

### Supplemental rules (3 — manual / documentation)

These are in the mSCP CIS L1 baseline but are documentation or guidance for manual audits — not automated checks. No new signals needed.

| mSCP rule | Title | Type | Notes |
|---|---|---|---|
| `supplemental_cis_manual` | CIS Manual Recommendations | List of ~19 manual-audit items | Covers §2.1 (iCloud audit), §2.3.3.11 (computer name PII), §2.6 (privacy audits), §2.9.1.1 (standby on Intel), §2.11.2 (Touch ID), §2.13–2.17 (various settings audits). These require human review, not automated signals. |
| `supplemental_filevault` | FileVault Supplemental | Implementation guidance | Guidance document for the FileVault enforcement process. The underlying control (`system_settings_filevault_enforce`) is T1-implemented. |
| `supplemental_password_policy` | Password Policy Supplemental | Policy guidance | Notes on NIST SP-800-63b alignment (no complexity requirements, no mandatory rotation). Relevant context for evaluator policy in ADR action item 3. |

---

## Custom T1 controls (patched.im baseline — no mSCP L1 equivalent)

These three controls are T1-implemented and already in production, but have no direct counterpart in the mSCP CIS L1 baseline. They are not counted in the 90 mSCP rules.

| rule_key | Title | Signal key | Rationale for inclusion |
|---|---|---|---|
| `cis_macos_5_8_local_admin_count` | Limit local administrator accounts | `local_admin_count` | Not in mSCP L1 as a specific rule, but widely expected by auditors. Proxy check for principle of least privilege — no mSCP check exists because CIS doesn't mandate a specific admin count threshold (it's org-defined). |
| `cis_macos_5_x_secure_boot_arm64` | Apple Silicon Secure Boot integrity | `secure_boot` | Arm64-specific; mSCP covers SIP and AMFI but not Secure Boot policy directly in L1. Checks `bputil --display-all-policies` for "Pairing Integrity". |
| `cis_macos_5_x_password_policy_non_default` | Password policy is not Apple default | `password_policy_is_default` | patched.im-specific heuristic: detects the Apple out-of-box 4-char fallback policy. mSCP's `pwpolicy_minimum_length_enforce` (§5.2.2) covers a strict minimum-length check; this is a different (simpler) signal for quick detection of completely unmanaged devices. Both can coexist. |

---

## Implementation notes

- **§3.5 audit permissions (11 rules):** All derive from the same audit directory path. A single collector function can emit all 11 signals in one pass — implement as a group in the collector refactor.

- **Password policy rules (§5.2 — 5 rules):** All parseable from the existing `password_policy_raw` field. No new shell invocation needed. The extractor or a new collector post-processing step can parse the XML and emit the 5 numeric signals.

- **§2.10.1 screensaver timeout:** Already collected as `screensaver_delay_seconds`. Either re-key this in compliance_rules using the existing signal_key, or rename/alias the existing key when adding the compliance rule.

- **User-context rules:** Three controls require per-user preference reads (`show_file_extensions` §6.1.1, `terminal_secure_keyboard` §6.4.1, `bluetooth_sharing_disabled` §2.3.3.10). These need `$CURRENT_USER` detection in the collector. Pattern: `stat -f %Su /dev/console` to identify the console user; fall back to empty if none.

- **Safari profile rules (§6.3 — 6 rules):** All use `profiles -P -o stdout`. This reads deployed MDM profiles. If no MDM Safari profile is deployed, all 6 will read as "not configured" (fail). Collect as a group in a single `profiles -P -o stdout` pass.

- **osascript JXA checks:** Many T2 controls use JavaScript for Automation via `osascript -l JavaScript`. These read from `NSUserDefaults` (managed preferences) and work correctly when run as root. The collector doesn't currently use osascript — adding it is a new dependency but straightforward.

- **`// TBD` items:** No signal_keys were left as `// TBD`. All 73 gap controls have a proposed slug. Review the slugs for §3.5 (11 audit permission rules) — if they feel too granular as separate signals, they could be collapsed to a single `audit_permissions_ok` composite bool, trading resolution for simplicity. Andy to decide before collector refactor.

- **`// needs-review` items:** None — all gap rules have a clear collection method from mSCP's `check` field. The most complex is `system_prefs_admin_lock` (§2.6.8), which checks 8 auth DB entries — the collector can emit a pass/fail composite rather than the raw auth DB state.

---

## Cross-cutting observations

1. **Software update fragmentation (§1):** CIS L1 splits update enforcement across 5 separate keys in `com.apple.SoftwareUpdate` (AutomaticCheckEnabled, AutomaticDownload, AutomaticallyInstallMacOSUpdates, AutomaticallyInstallAppUpdates, CriticalUpdateInstall) plus a separate XProtect/Gatekeeper data update (ConfigDataInstall). Our existing `auto_security_updates` signal maps to §1.4 (macOS updates) but misses 4 adjacent controls. The §1 group is high-priority for the first collection batch — all 6 gap signals are `defaults read`-style, low risk.

2. **Sharing services cluster (§2.3.3):** Five sharing-disable controls beyond our existing SSH/Screen Sharing/RAE signals — SMB, Printer, Remote Management, Internet Sharing, Bluetooth Sharing. All use `launchctl`, `cupsctl`, or `mdmclient` — already-familiar patterns in the collector. Screen Sharing (T1) and SSH (T1) are there; the rest are a natural batch.

3. **Audit log permissions group (§3.5 — 11 controls):** The largest single CIS subsection. All 11 rules check the same `/var/audit` directory tree. A single well-structured collector function can emit all 11 signals in one pass. Despite the count, this is low complexity per control.

4. **Password policy signals already latent:** `password_policy_raw` is already collected but not evaluated. Five new T2 signals (lockout threshold, lockout timeout, min length, max age, history depth) can be derived from it by parsing the XML — no new shell invocations. This is the highest-leverage T2 batch: 5 compliance signals from zero new collection cost.

5. **Safari profile signals (§6.3 — 6 controls):** All read from `profiles -P -o stdout`. If no Safari profile is deployed, all 6 fail. Worth noting in the evaluator policy design (action item 3) that these signals are MDM-profile-dependent — unmanaged devices will fail by design, which is the correct compliance outcome.

6. **osascript dependency:** 25+ T2 controls use `osascript JXA` (JavaScript for Automation) to read `NSUserDefaults` managed preferences. The collector doesn't currently use osascript. The collector refactor (action item 2) should add a reusable `read_managed_pref <domain> <key>` helper function built on `osascript -l JavaScript`. This unlocks the entire §2 gap batch.

7. **User-context dependency is minimal:** Only 3 controls require per-user context (§2.3.3.10, §6.1.1, §6.4.1). All others work correctly as root. The `stat -f %Su /dev/console` pattern for console-user detection is already well-understood in macOS scripting.

8. **Severity gaps in mSCP:** 22 of the 73 T2 gap controls have no `severity` field set in the mSCP YAML. The evaluator schema requires a severity for every rule. CIS benchmark PDFs assign these (typically `low` or `medium`). In the absence of the CIS PDF, assign `medium` as the default when writing the migration — revisit against the official benchmark before enabling for any tenant. Flag in the SQL INSERT comment.
