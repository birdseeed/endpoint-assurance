package remediation

// Curated remediation mappings. Deliberately a small, confidently-sourced
// subset of the seeded compliance_rules (migrations/0003, 0019 and later) —
// not an attempt to cover every rule. A rule_key absent from these maps
// returns ErrNoMapping rather than a guessed-at profile/policy payload; see
// the package doc comment.
//
// Each entry documents the real Apple configuration-profile key or the real
// Intune/Policy-CSP setting it targets, and why that key's target value
// corresponds to the compliance_rules row's PASS condition (which is not
// always the same string the collector's signal reports — e.g. Gatekeeper's
// signal is the text output of `spctl --status`, but the real profile key is
// a boolean).
//
// Source citation convention (PAT-1827 and after): every entry added from
// this point on carries a `// Source: <url>` comment immediately above it,
// citing the exact developer.apple.com Configuration Profile Reference page
// or learn.microsoft.com Policy CSP page the key/settingDefinitionId and its
// enable/disable semantics were verified against, so the mapping is
// spot-checkable later without re-deriving it from memory. The original 10
// entries below predate this convention and don't carry one; do not treat
// their absence of a citation as licence to add a new entry without one.

// macOSSetting is one PayloadContent key/value pair inside a generated
// .mobileconfig payload dict. Kind selects how Value is rendered in the
// plist (a plist <string>/<true/false/>/<integer> element).
type macOSSetting struct {
	Key   string
	Kind  string // "string" | "bool" | "int"
	Value string // decimal for "int"; "true"/"false" for "bool"
}

// macOSPayloadSpec is the curated remediation payload for one macOS
// compliance_rules.rule_key.
type macOSPayloadSpec struct {
	PayloadType string // real Apple configuration-profile payload type
	Settings    []macOSSetting
	Rationale   string // embedded in the generated profile's PayloadDescription
}

// macOSMappings covers 5 of the 16 seeded macOS T1 rules (0003_compliance_rules.sql;
// corrected from a prior "17" here — recounted directly against the
// migration for PAT-1827) — the ones with a real, single-key-or-few-key
// Apple profile payload this ticket can state with confidence. The rest have
// no such mapping and are reported as deferred follow-up, not guessed at:
//
//   - SIP, Gatekeeper's sibling controls needing recovery-mode changes,
//     local admin count, password policy, MDM enrolment itself, sealed
//     system volume, secure boot: no profile equivalent (pre-PAT-1827).
//   - remote_login (SSH) and screen_sharing (VNC): Sharing-pane services
//     toggled via `systemsetup`/launchd, no Configuration Profile Reference
//     payload key (pre-PAT-1827).
//   - cis_macos_2_4_1_remote_apple_events (PAT-1827): investigated and
//     deferred — architecturally identical to remote_login/screen_sharing
//     above (a Sharing-pane service toggled via `systemsetup
//     -setremoteappleevents`/launchd), and developer.apple.com's Restrictions
//     and profile-specific payload references have no Apple Events/eppc key.
//   - cis_macos_5_1_auto_login_disabled (PAT-1827): investigated and
//     deferred — the only documented com.apple.loginwindow key in this area
//     is DisableFDEAutoLogin, which suppresses the FileVault pre-boot
//     auto-login bypass specifically. It does not clear or prohibit the
//     `autoLoginUser` preference the rule's signal actually reads, so it is
//     not equivalent to the rule's PASS condition and would misrepresent
//     what the artefact does. No key exists for autoLoginUser itself.
//   - cis_macos_3_x_audit_logging (PAT-1827): investigated and deferred —
//     no Configuration Profile Reference payload configures BSM audit
//     (audit_control); the closest candidate, the SystemLogging payload,
//     governs unified logging (os_log) verbosity, a different subsystem.
//     Apple's own developer forums additionally state the BSM audit(4)
//     subsystem has been deprecated since macOS 11 and disabled since
//     macOS 14, which would make any such mapping moot on current macOS
//     even if a key existed.
//   - cis_macos_1_1_pending_security_updates (PAT-1827): investigated and
//     deferred — this rule asserts a point-in-time count (pending update
//     backlog), not a configurable setting. There is no profile payload
//     that declares "zero pending updates"; the only way to affect this is
//     to actuate an install (an MDM command, e.g. ScheduleOSUpdate), which
//     is a different artefact shape than the declarative profiles this
//     package generates and out of this ticket's scope.
var macOSMappings = map[string]macOSPayloadSpec{
	"cis_macos_2_5_1_1_filevault": {
		PayloadType: "com.apple.MCX.FileVault2",
		Settings: []macOSSetting{
			{Key: "Enable", Kind: "string", Value: "On"},
			{Key: "Defer", Kind: "bool", Value: "true"},
		},
		Rationale: "Enables FileVault at next login with deferred activation, matching the rule's expected_values ['On'] for the filevault signal.",
	},
	"cis_macos_2_5_2_1_gatekeeper": {
		PayloadType: "com.apple.systempolicy.control",
		Settings: []macOSSetting{
			{Key: "EnableAssessment", Kind: "bool", Value: "true"},
		},
		Rationale: "EnableAssessment=true is the real Gatekeeper profile key; the rule's signal is the text output of `spctl --status` ('assessments enabled'), a different representation of the same control.",
	},
	"cis_macos_2_5_2_2_firewall": {
		PayloadType: "com.apple.security.firewall",
		Settings: []macOSSetting{
			{Key: "EnableFirewall", Kind: "bool", Value: "true"},
		},
		Rationale: "EnableFirewall=true turns on the Application Layer Firewall, matching the rule's expected 'enabled' state for the firewall signal.",
	},
	"cis_macos_2_10_screensaver_password": {
		PayloadType: "com.apple.screensaver",
		Settings: []macOSSetting{
			{Key: "askForPassword", Kind: "int", Value: "1"},
			{Key: "askForPasswordDelay", Kind: "int", Value: "0"},
		},
		Rationale: "askForPassword=1 with zero grace delay is the profile-key equivalent of the rule's expected 'Yes' screensaver_password state.",
	},
	"cis_macos_1_4_auto_security_updates": {
		PayloadType: "com.apple.SoftwareUpdate",
		Settings: []macOSSetting{
			{Key: "AutomaticCheckEnabled", Kind: "bool", Value: "true"},
			{Key: "AutomaticDownload", Kind: "bool", Value: "true"},
			{Key: "ConfigDataInstall", Kind: "bool", Value: "true"},
			{Key: "CriticalUpdateInstall", Kind: "bool", Value: "true"},
		},
		Rationale: "Enables automatic background download and install of critical/security updates, matching the rule's expected 'On' auto_security_updates state.",
	},
}

// windowsSettingSpec is the curated Intune settings-catalogue mapping for
// one Windows compliance_rules.rule_key. DefinitionID is the real
// Policy-CSP-derived settingDefinitionId Intune's settings catalogue uses;
// EnabledOptionSuffix is the choice-option suffix Graph appends to it for
// the "enabled" choice value (documented deviceManagementConfiguration
// shape: "<definitionId>_<optionIndex>").
type windowsSettingSpec struct {
	DefinitionID        string
	EnabledOptionSuffix string
	Rationale           string
}

// windowsMappings covers 10 of the 12 seeded Windows T1 rules
// (0019_windows_cis_l1_rules.sql) — the ones whose settingDefinitionId this
// ticket can state with confidence from the documented Policy CSP paths
// they derive from. The rest are deferred, not guessed at:
//
//   - cis_win_18_9_102_auto_updates (PAT-1827): investigated and deferred.
//     The underlying CSP (Update/AllowAutoUpdate) is real and documented,
//     but it's a 6-way enumeration, not a two-state toggle, and the Intune
//     settings-catalogue choice-option index does NOT equal the CSP's own
//     literal integer value for this setting — catalogue option "5" ("Auto
//     install and restart without end-user control") corresponds to the
//     documented literal value 4, an off-by-one that only shows up once you
//     inspect the catalogue's actual option list, not the Policy CSP page
//     alone. learn.microsoft.com/.../policy-csp-update (this ticket's
//     authorised source) documents the literal CSP values, not the
//     catalogue's internal option ordering, so the correct option suffix
//     can't be confidently stated from it. Shipping the wrong suffix here
//     silently selects a different update-install behaviour on a real
//     customer's Intune tenant. Needs verification against a live tenant
//     or Graph response before mapping, which is outside this ticket.
//   - cis_win_19_1_3_4_screensaver_timeout (PAT-1827): investigated and
//     deferred. CPL_Personalization_ScreenSaverTimeOut
//     (policy-csp-admx-controlpaneldisplay) is real, but it's a genuine
//     integer value (1-86400 seconds), not an enable/disable choice. The
//     Intune settings-catalogue models integer-valued settings as a
//     deviceManagementConfigurationSimpleSettingInstance/IntegerSettingValue,
//     a different JSON shape than the
//     ChoiceSettingInstance/ChoiceSettingValue this package's
//     buildIntuneSettingsCatalogue (internal/remediation/intune.go) always
//     emits. Representing it correctly needs a generator code change (a
//     new windowsSettingSpec variant for simple/integer settings), which is
//     beyond a mapping-only ticket — flagged as a follow-up rather than
//     forced into the wrong shape.
var windowsMappings = map[string]windowsSettingSpec{
	"cis_win_18_10_11_bitlocker_os_drive": {
		DefinitionID:        "device_vendor_msft_bitlocker_requiredeviceencryption",
		EnabledOptionSuffix: "1",
		Rationale:           "BitLocker/RequireDeviceEncryption Policy CSP, matching the rule's expected 'On' bitlocker_os_drive state.",
	},
	"cis_win_9_1_1_firewall_domain": {
		DefinitionID:        "device_vendor_msft_firewall_mdmstore_domainprofile_enablefirewall",
		EnabledOptionSuffix: "1",
		Rationale:           "Firewall/MdmStore/DomainProfile/EnableFirewall Policy CSP, matching the rule's expected 'enabled' windows_firewall_domain state.",
	},
	"cis_win_9_2_1_firewall_private": {
		DefinitionID:        "device_vendor_msft_firewall_mdmstore_privateprofile_enablefirewall",
		EnabledOptionSuffix: "1",
		Rationale:           "Firewall/MdmStore/PrivateProfile/EnableFirewall Policy CSP, matching the rule's expected 'enabled' windows_firewall_private state.",
	},
	"cis_win_9_3_1_firewall_public": {
		DefinitionID:        "device_vendor_msft_firewall_mdmstore_publicprofile_enablefirewall",
		EnabledOptionSuffix: "1",
		Rationale:           "Firewall/MdmStore/PublicProfile/EnableFirewall Policy CSP, matching the rule's expected 'enabled' windows_firewall_public state.",
	},
	"cis_win_18_9_45_defender_realtime": {
		DefinitionID:        "device_vendor_msft_policy_config_defender_allowrealtimemonitoring",
		EnabledOptionSuffix: "1",
		Rationale:           "Defender/AllowRealtimeMonitoring Policy CSP, matching the rule's expected 'enabled' defender_realtime state.",
	},

	// Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#localpoliciessecurityoptions-microsoftnetworkclient-digitallysigncommunicationsalways
	"cis_win_2_3_8_1_smb_signing": {
		DefinitionID:        "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways",
		EnabledOptionSuffix: "1",
		Rationale:           "LocalPoliciesSecurityOptions/MicrosoftNetworkClient_DigitallySignCommunicationsAlways Policy CSP (int, 0=Disable default, 1=Enable) is the direct MDM equivalent of the 'Microsoft network client: Digitally sign communications (always)' security option the rule's RequireSecuritySignature/smb_signing_required signal reads; 1 matches the rule's expected 'Yes'.",
	},
	// Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#localpoliciessecurityoptions-useraccountcontrol-runalladministratorsinadminapprovalmode
	"cis_win_2_3_17_1_uac_enabled": {
		DefinitionID:        "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode",
		EnabledOptionSuffix: "1",
		Rationale:           "LocalPoliciesSecurityOptions/UserAccountControl_RunAllAdministratorsInAdminApprovalMode Policy CSP (sint32) is the MDM equivalent of EnableLUA: 'Not configured' disables Admin Approval Mode and all related UAC policy settings, 'Enabled' (1) activates it, matching the rule's expected 'Yes' uac_enabled state.",
	},
	// Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktopservices (AllowUsersToConnectRemotely)
	"cis_win_18_10_56_2_rdp_disabled": {
		DefinitionID:        "device_vendor_msft_policy_config_remotedesktopservices_allowuserstoconnectremotely",
		EnabledOptionSuffix: "0",
		Rationale:           "RemoteDesktopServices/AllowUsersToConnectRemotely Policy CSP, ADMX-backed (TS_DISABLE_CONNECTIONS/TerminalServer.admx): 'If you disable this policy setting, users can't connect remotely... won't accept any new incoming connections'. The option-0 (Disabled) state is the one that denies RDP, matching the rule's expected 'disabled' remote_desktop_enabled state (fDenyTSConnections=1). Note the suffix here is 0/Disabled, not 1/Enabled, because the rule's PASS condition is the policy in its disabled state, not enabled: the opposite direction from every other entry in this map.",
	},
	// Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay (CPL_Personalization_EnableScreenSaver)
	"cis_win_19_1_3_2_screensaver_enabled": {
		DefinitionID:        "user_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_enablescreensaver",
		EnabledOptionSuffix: "1",
		Rationale:           "ADMX_ControlPanelDisplay/CPL_Personalization_EnableScreenSaver Policy CSP, ADMX-backed (ControlPanelDisplay.admx, registry value ScreenSaveActive): 'If you enable it, a screen saver runs', matching the rule's expected 'Yes' screensaver_enabled state. This setting is User-scoped only (no Device scope exists for it), hence the user_vendor_msft_ prefix rather than device_vendor_msft_ used elsewhere in this map.",
	},
	// Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay (CPL_Personalization_ScreenSaverIsSecure)
	"cis_win_19_1_3_3_screensaver_password": {
		DefinitionID:        "user_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_screensaverissecure",
		EnabledOptionSuffix: "1",
		Rationale:           "ADMX_ControlPanelDisplay/CPL_Personalization_ScreenSaverIsSecure Policy CSP, ADMX-backed (ControlPanelDisplay.admx, registry value ScreenSaverIsSecure): 'If you enable this setting, all screen savers are password protected', matching the rule's expected 'Yes' screensaver_password_required state. User-scoped only, same user_vendor_msft_ prefix note as the sibling EnableScreenSaver entry above.",
	},
}
