package remediation

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
}

func TestGenerate_MacOS_MappedRule_ProducesWellFormedMobileconfig(t *testing.T) {
	in := GenerateInput{
		TenantID: "11111111-1111-1111-1111-111111111111",
		DeviceID: "22222222-2222-2222-2222-222222222222",
		Rule: RuleContext{
			RuleID:           "33333333-3333-3333-3333-333333333333",
			RuleKey:          "cis_macos_2_5_1_1_filevault",
			Title:            "Enable FileVault",
			Platform:         "macos",
			BenchmarkVersion: "v3.0.0",
		},
		GeneratedAt: mustTime(t),
	}

	res, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Platform != "macos" {
		t.Fatalf("Platform = %q, want macos", res.Platform)
	}
	if res.ContentHash == "" || len(res.ContentHash) != 64 {
		t.Fatalf("ContentHash = %q, want 64-char hex sha256", res.ContentHash)
	}

	body := string(res.Payload)
	for _, want := range []string{
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
		"<!DOCTYPE plist PUBLIC",
		"com.apple.MCX.FileVault2",
		"<key>Enable</key>",
		"<string>On</string>",
		"PayloadOrganization",
		"Patched.im Ltd",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("mobileconfig missing expected content %q\n---\n%s", want, body)
		}
	}
	// No AI/shippable-copy em dash in generated user-visible strings.
	if strings.ContainsRune(body, '—') {
		t.Errorf("mobileconfig payload must not contain an em dash")
	}
}

func TestGenerate_MacOS_Deterministic(t *testing.T) {
	in := GenerateInput{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Rule: RuleContext{
			RuleKey:          "cis_macos_2_5_2_1_gatekeeper",
			Title:            "Enable Gatekeeper",
			Platform:         "macos",
			BenchmarkVersion: "v3.0.0",
		},
		GeneratedAt: mustTime(t),
	}
	a, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate #1: %v", err)
	}
	b, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate #2: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Fatalf("identical inputs produced different content hashes: %s vs %s", a.ContentHash, b.ContentHash)
	}
}

func TestGenerate_MacOS_UnmappedRule_ReturnsErrNoMapping(t *testing.T) {
	in := GenerateInput{
		TenantID: "t",
		DeviceID: "d",
		Rule: RuleContext{
			RuleKey:  "cis_macos_2_5_3_sip", // deliberately not in macOSMappings
			Platform: "macos",
		},
		GeneratedAt: mustTime(t),
	}
	_, err := Generate(in)
	if !errors.Is(err, ErrNoMapping) {
		t.Fatalf("Generate = %v, want ErrNoMapping", err)
	}
}

func TestGenerate_Windows_MappedRule_ProducesWellFormedIntunePayload(t *testing.T) {
	in := GenerateInput{
		TenantID: "t",
		DeviceID: "d",
		Rule: RuleContext{
			RuleKey:          "cis_win_18_10_11_bitlocker_os_drive",
			Title:            "Enable BitLocker on the OS drive",
			Platform:         "windows",
			BenchmarkVersion: "v2.0.0",
		},
		GeneratedAt: mustTime(t),
	}

	res, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Platform != "windows" {
		t.Fatalf("Platform = %q, want windows", res.Platform)
	}

	var doc map[string]any
	if err := json.Unmarshal(res.Payload, &doc); err != nil {
		t.Fatalf("payload is not valid JSON: %v\n%s", err, res.Payload)
	}
	if doc["platforms"] != "windows10" {
		t.Errorf("platforms = %v, want windows10", doc["platforms"])
	}
	if doc["technologies"] != "mdm" {
		t.Errorf("technologies = %v, want mdm", doc["technologies"])
	}
	settings, ok := doc["settings"].([]any)
	if !ok || len(settings) != 1 {
		t.Fatalf("settings = %v, want a single-element array", doc["settings"])
	}
	settingInstance := settings[0].(map[string]any)["settingInstance"].(map[string]any)
	if settingInstance["settingDefinitionId"] != "device_vendor_msft_bitlocker_requiredeviceencryption" {
		t.Errorf("settingDefinitionId = %v, want device_vendor_msft_bitlocker_requiredeviceencryption", settingInstance["settingDefinitionId"])
	}
	choiceValue := settingInstance["choiceSettingValue"].(map[string]any)
	if choiceValue["value"] != "device_vendor_msft_bitlocker_requiredeviceencryption_1" {
		t.Errorf("choiceSettingValue.value = %v, want the _1 (enabled) option", choiceValue["value"])
	}
	provenance, ok := doc["_patched_provenance"].(map[string]any)
	if !ok {
		t.Fatalf("_patched_provenance missing or wrong shape: %v", doc["_patched_provenance"])
	}
	if provenance["rule_key"] != "cis_win_18_10_11_bitlocker_os_drive" {
		t.Errorf("_patched_provenance.rule_key = %v", provenance["rule_key"])
	}
}

// windowsMappedRuleCases covers every new curated mapping added for
// PAT-1827: each case asserts the generated settingDefinitionId and the
// choice value the generator selects for the rule's PASS condition
// (spot-checking that the EnabledOptionSuffix is actually applied, since
// cis_win_18_10_56_2_rdp_disabled's PASS state is the policy's *disabled*
// option, the reverse of every pre-PAT-1827 entry).
func TestGenerate_Windows_MappedRule_NewMappings(t *testing.T) {
	cases := []struct {
		name             string
		ruleKey          string
		wantDefinitionID string
		wantChoiceValue  string
	}{
		{
			name:             "smb_signing",
			ruleKey:          "cis_win_2_3_8_1_smb_signing",
			wantDefinitionID: "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways",
			wantChoiceValue:  "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways_1",
		},
		{
			name:             "uac_enabled",
			ruleKey:          "cis_win_2_3_17_1_uac_enabled",
			wantDefinitionID: "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode",
			wantChoiceValue:  "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode_1",
		},
		{
			name:             "rdp_disabled",
			ruleKey:          "cis_win_18_10_56_2_rdp_disabled",
			wantDefinitionID: "device_vendor_msft_policy_config_remotedesktopservices_allowuserstoconnectremotely",
			wantChoiceValue:  "device_vendor_msft_policy_config_remotedesktopservices_allowuserstoconnectremotely_0",
		},
		{
			name:             "screensaver_enabled",
			ruleKey:          "cis_win_19_1_3_2_screensaver_enabled",
			wantDefinitionID: "user_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_enablescreensaver",
			wantChoiceValue:  "user_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_enablescreensaver_1",
		},
		{
			name:             "screensaver_password",
			ruleKey:          "cis_win_19_1_3_3_screensaver_password",
			wantDefinitionID: "user_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_screensaverissecure",
			wantChoiceValue:  "user_vendor_msft_policy_config_admx_controlpaneldisplay_cpl_personalization_screensaverissecure_1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := GenerateInput{
				TenantID: "t",
				DeviceID: "d",
				Rule: RuleContext{
					RuleKey:          c.ruleKey,
					Title:            "test rule",
					Platform:         "windows",
					BenchmarkVersion: "v2.0.0",
				},
				GeneratedAt: mustTime(t),
			}

			res, err := Generate(in)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			var doc map[string]any
			if err := json.Unmarshal(res.Payload, &doc); err != nil {
				t.Fatalf("payload is not valid JSON: %v\n%s", err, res.Payload)
			}
			settings, ok := doc["settings"].([]any)
			if !ok || len(settings) != 1 {
				t.Fatalf("settings = %v, want a single-element array", doc["settings"])
			}
			settingInstance := settings[0].(map[string]any)["settingInstance"].(map[string]any)
			if settingInstance["settingDefinitionId"] != c.wantDefinitionID {
				t.Errorf("settingDefinitionId = %v, want %v", settingInstance["settingDefinitionId"], c.wantDefinitionID)
			}
			choiceValue := settingInstance["choiceSettingValue"].(map[string]any)
			if choiceValue["value"] != c.wantChoiceValue {
				t.Errorf("choiceSettingValue.value = %v, want %v", choiceValue["value"], c.wantChoiceValue)
			}

			// Same shippable-copy rule the macOS test enforces: no em dash
			// in generated user-visible strings (Description embeds Rationale).
			if strings.ContainsRune(string(res.Payload), '—') {
				t.Errorf("Intune payload must not contain an em dash")
			}
		})
	}
}

func TestGenerate_Windows_UnmappedRule_ReturnsErrNoMapping(t *testing.T) {
	in := GenerateInput{
		Rule: RuleContext{
			RuleKey:  "cis_win_does_not_exist",
			Platform: "windows",
		},
		GeneratedAt: mustTime(t),
	}
	_, err := Generate(in)
	if !errors.Is(err, ErrNoMapping) {
		t.Fatalf("Generate = %v, want ErrNoMapping", err)
	}
}

func TestGenerate_CrossPlatformRule_ReturnsErrUnsupportedPlatform(t *testing.T) {
	in := GenerateInput{
		Rule: RuleContext{
			RuleKey:  "some_cross_platform_rule",
			Platform: "cross-platform",
		},
		GeneratedAt: mustTime(t),
	}
	_, err := Generate(in)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Generate = %v, want ErrUnsupportedPlatform", err)
	}
}

func TestHasMapping(t *testing.T) {
	cases := []struct {
		platform, ruleKey string
		want              bool
	}{
		{"macos", "cis_macos_2_5_1_1_filevault", true},
		{"macos", "cis_macos_2_5_3_sip", false},
		{"windows", "cis_win_18_10_11_bitlocker_os_drive", true},
		{"windows", "cis_win_2_3_8_1_smb_signing", true},
		{"windows", "cis_win_18_10_56_2_rdp_disabled", true},
		{"windows", "cis_win_18_9_102_auto_updates", false},        // investigated, deferred (PAT-1827)
		{"windows", "cis_win_19_1_3_4_screensaver_timeout", false}, // investigated, deferred (PAT-1827)
		{"windows", "nonexistent", false},
		{"cross-platform", "anything", false},
	}
	for _, c := range cases {
		if got := HasMapping(c.platform, c.ruleKey); got != c.want {
			t.Errorf("HasMapping(%q, %q) = %v, want %v", c.platform, c.ruleKey, got, c.want)
		}
	}
}

func TestEscapePlist(t *testing.T) {
	got := escapePlist(`a & b < c > d "e" 'f'`)
	want := `a &amp; b &lt; c &gt; d &quot;e&quot; &apos;f&apos;`
	if got != want {
		t.Errorf("escapePlist = %q, want %q", got, want)
	}
}

func TestDeterministicUUID_StableAndFormatted(t *testing.T) {
	a := deterministicUUID("x", "y", "z")
	b := deterministicUUID("x", "y", "z")
	if a != b {
		t.Fatalf("deterministicUUID not stable: %s vs %s", a, b)
	}
	c := deterministicUUID("x", "y", "different")
	if a == c {
		t.Fatalf("deterministicUUID collided across different inputs")
	}
	parts := strings.Split(a, "-")
	if len(parts) != 5 {
		t.Fatalf("deterministicUUID = %q, want 5 dash-separated groups", a)
	}
	lens := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != lens[i] {
			t.Errorf("group %d = %q (len %d), want len %d", i, p, len(p), lens[i])
		}
	}
}
