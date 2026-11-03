package handlers

// PAT-1973 regression: the Cyber Essentials scoring engine (ce.go) listed only
// cis_macos_* rule keys, because it was written before the Windows CIS rules
// were seeded. ceControlStatus sums pass/fail counts across a control's rule
// keys, so on a mixed Windows and macOS estate the control resolved from the
// Mac evidence alone and excluded every Windows device from both sides of the
// ratio. A Windows-only estate got "unknown", which is safe; a mixed estate got
// a confident "pass" that had never looked at a Windows device, which is not.
//
// These are pure-function tests over ceControlStatus and ceModel. No database,
// so they run in the normal `go test ./...` pass rather than only where
// TEST_DATABASE_URL is set.

import (
	"strings"
	"testing"
)

// findControl returns the control with the given ID from ceModel.
func findControl(t *testing.T, controlID string) ceControlDef {
	t.Helper()
	for _, area := range ceModel {
		for _, ctrl := range area.Controls {
			if ctrl.ID == controlID {
				return ctrl
			}
		}
	}
	t.Fatalf("control %q not found in ceModel", controlID)
	return ceControlDef{}
}

func hasKeyPrefix(keys []string, prefix string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// Every auto-evidenced control that has a Windows equivalent must list it.
// Controls with no Windows rule are named here explicitly so that adding one
// later is a deliberate change to this list rather than a silent omission.
func TestCEModelAutoControlsCoverWindowsWhereRulesExist(t *testing.T) {
	// Controls with no Windows rule available. Each has a comment in ce.go
	// giving the reason; keep the two in step.
	macOSOnly := map[string]string{
		"ce_cfg_auto_login":      "no Windows rule evaluates automatic logon",
		"ce_uac_password_policy": "Windows account policy rules are T2, evaluated per tenant_rules",
		"ce_mal_gatekeeper":      "Gatekeeper is a macOS concept",
		"ce_mal_sip":             "SIP is a macOS concept",
		"ce_patch_pending":       "no CIS rule evaluates Windows pending updates",
	}

	for _, area := range ceModel {
		for _, ctrl := range area.Controls {
			if ctrl.Source != ceSourceAuto {
				continue
			}
			if !hasKeyPrefix(ctrl.RuleKeys, "cis_macos_") {
				t.Errorf("control %q: auto-evidenced but lists no macOS rule key", ctrl.ID)
			}
			reason, expectedMacOSOnly := macOSOnly[ctrl.ID]
			hasWindows := hasKeyPrefix(ctrl.RuleKeys, "cis_win_")
			switch {
			case expectedMacOSOnly && hasWindows:
				t.Errorf("control %q lists a Windows rule but is recorded as macOS-only (%s); "+
					"update the macOSOnly map and the comment in ce.go", ctrl.ID, reason)
			case !expectedMacOSOnly && !hasWindows:
				t.Errorf("control %q is auto-evidenced with no Windows rule key and no recorded "+
					"reason; a mixed estate would score this control from macOS devices alone", ctrl.ID)
			}
		}
	}
}

// The specific controls the fix covers, pinned by rule key so a later edit
// cannot quietly drop them.
func TestCEModelWindowsRuleKeysPresent(t *testing.T) {
	want := map[string][]string{
		"ce_fw_host": {
			"cis_win_9_1_1_firewall_domain",
			"cis_win_9_2_1_firewall_private",
			"cis_win_9_3_1_firewall_public",
		},
		"ce_cfg_screen_lock": {
			"cis_win_19_1_3_2_screensaver_enabled",
			"cis_win_19_1_3_3_screensaver_password",
			"cis_win_19_1_3_4_screensaver_timeout",
		},
		"ce_patch_auto_updates": {
			"cis_win_18_9_102_auto_updates",
		},
		"ce_uac_admin_count": {
			"cis_win_5_8_local_admin_count",
		},
	}

	for controlID, keys := range want {
		ctrl := findControl(t, controlID)
		for _, k := range keys {
			found := false
			for _, have := range ctrl.RuleKeys {
				if have == k {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("control %q is missing rule key %q", controlID, k)
			}
		}
	}
}

// The regression itself: a mixed estate where every Mac passes and a Windows
// device has a real, evidenced fail must fail the control. Before the fix the
// Windows rule key was absent from ceModel, its evaluations were never fetched,
// and the control read "pass".
func TestCEControlStatusMixedEstateWindowsFailFailsTheControl(t *testing.T) {
	ctrl := findControl(t, "ce_fw_host")

	evalMap := map[string]ruleEvalCounts{
		// 20 Macs, all passing the application firewall rule.
		"cis_macos_2_5_2_2_firewall": {PassCount: 20, TotalCount: 20},
		// 5 Windows devices with the domain profile firewall genuinely off.
		// observed_value is non-NULL, so this is a real fail, not undetermined.
		"cis_win_9_1_1_firewall_domain": {FailCount: 5, TotalCount: 5},
	}

	if got := ceControlStatus(ctrl, evalMap, nil); got != "fail" {
		t.Errorf("mixed estate with 5 real Windows firewall fails: got %q, want \"fail\"", got)
	}
}

// A Windows-only estate previously produced "unknown" for every auto control,
// because no macOS rule had any evaluations. It should now resolve from the
// Windows evidence.
func TestCEControlStatusWindowsOnlyEstateResolves(t *testing.T) {
	ctrl := findControl(t, "ce_fw_host")

	evalMap := map[string]ruleEvalCounts{
		"cis_win_9_1_1_firewall_domain":  {PassCount: 12, TotalCount: 12},
		"cis_win_9_2_1_firewall_private": {PassCount: 12, TotalCount: 12},
		"cis_win_9_3_1_firewall_public":  {PassCount: 12, TotalCount: 12},
	}

	if got := ceControlStatus(ctrl, evalMap, nil); got != "pass" {
		t.Errorf("Windows-only estate, all profiles passing: got %q, want \"pass\"", got)
	}
}

// PAT-1974's own named verification requirement: ce_uac_admin_count now
// resolves from Windows-only evidence on a Windows-only tenant. Before the
// Windows collector gained local_admin_count (Patched-LTD/updater #631) and
// cis_win_5_8_local_admin_count was seeded (migration 0160), this control had
// no Windows rule key at all and a Windows-only estate always read "unknown"
// for it — see the (now-removed) macOSOnly entry this test replaces.
func TestCEControlStatusWindowsOnlyEstateResolvesAdminCount(t *testing.T) {
	ctrl := findControl(t, "ce_uac_admin_count")

	evalMap := map[string]ruleEvalCounts{
		"cis_win_5_8_local_admin_count": {PassCount: 8, TotalCount: 8},
	}

	if got := ceControlStatus(ctrl, evalMap, nil); got != "pass" {
		t.Errorf("Windows-only estate, all devices at or under the admin threshold: got %q, want \"pass\"", got)
	}

	failEvalMap := map[string]ruleEvalCounts{
		"cis_win_5_8_local_admin_count": {FailCount: 3, TotalCount: 8},
	}
	if got := ceControlStatus(ctrl, failEvalMap, nil); got != "fail" {
		t.Errorf("Windows-only estate with a real evidenced admin-count fail: got %q, want \"fail\"", got)
	}
}

// Absence of evidence stays "unknown" rather than becoming a pass. This is the
// existing guarantee the fix must not weaken: adding rule keys must not make an
// estate with no evaluations for them look compliant.
func TestCEControlStatusNoEvidenceStaysUnknown(t *testing.T) {
	ctrl := findControl(t, "ce_fw_host")

	if got := ceControlStatus(ctrl, map[string]ruleEvalCounts{}, nil); got != "unknown" {
		t.Errorf("no evaluations at all: got %q, want \"unknown\"", got)
	}

	// Undetermined-only evidence (PAT-1776: a fail row with a NULL observed
	// value) must also stay unknown, on the Windows keys as well as the macOS
	// ones.
	undetermined := map[string]ruleEvalCounts{
		"cis_win_9_1_1_firewall_domain": {UndeterminedCount: 7, TotalCount: 7},
	}
	if got := ceControlStatus(ctrl, undetermined, nil); got != "unknown" {
		t.Errorf("Windows evidence all undetermined: got %q, want \"unknown\"", got)
	}
}
