package extractor

import (
	"encoding/json"
	"testing"

	"patched.im/api/internal/evaluator"
)

// TestBuildSignalsMapWithFindings covers the mixed case: a payload that both
// flags a violation (Fail) and attests a clean control (Pass) via
// compliance_assessments. A finding always wins over an attestation for the
// same control (PAT-913, Option B).
func TestBuildSignalsMapWithFindings(t *testing.T) {
	p := &payload{
		Compliance: complianceMap{
			"sip": json.RawMessage(`"enabled"`),
		},
		ComplianceFindings: []complianceFinding{
			{
				ID:       "disk_encryption_off",
				Severity: "critical",
			},
			{
				ID:       "removable_storage_unencrypted",
				Severity: "medium",
				Volumes:  json.RawMessage(`[{"mount": "/Volumes/USB"}]`),
			},
		},
		// The agent says it assessed both controls this run. disk_encryption_off
		// is also flagged, so it must stay Fail; removable is flagged too here.
		ComplianceAssessments: complianceAssessments{
			ControlsAssessed: []string{"disk_encryption_off", "removable_storage_unencrypted"},
		},
		ICloud: iCloudPart{
			SignedIn: "Yes",
		},
	}

	signals := buildSignalsMap(p, nil)

	if signals["sip"] != "enabled" {
		t.Errorf("expected sip=enabled, got %q", signals["sip"])
	}
	if signals["icloud_signed_in"] != "Yes" {
		t.Errorf("expected icloud_signed_in=Yes, got %q", signals["icloud_signed_in"])
	}

	// A flagged control is Fail even though it is also in controls_assessed.
	if signals["disk_encryption_off"] != "Fail" {
		t.Errorf("expected disk_encryption_off=Fail (finding wins over attestation), got %q", signals["disk_encryption_off"])
	}
	expectedVolumes := `[{"mount": "/Volumes/USB"}]`
	if signals["removable_storage_unencrypted"] != expectedVolumes {
		t.Errorf("expected removable_storage_unencrypted=%s, got %q", expectedVolumes, signals["removable_storage_unencrypted"])
	}
}

// TestBuildSignalsMap_AttestedClean covers the crux of PAT-913 (Option B): an
// agent that ran the assessment and found nothing wrong lists the controls in
// compliance_assessments.controls_assessed and emits no matching finding.
// buildSignalsMap must turn each attested-and-unflagged control into a positive
// "Pass" signal, so a clean device still passes after the treat_unknown_as flip
// to 'fail'.
func TestBuildSignalsMap_AttestedClean(t *testing.T) {
	p := &payload{
		Compliance: complianceMap{"sip": json.RawMessage(`"enabled"`)},
		ComplianceAssessments: complianceAssessments{
			ControlsAssessed: []string{"disk_encryption_off", "removable_storage_unencrypted"},
		},
	}

	signals := buildSignalsMap(p, nil)

	for _, key := range []string{"disk_encryption_off", "removable_storage_unencrypted"} {
		if signals[key] != "Pass" {
			t.Errorf("attested-clean device: expected %s=Pass, got %q", key, signals[key])
		}
	}
}

// TestBuildSignalsMap_EmptyControlsAssessed: an explicit empty attestation list
// attests nothing. No control gets a Pass; the evaluator will fall through to
// treat_unknown_as. Must be indistinguishable from the absent-section case.
func TestBuildSignalsMap_EmptyControlsAssessed(t *testing.T) {
	p := &payload{
		Compliance:            complianceMap{"sip": json.RawMessage(`"enabled"`)},
		ComplianceAssessments: complianceAssessments{ControlsAssessed: []string{}},
	}

	signals := buildSignalsMap(p, nil)

	for _, key := range []string{"disk_encryption_off", "removable_storage_unencrypted"} {
		if _, present := signals[key]; present {
			t.Errorf("empty controls_assessed: expected %s absent, got %q", key, signals[key])
		}
	}
}

// TestBuildSignalsMap_AbsentAssessments covers the never-attested case — every
// agent deployed before PAT-913. The compliance_assessments key is absent, so
// the value-typed field is its zero value (nil ControlsAssessed). No positive
// signal is written and the evaluator falls through to treat_unknown_as. This
// must behave identically to the empty-list case above.
func TestBuildSignalsMap_AbsentAssessments(t *testing.T) {
	p := &payload{
		Compliance: complianceMap{"sip": json.RawMessage(`"enabled"`)},
		// ComplianceAssessments left as zero value: no key in the payload.
	}

	signals := buildSignalsMap(p, nil)

	for _, key := range []string{"disk_encryption_off", "removable_storage_unencrypted"} {
		if _, present := signals[key]; present {
			t.Errorf("absent compliance_assessments: expected %s absent, got %q", key, signals[key])
		}
	}
}

// TestBuildSignalsMap_OutOfEnumControlSkipped is the belt-and-braces half of the
// PAT-913 round-2 gate fix: ValidatePayload rejects out-of-enum controls_assessed
// entries at ingestion, but raw_payloads may hold rows ingested before that
// enforcement existed and re-extraction replays them through buildSignalsMap. An
// entry outside the shared finding-control enum must be skipped (warn-logged),
// never turned into a Pass signal — otherwise an attacker-controlled list could
// fabricate a Pass for ANY signal key (filevault, defender_realtime, ...).
func TestBuildSignalsMap_OutOfEnumControlSkipped(t *testing.T) {
	p := &payload{
		Compliance: complianceMap{"filevault": json.RawMessage(`"Off"`)},
		ComplianceAssessments: complianceAssessments{
			ControlsAssessed: []string{
				"filevault",           // real signal key, NOT a finding control — must not become Pass
				"defender_realtime",   // ditto
				"totally_made_up",     // unknown key — must not appear at all
				"disk_encryption_off", // legitimate — must become Pass
			},
		},
	}

	signals := buildSignalsMap(p, nil)

	// The compliance-bag value must survive untouched, not be overwritten to "Pass".
	if signals["filevault"] != "Off" {
		t.Errorf("filevault: expected bag value \"Off\" preserved, got %q", signals["filevault"])
	}
	if v, present := signals["defender_realtime"]; present {
		t.Errorf("defender_realtime: expected absent (out-of-enum attestation skipped), got %q", v)
	}
	if v, present := signals["totally_made_up"]; present {
		t.Errorf("totally_made_up: expected absent, got %q", v)
	}
	if signals["disk_encryption_off"] != "Pass" {
		t.Errorf("disk_encryption_off: expected Pass (legitimate attestation), got %q", signals["disk_encryption_off"])
	}
}

// TestValidatePayload_ControlsAssessedEnum asserts the ingestion validator's
// strict enforcement (PAT-913 round-2 gate): compliance_assessments must be an
// object with only controls_assessed, an array of strings drawn exactly from
// the finding-control enum in docs/payload.schema.json. Unknown IDs are
// rejected (the standard 400 path), not silently dropped — these entries mint
// Pass signals, so an arbitrary string here would be a fail-open hole.
// Complements the fixture-suite coverage with targeted shapes.
func TestValidatePayload_ControlsAssessedEnum(t *testing.T) {
	base := func(assessments string) []byte {
		return []byte(`{
			"schema_version": 2, "agent": "t", "agent_version": "1", "tenant_id": "t",
			"collected_at": "2026-07-16T00:00:00Z",
			"device": {"serial":"s","hw_uuid":"u","hostname":"h","hw_model":"m","arch":"arm64","last_boot":"2026-07-16T00:00:00Z"},
			"hardware": {"cpu_model":"c","cpu_cores":8,"ram_gb":8,"disk_total_gb":1,"disk_free_gb":1},
			"os": {"name":"macOS","version":"15.5","build":"24F74"},
			"compliance": {}, "security_tools": [], "system_extensions": [], "background_items": [],
			"icloud": {"signed_in":"Yes"},
			"apps": [{"name":"a","version":"1","bundle_id":"b"}],
			"compliance_assessments": ` + assessments + `
		}`)
	}

	cases := []struct {
		name        string
		assessments string
		wantErr     bool
	}{
		{"valid_both_controls", `{"controls_assessed": ["disk_encryption_off", "removable_storage_unencrypted"]}`, false},
		{"valid_empty_list", `{"controls_assessed": []}`, false},
		{"valid_empty_object", `{}`, false},
		{"unknown_control_rejected", `{"controls_assessed": ["filevault"]}`, true},
		{"mixed_known_unknown_rejected", `{"controls_assessed": ["disk_encryption_off", "made_up"]}`, true},
		{"non_string_entry_rejected", `{"controls_assessed": [42]}`, true},
		{"non_array_rejected", `{"controls_assessed": "disk_encryption_off"}`, true},
		{"extra_key_rejected", `{"controls_assessed": [], "extra": true}`, true},
		{"non_object_rejected", `["disk_encryption_off"]`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(base(tc.assessments))
			if tc.wantErr && err == nil {
				t.Error("expected validation to reject payload but it passed")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected validation to pass, got: %v", err)
			}
		})
	}
}

// TestValidatePayload_ReservedNamespace asserts the round-3 gate fix: the
// finding-control IDs form a reserved namespace. They may never appear as
// free-form compliance bag keys (a bag key would pre-seat a forged Pass the
// attestation loop leaves untouched), and compliance_findings[].id must be in
// the enum (a finding writes Fail-state values, so an arbitrary id could force
// a Fail onto any rule signal). Legitimate bags and findings must be untouched.
func TestValidatePayload_ReservedNamespace(t *testing.T) {
	base := func(compliance, findings string) []byte {
		return []byte(`{
			"schema_version": 2, "agent": "t", "agent_version": "1", "tenant_id": "t",
			"collected_at": "2026-07-17T00:00:00Z",
			"device": {"serial":"s","hw_uuid":"u","hostname":"h","hw_model":"m","arch":"arm64","last_boot":"2026-07-17T00:00:00Z"},
			"hardware": {"cpu_model":"c","cpu_cores":8,"ram_gb":8,"disk_total_gb":1,"disk_free_gb":1},
			"os": {"name":"macOS","version":"15.5","build":"24F74"},
			"compliance": ` + compliance + `,
			"compliance_findings": ` + findings + `,
			"security_tools": [], "system_extensions": [], "background_items": [],
			"icloud": {"signed_in":"Yes"},
			"apps": [{"name":"a","version":"1","bundle_id":"b"}]
		}`)
	}

	cases := []struct {
		name       string
		compliance string
		findings   string
		wantErr    bool
	}{
		// Legitimate shapes: unrelated bag keys and enum'd findings pass.
		{"legit_bag_and_findings", `{"filevault":"On","sip":"enabled","local_admin_count":1}`, `[{"id":"disk_encryption_off","severity":"critical"}]`, false},
		{"legit_empty_findings", `{"filevault":"On"}`, `[]`, false},
		// Bag forgery: reserved finding-control IDs as bag keys are rejected.
		{"bag_forged_disk_pass_rejected", `{"disk_encryption_off":"Pass"}`, `[]`, true},
		{"bag_forged_removable_rejected", `{"removable_storage_unencrypted":"Pass"}`, `[]`, true},
		{"bag_forged_alongside_legit_rejected", `{"filevault":"On","disk_encryption_off":"Pass"}`, `[]`, true},
		// Findings enum: out-of-enum finding IDs are rejected.
		{"finding_out_of_enum_rejected", `{}`, `[{"id":"filevault","severity":"critical"}]`, true},
		{"finding_missing_severity_rejected", `{}`, `[{"id":"disk_encryption_off"}]`, true},
		{"finding_non_string_id_rejected", `{}`, `[{"id":42,"severity":"critical"}]`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(base(tc.compliance, tc.findings))
			if tc.wantErr && err == nil {
				t.Error("expected validation to reject payload but it passed")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected validation to pass, got: %v", err)
			}
		})
	}
}

// TestBuildSignalsMap_BagForgedControlSkipped is the extraction-path half of
// the round-3 fix: a stored payload whose compliance bag names a reserved
// finding-control key (ingested before the validator enforced the reserved
// namespace, or via any bypass) must yield NO signal for that control — it
// falls through to treat_unknown_as='fail' — while legitimate bag keys are
// untouched. Also proves loop-order independence: a legitimate attestation
// still mints its Pass even when the bag tried to pre-seat the same key.
func TestBuildSignalsMap_BagForgedControlSkipped(t *testing.T) {
	t.Run("forged_bag_no_attestation", func(t *testing.T) {
		p := &payload{
			Compliance: complianceMap{
				"disk_encryption_off": json.RawMessage(`"Pass"`), // forged
				"filevault":           json.RawMessage(`"On"`),   // legitimate
			},
		}
		signals := buildSignalsMap(p, nil)
		if v, present := signals["disk_encryption_off"]; present {
			t.Errorf("disk_encryption_off: expected NO signal (bag-forged key skipped), got %q", v)
		}
		if signals["filevault"] != "On" {
			t.Errorf("filevault: expected legitimate bag value \"On\" preserved, got %q", signals["filevault"])
		}

		// End-to-end: with no signal, the critical rule fails-unknown.
		rule := evaluator.Rule{
			ID: "disk-rule", RuleKey: "patched_macos_disk_encryption_off",
			Severity: "critical", SignalKey: "disk_encryption_off",
			Comparator: evaluator.ComparatorEq, ExpectedValues: []string{"Pass"},
			TreatUnknownAs: evaluator.UnknownAsFail,
		}
		evals := evaluator.Evaluate([]evaluator.Rule{rule}, signals, "arm64")
		if evals[0].Status != evaluator.StatusFail {
			t.Errorf("bag-forged payload: expected FAIL (fail-unknown), got %s", evals[0].Status)
		}
	})

	t.Run("forged_bag_with_real_attestation", func(t *testing.T) {
		// The bag key is skipped, so the attestation loop's already-present
		// check does not see it and the legitimate Pass is still minted —
		// semantics independent of bag contents, whichever loop runs first.
		p := &payload{
			Compliance: complianceMap{"disk_encryption_off": json.RawMessage(`"garbage"`)},
			ComplianceAssessments: complianceAssessments{
				ControlsAssessed: []string{"disk_encryption_off"},
			},
		}
		signals := buildSignalsMap(p, nil)
		if signals["disk_encryption_off"] != "Pass" {
			t.Errorf("expected Pass from legitimate attestation regardless of bag contents, got %q", signals["disk_encryption_off"])
		}
	})
}

// TestBuildSignalsMap_OutOfEnumFindingSkipped: the findings loop may only
// write reserved finding-control keys. An out-of-enum finding ID (only
// possible in pre-enforcement stored rows) must not force a Fail-state value
// onto an arbitrary rule signal or clobber a legitimate bag key.
func TestBuildSignalsMap_OutOfEnumFindingSkipped(t *testing.T) {
	p := &payload{
		Compliance: complianceMap{"filevault": json.RawMessage(`"On"`)},
		ComplianceFindings: []complianceFinding{
			{ID: "filevault", Severity: "critical"},           // out-of-enum: skipped
			{ID: "disk_encryption_off", Severity: "critical"}, // legitimate: Fail
		},
	}
	signals := buildSignalsMap(p, nil)
	if signals["filevault"] != "On" {
		t.Errorf("filevault: expected bag value \"On\" preserved (out-of-enum finding skipped), got %q", signals["filevault"])
	}
	if signals["disk_encryption_off"] != "Fail" {
		t.Errorf("disk_encryption_off: expected Fail from legitimate finding, got %q", signals["disk_encryption_off"])
	}
}

// TestFindings_ThreeDeviceStates is the end-to-end assertion the PAT-913 spec
// demands, exercised on both platform rule sets: build the signal map exactly as
// the extractor does, then evaluate against rules mirroring the seeded critical
// disk_encryption_off + removable_storage_unencrypted rules (eq ['Pass'],
// treat_unknown_as = 'fail' after migration 0083). The buildSignalsMap logic is
// platform-neutral — the same signal keys drive both macOS and Windows rules —
// so both platforms must resolve the three states identically.
func TestFindings_ThreeDeviceStates(t *testing.T) {
	// mkRules returns the two finding rules for a platform, matching the
	// post-0083 seeded rows. Signal keys and comparators are platform-neutral;
	// only rule_key differs.
	mkRules := func(platform string) []evaluator.Rule {
		prefix := "patched_" + platform + "_"
		return []evaluator.Rule{
			{
				ID:             prefix + "disk_encryption_off",
				RuleKey:        prefix + "disk_encryption_off",
				Severity:       "critical",
				SignalKey:      "disk_encryption_off",
				Comparator:     evaluator.ComparatorEq,
				ExpectedValues: []string{"Pass"},
				TreatUnknownAs: evaluator.UnknownAsFail,
			},
			{
				ID:             prefix + "removable_storage_unencrypted",
				RuleKey:        prefix + "removable_storage_unencrypted",
				Severity:       "medium",
				SignalKey:      "removable_storage_unencrypted",
				Comparator:     evaluator.ComparatorEq,
				ExpectedValues: []string{"Pass"},
				TreatUnknownAs: evaluator.UnknownAsFail,
			},
		}
	}

	cases := []struct {
		name        string
		findings    []complianceFinding
		assessments complianceAssessments
		wantDisk    string
		wantRemove  string
	}{
		{
			// (i) attested both controls, no findings → PASS both
			name:        "attested_clean",
			findings:    nil,
			assessments: complianceAssessments{ControlsAssessed: []string{"disk_encryption_off", "removable_storage_unencrypted"}},
			wantDisk:    evaluator.StatusPass,
			wantRemove:  evaluator.StatusPass,
		},
		{
			// (ii) attested both, disk flagged → disk FAIL, removable PASS
			name:        "attested_with_disk_finding",
			findings:    []complianceFinding{{ID: "disk_encryption_off", Severity: "critical"}},
			assessments: complianceAssessments{ControlsAssessed: []string{"disk_encryption_off", "removable_storage_unencrypted"}},
			wantDisk:    evaluator.StatusFail,
			wantRemove:  evaluator.StatusPass,
		},
		{
			// (iii) unattested, explicit empty list → FAIL-UNKNOWN both
			name:        "unattested_empty_list",
			findings:    nil,
			assessments: complianceAssessments{ControlsAssessed: []string{}},
			wantDisk:    evaluator.StatusFail,
			wantRemove:  evaluator.StatusFail,
		},
		{
			// (iv) unattested, section absent (pre-PAT-913 agent) → FAIL-UNKNOWN both
			name:        "unattested_absent_section",
			findings:    nil,
			assessments: complianceAssessments{}, // zero value: no controls_assessed
			wantDisk:    evaluator.StatusFail,
			wantRemove:  evaluator.StatusFail,
		},
		{
			// (v) finding present but control never attested → still FAIL (finding wins)
			name:        "finding_without_attestation",
			findings:    []complianceFinding{{ID: "disk_encryption_off", Severity: "critical"}},
			assessments: complianceAssessments{}, // never attested
			wantDisk:    evaluator.StatusFail,
			wantRemove:  evaluator.StatusFail, // removable neither flagged nor attested → fail-unknown
		},
	}

	for _, platform := range []string{"macos", "win"} {
		rules := mkRules(platform)
		for _, tc := range cases {
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				p := &payload{
					ComplianceFindings:    tc.findings,
					ComplianceAssessments: tc.assessments,
				}
				signals := buildSignalsMap(p, nil)
				evals := evaluator.Evaluate(rules, signals, "arm64")
				if evals[0].Status != tc.wantDisk {
					t.Errorf("disk_encryption_off: got %s want %s", evals[0].Status, tc.wantDisk)
				}
				if evals[1].Status != tc.wantRemove {
					t.Errorf("removable_storage_unencrypted: got %s want %s", evals[1].Status, tc.wantRemove)
				}
			})
		}
	}
}
