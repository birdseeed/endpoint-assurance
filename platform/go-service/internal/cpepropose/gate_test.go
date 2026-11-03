package cpepropose

import (
	"fmt"
	"strings"
	"testing"

	"patched.im/api/internal/cvematch"
)

var testAliases = []Alias{
	{Kind: "macos_team_id", Value: "UBF8T346G9", Vendor: "microsoft"},
	{Kind: "macos_team_id", Value: "AAAAAAAAA1", Vendor: "acme"},
	{Kind: "windows_subject_org", Value: "Microsoft Corporation", Vendor: "microsoft"},
}

func TestSubjectOrganization(t *testing.T) {
	cases := map[string]string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": "Microsoft Corporation",
		`CN=Foo, O="Foo, Inc.", C=US`: "Foo, Inc.",
		`CN=Foo, O=Foo\, Ltd, C=GB`:   "Foo, Ltd",
		"CN=No Org, C=US":             "",
		"CN=Two, O=A, O=B":            "",
		"o=lower case key, CN=x":      "lower case key",
		"CN=Tailscale Inc., O=Tailscale Inc., L=Toronto, OID.2.5.4.15=Private Organization": "Tailscale Inc.",
	}
	for dn, want := range cases {
		if got := SubjectOrganization(dn); got != want {
			t.Errorf("SubjectOrganization(%q) = %q, want %q", dn, got, want)
		}
	}
}

func TestCorroborate(t *testing.T) {
	devID := "Developer ID Application"
	signedMS := Installation{SigningStatus: "signed", TeamID: "UBF8T346G9", Authority: devID}
	legacyMS := Installation{TeamID: "ubf8t346g9", Authority: devID} // older agent: no status reported
	storeMS := Installation{SigningStatus: "signed", TeamID: "UBF8T346G9", Authority: "Apple Mac OS Application Signing"}
	winMS := Installation{SignatureState: "valid", RootKind: "microsoft",
		SubjectDN: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}
	cases := []struct {
		name     string
		platform string
		installs []Installation
		vendor   string
		ok       bool
		reason   string
	}{
		{"mac signed team id aliased", "macos", []Installation{signedMS, legacyMS, storeMS}, "microsoft", true, ""},
		// A development certificate carries a real Team ID but is not a
		// public-distribution signature (and names a person).
		{"development-signed with team id", "macos", []Installation{signedMS, {SigningStatus: "signed", TeamID: "UBF8T346G9", Authority: "Apple Development"}}, "microsoft", false, ReasonSignerUntrusted},
		{"team id with no authority reported", "macos", []Installation{{SigningStatus: "signed", TeamID: "UBF8T346G9"}}, "microsoft", false, ReasonSignerUntrusted},
		{"name only: no installations", "macos", nil, "microsoft", false, ReasonNoSignerEvidence},
		{"no team id", "macos", []Installation{{SigningStatus: "signed"}}, "microsoft", false, ReasonNoSignerEvidence},
		{"adhoc with team id", "macos", []Installation{signedMS, {SigningStatus: "adhoc", TeamID: "UBF8T346G9", Authority: devID}}, "microsoft", false, ReasonSignerUntrusted},
		{"invalid signature with team id", "macos", []Installation{{SigningStatus: "invalid", TeamID: "UBF8T346G9", Authority: devID}}, "microsoft", false, ReasonSignerUntrusted},
		{"installations disagree", "macos", []Installation{signedMS, {SigningStatus: "signed", TeamID: "AAAAAAAAA1", Authority: devID}}, "microsoft", false, ReasonSignerInconsistent},
		{"team id not aliased", "macos", []Installation{{SigningStatus: "signed", TeamID: "ZZZZZZZZZ9", Authority: devID}}, "microsoft", false, ReasonSignerNotAliased},
		{"alias names another vendor", "macos", []Installation{signedMS}, "acme", false, ReasonSignerVendorMismatch},
		{"windows valid public root", "windows", []Installation{winMS}, "microsoft", true, ""},
		{"windows enterprise root", "windows", []Installation{{SignatureState: "valid", RootKind: "enterprise", SubjectDN: winMS.SubjectDN}}, "microsoft", false, ReasonSignerUntrusted},
		{"windows unsigned", "windows", []Installation{{SignatureState: "unsigned"}}, "microsoft", false, ReasonSignerUntrusted},
		{"windows not reported", "windows", []Installation{{}}, "microsoft", false, ReasonNoSignerEvidence},
		{"windows lookalike org", "windows", []Installation{{SignatureState: "valid", RootKind: "public",
			SubjectDN: "CN=Microsoft, O=Microsoft Corp, C=US"}}, "microsoft", false, ReasonSignerNotAliased},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Corroborate(tc.platform, tc.installs, testAliases, tc.vendor)
			if got.OK != tc.ok || got.Reason != tc.reason {
				t.Fatalf("got %+v, want ok=%v reason=%q", got, tc.ok, tc.reason)
			}
		})
	}
}

// publicSigner decides what may leave the platform: only public-distribution
// signers, and only their Team ID or O=.
func TestPublicSigner(t *testing.T) {
	dn := "CN=Acme Ltd, O=Acme Ltd, L=London, C=GB"
	cases := []struct {
		name     string
		platform string
		in       Installation
		value    string
		ok       bool
	}{
		{"developer id", "macos", Installation{SigningStatus: "signed", TeamID: "AAAAAAAAA1", Authority: "Developer ID Application"}, "AAAAAAAAA1", true},
		{"app store", "macos", Installation{TeamID: "AAAAAAAAA1", Authority: "Apple Mac OS Application Signing"}, "AAAAAAAAA1", true},
		{"development", "macos", Installation{SigningStatus: "signed", TeamID: "AAAAAAAAA1", Authority: "Apple Development"}, "", false},
		{"adhoc", "macos", Installation{SigningStatus: "adhoc", TeamID: "AAAAAAAAA1", Authority: "Developer ID Application"}, "", false},
		{"unsigned", "macos", Installation{SigningStatus: "unsigned"}, "", false},
		{"not reported", "macos", Installation{}, "", false},
		{"apple platform binary", "macos", Installation{SigningStatus: "signed", Authority: "Software Signing"}, "", false},
		{"windows public root", "windows", Installation{SignatureState: "valid", RootKind: "public", SubjectDN: dn}, "Acme Ltd", true},
		{"windows microsoft root", "windows", Installation{SignatureState: "valid", RootKind: "microsoft", SubjectDN: dn}, "Acme Ltd", true},
		{"windows enterprise root", "windows", Installation{SignatureState: "valid", RootKind: "enterprise", SubjectDN: dn}, "", false},
		{"windows unsigned", "windows", Installation{SignatureState: "unsigned"}, "", false},
		{"windows unknown", "windows", Installation{SignatureState: "unknown"}, "", false},
		{"windows no O=", "windows", Installation{SignatureState: "valid", RootKind: "public", SubjectDN: "CN=Jane Doe"}, "", false},
	}
	for _, tc := range cases {
		_, v, ok := publicSigner(tc.platform, tc.in)
		if ok != tc.ok || v != tc.value {
			t.Errorf("%s: publicSigner = %q %v, want %q %v", tc.name, v, ok, tc.value, tc.ok)
		}
	}
}

func corroborated() Corroboration {
	return Corroboration{OK: true, Signer: "AAAAAAAAA1", Vendors: []string{"acme"}}
}

func TestDecide(t *testing.T) {
	cands := []Candidate{{Vendor: "acme", Product: "widget", CVECount: 3}, {Vendor: "acme", Product: "old", Deprecated: true},
		{Vendor: "acme", Product: "widget_server", CVECount: 9}}
	high := ModelChoice{Choice: "acme:widget", Confidence: ConfidenceHigh}
	const name = "acme widget"
	cases := []struct {
		name   string
		in     GateInput
		state  string
		reason string
	}{
		{"all evidence agrees", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: high, Corroboration: corroborated()}, StateAutoPublished, ""},
		// Name-only: the model is certain, but nothing independent agrees.
		{"name only never publishes", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: high,
			Corroboration: Corroboration{Reason: ReasonNoSignerEvidence}}, StateNeedsReview, ReasonNoSignerEvidence},
		{"zero-value corroboration never publishes", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: high}, StateNeedsReview, ReasonNoSignerEvidence},
		{"no candidates", GateInput{NormalizedName: name, AutoPublishEnabled: true, Choice: high, Corroboration: corroborated()}, StateNeedsReview, ReasonNoCandidates},
		{"model unavailable", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, ModelErr: fmt.Errorf("%w: x", ErrModelUnavailable)}, StateNeedsReview, ReasonModelUnavailable},
		{"model invalid", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, ModelErr: fmt.Errorf("%w: x", ErrInvalidModelResponse)}, StateNeedsReview, ReasonModelInvalidResponse},
		{"model chose none", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: ModelChoice{Choice: ChoiceNone, Confidence: ConfidenceHigh}, Corroboration: corroborated()}, StateNeedsReview, ReasonModelChoseNone},
		// A Chooser implementation returning a key outside the list is
		// refused by the gate too, not only by AnthropicChooser.
		{"choice outside list", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: ModelChoice{Choice: "evil:x", Confidence: ConfidenceHigh}, Corroboration: corroborated()}, StateNeedsReview, ReasonModelInvalidResponse},
		{"medium confidence", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: ModelChoice{Choice: "acme:widget", Confidence: ConfidenceMedium}, Corroboration: corroborated()}, StateNeedsReview, ReasonModelNotConfident},
		{"deprecated candidate", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: ModelChoice{Choice: "acme:old", Confidence: ConfidenceHigh}, Corroboration: corroborated()}, StateNeedsReview, ReasonCandidateDeprecated},
		{"broad match name", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands, Choice: high, Corroboration: corroborated(), OtherCoveredNames: []string{"Widget Helper"}}, StateNeedsReview, ReasonMatchNameTooBroad},
		// Same vendor, wrong product: the signer corroborates acme, the model
		// (steered, or wrong) picks acme's server edition; the product-token
		// check refuses it.
		{"same vendor wrong product", GateInput{NormalizedName: name, AutoPublishEnabled: true, Candidates: cands,
			Choice: ModelChoice{Choice: "acme:widget_server", Confidence: ConfidenceHigh}, Corroboration: corroborated()}, StateNeedsReview, ReasonProductNameMismatch},
		{"name does not name the product", GateInput{NormalizedName: "acme widget helper", AutoPublishEnabled: true, Candidates: cands,
			Choice: high, Corroboration: corroborated()}, StateNeedsReview, ReasonProductNameMismatch},
		{"feature flag off", GateInput{NormalizedName: name, AutoPublishEnabled: false, Candidates: cands, Choice: high, Corroboration: corroborated()}, StateNeedsReview, ReasonAutoPublishDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.in)
			if got.State != tc.state || got.Reason != tc.reason {
				t.Fatalf("got %+v, want %s/%s", got, tc.state, tc.reason)
			}
			if got.State == StateAutoPublished && (got.Vendor != "acme" || got.Product != "widget") {
				t.Fatalf("published %s:%s", got.Vendor, got.Product)
			}
		})
	}
}

// An automatic mapping must rest on a CPE with CVEs filed under it, and on
// the only same-vendor candidate that names the product with at least as
// many: otherwise "assessed, 0 CVEs" could come from a thin or wrong sibling.
func TestDecideRefusesThinOrAmbiguousCPE(t *testing.T) {
	corr := Corroboration{OK: true, Signer: "UBF8T346G9", Vendors: []string{"microsoft"}}
	edge := []Candidate{
		{Vendor: "microsoft", Product: "edge", CVECount: 0},
		{Vendor: "microsoft", Product: "edge_chromium", CVECount: 1200},
	}
	d := Decide(GateInput{NormalizedName: "microsoft edge", AutoPublishEnabled: true, Candidates: edge,
		Choice: ModelChoice{Choice: "microsoft:edge", Confidence: ConfidenceHigh}, Corroboration: corr})
	if d.State != StateNeedsReview || d.Reason != "candidate_has_no_cves" {
		t.Fatalf("Edge on a CPE with no CVEs = %+v, want needs_review/candidate_has_no_cves", d)
	}
	zcorr := Corroboration{OK: true, Signer: "BJ4HAAB9B3", Vendors: []string{"zoom"}}
	zoom := []Candidate{
		{Vendor: "zoom", Product: "zoom", CVECount: 2},
		{Vendor: "zoom", Product: "zoom_client", CVECount: 40}, // "client" is CPE-side noise: also names "Zoom"
		{Vendor: "zoom", Product: "zoom_client_for_meetings", CVECount: 150},
	}
	d = Decide(GateInput{NormalizedName: "zoom", AutoPublishEnabled: true, Candidates: zoom,
		Choice: ModelChoice{Choice: "zoom:zoom", Confidence: ConfidenceHigh}, Corroboration: zcorr})
	if d.State != StateNeedsReview || d.Reason != "ambiguous_candidates" {
		t.Fatalf("Zoom with a richer sibling = %+v, want needs_review/ambiguous_candidates", d)
	}
	// Picking the richest candidate that names the product publishes.
	d = Decide(GateInput{NormalizedName: "zoom", AutoPublishEnabled: true, Candidates: zoom,
		Choice: ModelChoice{Choice: "zoom:zoom_client", Confidence: ConfidenceHigh}, Corroboration: zcorr})
	if d.State != StateAutoPublished {
		t.Fatalf("Zoom on its richest naming CPE = %+v, want auto_published", d)
	}
}

func TestUnmappedAndNormalize(t *testing.T) {
	mappings := []cvematch.CPEMapping{
		{MatchName: "Zoom", CPEVendor: "zoom", CPEProduct: "zoom", Platform: "any"},
		{MatchName: "Word", CPEVendor: "microsoft", CPEProduct: "word", Platform: "windows"},
	}
	got := Unmapped([]string{"Zoom Workplace", "Word", "word ", "macOS", "openssl@3 (Homebrew formula)", "  Notion  ", "---", "notion"}, "macos", mappings)
	want := []string{"Word", "  Notion  "} // Word is mapped only for Windows
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Unmapped = %q, want %q", got, want)
	}
	if NormalizeName("  Visual   Studio\tCode ") != "visual studio code" {
		t.Fatal("NormalizeName did not collapse whitespace")
	}
	if _, ok := ProposalPlatform(""); ok {
		t.Fatal("an unknown platform must not produce proposals")
	}
}

func TestKeywords(t *testing.T) {
	cases := map[string][]string{
		"Microsoft Visual Studio Code": {"Microsoft Visual Studio Code", "Microsoft Visual"},
		"7-Zip 26.03 (x64)":            {"7-Zip"},
		"Notepad++ 8.6":                {"Notepad++"},
		"Zoom":                         {"Zoom"},
		"PowerToys (Preview) ARM64":    {"PowerToys"},
		"Microsoft .NET SDK 10.0.301":  {"Microsoft NET SDK", "Microsoft NET"},
		"()":                           nil,
	}
	for in, want := range cases {
		got := Keywords(in)
		if want == nil {
			if got != nil {
				t.Errorf("Keywords(%q) = %q, want none", in, got)
			}
			continue
		}
		if got[0] != want[0] {
			t.Errorf("Keywords(%q)[0] = %q, want %q", in, got[0], want[0])
		}
		if len(want) > 1 && want[1] != "" && (len(got) < 2 || got[1] != want[1]) {
			t.Errorf("Keywords(%q) = %q, want second %q", in, got, want[1])
		}
	}
}

// One Team ID can alias several vendors (Slack's BQR82RBBHL: slack and
// salesforce, both seeded by 0192). Corroboration holds only for a vendor
// the alias actually lists, whichever order the rows come in, never for an
// arbitrary first match.
func TestCorroborateMultiVendorAlias(t *testing.T) {
	slack := []Installation{{SigningStatus: "signed", TeamID: "BQR82RBBHL", Authority: "Developer ID Application"}}
	for _, aliases := range [][]Alias{
		{{Kind: "macos_team_id", Value: "BQR82RBBHL", Vendor: "slack"}, {Kind: "macos_team_id", Value: "BQR82RBBHL", Vendor: "salesforce"}},
		{{Kind: "macos_team_id", Value: "BQR82RBBHL", Vendor: "salesforce"}, {Kind: "macos_team_id", Value: "BQR82RBBHL", Vendor: "slack"}},
	} {
		for vendor, ok := range map[string]bool{"slack": true, "salesforce": true, "microsoft": false, "zoom": false} {
			c := Corroborate("macos", slack, aliases, vendor)
			if c.OK != ok {
				t.Errorf("vendor %s with alias order %v: ok = %v, want %v", vendor, aliases[0].Vendor, c.OK, ok)
			}
			if !ok && c.Reason != ReasonSignerVendorMismatch {
				t.Errorf("vendor %s: reason %q, want signer_vendor_mismatch", vendor, c.Reason)
			}
			if strings.Join(c.Vendors, ",") != "salesforce,slack" {
				t.Errorf("vendors = %v, want sorted [salesforce slack]", c.Vendors)
			}
		}
	}
}
