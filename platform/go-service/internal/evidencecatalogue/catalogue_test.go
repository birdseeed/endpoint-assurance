package evidencecatalogue

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEmbeddedCatalogueIsCommerciallyUsefulAndValid(t *testing.T) {
	catalogue, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if got := len(catalogue.Entries); got < 20 || got > 30 {
		t.Fatalf("entry count = %d, want 20..30", got)
	}

	products := make(map[string]struct{}, len(catalogue.Entries))
	for _, entry := range catalogue.Entries {
		products[entry.CanonicalIdentity.ProductKey] = struct{}{}
	}
	for _, key := range []string{"google-chrome", "microsoft-word", "slack", "zoom-workplace", "tailscale"} {
		if _, ok := products[key]; !ok {
			t.Errorf("missing representative business product %q", key)
		}
	}

	for _, prohibited := range []string{`"installer"`, `"package"`, `"deployment"`, `"remediation"`, `"script"`} {
		if strings.Contains(string(embeddedCatalogue), prohibited) {
			t.Errorf("catalogue data contains prohibited execution-authority field %s", prohibited)
		}
	}
}

func TestSchemaDocumentIsJSONAndProhibitsDisplayNameIdentity(t *testing.T) {
	data, err := os.ReadFile("catalogue.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema JSON: %v", err)
	}
	if strings.Contains(string(data), "display_name") {
		t.Fatal("schema must not permit display-name identity")
	}
}

func TestPortableSchemaRejectsInvalidAuthenticodeSubject(t *testing.T) {
	type valueConstraints struct {
		MinLength int `json:"minLength"`
		MaxLength int `json:"maxLength"`
		AllOf     []struct {
			Pattern string `json:"pattern"`
		} `json:"allOf"`
	}
	type condition struct {
		If struct {
			Properties struct {
				Kind struct {
					Const string `json:"const"`
				} `json:"kind"`
			} `json:"properties"`
		} `json:"if"`
		Then struct {
			Properties struct {
				Value valueConstraints `json:"value"`
			} `json:"properties"`
		} `json:"then"`
	}
	var schema struct {
		Defs struct {
			Signer struct {
				AllOf []condition `json:"allOf"`
			} `json:"signer"`
		} `json:"$defs"`
	}
	data, err := os.ReadFile("catalogue.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}

	var constraints valueConstraints
	for _, candidate := range schema.Defs.Signer.AllOf {
		if candidate.If.Properties.Kind.Const == "authenticode_subject" {
			constraints = candidate.Then.Properties.Value
		}
	}
	if constraints.MinLength != 3 || constraints.MaxLength != 8192 || len(constraints.AllOf) < 2 {
		t.Fatalf("portable Authenticode constraints incomplete: %+v", constraints)
	}
	accepts := func(value string) bool {
		length := utf8.RuneCountInString(value)
		if length < constraints.MinLength || length > constraints.MaxLength {
			return false
		}
		for _, item := range constraints.AllOf {
			pattern, err := regexp.Compile(item.Pattern)
			if err != nil {
				t.Fatalf("compile schema pattern %q: %v", item.Pattern, err)
			}
			if !pattern.MatchString(value) {
				return false
			}
		}
		return true
	}
	for _, value := range []string{"Microsoft Corporation", "Éditeur Logiciel SA"} {
		if !accepts(value) {
			t.Errorf("portable schema rejected representative subject %q", value)
		}
	}
	for _, value := range []string{"x", "!!!", "Example\nCorporation", "Example\x7fCorporation"} {
		if accepts(value) {
			t.Errorf("portable schema accepted invalid subject %q", value)
		}
	}
}

func TestParseRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"schema_version":1,"catalogue_version":"v1","published_at":"2026-09-20T00:00:00Z","entries":[],"authority":true}`),
		append(append([]byte(nil), embeddedCatalogue...), []byte(` {}`)...),
	} {
		if _, err := Parse(data); err == nil {
			t.Fatal("Parse accepted an unknown field or trailing JSON value")
		}
	}
}

func TestValidateRejectsIncompleteIdentityClaims(t *testing.T) {
	base := validMacEntry()
	tests := []struct {
		name   string
		mutate func(*Entry)
	}{
		{"missing stable identifier", func(entry *Entry) { entry.StableIdentifiers = nil }},
		{"display name identifier", func(entry *Entry) { entry.StableIdentifiers[0].Kind = "display_name" }},
		{"missing path", func(entry *Entry) { entry.PermittedPaths = nil }},
		{"relative path", func(entry *Entry) { entry.PermittedPaths = []string{"Example.app"} }},
		{"wildcard path", func(entry *Entry) { entry.PermittedPaths = []string{"/Applications/*/Example.app"} }},
		{"missing signer", func(entry *Entry) { entry.ExpectedSigner = Signer{} }},
		{"signer wrong platform", func(entry *Entry) { entry.ExpectedSigner.Kind = "authenticode_subject" }},
		{"missing source", func(entry *Entry) { entry.Sources = nil }},
		{"non vendor source", func(entry *Entry) { entry.Sources[0].Kind = "community" }},
		{"missing artifact proof", func(entry *Entry) { entry.Review.CodeDirectoryHash = "" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := cloneEntry(t, base)
			test.mutate(&entry)
			catalogue := validCatalogue(entry)
			if err := Validate(&catalogue); err == nil {
				t.Fatal("Validate accepted incomplete identity claim")
			}
		})
	}
}

func TestValidateSupportsWindowsIdentityWithoutWeakeningIt(t *testing.T) {
	entry := validWindowsEntry("winget_id", "Example.CorporateApp")
	if err := validateCatalogueEntry(entry); err != nil {
		t.Fatalf("valid Windows evidence rejected: %v", err)
	}

	for _, path := range []string{`C:\Program Files\..\CorporateApp.exe`, `C:\Program Files\\CorporateApp.exe`, `1:\Program Files\Example.exe`} {
		invalid := cloneEntry(t, entry)
		invalid.PermittedPaths = []string{path}
		if err := validateCatalogueEntry(invalid); err == nil {
			t.Fatalf("unsafe Windows path accepted: %q", path)
		}
	}
}

func TestValidatePlatformIdentifierFormats(t *testing.T) {
	exact128WingetID := strings.Join([]string{
		strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32),
		strings.Repeat("d", 20), "e", "f", "g", "hh",
	}, ".")
	if got := utf8.RuneCountInString(exact128WingetID); got != 128 {
		t.Fatalf("exact boundary fixture length = %d, want 128", got)
	}
	tests := []struct {
		name      string
		entry     Entry
		wantValid bool
	}{
		{"mac bundle", withStableIdentifier(validMacEntry(), "bundle_id", "com.example-App.product"), true},
		{"mac at sign", withStableIdentifier(validMacEntry(), "bundle_id", "com.example@app"), false},
		{"mac empty component", withStableIdentifier(validMacEntry(), "bundle_id", "com..example"), false},
		{"mac leading period", withStableIdentifier(validMacEntry(), "bundle_id", ".com.example"), false},
		{"winget package identifier", validWindowsEntry("winget_id", "Microsoft.VisualStudioCode"), true},
		{"winget exact eight segments", validWindowsEntry("winget_id", "a.b.c.d.e.f.g.h"), true},
		{"winget exact 128 characters", validWindowsEntry("winget_id", exact128WingetID), true},
		{"winget permits Unicode outside prohibited class", validWindowsEntry("winget_id", "Éditeur.Application"), true},
		{"winget requires two segments", validWindowsEntry("winget_id", "VisualStudioCode"), false},
		{"winget rejects empty segment", validWindowsEntry("winget_id", "Microsoft..VisualStudioCode"), false},
		{"winget rejects reserved punctuation", validWindowsEntry("winget_id", "Microsoft:VisualStudioCode"), false},
		{"winget rejects ninth segment", validWindowsEntry("winget_id", "a.b.c.d.e.f.g.h.i"), false},
		{"winget rejects 33 character segment", validWindowsEntry("winget_id", "Microsoft."+strings.Repeat("a", 33)), false},
		{"msix package family", validWindowsEntry("msix_package_family_name", "Microsoft.Windows.Photos_8wekyb3d8bbwe"), true},
		{"msix publisher is case insensitive", validWindowsEntry("msix_package_family_name", "Microsoft.Windows.Photos_8WEKYB3D8BBWE"), true},
		{"msix publisher length", validWindowsEntry("msix_package_family_name", "Microsoft.Windows.Photos_8wekyb3d8bbw"), false},
		{"msix publisher alphabet", validWindowsEntry("msix_package_family_name", "Microsoft.Windows.Photos_8wekyb3d8bbwi"), false},
		{"msix package name characters", validWindowsEntry("msix_package_family_name", "Microsoft_Windows.Photos_8wekyb3d8bbwe"), false},
		{"msix reserved package name", validWindowsEntry("msix_package_family_name", "CON_8wekyb3d8bbwe"), false},
		{"msix reserved package name case insensitive", validWindowsEntry("msix_package_family_name", "cOn_8wekyb3d8bbwe"), false},
		{"msix reserved package name prefix", validWindowsEntry("msix_package_family_name", "Lpt9.Tools_8wekyb3d8bbwe"), false},
		{"msix punycode package name prefix", validWindowsEntry("msix_package_family_name", "xn--spoof_8wekyb3d8bbwe"), false},
		{"msix embedded punycode component", validWindowsEntry("msix_package_family_name", "Example.xn--spoof_8wekyb3d8bbwe"), false},
		{"msix similar non-reserved package name", validWindowsEntry("msix_package_family_name", "Console.Tools_8wekyb3d8bbwe"), true},
		{"msix package name trailing period", validWindowsEntry("msix_package_family_name", "Microsoft.Windows.Photos._8wekyb3d8bbwe"), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCatalogueEntry(test.entry)
			if test.wantValid && err != nil {
				t.Fatalf("valid identifier rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("invalid identifier accepted")
			}
		})
	}
}

func TestValidateAuthenticodeSubject(t *testing.T) {
	valid := []string{
		"Microsoft Corporation",
		"Zoom Video Communications, Inc.",
		"Éditeur Logiciel SA",
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
		`CN="C++ Inc.", O=Example Corporation, C=US`,
		`CN="William ""Bill"" Smith", O=Example Corporation, C=US`,
		"O=Example Corporation, C=US, CN=Example Publisher",
		"CN=Example Publisher, OID.2.5.4.34=1234",
	}
	invalid := []string{
		"x",
		"!!!",
		"https://example.com",
		"CN=",
		"CN=Example,O=Example",
		"O=Example Corporation, C=US",
		"UNKNOWN=Example, CN=Example Corporation",
		"CN=Example Corporation, ",
		"CN=Example Corporation,",
		`CN="Example Corporation, O=Example Corporation`,
		`CN="Example "Nested" Corporation", O=Example Corporation`,
		`CN="Example ""Corporation, O=Example Corporation`,
		"=Example Corporation, CN=Example Corporation",
		"CN=, O=Example Corporation",
		" Example Corporation",
		"Example\nCorporation",
	}
	for _, subject := range valid {
		t.Run("valid "+subject, func(t *testing.T) {
			entry := validWindowsEntry("winget_id", "Example.CorporateApp")
			entry.ExpectedSigner.Value = subject
			if err := validateCatalogueEntry(entry); err != nil {
				t.Fatalf("valid Authenticode subject rejected: %v", err)
			}
		})
	}
	for _, subject := range invalid {
		t.Run("invalid "+subject, func(t *testing.T) {
			entry := validWindowsEntry("winget_id", "Example.CorporateApp")
			entry.ExpectedSigner.Value = subject
			if err := validateCatalogueEntry(entry); err == nil {
				t.Fatal("invalid Authenticode subject accepted")
			}
		})
	}
}

func TestValidateRejectsEmptyCatalogue(t *testing.T) {
	catalogue := validCatalogue()
	if err := Validate(&catalogue); err == nil || !strings.Contains(err.Error(), "entries must not be empty") {
		t.Fatalf("Validate empty catalogue error = %v", err)
	}
}

func TestWindowsMatcherNormalisesDriveLetterAndPathCase(t *testing.T) {
	entry := validWindowsEntry("winget_id", "Example.CorporateApp")
	entry.PermittedPaths = []string{`c:\Program Files\Example\CorporateApp.exe`}
	matcher, err := NewMatcher(cataloguePointer(validCatalogue(entry)))
	if err != nil {
		t.Fatal(err)
	}
	got := matcher.Match(Observation{
		Platform: "windows", IdentifierKind: "winget_id", IdentifierValue: "example.corporateapp",
		Path: `C:\PROGRAM FILES\EXAMPLE\CORPORATEAPP.EXE`, SignerKind: "authenticode_subject", SignerValue: "example corporation",
	})
	if got.Status != MatchExpected || got.EntryID != "example.windows" {
		t.Fatalf("case-normalised Windows match = %+v", got)
	}
}

func TestValidateRejectsDuplicateStableIdentity(t *testing.T) {
	first := validMacEntry()
	second := cloneEntry(t, first)
	second.ID = "other-example.macos"
	second.CanonicalIdentity.ProductKey = "other-example"
	second.CanonicalIdentity.ProductName = "Other Example"

	catalogue := validCatalogue(first, second)
	if err := Validate(&catalogue); err == nil || !strings.Contains(err.Error(), "duplicates entry") {
		t.Fatalf("Validate duplicate identity error = %v", err)
	}
}

func TestMatcherExpectedUnexpectedPathSignerMismatchAndOutliers(t *testing.T) {
	catalogue, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := NewMatcher(catalogue)
	if err != nil {
		t.Fatal(err)
	}
	base := Observation{
		Platform:        "macos",
		IdentifierKind:  "bundle_id",
		IdentifierValue: "com.google.Chrome",
		Path:            "/Applications/Google Chrome.app",
		SignerKind:      "apple_team_id",
		SignerValue:     "EQHXZ8M8AV",
	}

	tests := []struct {
		name        string
		observation Observation
		want        MatchStatus
	}{
		{"expected", base, MatchExpected},
		{"unexpected path", withPath(base, "/Users/example/Applications/Google Chrome.app"), MatchUnexpectedPath},
		{"signer mismatch", withSigner(base, "AAAAAAAAAA"), MatchSignerMismatch},
		{"team ID case mismatch", withSigner(base, "eqhxz8m8av"), MatchSignerMismatch},
		{"malformed bundle outlier", withIdentifier(base, "com.google@Chrome"), MatchUnrecognised},
		{"unknown bundle outlier", withIdentifier(base, "com.example.lookalike"), MatchUnrecognised},
		{"display name outlier", withKindAndIdentifier(base, "display_name", "Google Chrome"), MatchUnrecognised},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := matcher.Match(test.observation)
			if got.Status != test.want {
				t.Fatalf("status = %q, want %q", got.Status, test.want)
			}
			if test.want == MatchUnrecognised && got.EntryID != "" {
				t.Fatalf("unrecognised observation disclosed entry %q", got.EntryID)
			}
			if test.want != MatchUnrecognised && got.EntryID != "google-chrome.macos" {
				t.Fatalf("entry = %q, want google-chrome.macos", got.EntryID)
			}
		})
	}
}

func TestCatalogueVersionCanRollBackWithoutCodeOrEndpointBehaviour(t *testing.T) {
	current, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	prior := cloneCatalogue(t, current)
	prior.CatalogueVersion = "2026.09.19.1"
	prior.PublishedAt = "2026-09-19T00:00:00Z"
	prior.Entries = prior.Entries[:len(prior.Entries)-1]

	currentMatcher, err := NewMatcher(current)
	if err != nil {
		t.Fatal(err)
	}
	priorMatcher, err := NewMatcher(prior)
	if err != nil {
		t.Fatalf("prior catalogue remains schema-compatible: %v", err)
	}
	spotify := Observation{
		Platform: "macos", IdentifierKind: "bundle_id", IdentifierValue: "com.spotify.client",
		Path: "/Applications/Spotify.app", SignerKind: "apple_team_id", SignerValue: "2FNC3A47ZF",
	}
	if got := currentMatcher.Match(spotify).Status; got != MatchExpected {
		t.Fatalf("current Spotify status = %q", got)
	}
	if got := priorMatcher.Match(spotify).Status; got != MatchUnrecognised {
		t.Fatalf("rolled-back Spotify status = %q, want unrecognised", got)
	}
}

func validateCatalogueEntry(entry Entry) error {
	catalogue := validCatalogue(entry)
	return Validate(&catalogue)
}

func validCatalogue(entries ...Entry) Catalogue {
	return Catalogue{SchemaVersion: SchemaVersion, CatalogueVersion: "test.1", PublishedAt: "2026-09-20T00:00:00Z", Entries: entries}
}

func validMacEntry() Entry {
	return Entry{
		ID: "example.macos", Rationale: "Test evidence",
		CanonicalIdentity: CanonicalIdentity{ProductKey: "example", ProductName: "Example", VendorName: "Example Corporation"},
		Platform:          "macos", StableIdentifiers: []StableIdentifier{{Kind: "bundle_id", Value: "com.example.app"}},
		PermittedPaths: []string{"/Applications/Example.app"}, ExpectedSigner: Signer{Kind: "apple_team_id", Value: "ABCDE12345"},
		Sources: []SourceProvenance{{Kind: "primary_vendor", URL: "https://example.com/download", Supports: "Vendor distribution", ReviewedAt: "2026-09-20T00:00:00Z"}},
		Review:  ReviewProvenance{Reference: "PAT-test", Method: "codesign_bundle_inspection", ReviewedAt: "2026-09-20T00:00:00Z", ArtifactVersion: "1.0", CodeDirectoryHash: strings.Repeat("a", 40)},
	}
}

func validWindowsEntry(kind, value string) Entry {
	entry := validMacEntry()
	entry.ID = "example.windows"
	entry.Platform = "windows"
	entry.StableIdentifiers = []StableIdentifier{{Kind: kind, Value: value}}
	entry.PermittedPaths = []string{`C:\Program Files\Example\CorporateApp.exe`}
	entry.ExpectedSigner = Signer{Kind: "authenticode_subject", Value: "Example Corporation"}
	entry.Review.Method = "authenticode_artifact_inspection"
	entry.Review.CodeDirectoryHash = ""
	entry.Review.ArtifactSHA256 = strings.Repeat("a", 64)
	return entry
}

func withStableIdentifier(entry Entry, kind, value string) Entry {
	entry.StableIdentifiers = []StableIdentifier{{Kind: kind, Value: value}}
	return entry
}

func cataloguePointer(catalogue Catalogue) *Catalogue {
	return &catalogue
}

func cloneEntry(t *testing.T, entry Entry) Entry {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var clone Entry
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func cloneCatalogue(t *testing.T, catalogue *Catalogue) *Catalogue {
	t.Helper()
	data, err := json.Marshal(catalogue)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

func withPath(observation Observation, path string) Observation {
	observation.Path = path
	return observation
}

func withSigner(observation Observation, signer string) Observation {
	observation.SignerValue = signer
	return observation
}

func withIdentifier(observation Observation, identifier string) Observation {
	observation.IdentifierValue = identifier
	return observation
}

func withKindAndIdentifier(observation Observation, kind, identifier string) Observation {
	observation.IdentifierKind = kind
	observation.IdentifierValue = identifier
	return observation
}
