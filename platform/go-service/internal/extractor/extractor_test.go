package extractor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// loadFixture reads the sample schema_v2 payload that mirrors what
// patched-collect.sh emits on a real Mac. Real-DB extraction is tested
// out-of-band against the live patched-api-01 box; these unit tests cover
// the pieces that are easy to get wrong without that context.
func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sample-payload-v2.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestPayloadParse(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if p.SchemaVersion != 2 {
		t.Errorf("schema_version: got %d want 2", p.SchemaVersion)
	}
	if p.AgentVersion != "0.2.0" {
		t.Errorf("agent_version: got %q want 0.2.0", p.AgentVersion)
	}
	if got, want := p.Device.HWUUID, "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"; got != want {
		t.Errorf("hw_uuid: got %q want %q", got, want)
	}
	if got, want := p.OS.Version, "15.4.1"; got != want {
		t.Errorf("os.version: got %q want %q", got, want)
	}
	if got, want := len(p.Apps), 3; got != want {
		t.Errorf("apps len: got %d want %d", got, want)
	}
	if p.Apps[1].Notarized == nil || !*p.Apps[1].Notarized {
		t.Error("Slack should be notarized=true in fixture")
	}
	if len(p.Hardware) == 0 {
		t.Error("hardware RawMessage should not be empty")
	}
	if got, want := p.ICloud.SignedIn, "Yes"; got != want {
		t.Errorf("icloud.signed_in: got %q want %q", got, want)
	}
}

func TestUUIDRegex(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A", true},
		{"9c8b7a6f-5e4d-3c2b-1a09-8f7e6d5c4b3a", true}, // lowercase variant
		{"Unknown", false},
		{"", false},
		{"9C8B7A6F-5E4D-3C2B-1A09", false}, // truncated
		{"9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A-extra", false}, // suffix
		{"ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ", false},       // non-hex
	}
	for _, tc := range cases {
		if got := uuidRegex.MatchString(tc.in); got != tc.want {
			t.Errorf("uuidRegex(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestRenderJSONValue(t *testing.T) {
	cases := []struct {
		raw    string
		want   string
		wantOK bool
	}{
		{`"On"`, "On", true},
		{`"DefaultAssumed"`, "DefaultAssumed", true},
		{`"contains \"quotes\""`, `contains "quotes"`, true},
		{`5`, "5", true},
		{`-1`, "-1", true},
		{`true`, "true", true},
		{`false`, "false", true},
		{`null`, "", false},
		{``, "", false},
		{`"with\ttab"`, "with\ttab", true},
	}
	for _, tc := range cases {
		got, ok := renderJSONValue(json.RawMessage(tc.raw))
		if ok != tc.wantOK {
			t.Errorf("renderJSONValue(%q) ok=%v want %v", tc.raw, ok, tc.wantOK)
			continue
		}
		if got != tc.want {
			t.Errorf("renderJSONValue(%q) = %q want %q", tc.raw, got, tc.want)
		}
	}
}

func TestNullIfHelpers(t *testing.T) {
	if v := nullIfEmpty(""); v != nil {
		t.Errorf("nullIfEmpty(\"\") = %v, want nil", v)
	}
	if v := nullIfEmpty("x"); v != "x" {
		t.Errorf("nullIfEmpty(\"x\") = %v, want x", v)
	}
	if v := nullIfPlaceholder("Unknown"); v != nil {
		t.Errorf("nullIfPlaceholder(\"Unknown\") = %v, want nil", v)
	}
	if v := nullIfPlaceholder(""); v != nil {
		t.Errorf("nullIfPlaceholder(\"\") = %v, want nil", v)
	}
	if v := nullIfPlaceholder("Software Signing"); v != "Software Signing" {
		t.Errorf("nullIfPlaceholder real string roundtrip failed, got %v", v)
	}
}

// loadWindowsFixture reads the sample schema_v3 Windows payload.
func loadWindowsFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sample-payload-v3-windows.json"))
	if err != nil {
		t.Fatalf("read windows fixture: %v", err)
	}
	return b
}

// TestV3WindowsPayloadParse verifies that a v3 Windows payload parses cleanly
// and that the new fields (Platform, Identifier, Publisher) survive unmarshal.
func TestV3WindowsPayloadParse(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadWindowsFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.SchemaVersion != 3 {
		t.Errorf("schema_version: got %d want 3", p.SchemaVersion)
	}
	if p.Platform != "windows" {
		t.Errorf("platform: got %q want windows", p.Platform)
	}
	if got, want := len(p.Apps), 3; got != want {
		t.Fatalf("apps len: got %d want %d", got, want)
	}
	if got, want := p.Apps[0].Identifier, "Microsoft Edge"; got != want {
		t.Errorf("apps[0].identifier: got %q want %q", got, want)
	}
	if got, want := p.Apps[0].Publisher, "Microsoft Corporation"; got != want {
		t.Errorf("apps[0].publisher: got %q want %q", got, want)
	}
	if p.Apps[0].BundleID != "" {
		t.Errorf("apps[0].bundle_id: expected empty for Windows app, got %q", p.Apps[0].BundleID)
	}
}

func TestWindowsWingetInventoryCapabilityValidation(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(loadWindowsFixture(t), &doc); err != nil {
		t.Fatal(err)
	}
	// Existing collectors remain valid inventory uploads but declare no
	// completeness, so mandatory evaluation will fail closed rather than infer
	// app absence.
	legacy, _ := json.Marshal(doc)
	if err := ValidatePayload(legacy); err != nil {
		t.Fatalf("legacy Windows inventory unexpectedly invalid: %v", err)
	}
	doc["inventory_capabilities"] = map[string]any{"schema_version": 1, "windows_winget_inventory_complete": true}
	apps := doc["apps"].([]any)
	for _, raw := range apps {
		raw.(map[string]any)["identifier_kind"] = "native"
	}
	apps[0].(map[string]any)["identifier"] = "microsoft.edge"
	apps[0].(map[string]any)["identifier_kind"] = "winget"
	valid, _ := json.Marshal(doc)
	if err := ValidatePayload(valid); err != nil {
		t.Fatalf("versioned complete Winget inventory invalid: %v", err)
	}
	delete(apps[1].(map[string]any), "identifier_kind")
	missingKind, _ := json.Marshal(doc)
	if err := ValidatePayload(missingKind); err == nil || !strings.Contains(err.Error(), "identifier_kind") {
		t.Fatalf("complete inventory accepted untyped app: %v", err)
	}
	apps[1].(map[string]any)["identifier_kind"] = "native"
	apps[0].(map[string]any)["identifier"] = "Microsoft.Edge"
	uppercaseWinget, _ := json.Marshal(doc)
	if err := ValidatePayload(uppercaseWinget); err != nil {
		t.Fatalf("official Winget schema permits case-sensitive mixed-case IDs: %v", err)
	}

	for _, tc := range []struct {
		name string
		caps map[string]any
	}{
		{"explicit false", map[string]any{"schema_version": 1, "windows_winget_inventory_complete": false}},
		{"unsupported false", map[string]any{"schema_version": 2, "windows_winget_inventory_complete": false}},
		{"partial schema only", map[string]any{"schema_version": 1}},
		{"partial completeness only", map[string]any{"windows_winget_inventory_complete": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var partial map[string]any
			if err := json.Unmarshal(loadWindowsFixture(t), &partial); err != nil {
				t.Fatal(err)
			}
			partial["inventory_capabilities"] = tc.caps
			body, _ := json.Marshal(partial)
			if err := ValidatePayload(body); err != nil {
				t.Fatalf("non-authoritative capability must preserve inventory: %v", err)
			}
		})
	}
	var invalidKind map[string]any
	if err := json.Unmarshal(loadWindowsFixture(t), &invalidKind); err != nil {
		t.Fatal(err)
	}
	invalidKind["inventory_capabilities"] = map[string]any{"schema_version": 1, "windows_winget_inventory_complete": false}
	invalidKind["apps"].([]any)[0].(map[string]any)["identifier_kind"] = "msi"
	invalidKindBody, _ := json.Marshal(invalidKind)
	if err := ValidatePayload(invalidKindBody); err == nil || !strings.Contains(err.Error(), "value must be winget or native") {
		t.Fatalf("false capability accepted invalid identifier_kind: %v", err)
	}
	var nonWindows map[string]any
	if err := json.Unmarshal(loadWindowsFixture(t), &nonWindows); err != nil {
		t.Fatal(err)
	}
	nonWindows["platform"] = "macos"
	nonWindows["inventory_capabilities"] = map[string]any{
		"schema_version": 1, "windows_winget_inventory_complete": false,
	}
	nonWindowsBody, _ := json.Marshal(nonWindows)
	if err := ValidatePayload(nonWindowsBody); err != nil {
		t.Fatalf("non-Windows false capability must preserve inventory: %v", err)
	}
	nonWindows["inventory_capabilities"] = map[string]any{
		"schema_version": 1, "windows_winget_inventory_complete": true,
	}
	invalidPositiveBody, _ := json.Marshal(nonWindows)
	if err := ValidatePayload(invalidPositiveBody); err == nil || !strings.Contains(err.Error(), "requires Windows schema_version 1") {
		t.Fatalf("non-Windows positive capability gained authority: %v", err)
	}

	var nonObject map[string]any
	if err := json.Unmarshal(loadWindowsFixture(t), &nonObject); err != nil {
		t.Fatal(err)
	}
	nonObject["inventory_capabilities"] = map[string]any{"schema_version": 1, "windows_winget_inventory_complete": true}
	nonObject["apps"] = []any{float64(1)}
	nonObjectBody, _ := json.Marshal(nonObject)
	if err := ValidatePayload(nonObjectBody); err == nil || !strings.Contains(err.Error(), "apps[0]: must be an object") {
		t.Fatalf("positive capability with non-object app did not fail safely: %v", err)
	}
}

func TestWingetPackageIdentifierSchema(t *testing.T) {
	valid := []string{
		"notepad++.notepad++",
		"dotpdnllc.paint.net",
		"Microsoft.VisualStudioCode",
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + ".c.d.e",
	}
	for _, id := range valid {
		if !isCanonicalWingetInventoryID(id) {
			t.Errorf("official Winget PackageIdentifier rejected: %q", id)
		}
	}
	invalid := []string{
		"single", "bad..segment", ".leading.dot", "trailing.dot.",
		"bad/id", "bad\\id", "bad:id", "bad id", "bad\x01id",
		strings.Repeat("a", 33) + ".b",
		"a.b.c.d.e.f.g.h.i",
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + "." + strings.Repeat("c", 32) + "." + strings.Repeat("d", 30),
	}
	for _, id := range invalid {
		if isCanonicalWingetInventoryID(id) {
			t.Errorf("invalid Winget PackageIdentifier accepted: %q", id)
		}
	}
}

func TestLegacySchemaClearsInventoryAuthority(t *testing.T) {
	p := payload{
		SchemaVersion:         2,
		InventoryCapabilities: &inventoryCapabilitiesPart{SchemaVersion: 1, WindowsWingetInventoryComplete: true},
		Apps:                  []appPart{{Identifier: "Microsoft.Edge", IdentifierKind: "winget"}},
	}
	clearLegacyInventoryAuthority(&p)
	if p.InventoryCapabilities != nil || p.Apps[0].IdentifierKind != "" {
		t.Fatalf("legacy schema retained inventory authority: %#v", p)
	}
}

// TestMeteringFieldsParse verifies that the v0.10.0 software-metering fields
// unmarshal into the pointer types, that an app omitting them yields nil (the
// signal that distinguishes "no data" from a real zero in upsertApps), and that
// the top-level metering_status provenance field is captured.
func TestMeteringFieldsParse(t *testing.T) {
	const body = `{
		"schema_version": 3,
		"metering_status": "ok",
		"apps": [
			{"name":"Safari","version":"17.4","identifier":"com.apple.Safari","last_used_at":"2026-12-13T09:27:44Z","launch_count":503},
			{"name":"Unused","version":"1.0","identifier":"com.example.unused","last_used_at":null,"launch_count":null},
			{"name":"OldAgent","version":"1.0","identifier":"com.example.old"}
		]
	}`
	var p payload
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, want := p.MeteringStatus, "ok"; got != want {
		t.Errorf("metering_status: got %q want %q", got, want)
	}
	if got, want := len(p.Apps), 3; got != want {
		t.Fatalf("apps len: got %d want %d", got, want)
	}
	// Used app: both fields populated.
	if p.Apps[0].LastUsedAt == nil || *p.Apps[0].LastUsedAt != "2026-12-13T09:27:44Z" {
		t.Errorf("apps[0].last_used_at: got %v want 2026-12-13T09:27:44Z", p.Apps[0].LastUsedAt)
	}
	if p.Apps[0].LaunchCount == nil || *p.Apps[0].LaunchCount != 503 {
		t.Errorf("apps[0].launch_count: got %v want 503", p.Apps[0].LaunchCount)
	}
	// Explicit JSON null and omitted field must both yield nil — never a zero
	// that would clobber a stored value on re-extraction.
	for _, i := range []int{1, 2} {
		if p.Apps[i].LastUsedAt != nil {
			t.Errorf("apps[%d].last_used_at: got %v want nil", i, *p.Apps[i].LastUsedAt)
		}
		if p.Apps[i].LaunchCount != nil {
			t.Errorf("apps[%d].launch_count: got %v want nil", i, *p.Apps[i].LaunchCount)
		}
	}
}

// TestPlatformResolution verifies the v2→macos defaulting and v3 explicit platform.
func TestPlatformResolution(t *testing.T) {
	cases := []struct {
		name     string
		fixture  func(*testing.T) []byte
		wantPlat string
	}{
		{"v2 macOS (absent platform field)", loadFixture, "macos"},
		{"v3 Windows (explicit platform)", loadWindowsFixture, "windows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p payload
			if err := json.Unmarshal(tc.fixture(t), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			platform := p.Platform
			if platform == "" {
				platform = "macos"
			}
			if platform != tc.wantPlat {
				t.Errorf("resolved platform: got %q want %q", platform, tc.wantPlat)
			}
		})
	}
}

// TestIdentifierFallback verifies that upsertApps prefers the v3 `identifier`
// field and falls back to `bundle_id` for v2 macOS payloads.
func TestIdentifierFallback(t *testing.T) {
	cases := []struct {
		name      string
		app       appPart
		wantIdent string
		wantSkip  bool
	}{
		{
			name:      "v3: identifier present, no bundle_id",
			app:       appPart{Name: "Edge", Version: "1.0", Identifier: "Microsoft Edge"},
			wantIdent: "Microsoft Edge",
		},
		{
			name:      "v2: bundle_id fallback when identifier absent",
			app:       appPart{Name: "Safari", Version: "18.4", BundleID: "com.apple.Safari"},
			wantIdent: "com.apple.Safari",
		},
		{
			name:      "v3: identifier takes precedence over bundle_id",
			app:       appPart{Name: "App", Version: "1.0", Identifier: "the-identifier", BundleID: "com.example.app"},
			wantIdent: "the-identifier",
		},
		{
			name:     "skip: both identifier and bundle_id empty",
			app:      appPart{Name: "Bad App", Version: "1.0"},
			wantSkip: true,
		},
		{
			name:     "skip: bundle_id is Unknown placeholder",
			app:      appPart{Name: "Broken", Version: "1.0", BundleID: "Unknown"},
			wantSkip: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			identifier := strings.TrimSpace(tc.app.Identifier)
			if identifier == "" {
				identifier = strings.TrimSpace(tc.app.BundleID)
			}
			skip := identifier == "" || identifier == "Unknown"
			if skip != tc.wantSkip {
				t.Errorf("skip=%v want %v (resolved identifier=%q)", skip, tc.wantSkip, identifier)
				return
			}
			if !skip && identifier != tc.wantIdent {
				t.Errorf("identifier: got %q want %q", identifier, tc.wantIdent)
			}
		})
	}
}

// TestSchemaVersionRange verifies the supported version window. v2 and v3 must
// parse cleanly; v1 and v4 must be rejected by the same logic processRow uses.
// (processRow itself needs a real DB — this tests the logic directly.)
func TestSchemaVersionRange(t *testing.T) {
	base := loadFixture(t)

	for _, tc := range []struct {
		version int
		wantOK  bool
	}{
		{1, false},
		{2, true},
		{3, true},
		{4, false},
	} {
		// Patch schema_version in the raw JSON by unmarshalling into a map,
		// changing the field, and re-marshalling. Keeps the test independent
		// of payload struct internals.
		var m map[string]any
		if err := json.Unmarshal(base, &m); err != nil {
			t.Fatalf("unmarshal base: %v", err)
		}
		m["schema_version"] = tc.version
		patched, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal patched v%d: %v", tc.version, err)
		}
		var p payload
		if err := json.Unmarshal(patched, &p); err != nil {
			t.Fatalf("unmarshal v%d payload: %v", tc.version, err)
		}
		accepted := p.SchemaVersion >= minSupportedSchemaVersion && p.SchemaVersion <= maxSupportedSchemaVersion
		if accepted != tc.wantOK {
			t.Errorf("schema_version %d: accepted=%v, want %v", tc.version, accepted, tc.wantOK)
		}
	}
}

// TestV3CompliancePassthrough verifies that a v3 payload carrying T2 compliance
// signals (keys unknown to the extractor at compile time) parses without error
// and those keys survive the renderJSONValue pass. This is the core property
// that lets T2 signals flow through without any code change to the extractor.
func TestV3CompliancePassthrough(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["schema_version"] = 3
	// Inject a T2 signal that doesn't exist in v2.
	compliance, _ := m["compliance"].(map[string]any)
	compliance["pwpolicy_min_length"] = 12
	m["compliance"] = compliance

	patched, _ := json.Marshal(m)
	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal v3 payload: %v", err)
	}
	raw, ok := p.Compliance["pwpolicy_min_length"]
	if !ok {
		t.Fatal("T2 signal pwpolicy_min_length missing from compliance map after parse")
	}
	got, ok := renderJSONValue(raw)
	if !ok {
		t.Fatal("renderJSONValue(pwpolicy_min_length) returned not-ok")
	}
	if got != "12" {
		t.Errorf("pwpolicy_min_length: got %q want \"12\"", got)
	}
}

// TestComplianceRender confirms that the values from the fixture's
// compliance bag survive the JSON-render pass. Catches changes to the
// shape of complianceMap that would otherwise silently degrade signals.
func TestComplianceRender(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	expect := map[string]string{
		"filevault":                 "On",
		"sip":                       "enabled",
		"pending_updates_count":     "0",
		"screensaver_delay_seconds": "-1",
		"local_admin_count":         "1",
		"password_policy_raw":       "(apple-default-4char-fallback)",
		"mdm_enrolled":              "Yes",
		"mdm_enrolled_via_dep":      "Yes",
		"mdm_enrolment":             "dep=Yes mdm=Yes",
	}
	for key, want := range expect {
		raw, ok := p.Compliance[key]
		if !ok {
			t.Errorf("compliance: missing key %q in fixture", key)
			continue
		}
		got, ok := renderJSONValue(raw)
		if !ok {
			t.Errorf("compliance: %q rendered as not-ok", key)
			continue
		}
		if got != want {
			t.Errorf("compliance[%q]: got %q want %q", key, got, want)
		}
	}
}

// ── Certificate payload parsing ───────────────────────────────────────────────

// TestCertPayloadAbsentKey verifies acceptance criterion 4: a payload that
// carries no "certificates" key at all must leave p.Certificates nil so the
// extractor's no-op branch fires and existing DB rows are untouched.
func TestCertPayloadAbsentKey(t *testing.T) {
	// The v2 fixture has no "certificates" key — representative of every agent
	// version that predates PAT-216.
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Certificates != nil {
		t.Error("Certificates must be nil (pointer) when the key is absent — required for no-op semantics")
	}
}

// TestCertPayloadExplicitEmpty verifies acceptance criterion 3: a payload with
// "certificates": [] must produce a non-nil pointer to an empty slice so the
// extractor's prune-all branch fires.
func TestCertPayloadExplicitEmpty(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["certificates"] = []any{}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if p.Certificates == nil {
		t.Fatal("Certificates must be non-nil when the key is present (even if empty) — required for prune-all semantics")
	}
	if len(*p.Certificates) != 0 {
		t.Errorf("Certificates slice must be empty for 'certificates: []'; got len=%d", len(*p.Certificates))
	}
}

// TestCertPayloadNonEmpty verifies acceptance criterion 2 (parsing half): a
// non-empty certificates array must unmarshal all five fields correctly.
func TestCertPayloadNonEmpty(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["certificates"] = []any{
		map[string]any{
			"subject_cn":        "example.com",
			"issuer_cn":         "DigiCert Global Root CA",
			"sha1":              "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			"not_after":         "2027-01-15T00:00:00Z",
			"days_until_expiry": 588,
		},
		map[string]any{
			"subject_cn":        "other.example.com",
			"issuer_cn":         "Let's Encrypt R3",
			"sha1":              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"not_after":         "2026-09-01T00:00:00Z",
			"days_until_expiry": 87,
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if p.Certificates == nil {
		t.Fatal("Certificates must be non-nil for non-empty array")
	}
	if got, want := len(*p.Certificates), 2; got != want {
		t.Fatalf("Certificates len: got %d want %d", got, want)
	}

	c := (*p.Certificates)[0]
	if c.SubjectCN != "example.com" {
		t.Errorf("subject_cn: got %q want example.com", c.SubjectCN)
	}
	if c.IssuerCN != "DigiCert Global Root CA" {
		t.Errorf("issuer_cn: got %q want DigiCert Global Root CA", c.IssuerCN)
	}
	if c.SHA1 != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" {
		t.Errorf("sha1: got %q", c.SHA1)
	}
	if c.NotAfter != "2027-01-15T00:00:00Z" {
		t.Errorf("not_after: got %q", c.NotAfter)
	}
	if c.DaysUntilExpiry != 588 {
		t.Errorf("days_until_expiry: got %d want 588", c.DaysUntilExpiry)
	}

	// not_after must be parseable as RFC3339 (as upsertCertificates requires).
	if _, err := time.Parse(time.RFC3339, c.NotAfter); err != nil {
		t.Errorf("not_after %q is not RFC3339: %v", c.NotAfter, err)
	}
}

// ── upsertCertificates dispatch semantics ─────────────────────────────────────

// TestCertAbsentVsEmptyDistinction is the crux of the absent-vs-empty
// semantic. It verifies that the *[]certPart pointer distinguishes the two
// cases that a plain []certPart cannot:
//
//   - nil pointer  → absent key (no-op)
//   - non-nil ptr  → key present (prune-all or upsert+prune)
func TestCertAbsentVsEmptyDistinction(t *testing.T) {
	// Case 1: nil (absent) — must be nil so upsertCertificates early-returns.
	var absent *[]certPart
	if absent != nil {
		t.Error("absent certs pointer must be nil")
	}

	// Case 2: non-nil empty — must be non-nil so the prune-all path fires.
	empty := &[]certPart{}
	if empty == nil {
		t.Error("explicit-empty certs pointer must be non-nil")
	}
	if len(*empty) != 0 {
		t.Error("explicit-empty certs slice must have zero elements")
	}

	// Case 3: non-nil non-empty — upsert+prune path.
	nonEmpty := &[]certPart{
		{SubjectCN: "x", IssuerCN: "y", SHA1: "abc", NotAfter: "2027-01-01T00:00:00Z", DaysUntilExpiry: 200},
	}
	if nonEmpty == nil {
		t.Error("non-empty certs pointer must be non-nil")
	}
	if len(*nonEmpty) != 1 {
		t.Errorf("non-empty certs slice: got len=%d want 1", len(*nonEmpty))
	}
}

// ── Query helper unit tests ───────────────────────────────────────────────────

// TestListCertsQueryUsesNotAfter verifies acceptance criterion 5 at the SQL
// level: the expiring-within-N-days filter must reference dc.not_after, never
// the stored days_until_expiry_at_collection snapshot that goes stale between
// agent check-ins.
func TestListCertsQueryUsesNotAfter(t *testing.T) {
	q, args := buildListCertsQuery("tenant-1", ListCertsFilter{ExpiringWithinDays: 30})

	// Scope the assertion to the WHERE clause — SELECT legitimately returns
	// days_until_expiry_at_collection as an audit column; what matters is that
	// the filter does not use it.
	where := q[strings.Index(q, "WHERE"):]
	if strings.Contains(where, "days_until_expiry_at_collection") {
		t.Error("expiry filter must NOT reference days_until_expiry_at_collection — it uses the stale snapshot; use not_after")
	}
	if !strings.Contains(q, "dc.not_after") {
		t.Error("expiry filter must reference dc.not_after for a live recomputed comparison")
	}
	if !strings.Contains(q, "now()") {
		t.Error("expiry filter must use now() so the comparison is always current")
	}
	if len(args) != 2 {
		t.Errorf("expected 2 query args (tenantID + days), got %d", len(args))
	}
	if args[1] != 30 {
		t.Errorf("second arg must be ExpiringWithinDays=30, got %v", args[1])
	}
}

// TestListCertsQueryTenantScopedViaJoin verifies that the query scopes results
// to the tenant by joining through devices.tenant_id, matching the isolation
// pattern used by LoadRules / LoadRulesForTenant.
func TestListCertsQueryTenantScopedViaJoin(t *testing.T) {
	q, args := buildListCertsQuery("my-tenant", ListCertsFilter{})

	if !strings.Contains(q, "JOIN devices d ON d.id = dc.device_id") {
		t.Error("query must join device_certificates through devices for tenant isolation")
	}
	if !strings.Contains(q, "d.tenant_id") {
		t.Error("query must filter by d.tenant_id (join-based scoping)")
	}
	if len(args) != 1 {
		t.Errorf("expected 1 arg (tenantID only), got %d", len(args))
	}
	if args[0] != "my-tenant" {
		t.Errorf("first arg must be tenantID, got %v", args[0])
	}
}

// TestListCertsQueryDeviceFilter verifies that the optional device_id filter is
// appended as an additional AND clause.
func TestListCertsQueryDeviceFilter(t *testing.T) {
	q, args := buildListCertsQuery("tenant-1", ListCertsFilter{DeviceID: "device-uuid"})

	if !strings.Contains(q, "dc.device_id") {
		t.Error("query must filter by dc.device_id when DeviceID is set")
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args (tenantID + deviceID), got %d", len(args))
	}
	if args[1] != "device-uuid" {
		t.Errorf("second arg must be DeviceID, got %v", args[1])
	}
}

// TestListCertsQueryNoExpiryFilterWhenZero verifies that ExpiringWithinDays=0
// (the zero value) does not inject an expiry clause.
func TestListCertsQueryNoExpiryFilterWhenZero(t *testing.T) {
	q, args := buildListCertsQuery("tenant-1", ListCertsFilter{ExpiringWithinDays: 0})

	if strings.Contains(q, "not_after <") {
		t.Error("query must not include an expiry clause when ExpiringWithinDays is 0")
	}
	if len(args) != 1 {
		t.Errorf("expected 1 arg when no expiry filter, got %d", len(args))
	}
}

// ── PAT-221: new classification fields ───────────────────────────────────────

// TestCertPayloadNewFields verifies that a non-empty cert array with all three
// PAT-220 classification fields populated unmarshals correctly.
func TestCertPayloadNewFields(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["certificates"] = []any{
		map[string]any{
			"subject_cn":           "example.com",
			"issuer_cn":            "DigiCert Global Root CA",
			"sha1":                 "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			"not_after":            "2027-01-15T00:00:00Z",
			"days_until_expiry":    588,
			"ext_key_usage":        []any{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"},
			"basic_constraints_ca": true,
			"is_self_signed":       false,
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if p.Certificates == nil {
		t.Fatal("Certificates must be non-nil")
	}
	c := (*p.Certificates)[0]
	if got, want := len(c.EKU), 2; got != want {
		t.Fatalf("EKU len: got %d want %d", got, want)
	}
	if c.EKU[0] != "1.3.6.1.5.5.7.3.1" {
		t.Errorf("EKU[0]: got %q want 1.3.6.1.5.5.7.3.1", c.EKU[0])
	}
	if c.EKU[1] != "1.3.6.1.5.5.7.3.2" {
		t.Errorf("EKU[1]: got %q want 1.3.6.1.5.5.7.3.2", c.EKU[1])
	}
	if !c.BasicConstraintsCA {
		t.Error("basic_constraints_ca: got false want true")
	}
	if c.IsSelfSigned {
		t.Error("is_self_signed: got true want false")
	}
}

// TestCertPayloadNewFieldsAbsent verifies backwards compatibility with PAT-216-only
// agents: a cert array that omits the three PAT-220 fields unmarshals to Go zero
// values (nil/empty slice for EKU, false for the booleans).
func TestCertPayloadNewFieldsAbsent(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["certificates"] = []any{
		map[string]any{
			"subject_cn":        "example.com",
			"issuer_cn":         "DigiCert Global Root CA",
			"sha1":              "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			"not_after":         "2027-01-15T00:00:00Z",
			"days_until_expiry": 588,
			// ext_key_usage, basic_constraints_ca, is_self_signed intentionally absent
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if p.Certificates == nil {
		t.Fatal("Certificates must be non-nil for non-empty array")
	}
	c := (*p.Certificates)[0]
	if len(c.EKU) != 0 {
		t.Errorf("EKU: got len=%d want 0 (zero value for absent field)", len(c.EKU))
	}
	if c.BasicConstraintsCA {
		t.Error("basic_constraints_ca: got true want false (zero value for absent field)")
	}
	if c.IsSelfSigned {
		t.Error("is_self_signed: got true want false (zero value for absent field)")
	}
}

// TestListCertsQueryReturnsNewColumns verifies that the SELECT built by
// buildListCertsQuery includes the three PAT-221 classification columns so that
// ListCertificates can scan them into CertRow.
func TestListCertsQueryReturnsNewColumns(t *testing.T) {
	q, _ := buildListCertsQuery("tenant-1", ListCertsFilter{})

	for _, col := range []string{"ext_key_usage", "basic_constraints_ca", "is_self_signed", "dc.store"} {
		if !strings.Contains(q, col) {
			t.Errorf("SELECT must include column %q for PAT-221/PAT-1738 classification", col)
		}
	}
}

// TestCertPayloadStoreField (PAT-1738) verifies the store field round-trips
// through JSON unmarshal into certPart.Store.
func TestCertPayloadStoreField(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["certificates"] = []any{
		map[string]any{
			"subject_cn":        "Windows Root CA",
			"issuer_cn":         "Windows Root CA",
			"sha1":              "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			"not_after":         "2027-01-15T00:00:00Z",
			"days_until_expiry": 588,
			"store":             "Root",
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	c := (*p.Certificates)[0]
	if c.Store != "Root" {
		t.Errorf("Store: got %q want %q", c.Store, "Root")
	}
}

// TestCertPayloadStoreFieldAbsent (PAT-1738) verifies an un-upgraded agent's
// payload (no store field) unmarshals to the Go zero value — upsertCertificates
// is what applies the "My" default, not JSON unmarshal, so this only checks
// the wire-format side of backward compatibility.
func TestCertPayloadStoreFieldAbsent(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["certificates"] = []any{
		map[string]any{
			"subject_cn":        "example.com",
			"issuer_cn":         "DigiCert Global Root CA",
			"sha1":              "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			"not_after":         "2027-01-15T00:00:00Z",
			"days_until_expiry": 588,
			// store intentionally absent — pre-PAT-1738 agent payload shape.
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	c := (*p.Certificates)[0]
	if c.Store != "" {
		t.Errorf("Store: got %q want empty (zero value for absent field)", c.Store)
	}
}

// ── Hardware health payload parsing ──────────────────────────────────────────

// TestHardwareHealthPayloadAbsentKey verifies that a payload without the
// "hardware_health" key produces a nil HardwareHealth pointer, triggering the
// no-op branch in upsertHardwareHealth.
func TestHardwareHealthPayloadAbsentKey(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.HardwareHealth != nil {
		t.Error("HardwareHealth must be nil when the key is absent — required for no-op semantics")
	}
}

// TestHardwareHealthPayloadPresent verifies that a payload carrying the
// hardware_health key unmarshals battery, storage, and disk fields correctly.
func TestHardwareHealthPayloadPresent(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	cycleCount := 42
	maxCap := 94
	m["hardware_health"] = map[string]any{
		"battery": map[string]any{
			"present":          true,
			"cycle_count":      cycleCount,
			"condition":        "Normal",
			"max_capacity_pct": maxCap,
		},
		"storage": []any{
			map[string]any{
				"mount": "/", "total_bytes": 494384795648, "free_bytes": 309000000000, "used_pct": 37,
			},
		},
		"disks": []any{
			map[string]any{
				"device": "disk0", "smart_status": "Verified", "internal": true, "solid_state": true,
			},
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if p.HardwareHealth == nil {
		t.Fatal("HardwareHealth must be non-nil when the key is present")
	}
	hh := p.HardwareHealth
	if !hh.Battery.Present {
		t.Error("battery.present: got false want true")
	}
	if hh.Battery.CycleCount == nil || *hh.Battery.CycleCount != cycleCount {
		t.Errorf("battery.cycle_count: want %d, got %v", cycleCount, hh.Battery.CycleCount)
	}
	if hh.Battery.Condition == nil || *hh.Battery.Condition != "Normal" {
		t.Errorf("battery.condition: want Normal, got %v", hh.Battery.Condition)
	}
	if hh.Battery.MaxCapacityPct == nil || *hh.Battery.MaxCapacityPct != maxCap {
		t.Errorf("battery.max_capacity_pct: want %d, got %v", maxCap, hh.Battery.MaxCapacityPct)
	}
	if got, want := len(hh.Storage), 1; got != want {
		t.Fatalf("storage len: got %d want %d", got, want)
	}
	if hh.Storage[0].Mount != "/" {
		t.Errorf("storage[0].mount: got %q want /", hh.Storage[0].Mount)
	}
	if got, want := len(hh.Disks), 1; got != want {
		t.Fatalf("disks len: got %d want %d", got, want)
	}
	if hh.Disks[0].Device != "disk0" {
		t.Errorf("disks[0].device: got %q want disk0", hh.Disks[0].Device)
	}
	if !hh.Disks[0].SolidState {
		t.Error("disks[0].solid_state: got false want true")
	}
}

// TestHardwareHealthMaxCapacityIsInt verifies that max_capacity_pct decodes
// as an integer (*int), not a float — the schema and collector both guarantee
// integer values and the Go field type must agree.
func TestHardwareHealthMaxCapacityIsInt(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["hardware_health"] = map[string]any{
		"battery": map[string]any{
			"present": true, "max_capacity_pct": 94,
		},
		"storage": []any{},
		"disks":   []any{},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.HardwareHealth == nil {
		t.Fatal("HardwareHealth nil")
	}
	if p.HardwareHealth.Battery.MaxCapacityPct == nil {
		t.Fatal("MaxCapacityPct nil — should be 94")
	}
	if *p.HardwareHealth.Battery.MaxCapacityPct != 94 {
		t.Errorf("MaxCapacityPct: got %d want 94", *p.HardwareHealth.Battery.MaxCapacityPct)
	}
}

// ── Hardware health DB round-trip ─────────────────────────────────────────────

// TestHardwareHealthIngest is a DB round-trip test for upsertHardwareHealth.
// It requires a real Postgres instance with all migrations applied, pointed to
// by the TEST_DATABASE_URL environment variable. The test wraps all writes in a
// transaction that is rolled back at the end — no persistent state is left.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestHardwareHealthIngest -v
func TestHardwareHealthIngest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	// Wrap all writes in a transaction that rolls back — no test pollution.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Insert a throwaway tenant (FK required by devices).
	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('hw-health-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	// Insert a minimal device row.
	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'HWTEST001')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	// ── Nil hardware_health (absent key) → no-op ──────────────────────────
	n, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", nil, nil)
	if err != nil {
		t.Fatalf("upsertHardwareHealth(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("nil hardware_health: want 0 rows written, got %d", n)
	}
	var hwRowsAfterNoOp int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwRowsAfterNoOp); err != nil {
		t.Fatalf("count device_hardware after no-op: %v", err)
	}
	if hwRowsAfterNoOp != 0 {
		t.Errorf("device_hardware rows after no-op: want 0, got %d", hwRowsAfterNoOp)
	}

	// ── First ingest — writes device_hardware + storage + disk rows ───────
	cycleCount := 42
	condition := "Normal"
	maxCap := 94
	hw1 := &hardwareHealthPart{
		Battery: batteryPart{
			Present:        true,
			CycleCount:     &cycleCount,
			Condition:      &condition,
			MaxCapacityPct: &maxCap,
		},
		Storage: []storageVolumePart{
			{Mount: "/", TotalBytes: 494384795648, FreeBytes: 309000000000, UsedPct: 37},
			{Mount: "/System/Volumes/Data", TotalBytes: 494384795648, FreeBytes: 290000000000, UsedPct: 41},
		},
		Disks: []diskPart{
			{Device: "disk0", SmartStatus: "Verified", Internal: true, SolidState: true},
		},
	}

	written1, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", hw1, nil)
	if err != nil {
		t.Fatalf("first upsertHardwareHealth: %v", err)
	}
	if written1 != 3 { // 2 storage + 1 disk
		t.Errorf("first ingest written count: want 3, got %d", written1)
	}

	var hwID int64
	var gotPresent bool
	var gotCycleCount *int
	var gotMaxCap *int
	if err := tx.QueryRow(ctx, `
		SELECT id, battery_present, battery_cycle_count, battery_max_capacity_pct
		FROM device_hardware WHERE device_id = $1::uuid
	`, deviceID).Scan(&hwID, &gotPresent, &gotCycleCount, &gotMaxCap); err != nil {
		t.Fatalf("select device_hardware after first ingest: %v", err)
	}
	if !gotPresent {
		t.Error("battery_present: want true")
	}
	if gotCycleCount == nil || *gotCycleCount != 42 {
		t.Errorf("battery_cycle_count: want 42, got %v", gotCycleCount)
	}
	if gotMaxCap == nil || *gotMaxCap != 94 {
		t.Errorf("battery_max_capacity_pct: want 94, got %v", gotMaxCap)
	}

	var storageCount1 int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_storage_volume WHERE device_hardware_id = $1`, hwID).Scan(&storageCount1); err != nil {
		t.Fatalf("count storage volumes: %v", err)
	}
	if storageCount1 != 2 {
		t.Errorf("storage volume count after first ingest: want 2, got %d", storageCount1)
	}

	var diskCount1 int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_disk WHERE device_hardware_id = $1`, hwID).Scan(&diskCount1); err != nil {
		t.Fatalf("count disks: %v", err)
	}
	if diskCount1 != 1 {
		t.Errorf("disk count after first ingest: want 1, got %d", diskCount1)
	}

	// ── Re-ingest — snapshot replaced, no duplicates ──────────────────────
	cycleCount2 := 50
	hw2 := &hardwareHealthPart{
		Battery: batteryPart{
			Present:        true,
			CycleCount:     &cycleCount2,
			Condition:      &condition,
			MaxCapacityPct: &maxCap,
		},
		Storage: []storageVolumePart{
			// one fewer volume than before — the old two must not survive
			{Mount: "/", TotalBytes: 494384795648, FreeBytes: 250000000000, UsedPct: 49},
		},
		Disks: []diskPart{
			// one more disk than before — the old one must not be duplicated
			{Device: "disk0", SmartStatus: "Verified", Internal: true, SolidState: true},
			{Device: "disk1", SmartStatus: "Verified", Internal: false, SolidState: false},
		},
	}

	written2, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", hw2, nil)
	if err != nil {
		t.Fatalf("second upsertHardwareHealth: %v", err)
	}
	if written2 != 3 { // 1 storage + 2 disks
		t.Errorf("second ingest written count: want 3, got %d", written2)
	}

	// device_hardware: still exactly one row (ON CONFLICT UPDATE).
	var hwRowCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwRowCount); err != nil {
		t.Fatalf("count device_hardware rows after reingest: %v", err)
	}
	if hwRowCount != 1 {
		t.Errorf("device_hardware rows after reingest: want 1 (no duplicate), got %d", hwRowCount)
	}

	var gotCycleCount2 int
	if err := tx.QueryRow(ctx, `SELECT battery_cycle_count FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&gotCycleCount2); err != nil {
		t.Fatalf("select updated battery_cycle_count: %v", err)
	}
	if gotCycleCount2 != 50 {
		t.Errorf("battery_cycle_count after reingest: want 50, got %d", gotCycleCount2)
	}

	// storage snapshot replaced: 1 row (down from 2 — no stale rows).
	var storageCount2 int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_storage_volume WHERE device_hardware_id = $1`, hwID).Scan(&storageCount2); err != nil {
		t.Fatalf("count storage volumes after reingest: %v", err)
	}
	if storageCount2 != 1 {
		t.Errorf("storage volume count after reingest: want 1 (replaced), got %d", storageCount2)
	}

	// disk snapshot replaced: 2 rows (up from 1 — old row not duplicated).
	var diskCount2 int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_disk WHERE device_hardware_id = $1`, hwID).Scan(&diskCount2); err != nil {
		t.Fatalf("count disks after reingest: %v", err)
	}
	if diskCount2 != 2 {
		t.Errorf("disk count after reingest: want 2 (replaced), got %d", diskCount2)
	}
}

// ── PAT-1720: hardware_health.collection_status ──────────────────────────────

// newHWTestDevice inserts a throwaway tenant + device row inside tx and
// returns the device id. Shared setup for the collection_status tests below —
// mirrors the setup TestHardwareHealthIngest does inline.
func newHWTestDevice(t *testing.T, ctx context.Context, tx pgx.Tx, serial string) string {
	t.Helper()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('hw-health-status-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', $2)
		RETURNING id::text
	`, tenantID, serial).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}
	return deviceID
}

// TestHardwareHealthDisksUnavailableKeepsExistingRows verifies acceptance
// criterion (b): a payload reporting disks collection_status "unavailable"
// with disks:[] must leave previously stored device_disk rows untouched — a
// failed diskutil call on the endpoint must never read as "no disks".
func TestHardwareHealthDisksUnavailableKeepsExistingRows(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "HWTEST-DISKS-UNAVAIL")

	// First ingest: complete disks collection — establishes a baseline row.
	first := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Storage: nil,
		Disks: []diskPart{
			{Device: "disk0", SmartStatus: "Verified", Internal: true, SolidState: true},
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", first, nil); err != nil {
		t.Fatalf("first upsertHardwareHealth: %v", err)
	}

	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}
	var diskCountBefore int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_disk WHERE device_hardware_id = $1`, hwID).Scan(&diskCountBefore); err != nil {
		t.Fatalf("count disks before: %v", err)
	}
	if diskCountBefore != 1 {
		t.Fatalf("baseline disk count: want 1, got %d", diskCountBefore)
	}

	// Second ingest: diskutil failed on the endpoint — disks:[] with
	// collection_status.disks = "unavailable". The baseline row must survive.
	degraded := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Storage: nil,
		Disks:   []diskPart{},
		CollectionStatus: &hwCollectionStatusPart{
			Disks: "unavailable",
		},
	}
	written, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", degraded, nil)
	if err != nil {
		t.Fatalf("second upsertHardwareHealth: %v", err)
	}
	if written != 0 {
		t.Errorf("written count for unavailable disks: want 0, got %d", written)
	}

	var diskCountAfter int
	var gotDevice string
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_disk WHERE device_hardware_id = $1`, hwID).Scan(&diskCountAfter); err != nil {
		t.Fatalf("count disks after: %v", err)
	}
	if diskCountAfter != 1 {
		t.Fatalf("disk count after unavailable collection: want 1 (unchanged), got %d", diskCountAfter)
	}
	if err := tx.QueryRow(ctx, `SELECT device_node FROM device_disk WHERE device_hardware_id = $1`, hwID).Scan(&gotDevice); err != nil {
		t.Fatalf("select surviving disk: %v", err)
	}
	if gotDevice != "disk0" {
		t.Errorf("surviving disk device_node: want disk0, got %q", gotDevice)
	}
}

// TestHardwareHealthStoragePartialKeepsUnsentVolume verifies acceptance
// criterion (c): a payload reporting storage collection_status "partial"
// with only one of two previously known volumes must update the sent volume
// and leave the unsent volume's row intact — no deletion, unlike "complete".
func TestHardwareHealthStoragePartialKeepsUnsentVolume(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "HWTEST-STORAGE-PARTIAL")

	// First ingest: complete storage collection — two volumes.
	first := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Storage: []storageVolumePart{
			{Mount: "/", TotalBytes: 494384795648, FreeBytes: 309000000000, UsedPct: 37},
			{Mount: "/Volumes/Data", TotalBytes: 1000000000000, FreeBytes: 500000000000, UsedPct: 50},
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", first, nil); err != nil {
		t.Fatalf("first upsertHardwareHealth: %v", err)
	}

	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}

	// Second ingest: df failed for one volume — only "/" is sent, marked
	// partial. "/Volumes/Data" must survive untouched and unpruned.
	partial := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Storage: []storageVolumePart{
			{Mount: "/", TotalBytes: 494384795648, FreeBytes: 200000000000, UsedPct: 59},
		},
		CollectionStatus: &hwCollectionStatusPart{
			Storage: "partial",
		},
	}
	written, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", partial, nil)
	if err != nil {
		t.Fatalf("second upsertHardwareHealth: %v", err)
	}
	if written != 1 {
		t.Errorf("written count for partial storage: want 1, got %d", written)
	}

	var volCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_storage_volume WHERE device_hardware_id = $1`, hwID).Scan(&volCount); err != nil {
		t.Fatalf("count storage volumes: %v", err)
	}
	if volCount != 2 {
		t.Fatalf("storage volume count after partial collection: want 2 (both survive), got %d", volCount)
	}

	var rootUsedPct int
	if err := tx.QueryRow(ctx, `SELECT used_pct FROM device_storage_volume WHERE device_hardware_id = $1 AND mount = '/'`, hwID).Scan(&rootUsedPct); err != nil {
		t.Fatalf("select updated root volume: %v", err)
	}
	if rootUsedPct != 59 {
		t.Errorf("root volume used_pct: want 59 (updated), got %d", rootUsedPct)
	}

	var dataUsedPct int
	if err := tx.QueryRow(ctx, `SELECT used_pct FROM device_storage_volume WHERE device_hardware_id = $1 AND mount = '/Volumes/Data'`, hwID).Scan(&dataUsedPct); err != nil {
		t.Fatalf("select unsent volume: %v", err)
	}
	if dataUsedPct != 50 {
		t.Errorf("unsent volume used_pct: want 50 (unchanged), got %d", dataUsedPct)
	}
}

// TestHardwareHealthBatteryUnavailableKeepsStoredValues verifies acceptance
// criterion (d): a payload reporting battery collection_status "unavailable"
// must not overwrite the stored battery columns on device_hardware, and must
// not write a device_hardware_history row for that run.
func TestHardwareHealthBatteryUnavailableKeepsStoredValues(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "HWTEST-BATTERY-UNAVAIL")

	cycleCount := 100
	condition := "Normal"
	maxCap := 92
	first := &hardwareHealthPart{
		Battery: batteryPart{
			Present:        true,
			CycleCount:     &cycleCount,
			Condition:      &condition,
			MaxCapacityPct: &maxCap,
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", first, nil); err != nil {
		t.Fatalf("first upsertHardwareHealth: %v", err)
	}

	var historyCountBefore int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_hardware_history WHERE device_id = $1::uuid`, deviceID).Scan(&historyCountBefore); err != nil {
		t.Fatalf("count history before: %v", err)
	}
	if historyCountBefore != 1 {
		t.Fatalf("baseline history row count: want 1, got %d", historyCountBefore)
	}

	// Second ingest: battery read failed on the endpoint — the agent sends
	// present:false with collection_status.battery = "unavailable". Stored
	// values must survive and no new history row is written for this run.
	degraded := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		CollectionStatus: &hwCollectionStatusPart{
			Battery: "unavailable",
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", degraded, nil); err != nil {
		t.Fatalf("second upsertHardwareHealth: %v", err)
	}

	var gotPresent bool
	var gotCycleCount, gotMaxCap *int
	var gotCondition *string
	if err := tx.QueryRow(ctx, `
		SELECT battery_present, battery_cycle_count, battery_condition, battery_max_capacity_pct
		FROM device_hardware WHERE device_id = $1::uuid
	`, deviceID).Scan(&gotPresent, &gotCycleCount, &gotCondition, &gotMaxCap); err != nil {
		t.Fatalf("select device_hardware after degraded ingest: %v", err)
	}
	if !gotPresent {
		t.Error("battery_present: want true (preserved), got false")
	}
	if gotCycleCount == nil || *gotCycleCount != cycleCount {
		t.Errorf("battery_cycle_count: want %d (preserved), got %v", cycleCount, gotCycleCount)
	}
	if gotCondition == nil || *gotCondition != condition {
		t.Errorf("battery_condition: want %q (preserved), got %v", condition, gotCondition)
	}
	if gotMaxCap == nil || *gotMaxCap != maxCap {
		t.Errorf("battery_max_capacity_pct: want %d (preserved), got %v", maxCap, gotMaxCap)
	}

	var historyCountAfter int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_hardware_history WHERE device_id = $1::uuid`, deviceID).Scan(&historyCountAfter); err != nil {
		t.Fatalf("count history after: %v", err)
	}
	if historyCountAfter != 1 {
		t.Errorf("history row count after degraded ingest: want 1 (no new row), got %d", historyCountAfter)
	}
}

// TestHardwareHealthUnknownCollectionStatusTreatedAsUnavailable verifies
// acceptance criterion (e) at the extractor layer: an unrecognised
// collection_status value must never behave as "complete" — it is treated as
// "unavailable", so a value neither ValidatePayload (which rejects it
// outright — see testdata/payload-fixtures/invalid/hardware-health-bad-
// collection-status.json) nor this fallback let through can ever manufacture
// a false mass-removal signal.
func TestHardwareHealthUnknownCollectionStatusTreatedAsUnavailable(t *testing.T) {
	status, known := normaliseHWCollectionStatus("mostly_ok")
	if known {
		t.Error("normaliseHWCollectionStatus(\"mostly_ok\"): want known=false")
	}
	if status != hwStatusUnavailable {
		t.Errorf("normaliseHWCollectionStatus(\"mostly_ok\"): want %q, got %q", hwStatusUnavailable, status)
	}

	// Absent key (empty string) is the one case that means "complete".
	if status, known := normaliseHWCollectionStatus(""); !known || status != hwStatusComplete {
		t.Errorf(`normaliseHWCollectionStatus(""): want (%q, true), got (%q, %v)`, hwStatusComplete, status, known)
	}
}

// ── PAT-1736: stale FriendlyName-keyed disks on a Windows device's first
// partial disks ingest ──────────────────────────────────────────────────────

// newHWTestDeviceOS is newHWTestDevice with an explicit os value, so PAT-1736
// tests can create Windows devices (newHWTestDevice always inserts 'macOS').
// A distinct tenant name per call keeps these tests independent of each
// other and of the shared (known-polluted, see local-patched-test-db-
// polluted) DB — every row here lives only inside this test's own
// transaction, which is rolled back (never committed) by the caller's
// deferred tx.Rollback, so no explicit t.Cleanup is needed to remove it.
func newHWTestDeviceOS(t *testing.T, ctx context.Context, tx pgx.Tx, tenantName, osName, serial string) string {
	t.Helper()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x00', '\x00')
		RETURNING id::text
	`, tenantName).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, $2, $3)
		RETURNING id::text
	`, tenantID, osName, serial).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}
	return deviceID
}

// diskNodes returns every device_node currently stored for hwID, for
// assertions below.
func diskNodes(t *testing.T, ctx context.Context, tx pgx.Tx, hwID int64) []string {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT device_node FROM device_disk WHERE device_hardware_id = $1`, hwID)
	if err != nil {
		t.Fatalf("query disk nodes: %v", err)
	}
	defer rows.Close()
	var nodes []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan disk node: %v", err)
		}
		nodes = append(nodes, n)
	}
	// Sort in Go: ORDER BY follows the database collation, which differs
	// between CI (C) and a local en_US database for keys containing spaces.
	sort.Strings(nodes)
	return nodes
}

// TestHardwareHealthWindowsFirstPartialPrunesFriendlyNameDisk verifies the
// PAT-1736 one-off: a Windows device carrying a pre-PAT-1733 FriendlyName-
// keyed disk row ("Msft Virtual Disk") whose first-ever
// hardware_health.collection_status.disks ingest is "partial" with a
// serial-keyed disk must end up with only the serial row — the stale
// FriendlyName row is pruned once, inline with that same ingest.
// TestHardwareHealthWindowsFirstPartialEmptyDisksKeepsRows: a first partial
// ingest that reports no disks has no serial-keyed evidence to replace the
// FriendlyName row with, so the one-off must not delete it (PAT-1736 review).
func TestHardwareHealthWindowsFirstPartialEmptyDisksKeepsRows(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDeviceOS(t, ctx, tx, "pat-1736-empty-disks-test", "Windows", "HWTEST-WIN-EMPTY")
	baseline := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks:   []diskPart{{Device: "Msft Virtual Disk", SmartStatus: "Unknown", Internal: true}},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", baseline, nil); err != nil {
		t.Fatalf("baseline upsertHardwareHealth: %v", err)
	}
	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}

	empty := &hardwareHealthPart{
		Battery:          batteryPart{Present: false},
		CollectionStatus: &hwCollectionStatusPart{Disks: "partial"},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", empty, nil); err != nil {
		t.Fatalf("empty partial upsertHardwareHealth: %v", err)
	}
	if got := diskNodes(t, ctx, tx, hwID); len(got) != 1 || got[0] != "Msft Virtual Disk" {
		t.Fatalf("partial ingest with no disks must not prune: want [\"Msft Virtual Disk\"], got %v", got)
	}
}

func TestHardwareHealthWindowsFirstPartialPrunesFriendlyNameDisk(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDeviceOS(t, ctx, tx, "pat-1736-prune-test", "Windows", "HWTEST-WIN-PRUNE")

	// Baseline: a pre-PAT-1733 agent reporting the old FriendlyName key,
	// absent collection_status (old agent) — "complete" semantics, full
	// replace, establishes the stale row exactly as a real upgrade would
	// leave it.
	baseline := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "Msft Virtual Disk", SmartStatus: "Unknown", Internal: true, SolidState: false},
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", baseline, nil); err != nil {
		t.Fatalf("baseline upsertHardwareHealth: %v", err)
	}

	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}
	if got := diskNodes(t, ctx, tx, hwID); len(got) != 1 || got[0] != "Msft Virtual Disk" {
		t.Fatalf("baseline disk rows: want [\"Msft Virtual Disk\"], got %v", got)
	}

	// First ingest to ever carry hardware_health.collection_status.disks:
	// the upgraded agent now sends the serial key and reports the virtual
	// disk's undetermined MediaType as partial (PAT-1733's own left-out
	// case), so the FriendlyName row is never sent and would otherwise
	// survive forever under ordinary partial semantics.
	upgraded := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "SERIAL123", SmartStatus: "Verified", Internal: true, SolidState: false},
		},
		CollectionStatus: &hwCollectionStatusPart{Disks: "partial"},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", upgraded, nil); err != nil {
		t.Fatalf("upgraded upsertHardwareHealth: %v", err)
	}
	// Mirrors extractor.go processRow: upsertCollectionStatus runs after
	// upsertHardwareHealth, in the same transaction, to record the reported
	// disks status — this is what makes the one-off run at most once.
	if err := upsertCollectionStatus(ctx, tx, deviceID, nil, upgraded.CollectionStatus, "", nil); err != nil {
		t.Fatalf("upsertCollectionStatus: %v", err)
	}

	got := diskNodes(t, ctx, tx, hwID)
	if len(got) != 1 || got[0] != "SERIAL123" {
		t.Fatalf("disk rows after first partial ingest: want [\"SERIAL123\"] (FriendlyName row pruned), got %v", got)
	}
}

// TestHardwareHealthWindowsSecondPartialNeverDeletes verifies the "at most
// once" half of PAT-1736: once a Windows device's stored
// hardware_health.disks status is no longer empty, a later partial ingest —
// even one that omits a previously-stored, whitespace-containing
// device_node — must not delete anything. Without the one-off's own guard,
// a naive re-application of the FriendlyName heuristic on every partial
// ingest would delete legitimate rows an operator has not actually lost.
func TestHardwareHealthWindowsSecondPartialNeverDeletes(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDeviceOS(t, ctx, tx, "pat-1736-second-partial-test", "Windows", "HWTEST-WIN-2ND-PARTIAL")

	first := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "SERIAL123", SmartStatus: "Verified", Internal: true, SolidState: false},
		},
		CollectionStatus: &hwCollectionStatusPart{Disks: "partial"},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", first, nil); err != nil {
		t.Fatalf("first upsertHardwareHealth: %v", err)
	}
	if err := upsertCollectionStatus(ctx, tx, deviceID, nil, first.CollectionStatus, "", nil); err != nil {
		t.Fatalf("upsertCollectionStatus after first ingest: %v", err)
	}

	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}

	// Directly plant a whitespace-keyed row the one-off would target if it
	// (incorrectly) ran again — simulates a row this partial ingest simply
	// doesn't mention this run, not a genuine FriendlyName leftover.
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_disk (device_hardware_id, device_node, smart_status, internal, solid_state)
		VALUES ($1, 'SERIAL WITH SPACE', 'Verified', true, false)
	`, hwID); err != nil {
		t.Fatalf("plant whitespace-keyed row: %v", err)
	}

	// Second partial ingest: a different subset (SERIAL456 only). Neither
	// SERIAL123 nor the planted whitespace-keyed row is sent this run.
	second := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "SERIAL456", SmartStatus: "Verified", Internal: true, SolidState: false},
		},
		CollectionStatus: &hwCollectionStatusPart{Disks: "partial"},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", second, nil); err != nil {
		t.Fatalf("second upsertHardwareHealth: %v", err)
	}

	got := diskNodes(t, ctx, tx, hwID)
	want := []string{"SERIAL WITH SPACE", "SERIAL123", "SERIAL456"}
	if len(got) != len(want) {
		t.Fatalf("disk rows after second partial ingest: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("disk rows after second partial ingest: want %v, got %v", want, got)
		}
	}
}

// TestHardwareHealthMacOSFirstPartialNeverPrunes verifies the platform gate:
// a macOS device's first-ever partial disks ingest must never run the
// PAT-1736 one-off, even though it is also that device's "first" partial
// ingest — a stored device_node not sent this run (disk0) must survive
// exactly as TestHardwareHealthStoragePartialKeepsUnsentVolume already
// establishes for storage.
func TestHardwareHealthMacOSFirstPartialNeverPrunes(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDeviceOS(t, ctx, tx, "pat-1736-macos-partial-test", "macOS", "HWTEST-MACOS-PARTIAL")

	baseline := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "disk0", SmartStatus: "Verified", Internal: true, SolidState: true},
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", baseline, nil); err != nil {
		t.Fatalf("baseline upsertHardwareHealth: %v", err)
	}

	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}

	// First-ever collection_status.disks ingest for this device is
	// "partial", and disk0 (the only stored row) is not sent — this must
	// survive on macOS exactly as it would pre-PAT-1736.
	partial := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "disk1", SmartStatus: "Verified", Internal: false, SolidState: false},
		},
		CollectionStatus: &hwCollectionStatusPart{Disks: "partial"},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "macos", partial, nil); err != nil {
		t.Fatalf("partial upsertHardwareHealth: %v", err)
	}

	got := diskNodes(t, ctx, tx, hwID)
	want := []string{"disk0", "disk1"}
	if len(got) != len(want) {
		t.Fatalf("disk rows after macOS first partial ingest: want %v (disk0 survives, no pruning), got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("disk rows after macOS first partial ingest: want %v, got %v", want, got)
		}
	}
}

// TestHardwareHealthWindowsExistingCollectionStatusSkipsPrune verifies the
// "first time" read itself: a Windows device whose devices.collection_status
// already records a hardware_health.disks status (here "unavailable", from
// an earlier ingest that never touched device_disk at all) must not run the
// one-off on a later partial ingest, even though upsertHardwareHealth has
// never itself pruned anything for this device before. Guards against a
// signal that only checks "have I pruned before" rather than the ticket's
// actual "has any disks status ever been stored" definition.
func TestHardwareHealthWindowsExistingCollectionStatusSkipsPrune(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping hardware health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDeviceOS(t, ctx, tx, "pat-1736-existing-status-test", "Windows", "HWTEST-WIN-EXISTING-STATUS")

	// Baseline: FriendlyName-keyed row from before PAT-1733, established with
	// no collection_status (old-agent "complete" semantics).
	baseline := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "Msft Virtual Disk", SmartStatus: "Unknown", Internal: true, SolidState: false},
		},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", baseline, nil); err != nil {
		t.Fatalf("baseline upsertHardwareHealth: %v", err)
	}
	var hwID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM device_hardware WHERE device_id = $1::uuid`, deviceID).Scan(&hwID); err != nil {
		t.Fatalf("select device_hardware id: %v", err)
	}

	// Record a stored hardware_health.disks status directly, as if an
	// earlier ingest already reported "unavailable" for disks (which writes
	// nothing to device_disk, but does record the status) — simulates the
	// device already having a stored status before this test's own partial
	// ingest, independent of whether upsertHardwareHealth itself ever ran
	// the one-off.
	if err := upsertCollectionStatus(ctx, tx, deviceID, nil, &hwCollectionStatusPart{Disks: "unavailable"}, "", nil); err != nil {
		t.Fatalf("seed existing collection_status: %v", err)
	}

	// Now a partial ingest arrives with a serial-keyed disk. Because
	// hardware_health.disks was already stored ("unavailable"), this must
	// not be treated as the device's first ever disks status, so the stale
	// FriendlyName row must survive.
	partial := &hardwareHealthPart{
		Battery: batteryPart{Present: false},
		Disks: []diskPart{
			{Device: "SERIAL123", SmartStatus: "Verified", Internal: true, SolidState: false},
		},
		CollectionStatus: &hwCollectionStatusPart{Disks: "partial"},
	}
	if _, err := upsertHardwareHealth(ctx, tx, deviceID, "windows", partial, nil); err != nil {
		t.Fatalf("partial upsertHardwareHealth: %v", err)
	}

	got := diskNodes(t, ctx, tx, hwID)
	want := []string{"Msft Virtual Disk", "SERIAL123"}
	if len(got) != len(want) {
		t.Fatalf("disk rows: want %v (no pruning — status already existed), got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("disk rows: want %v, got %v", want, got)
		}
	}
}

// ── PAT-1732: top-level collection_status.certificates ────────────────────────

// TestCertificatesCollectionStatusAbsentStillPrunesOnEmpty verifies acceptance
// criterion 2's regression guard: with collection_status absent entirely
// (nil), an explicit empty certificates array must still prune every stored
// row for the device — the exact PAT-216 behaviour, unchanged by PAT-1732.
func TestCertificatesCollectionStatusAbsentStillPrunesOnEmpty(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping certificates collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "CERTTEST-ABSENT-PRUNES")

	first := &[]certPart{
		{SubjectCN: "example.com", IssuerCN: "Root CA", SHA1: "aaaa", NotAfter: "2027-01-01T00:00:00Z"},
	}
	if _, err := upsertCertificates(ctx, tx, deviceID, first, nil, nil); err != nil {
		t.Fatalf("first upsertCertificates: %v", err)
	}

	var countBefore int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid`, deviceID).Scan(&countBefore); err != nil {
		t.Fatalf("count certs before: %v", err)
	}
	if countBefore != 1 {
		t.Fatalf("baseline cert count: want 1, got %d", countBefore)
	}

	empty := &[]certPart{}
	written, err := upsertCertificates(ctx, tx, deviceID, empty, nil, nil)
	if err != nil {
		t.Fatalf("second upsertCertificates: %v", err)
	}
	if written != 0 {
		t.Errorf("written count for explicit empty array: want 0, got %d", written)
	}

	var countAfter int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid`, deviceID).Scan(&countAfter); err != nil {
		t.Fatalf("count certs after: %v", err)
	}
	if countAfter != 0 {
		t.Errorf("cert count after explicit empty array with collection_status absent: want 0 (pruned), got %d", countAfter)
	}
}

// TestCertificatesPartialKeepsUnsentRow verifies that collection_status
// "partial" upserts only the certs actually sent and leaves an unsent cert's
// row untouched — no deletion, unlike "complete".
func TestCertificatesPartialKeepsUnsentRow(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping certificates collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "CERTTEST-PARTIAL")

	// First ingest: complete collection — two certs.
	first := &[]certPart{
		{SubjectCN: "a.example.com", IssuerCN: "Root CA", SHA1: "cert-a", NotAfter: "2027-01-01T00:00:00Z", DaysUntilExpiry: 100},
		{SubjectCN: "b.example.com", IssuerCN: "Root CA", SHA1: "cert-b", NotAfter: "2028-01-01T00:00:00Z", DaysUntilExpiry: 200},
	}
	if _, err := upsertCertificates(ctx, tx, deviceID, first, nil, nil); err != nil {
		t.Fatalf("first upsertCertificates: %v", err)
	}

	// Second ingest: the endpoint only managed to enumerate cert-a this run;
	// collection_status.certificates = "partial". cert-b must survive.
	partial := &[]certPart{
		{SubjectCN: "a.example.com", IssuerCN: "Root CA", SHA1: "cert-a", NotAfter: "2027-01-01T00:00:00Z", DaysUntilExpiry: 99},
	}
	written, err := upsertCertificates(ctx, tx, deviceID, partial, &collectionStatusPart{Certificates: "partial"}, nil)
	if err != nil {
		t.Fatalf("second upsertCertificates: %v", err)
	}
	if written != 1 {
		t.Errorf("written count for partial certificates: want 1, got %d", written)
	}

	var certCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid`, deviceID).Scan(&certCount); err != nil {
		t.Fatalf("count certs: %v", err)
	}
	if certCount != 2 {
		t.Fatalf("cert count after partial collection: want 2 (both survive), got %d", certCount)
	}

	var gotDays int
	if err := tx.QueryRow(ctx, `SELECT days_until_expiry_at_collection FROM device_certificates WHERE device_id = $1::uuid AND sha1 = 'cert-a'`, deviceID).Scan(&gotDays); err != nil {
		t.Fatalf("select updated cert-a: %v", err)
	}
	if gotDays != 99 {
		t.Errorf("cert-a days_until_expiry_at_collection: want 99 (updated), got %d", gotDays)
	}

	var stillThere int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid AND sha1 = 'cert-b'`, deviceID).Scan(&stillThere); err != nil {
		t.Fatalf("select unsent cert-b: %v", err)
	}
	if stillThere != 1 {
		t.Errorf("cert-b row: want present (unchanged), got count=%d", stillThere)
	}
}

// TestCertificatesUnavailableWithArrayPresentWritesNothing verifies that
// collection_status "unavailable" writes nothing at all, even when the agent
// still attached a non-empty certificates array — the server must not depend
// on agents omitting the key for a failed collection.
func TestCertificatesUnavailableWithArrayPresentWritesNothing(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping certificates collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "CERTTEST-UNAVAILABLE")

	// Baseline: one stored cert.
	first := &[]certPart{
		{SubjectCN: "example.com", IssuerCN: "Root CA", SHA1: "cert-baseline", NotAfter: "2027-01-01T00:00:00Z"},
	}
	if _, err := upsertCertificates(ctx, tx, deviceID, first, nil, nil); err != nil {
		t.Fatalf("first upsertCertificates: %v", err)
	}

	// Endpoint enumeration failed but the agent still attached a (stale or
	// partial) array, marked "unavailable". Nothing must be written, and
	// nothing must be deleted — not even the array's own contents.
	stale := &[]certPart{
		{SubjectCN: "attacker-injected.example", IssuerCN: "Root CA", SHA1: "cert-injected", NotAfter: "2027-01-01T00:00:00Z"},
	}
	written, err := upsertCertificates(ctx, tx, deviceID, stale, &collectionStatusPart{Certificates: "unavailable"}, nil)
	if err != nil {
		t.Fatalf("second upsertCertificates: %v", err)
	}
	if written != 0 {
		t.Errorf("written count for unavailable collection: want 0, got %d", written)
	}

	var gotSHA1 string
	if err := tx.QueryRow(ctx, `SELECT sha1 FROM device_certificates WHERE device_id = $1::uuid`, deviceID).Scan(&gotSHA1); err != nil {
		t.Fatalf("select certs after unavailable collection: %v", err)
	}
	if gotSHA1 != "cert-baseline" {
		t.Errorf("stored cert after unavailable collection: want cert-baseline (unchanged), got %q", gotSHA1)
	}

	var countAfter int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid`, deviceID).Scan(&countAfter); err != nil {
		t.Fatalf("count certs after unavailable collection: %v", err)
	}
	if countAfter != 1 {
		t.Errorf("cert count after unavailable collection: want 1 (unchanged, nothing added or removed), got %d", countAfter)
	}
}

// TestCertificatesUnknownCollectionStatusTreatedAsUnavailable verifies that
// an unrecognised collection_status.certificates value is never treated as
// "complete" — it normalises to "unavailable", so a value neither
// ValidatePayload (which rejects it outright — see
// testdata/payload-fixtures/invalid/certificates-bad-collection-status.json)
// nor this fallback let through can ever manufacture a false mass-removal
// signal, matching TestHardwareHealthUnknownCollectionStatusTreatedAsUnavailable's
// precedent (PAT-1720) via the same shared normaliseCollectionStatus helper.
func TestCertificatesUnknownCollectionStatusTreatedAsUnavailable(t *testing.T) {
	status, known := normaliseCollectionStatus("mostly_ok")
	if known {
		t.Error("normaliseCollectionStatus(\"mostly_ok\"): want known=false")
	}
	if status != statusUnavailable {
		t.Errorf("normaliseCollectionStatus(\"mostly_ok\"): want %q, got %q", statusUnavailable, status)
	}

	// Absent key (empty string) is the one case that means "complete".
	if status, known := normaliseCollectionStatus(""); !known || status != statusComplete {
		t.Errorf(`normaliseCollectionStatus(""): want (%q, true), got (%q, %v)`, statusComplete, status, known)
	}

	// End-to-end through upsertCertificates: an unknown value must behave
	// exactly like "unavailable" — nothing written, nothing deleted.
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping certificates collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "CERTTEST-UNKNOWN-STATUS")

	baseline := &[]certPart{
		{SubjectCN: "example.com", IssuerCN: "Root CA", SHA1: "cert-baseline-2", NotAfter: "2027-01-01T00:00:00Z"},
	}
	if _, err := upsertCertificates(ctx, tx, deviceID, baseline, nil, nil); err != nil {
		t.Fatalf("first upsertCertificates: %v", err)
	}

	written, err := upsertCertificates(ctx, tx, deviceID, &[]certPart{}, &collectionStatusPart{Certificates: "mostly_ok"}, nil)
	if err != nil {
		t.Fatalf("second upsertCertificates: %v", err)
	}
	if written != 0 {
		t.Errorf("written count for unknown collection_status: want 0, got %d", written)
	}

	var countAfter int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1::uuid`, deviceID).Scan(&countAfter); err != nil {
		t.Fatalf("count certs after unknown collection_status: %v", err)
	}
	if countAfter != 1 {
		t.Errorf("cert count after unknown collection_status (treated as unavailable): want 1 (unchanged), got %d", countAfter)
	}
}

// ── PAT-1738: certificates store field ─────────────────────────────────────────

// TestCertificatesStoreDefaultsToMy verifies the backward-compatibility
// contract documented in docs/PAYLOAD_SCHEMA.md: a cert with no store field
// (the zero value, matching an un-upgraded agent's payload) is persisted as
// "My" — the source every certificate implicitly came from before PAT-1738.
func TestCertificatesStoreDefaultsToMy(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping certificates store DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "CERTTEST-STORE-DEFAULT")

	certs := &[]certPart{
		{SubjectCN: "no-store.example.com", IssuerCN: "Root CA", SHA1: "storeaaa1", NotAfter: "2027-01-01T00:00:00Z"},
		{SubjectCN: "Windows Root CA", IssuerCN: "Windows Root CA", SHA1: "storebbb2", NotAfter: "2027-01-01T00:00:00Z", Store: "Root"},
	}
	if _, err := upsertCertificates(ctx, tx, deviceID, certs, nil, nil); err != nil {
		t.Fatalf("upsertCertificates: %v", err)
	}

	rows, err := tx.Query(ctx, `SELECT sha1, store FROM device_certificates WHERE device_id = $1::uuid`, deviceID)
	if err != nil {
		t.Fatalf("query stores: %v", err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var sha1, store string
		if err := rows.Scan(&sha1, &store); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[sha1] = store
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	if got["storeaaa1"] != "My" {
		t.Errorf("store for cert with no store field: got %q, want %q (default)", got["storeaaa1"], "My")
	}
	if got["storebbb2"] != "Root" {
		t.Errorf("store for cert with store=Root: got %q, want %q (verbatim)", got["storebbb2"], "Root")
	}
}

// ── PAT-1732: devices.collection_status persistence (migration 0128) ──────────

// getCollectionStatus reads the raw devices.collection_status JSON for a
// device, or nil when the column is SQL NULL.
func getCollectionStatus(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID string) []byte {
	t.Helper()
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT collection_status FROM devices WHERE id = $1::uuid`, deviceID).Scan(&raw); err != nil {
		t.Fatalf("select collection_status: %v", err)
	}
	return raw
}

// TestCollectionStatusCertificatesPartialIsStored verifies that a payload
// reporting collection_status.certificates = "partial" persists that
// normalised value under devices.collection_status.certificates.
func TestCollectionStatusCertificatesPartialIsStored(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping devices.collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "COLLSTATUS-CERTS-PARTIAL")

	if before := getCollectionStatus(t, ctx, tx, deviceID); before != nil {
		t.Fatalf("baseline collection_status: want NULL, got %s", before)
	}

	if err := upsertCollectionStatus(ctx, tx, deviceID, &collectionStatusPart{Certificates: "partial"}, nil, "", nil); err != nil {
		t.Fatalf("upsertCollectionStatus: %v", err)
	}

	var snap collectionStatusSnapshot
	if err := json.Unmarshal(getCollectionStatus(t, ctx, tx, deviceID), &snap); err != nil {
		t.Fatalf("unmarshal stored collection_status: %v", err)
	}
	if snap.Certificates != "partial" {
		t.Errorf("stored certificates status: want %q, got %q", "partial", snap.Certificates)
	}
	if snap.HardwareHealth != nil {
		t.Errorf("stored hardware_health: want nil (never reported), got %+v", snap.HardwareHealth)
	}
}

// TestCollectionStatusHardwareHealthSectionIsStoredNested verifies that a
// hardware_health.collection_status section is persisted under the nested
// devices.collection_status.hardware_health key.
func TestCollectionStatusHardwareHealthSectionIsStoredNested(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping devices.collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "COLLSTATUS-HW-NESTED")

	hwCS := &hwCollectionStatusPart{Disks: "unavailable"}
	if err := upsertCollectionStatus(ctx, tx, deviceID, nil, hwCS, "", nil); err != nil {
		t.Fatalf("upsertCollectionStatus: %v", err)
	}

	var snap collectionStatusSnapshot
	if err := json.Unmarshal(getCollectionStatus(t, ctx, tx, deviceID), &snap); err != nil {
		t.Fatalf("unmarshal stored collection_status: %v", err)
	}
	if snap.Certificates != "" {
		t.Errorf("stored certificates status: want empty (never reported), got %q", snap.Certificates)
	}
	if snap.HardwareHealth == nil {
		t.Fatal("stored hardware_health: want non-nil")
	}
	if snap.HardwareHealth.Disks != "unavailable" {
		t.Errorf("stored hardware_health.disks: want %q, got %q", "unavailable", snap.HardwareHealth.Disks)
	}
	if snap.HardwareHealth.Battery != "" || snap.HardwareHealth.Storage != "" {
		t.Errorf("stored hardware_health battery/storage: want empty (not reported this run), got battery=%q storage=%q",
			snap.HardwareHealth.Battery, snap.HardwareHealth.Storage)
	}
}

// TestCollectionStatusLaterCertsOnlyPayloadKeepsHardwareHealth verifies the
// core merge guarantee: a later payload that reports only certificates must
// leave a previously stored hardware_health section intact.
func TestCollectionStatusLaterCertsOnlyPayloadKeepsHardwareHealth(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping devices.collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "COLLSTATUS-MERGE-PRESERVE")

	// First ingest: hardware_health reports a degraded battery section.
	first := &hwCollectionStatusPart{Battery: "unavailable", Storage: "partial"}
	if err := upsertCollectionStatus(ctx, tx, deviceID, nil, first, "", nil); err != nil {
		t.Fatalf("first upsertCollectionStatus: %v", err)
	}

	// Second ingest: only the top-level certificates section is reported —
	// no hardware_health object in this payload at all.
	if err := upsertCollectionStatus(ctx, tx, deviceID, &collectionStatusPart{Certificates: "unavailable"}, nil, "", nil); err != nil {
		t.Fatalf("second upsertCollectionStatus: %v", err)
	}

	var snap collectionStatusSnapshot
	if err := json.Unmarshal(getCollectionStatus(t, ctx, tx, deviceID), &snap); err != nil {
		t.Fatalf("unmarshal stored collection_status: %v", err)
	}
	if snap.Certificates != "unavailable" {
		t.Errorf("stored certificates status: want %q, got %q", "unavailable", snap.Certificates)
	}
	if snap.HardwareHealth == nil {
		t.Fatal("stored hardware_health: want non-nil (must survive a certs-only payload)")
	}
	if snap.HardwareHealth.Battery != "unavailable" {
		t.Errorf("stored hardware_health.battery: want %q (preserved), got %q", "unavailable", snap.HardwareHealth.Battery)
	}
	if snap.HardwareHealth.Storage != "partial" {
		t.Errorf("stored hardware_health.storage: want %q (preserved), got %q", "partial", snap.HardwareHealth.Storage)
	}
}

// TestCollectionStatusPayloadWithNeitherLeavesColumnUntouched verifies that a
// payload carrying neither a top-level collection_status object nor a
// hardware_health.collection_status object leaves devices.collection_status
// exactly as it was — including not touching row version/side effects a
// stray UPDATE would otherwise leave.
func TestCollectionStatusPayloadWithNeitherLeavesColumnUntouched(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping devices.collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "COLLSTATUS-UNTOUCHED")

	if err := upsertCollectionStatus(ctx, tx, deviceID, &collectionStatusPart{Certificates: "complete"}, nil, "", nil); err != nil {
		t.Fatalf("seed upsertCollectionStatus: %v", err)
	}
	before := getCollectionStatus(t, ctx, tx, deviceID)

	// Neither object present at all — the exact shape of a payload that
	// predates PAT-1732 or simply has nothing degraded to report.
	if err := upsertCollectionStatus(ctx, tx, deviceID, nil, nil, "", nil); err != nil {
		t.Fatalf("no-op upsertCollectionStatus: %v", err)
	}

	after := getCollectionStatus(t, ctx, tx, deviceID)
	if string(before) != string(after) {
		t.Errorf("collection_status changed on a payload reporting neither section: before=%s after=%s", before, after)
	}
}

// TestCollectionStatusUnknownValueStoredAsUnavailable verifies that an
// unrecognised collection_status value is persisted as "unavailable", never
// as the raw value or as "complete" — matching normaliseCollectionStatus's
// fallback (PAT-1720 precedent, generalised by PAT-1732).
func TestCollectionStatusUnknownValueStoredAsUnavailable(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping devices.collection_status DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newHWTestDevice(t, ctx, tx, "COLLSTATUS-UNKNOWN-VALUE")

	if err := upsertCollectionStatus(ctx, tx, deviceID,
		&collectionStatusPart{Certificates: "mostly_ok"},
		&hwCollectionStatusPart{Storage: "kinda_sorta"},
		"",
		nil,
	); err != nil {
		t.Fatalf("upsertCollectionStatus: %v", err)
	}

	var snap collectionStatusSnapshot
	if err := json.Unmarshal(getCollectionStatus(t, ctx, tx, deviceID), &snap); err != nil {
		t.Fatalf("unmarshal stored collection_status: %v", err)
	}
	if snap.Certificates != "unavailable" {
		t.Errorf("stored certificates status for unknown value: want %q, got %q", "unavailable", snap.Certificates)
	}
	if snap.HardwareHealth == nil || snap.HardwareHealth.Storage != "unavailable" {
		t.Errorf("stored hardware_health.storage status for unknown value: want %q, got %+v", "unavailable", snap.HardwareHealth)
	}
}

// ── Migration SQL sanity ──────────────────────────────────────────────────────

// TestMigrationFilesExist verifies that both the forward and rollback migration
// files are present and contain the expected DDL landmarks. The full
// apply-and-rollback cycle requires a live database and is tested out-of-band.
func TestMigrationFilesExist(t *testing.T) {
	forward := filepath.Join("..", "..", "migrations", "0012_device_certificates.sql")
	rollback := filepath.Join("..", "..", "migrations", "0012_device_certificates_rollback.sql")

	for _, tc := range []struct {
		file        string
		mustContain []string
	}{
		{
			file: forward,
			mustContain: []string{
				"CREATE TABLE device_certificates",
				"UNIQUE (device_id, sha1)",
				"not_after",
				"days_until_expiry_at_collection",
				"0012_device_certificates",
			},
		},
		{
			file: rollback,
			mustContain: []string{
				"DROP TABLE IF EXISTS device_certificates",
				"0012_device_certificates",
			},
		},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("migration file not readable (%s): %v", tc.file, err)
			continue
		}
		body := string(b)
		for _, needle := range tc.mustContain {
			if !strings.Contains(body, needle) {
				t.Errorf("%s: missing expected SQL fragment %q", tc.file, needle)
			}
		}
	}
}

// TestMigration0014Files verifies that both the forward and rollback migration
// files for PAT-252 are present and contain the expected DDL landmarks.
func TestMigration0014Files(t *testing.T) {
	forward := filepath.Join("..", "..", "migrations", "0014_device_hardware.sql")
	rollback := filepath.Join("..", "..", "migrations", "0014_device_hardware_rollback.sql")

	for _, tc := range []struct {
		file        string
		mustContain []string
	}{
		{
			file: forward,
			mustContain: []string{
				"CREATE TABLE device_hardware",
				"CREATE TABLE device_storage_volume",
				"CREATE TABLE device_disk",
				"UNIQUE (device_id)",
				"battery_max_capacity_pct",
				"0014_device_hardware",
			},
		},
		{
			file: rollback,
			mustContain: []string{
				"DROP TABLE IF EXISTS device_disk",
				"DROP TABLE IF EXISTS device_storage_volume",
				"DROP TABLE IF EXISTS device_hardware",
				"0014_device_hardware",
			},
		},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("migration file not readable (%s): %v", tc.file, err)
			continue
		}
		body := string(b)
		for _, needle := range tc.mustContain {
			if !strings.Contains(body, needle) {
				t.Errorf("%s: missing expected SQL fragment %q", tc.file, needle)
			}
		}
	}
}

// TestMigration0013Files verifies that both the forward and rollback migration
// files for PAT-221 are present and contain the expected DDL landmarks.
func TestMigration0013Files(t *testing.T) {
	forward := filepath.Join("..", "..", "migrations", "0013_device_certificates_classification.sql")
	rollback := filepath.Join("..", "..", "migrations", "0013_device_certificates_classification_rollback.sql")

	for _, tc := range []struct {
		file        string
		mustContain []string
	}{
		{
			file: forward,
			mustContain: []string{
				"ADD COLUMN ext_key_usage",
				"ADD COLUMN basic_constraints_ca",
				"ADD COLUMN is_self_signed",
				"0013_device_certificates_classification",
			},
		},
		{
			file: rollback,
			mustContain: []string{
				"DROP COLUMN IF EXISTS ext_key_usage",
				"DROP COLUMN IF EXISTS basic_constraints_ca",
				"DROP COLUMN IF EXISTS is_self_signed",
				"0013_device_certificates_classification",
			},
		},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("migration file not readable (%s): %v", tc.file, err)
			continue
		}
		body := string(b)
		for _, needle := range tc.mustContain {
			if !strings.Contains(body, needle) {
				t.Errorf("%s: missing expected SQL fragment %q", tc.file, needle)
			}
		}
	}
}
