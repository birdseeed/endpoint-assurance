//go:build integration

package integration

// PAT-2152: the SAM software publisher report, end to end. Inventory is
// posted through /v1/inventory and extracted exactly as production does
// (reusing PAT-2093's macOS/Windows app builders and posting helper from
// new_software_urgency_test.go), so the publisher identity and trust state
// come from what the extractor really records, never a hand-written row.
// Covers the four required acceptance cases on both platforms (a signed
// trusted publisher, a signed untrusted publisher, an unsigned install, an
// install with no signing evidence), an invalid signature, a retired device
// excluded, tenant isolation and the CSV export.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"patched.im/api/internal/softwaregov"
)

type pubRow struct {
	PublisherKey      string  `json:"publisher_key"`
	Group             string  `json:"group"`
	Platform          string  `json:"platform"`
	IdentityBasis     string  `json:"identity_basis"`
	Publisher         *string `json:"publisher"`
	Trusted           bool    `json:"trusted"`
	Signing           string  `json:"signing"`
	Notarisation      string  `json:"notarisation"`
	ProductCount      int     `json:"product_count"`
	DeviceCount       int     `json:"device_count"`
	InstallationCount int     `json:"installation_count"`
}

type pubReport struct {
	Definition struct {
		ID string `json:"id"`
	} `json:"definition"`
	Summary struct {
		PublisherCount              int `json:"publisher_count"`
		TrustedPublisherCount       int `json:"trusted_publisher_count"`
		UntrustedPublisherCount     int `json:"untrusted_publisher_count"`
		UnsignedInstallationCount   int `json:"unsigned_installation_count"`
		InvalidInstallationCount    int `json:"invalid_installation_count"`
		UnverifiedInstallationCount int `json:"unverified_installation_count"`
		InstallationCount           int `json:"installation_count"`
	} `json:"summary"`
	Basis struct {
		DevicesTotal    int  `json:"devices_total"`
		DevicesAssessed int  `json:"devices_assessed"`
		DevicesRetired  int  `json:"devices_retired"`
		RetiredExcluded bool `json:"retired_devices_excluded"`
	} `json:"basis"`
	Total      int      `json:"total"`
	Publishers []pubRow `json:"publishers"`
}

func pubReportByGroup(rep pubReport, group string) []pubRow {
	var out []pubRow
	for _, p := range rep.Publishers {
		if p.Group == group {
			out = append(out, p)
		}
	}
	return out
}

func pubApprovMacTeam(t *testing.T, tenantID, teamID string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, team_id, platform, policy)
		VALUES ($1::uuid, $2, 'macos', 'approved')`, tenantID, teamID); err != nil {
		t.Fatalf("approve mac team %s: %v", teamID, err)
	}
}

func pubApproveWindowsKey(t *testing.T, tenantID, key string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, winget_id, platform, policy, publisher_key)
		VALUES ($1::uuid, $2, 'windows', 'approved', $3)`, tenantID, "pat2152."+randomHex(4), key); err != nil {
		t.Fatalf("approve windows key %s: %v", key, err)
	}
}

// TestSoftwarePublishersMacOS covers the four required acceptance cases on
// macOS: a signed trusted publisher (Team ID approved), a signed untrusted
// publisher (Team ID not approved), an unsigned install and an install with
// no signing evidence at all (the collector's sentinel with no explicit
// signing_status).
func TestSoftwarePublishersMacOS(t *testing.T) {
	tn := newUrgencyTenant(t, "publishers-mac")
	sfx := randomHex(4)
	teamTrusted := strings.ToUpper("TT" + randomHex(4))[:10]
	teamOther := strings.ToUpper("TO" + randomHex(4))[:10]
	devIDFor := func(tm string) string { return "Developer ID Application: Example " + tm + " (" + tm + ")" }
	name := func(s string) string { return "Pub Mac " + s + " " + sfx }
	bundle := func(s string) string { return "com.pat2152." + s + "." + sfx }

	pubApprovMacTeam(t, tn.id, teamTrusted)

	apps := []map[string]any{
		urgMacAppStatus(name("trusted"), bundle("trusted"), "1.0", teamTrusted, devIDFor(teamTrusted), "signed", "notarized"),
		urgMacAppStatus(name("untrusted"), bundle("untrusted"), "1.0", teamOther, devIDFor(teamOther), "signed", "notarized"),
		urgMacAppStatus(name("unsigned"), bundle("unsigned"), "1.0", "", "", "unsigned", "unknown"),
		urgMacApp(name("noevidence"), bundle("noevidence"), "1.0", "", "Unknown", false),
	}
	postUrgencyInventory(t, tn, "full.json", strings.ToUpper("aa"+randomHex(3)+"-1111-2222-3333-444455556666"), apps)

	rep := pubReport{}
	getJSON(t, "/v1/portal/reports/software/publishers", tn.viewerToken, &rep)

	verified := pubReportByGroup(rep, softwaregov.PublisherGroupVerified)
	var trustedRow, untrustedRow *pubRow
	for i := range verified {
		p := &verified[i]
		if p.Publisher != nil && *p.Publisher == teamTrusted {
			trustedRow = p
		}
		if p.Publisher != nil && *p.Publisher == teamOther {
			untrustedRow = p
		}
	}
	if trustedRow == nil {
		t.Fatalf("no verified row for the approved Team ID %s among %+v", teamTrusted, verified)
	}
	if !trustedRow.Trusted {
		t.Errorf("trusted team %s: trusted = false, want true", teamTrusted)
	}
	if trustedRow.IdentityBasis != softwaregov.PublisherBasisTeamID {
		t.Errorf("trusted team identity_basis = %q, want team_id", trustedRow.IdentityBasis)
	}
	if untrustedRow == nil {
		t.Fatalf("no verified row for the unapproved Team ID %s among %+v", teamOther, verified)
	}
	if untrustedRow.Trusted {
		t.Errorf("unapproved team %s: trusted = true, want false", teamOther)
	}

	unsigned := pubReportByGroup(rep, softwaregov.PublisherGroupUnsignedAdhoc)
	foundUnsigned := false
	for _, p := range unsigned {
		if p.Platform == "macos" {
			foundUnsigned = true
			if p.Publisher != nil {
				t.Errorf("unsigned row carries a publisher %v, want nil", p.Publisher)
			}
		}
	}
	if !foundUnsigned {
		t.Fatalf("no macos unsigned_or_adhoc row among %+v", rep.Publishers)
	}

	unverified := pubReportByGroup(rep, softwaregov.PublisherGroupUnverified)
	foundNoEvidence := false
	for _, p := range unverified {
		if p.Platform == "macos" {
			foundNoEvidence = true
			if p.Publisher != nil {
				t.Errorf("no-evidence row carries a publisher %v, want nil", p.Publisher)
			}
		}
	}
	if !foundNoEvidence {
		t.Fatalf("no macos unverified row among %+v", rep.Publishers)
	}

	// Regression: the publisher must never be the installer-claimed name.
	// name("trusted")/name("untrusted") etc. must never appear as a
	// Publisher value anywhere in the report.
	for _, p := range rep.Publishers {
		if p.Publisher == nil {
			continue
		}
		for _, s := range []string{name("trusted"), name("untrusted"), name("unsigned"), name("noevidence")} {
			if *p.Publisher == s {
				t.Fatalf("publisher %q equals an installer-claimed app name, never allowed", *p.Publisher)
			}
		}
	}
}

// TestSoftwarePublishersWindows covers the four required acceptance cases on
// Windows (a pinned trusted Authenticode publisher, a pinned but unapproved
// publisher, an unsigned install, an install with no signing evidence),
// plus an invalid signature and the pre-#668 "legacy" agent (valid, agreed
// signer, no root pin) that PAT-2093's own classifier trusts for back-compat
// but this report must show as unverified (PAT-2121 needs the root pin).
func TestSoftwarePublishersWindows(t *testing.T) {
	tn := newUrgencyTenant(t, "publishers-win")
	sfx := randomHex(4)
	name := func(s string) string { return "Pub Win " + s + " " + sfx }
	guid := func(n int) string { return fmt.Sprintf("{%s-%04d}", strings.ToUpper(randomHex(8)), n) }
	signerTrusted := "CN=Trusted " + sfx + " Ltd, O=Trusted " + sfx + " Ltd, C=GB"
	signerOther := "CN=Other " + sfx + " Ltd, O=Other " + sfx + " Ltd, C=GB"
	root := strings.Repeat("c", 64)

	trustedKey := softwaregov.AuthenticodePublisherKey(root, signerTrusted)
	pubApproveWindowsKey(t, tn.id, trustedKey)

	apps := []map[string]any{
		urgWinAppPinned(name("trusted"), guid(1), "valid", signerTrusted, root, "public"),
		urgWinAppPinned(name("untrusted"), guid(2), "valid", signerOther, root, "public"),
		urgWinAppEvidence(name("unsigned"), guid(3), "1.0", "", "unsigned", ""),
		urgWinApp(name("noevidence"), guid(4), "1.0", "Some Vendor Ltd"),
		urgWinAppEvidence(name("invalid"), guid(5), "1.0", "", "invalid", ""),
		urgWinAppEvidence(name("legacy"), guid(6), "1.0", "Registry Claim Ltd", "valid", signerTrusted),
	}
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("bb"+randomHex(3)+"-1111-2222-3333-444455556666"), apps)

	rep := pubReport{}
	getJSON(t, "/v1/portal/reports/software/publishers", tn.viewerToken, &rep)

	verified := pubReportByGroup(rep, softwaregov.PublisherGroupVerified)
	var trustedRow, untrustedRow *pubRow
	for i := range verified {
		p := &verified[i]
		if p.PublisherKey == trustedKey {
			trustedRow = p
		}
		if p.Publisher != nil && *p.Publisher == signerOther {
			untrustedRow = p
		}
	}
	if trustedRow == nil {
		t.Fatalf("no verified row for the approved publisher key among %+v", verified)
	}
	if !trustedRow.Trusted {
		t.Error("approved windows publisher: trusted = false, want true")
	}
	if trustedRow.IdentityBasis != softwaregov.PublisherBasisAuthenticode {
		t.Errorf("identity_basis = %q, want authenticode_signer", trustedRow.IdentityBasis)
	}
	if untrustedRow == nil {
		t.Fatalf("no verified row for the unapproved publisher among %+v", verified)
	}
	if untrustedRow.Trusted {
		t.Error("unapproved windows publisher: trusted = true, want false")
	}

	unsigned := pubReportByGroup(rep, softwaregov.PublisherGroupUnsignedAdhoc)
	if len(unsigned) == 0 {
		t.Fatalf("no unsigned_or_adhoc row among %+v", rep.Publishers)
	}
	invalid := pubReportByGroup(rep, softwaregov.PublisherGroupInvalid)
	if len(invalid) == 0 {
		t.Fatalf("no invalid row among %+v", rep.Publishers)
	}
	for _, p := range append(append([]pubRow{}, unsigned...), invalid...) {
		if p.Publisher != nil {
			t.Errorf("group %s row carries a publisher %v, want nil", p.Group, p.Publisher)
		}
	}

	// "noevidence" and "legacy" (valid, agreed signer, no root pin: an
	// agent older than updater #668) both land unverified, never under the
	// claimed signer or the registry Publisher string.
	unverified := pubReportByGroup(rep, softwaregov.PublisherGroupUnverified)
	if len(unverified) == 0 {
		t.Fatalf("no unverified row among %+v", rep.Publishers)
	}
	unverifiedInstalls := 0
	for _, p := range unverified {
		unverifiedInstalls += p.InstallationCount
		if p.Publisher != nil {
			t.Errorf("unverified row carries a publisher %q, want nil (never installer metadata)", *p.Publisher)
		}
	}
	if unverifiedInstalls < 2 {
		t.Errorf("unverified installation count = %d, want at least 2 (noevidence + legacy)", unverifiedInstalls)
	}
}

// TestSoftwarePublishersRetiredDeviceExcluded proves a retired device's
// installations are left out of every row and count, per the shared
// internal/deviceretirement rule (PAT-2135), matching PAT-2147/PAT-2148.
func TestSoftwarePublishersRetiredDeviceExcluded(t *testing.T) {
	tn := newUrgencyTenant(t, "publishers-retire")
	sfx := randomHex(4)
	team := strings.ToUpper("RT" + randomHex(4))[:10]
	devIDFor := "Developer ID Application: Example " + team + " (" + team + ")"
	name := "Pub Retire " + sfx
	bundle := "com.pat2152.retire." + sfx

	pubApprovMacTeam(t, tn.id, team)
	app := urgMacAppStatus(name, bundle, "1.0", team, devIDFor, "signed", "notarized")

	hwA := strings.ToUpper("cc" + randomHex(3) + "-1111-2222-3333-444455556666")
	hwB := strings.ToUpper("dd" + randomHex(3) + "-1111-2222-3333-444455556666")
	postUrgencyInventory(t, tn, "full.json", hwA, []map[string]any{app})
	postUrgencyInventory(t, tn, "full.json", hwB, []map[string]any{app})

	var retiredID string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2`, tn.id, hwB).Scan(&retiredID); err != nil {
		t.Fatalf("look up device for retirement: %v", err)
	}
	raRetireDevice(t, tn.id, retiredID)

	rep := pubReport{}
	getJSON(t, "/v1/portal/reports/software/publishers", tn.viewerToken, &rep)
	if rep.Basis.DevicesRetired != 1 {
		t.Errorf("devices_retired = %d, want 1", rep.Basis.DevicesRetired)
	}
	if !rep.Basis.RetiredExcluded {
		t.Error("retired_devices_excluded = false, want true")
	}
	if rep.Basis.DevicesAssessed != 1 {
		t.Errorf("devices_assessed = %d, want 1 (the retired device excluded)", rep.Basis.DevicesAssessed)
	}
	for _, p := range rep.Publishers {
		if p.Publisher != nil && *p.Publisher == team {
			if p.DeviceCount != 1 || p.InstallationCount != 1 {
				t.Errorf("publisher %s: device_count %d installation_count %d, want 1 and 1 (retired device excluded)",
					team, p.DeviceCount, p.InstallationCount)
			}
		}
	}
}

// TestSoftwarePublishersTenantIsolation proves one tenant's report never
// includes another tenant's installations.
func TestSoftwarePublishersTenantIsolation(t *testing.T) {
	tnA := newUrgencyTenant(t, "publishers-iso-a")
	tnB := newUrgencyTenant(t, "publishers-iso-b")
	sfx := randomHex(4)
	teamA := strings.ToUpper("IA" + randomHex(4))[:10]
	nameA := "Pub Iso A " + sfx
	bundleA := "com.pat2152.isoa." + sfx

	pubApprovMacTeam(t, tnA.id, teamA)
	app := urgMacAppStatus(nameA, bundleA, "1.0", teamA,
		"Developer ID Application: Example "+teamA+" ("+teamA+")", "signed", "notarized")
	postUrgencyInventory(t, tnA, "full.json", strings.ToUpper("ee"+randomHex(3)+"-1111-2222-3333-444455556666"), []map[string]any{app})

	repB := pubReport{}
	getJSON(t, "/v1/portal/reports/software/publishers", tnB.viewerToken, &repB)
	for _, p := range repB.Publishers {
		if p.Publisher != nil && *p.Publisher == teamA {
			t.Fatalf("tenant B report leaked tenant A's publisher %+v", p)
		}
	}
	if repB.Basis.DevicesAssessed != 0 {
		t.Errorf("tenant B devices_assessed = %d, want 0", repB.Basis.DevicesAssessed)
	}
}

// TestSoftwarePublishersCSV proves the devices drill-down CSV export.
func TestSoftwarePublishersCSV(t *testing.T) {
	tn := newUrgencyTenant(t, "publishers-csv")
	sfx := randomHex(4)
	team := strings.ToUpper("CS" + randomHex(4))[:10]
	name := "Pub CSV " + sfx
	bundle := "com.pat2152.csv." + sfx

	pubApprovMacTeam(t, tn.id, team)
	app := urgMacAppStatus(name, bundle, "1.0", team,
		"Developer ID Application: Example "+team+" ("+team+")", "signed", "notarized")
	postUrgencyInventory(t, tn, "full.json", strings.ToUpper("ff"+randomHex(3)+"-1111-2222-3333-444455556666"), []map[string]any{app})

	resp := portalDo(t, "GET", "/v1/portal/reports/software/publishers/devices?format=csv", tn.viewerToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("csv export = %d: %s", resp.StatusCode, b)
	}
	body, _ := io.ReadAll(resp.Body)
	csvText := string(body)
	if !strings.Contains(csvText, "device_id,hostname") {
		t.Fatalf("csv header missing: %s", csvText[:min(200, len(csvText))])
	}
	if !strings.Contains(csvText, team) {
		t.Fatalf("csv missing the trusted team's publisher row: %s", csvText)
	}
	if rows := resp.Header.Get("X-Patched-Export-Rows"); rows == "" || rows == "0" {
		t.Errorf("X-Patched-Export-Rows = %q, want a positive count", rows)
	}
}
