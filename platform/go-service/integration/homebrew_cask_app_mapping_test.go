//go:build integration

package integration

// PAT-2057: a Homebrew cask linked to its app bundle takes its finding from
// the app's mapping, not its own (PAT-2023). Publishing or removing that
// app's mapping therefore flips which of the two is the install's finding,
// and the mapping-publish path must re-match the cask as well as the app in
// the same drain. Neither test runs the nightly full match or ingests a
// payload after the mapping change.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
)

type caskAppFixture struct {
	tn                          cveTestTenant
	deviceID, appName, token    string
	cveID, caskDisplay, product string
}

// seedLinkedCaskDevice posts one Mac carrying app appName and the cask token
// that installed it (linked through homebrew_cask_app_links by the
// extractor), with a curated homebrew_cask mapping and a CVE in range for
// the version on disk. appMapped decides whether the app mapping exists
// before the first report. Returns once the ingest path has drained.
func seedLinkedCaskDevice(t *testing.T, label string, appMapped bool) (caskAppFixture, int64) {
	t.Helper()
	ctx := context.Background()
	sfx := randomHex(4)
	f := caskAppFixture{
		tn:      newCVETestTenant(t, "pat2057-"+label+"-"+sfx),
		appName: "Pat2057 Browser " + sfx,
		token:   "pat2057-browser-" + sfx,
		cveID:   "CVE-2099-" + sfx + "K",
	}
	f.caskDisplay = cvematch.HomebrewDisplayName("cask", f.token)
	f.product = "browser_" + sfx
	product := f.product
	var appMappingID int64
	if appMapped {
		appMappingID = seedCVEMapping(t, f.appName, "pat2057", product)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, 'pat2057', $2, 'PAT-2057 integration test', 'homebrew_cask', 'curated')
	`, f.token, product); err != nil {
		t.Fatal(err)
	}
	seedRealCVE(t, f.cveID, 8.8, "HIGH", cvematch.CPERange{Vendor: "pat2057", Product: product, VEndExcl: "150.0"})

	hw := sfx + "-2057-4000-8000-00000000000c"
	apps := []any{map[string]any{"name": f.appName, "version": "143.0", "bundle_id": "im.patched.pat2057." + sfx,
		"path": "/Applications/" + f.appName + ".app"}}
	casks := []any{map[string]any{
		"prefix": "/opt/homebrew", "token": f.token, "version": "143.0", "versions_on_disk": []any{"143.0"},
		"tap": "homebrew/cask", "installed_on_request": true, "installed_at": "2026-09-10T08:00:00Z",
		"receipt_status": "read", "apps": []any{map[string]any{"name": f.appName + ".app", "path": nil, "exists": nil}},
	}}
	postInventoryAs(t, f.tn.bearer, f.tn.hmacSecret, brewCVEPayload(t, f.tn, hw, "complete", nil, casks, apps))
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, hw)
	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM homebrew_cask_app_links WHERE device_id = $1::uuid`, f.deviceID); n != 1 {
		t.Fatalf("test invalid: %d cask-app links on the device, want 1", n)
	}
	return f, appMappingID
}

// installFindings lists the app_name of every finding for the fixture's CVE.
func (f caskAppFixture) installFindings(t *testing.T) []string {
	t.Helper()
	var names []string
	for k := range brewDeviceFindings(t, f.deviceID) {
		if strings.HasPrefix(k, f.cveID+"|") {
			names = append(names, strings.TrimPrefix(k, f.cveID+"|"))
		}
	}
	sort.Strings(names)
	return names
}

// drainOnceWithoutNightly runs exactly one Drain and fails if a full match
// or a payload ingest happened around it.
func drainOnceWithoutNightly(t *testing.T, deviceID string) cvepipeline.DrainResult {
	t.Helper()
	fullRuns := countRows(t, `SELECT count(*) FROM cve_match_runs WHERE run_kind = 'full_match'`)
	payloads := countRows(t, `SELECT count(*) FROM raw_payloads WHERE device_id = $1::uuid`, deviceID)
	res, err := cvepipeline.Drain(context.Background(), env.pool, nil, 1000)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if res.SkippedForFullMatch {
		t.Fatal("test invalid: drain skipped for a full match")
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_runs WHERE run_kind = 'full_match'`); n != fullRuns {
		t.Fatal("test invalid: a full match ran")
	}
	if n := countRows(t, `SELECT count(*) FROM raw_payloads WHERE device_id = $1::uuid`, deviceID); n != payloads {
		t.Fatal("test invalid: a payload was ingested")
	}
	return res
}

// Removing the app's mapping hands the install to the cask's own curated
// mapping in the same drain: the app finding is pruned and the cask finding
// appears, with no window in which the install has no finding.
func TestHomebrewCaskRematchOnAppMappingRemoval(t *testing.T) {
	f, appMappingID := seedLinkedCaskDevice(t, "rm", true)
	if got := f.installFindings(t); len(got) != 1 || got[0] != f.appName {
		t.Fatalf("before removal: findings %v, want exactly the app's (%q)", got, f.appName)
	}

	if _, err := env.pool.Exec(context.Background(), `DELETE FROM app_cpe_mappings WHERE id = $1`, appMappingID); err != nil {
		t.Fatal(err)
	}
	drainOnceWithoutNightly(t, f.deviceID)

	got := f.installFindings(t)
	if len(got) != 1 || got[0] != f.caskDisplay {
		t.Fatalf("after app mapping removal and one drain: findings %v, want exactly the cask's own (%q)", got, f.caskDisplay)
	}
	row := brewDeviceFindings(t, f.deviceID)[f.cveID+"|"+f.caskDisplay]
	if deref(row.Source) != cvematch.HomebrewCaskSource || deref(row.PkgName) != f.token || row.Version != "143.0" {
		t.Fatalf("cask finding = %+v source=%s pkg=%s", row, deref(row.Source), deref(row.PkgName))
	}
}

// Publishing a mapping for the linked app makes the app the install's one
// finding in the same drain: the cask's own finding is pruned, never left
// beside the app's as a duplicate.
func TestHomebrewCaskRematchOnAppMappingPublication(t *testing.T) {
	f, _ := seedLinkedCaskDevice(t, "pub", false)
	if got := f.installFindings(t); len(got) != 1 || got[0] != f.caskDisplay {
		t.Fatalf("before publication: findings %v, want exactly the cask's (%q)", got, f.caskDisplay)
	}

	seedCVEMapping(t, f.appName, "pat2057", f.product)
	drainOnceWithoutNightly(t, f.deviceID)

	if got := f.installFindings(t); len(got) != 1 || got[0] != f.appName {
		t.Fatalf("after app mapping publication and one drain: findings %v, want exactly the app's (%q)", got, f.appName)
	}
}
