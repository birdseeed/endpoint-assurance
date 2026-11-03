//go:build integration

package integration

// PAT-2023: Homebrew formulae and casks through both CVE match paths. The
// payload goes in through POST /v1/inventory and the extractor; findings
// come from cvepipeline.Drain (ingest path) and cvepipeline.MatchHomebrewFull
// (the nightly full match), never from hand-written finding rows.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cvelifecycle"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
)

// brewCVEPayload is the complete-block Homebrew fixture with the device,
// status, formulae, casks and apps replaced.
func brewCVEPayload(t *testing.T, tn cveTestTenant, hwUUID, status string, formulae, casks, apps []any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "with-homebrew-complete-macos.json"), &m); err != nil {
		t.Fatal(err)
	}
	m["tenant_id"] = tn.tenantID
	m["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	device := m["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2023" + strings.ToUpper(hwUUID[:8])
	device["hostname"] = "pat2023-" + strings.ToLower(hwUUID[:8])
	if apps == nil {
		apps = []any{}
	}
	m["apps"] = apps
	hb := m["homebrew"].(map[string]any)
	hb["collection_status"] = status
	if formulae == nil {
		formulae = []any{}
	}
	if casks == nil {
		casks = []any{}
	}
	hb["formulae"], hb["casks"] = formulae, casks
	hb["taps"] = []any{map[string]any{"prefix": "/opt/homebrew", "name": "homebrew/core",
		"directory": "homebrew/homebrew-core", "remote_url": "https://github.com/Homebrew/homebrew-core", "config_status": "read"}}
	prefixes := hb["prefixes"].([]any)
	p0 := prefixes[0].(map[string]any)
	p0["collection_status"], p0["formulae"], p0["casks"], p0["taps"] = status, len(formulae), len(casks), 1
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func brewFormula(name, version string, onRequest bool, deps []any, homepage any) map[string]any {
	if deps == nil {
		deps = []any{}
	}
	return map[string]any{
		"prefix": "/opt/homebrew", "name": name, "version": version, "tap": "homebrew/core",
		"installed_on_request": onRequest, "installed_as_dependency": !onRequest,
		"installed_at": "2026-09-01T10:00:00Z", "runtime_dependencies": deps,
		"homepage": homepage, "source_url": nil, "opt_linked": true,
		"receipt_status": "read", "formula_file_status": "read",
	}
}

// seedRealCVE writes a CVE with its real NVD shape (score, CPE key, range).
// Upserted, since the ID is real and fixed.
func seedRealCVE(t *testing.T, cveID string, score float64, severity string, r cvematch.CPERange) cvematch.CVEEntry {
	t.Helper()
	key := strings.ToLower(r.Vendor + ":" + r.Product)
	rangesJSON, _ := json.Marshal([]cvematch.CPERange{r})
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity, cpe_patterns, cpe_ranges)
		VALUES ($1, 'PAT-2023 integration test', 'nvd', $2, $3, $4, $5)
		ON CONFLICT (cve_id) DO UPDATE SET cvss_v3_score = EXCLUDED.cvss_v3_score, severity = EXCLUDED.severity,
			cpe_patterns = EXCLUDED.cpe_patterns, cpe_ranges = EXCLUDED.cpe_ranges
	`, cveID, score, severity, []string{key}, string(rangesJSON)); err != nil {
		t.Fatalf("seed %s: %v", cveID, err)
	}
	return cvematch.CVEEntry{CVEID: cveID, Score: &score, Severity: severity, Patterns: []string{key},
		Ranges: []cvematch.CPERange{r}}
}

type brewFindingRow struct {
	CVE, App, Version, Confidence, Fixed string
	Source, PkgName, Reason, Basis, Tier *string
	RequiredBy                           []string
}

func brewDeviceFindings(t *testing.T, deviceID string) map[string]brewFindingRow {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT cve_id, app_name, app_version, match_confidence, fixed_version,
		       package_source, package_name, install_reason, mapping_basis, confidence_tier,
		       COALESCE(required_by, '{}')
		FROM device_cve_findings WHERE device_id = $1::uuid
	`, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]brewFindingRow{}
	for rows.Next() {
		var r brewFindingRow
		if err := rows.Scan(&r.CVE, &r.App, &r.Version, &r.Confidence, &r.Fixed,
			&r.Source, &r.PkgName, &r.Reason, &r.Basis, &r.Tier, &r.RequiredBy); err != nil {
			t.Fatal(err)
		}
		out[r.CVE+"|"+r.App] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestHomebrewCVEMatchOldOpensslAndCurl is the ticket's acceptance case, end
// to end: a Mac with old openssl@3 and curl formulae gets the expected CVEs,
// version-confirmed with high confidence and NVD's fixed version, through the
// ingest path and again through the nightly full match; dependency versus
// on-request is on the finding; an unmapped formula produces no finding and
// lands in the review queue; a partial report never removes a finding and a
// complete one does, with closure gated on the homebrew scope.
func TestHomebrewCVEMatchOldOpensslAndCurl(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2023-brew-"+sfx)

	feed := []cvematch.CVEEntry{
		seedRealCVE(t, "CVE-2023-0286", 7.4, "HIGH",
			cvematch.CPERange{Vendor: "openssl", Product: "openssl", VStartIncl: "3.0.0", VEndExcl: "3.0.8"}),
		seedRealCVE(t, "CVE-2023-38545", 9.8, "CRITICAL",
			cvematch.CPERange{Vendor: "haxx", Product: "libcurl", VStartIncl: "7.69.0", VEndExcl: "8.4.0"}),
	}

	unmapped := "zzz-pat2023-" + sfx
	hw := sfx + "-2023-4000-8000-00000000000a"
	formulae := []any{
		brewFormula("openssl@3", "3.0.7", true, []any{"ca-certificates"}, "https://openssl-library.org"),
		brewFormula("curl", "8.2.1_1", false, []any{"openssl@3"}, "https://curl.se"),
		brewFormula("wget", "1.24.5", true, []any{"homebrew/core/curl", "openssl@3"}, "https://www.gnu.org/software/wget/"),
		brewFormula(unmapped, "1.0.0", true, nil, "https://github.com/pat2023-"+sfx+"/"+unmapped),
	}
	// An application literally named "curl": the Homebrew mapping for the
	// curl formula must never reach it through the application path.
	apps := []any{map[string]any{"name": "curl", "version": "8.2.1", "bundle_id": "se.curl.pat2023",
		"path": "/Applications/curl.app"}}
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", formulae, nil, apps))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)

	check := func(stage string) {
		t.Helper()
		got := brewDeviceFindings(t, deviceID)
		ossl, ok := got["CVE-2023-0286|openssl@3 (Homebrew formula)"]
		if !ok {
			t.Fatalf("%s: no CVE-2023-0286 on openssl@3; findings %+v", stage, got)
		}
		if ossl.Confidence != "version_confirmed" || deref(ossl.Tier) != "high" || ossl.Fixed != "3.0.8" ||
			deref(ossl.Source) != "homebrew_formula" || deref(ossl.PkgName) != "openssl@3" ||
			deref(ossl.Reason) != "on_request" || deref(ossl.Basis) != "curated" || ossl.Version != "3.0.7" {
			t.Fatalf("%s: openssl finding %+v tier=%s reason=%s", stage, ossl, deref(ossl.Tier), deref(ossl.Reason))
		}
		// Both curl's and wget's receipts list openssl@3.
		if want := []string{"curl", "wget"}; strings.Join(ossl.RequiredBy, ",") != strings.Join(want, ",") {
			t.Fatalf("%s: openssl required_by = %v, want %v", stage, ossl.RequiredBy, want)
		}
		curl, ok := got["CVE-2023-38545|curl (Homebrew formula)"]
		if !ok {
			t.Fatalf("%s: no CVE-2023-38545 on curl; findings %+v", stage, got)
		}
		if curl.Confidence != "version_confirmed" || deref(curl.Tier) != "high" || curl.Fixed != "8.4.0" ||
			deref(curl.Reason) != "dependency" || curl.Version != "8.2.1_1" ||
			strings.Join(curl.RequiredBy, ",") != "wget" {
			t.Fatalf("%s: curl finding %+v reason=%s", stage, curl, deref(curl.Reason))
		}
		for k := range got {
			if strings.HasSuffix(k, "|curl") {
				t.Fatalf("%s: the curl formula mapping reached the application named curl: %s", stage, k)
			}
			if strings.Contains(k, unmapped) || strings.Contains(k, "wget") {
				t.Fatalf("%s: unmapped formula produced a finding: %s", stage, k)
			}
		}
	}
	check("ingest path")

	// The unmapped formulae are queued for review by the nightly run
	// (PAT-2045: the ingest drain no longer writes review rows); no
	// suggestion, since no candidate key exists in the local NVD store.
	if n := countRows(t, `SELECT count(*) FROM homebrew_cpe_review_queue WHERE package_kind = 'formula' AND name = $1`, unmapped); n != 0 {
		t.Fatalf("the ingest drain wrote %d review rows", n)
	}
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, feed); err != nil {
		t.Fatalf("MatchHomebrewFull: %v", err)
	}
	var status string
	var homepage *string
	if err := env.pool.QueryRow(ctx, `
		SELECT status, homepage FROM homebrew_cpe_review_queue WHERE package_kind = 'formula' AND name = $1
	`, unmapped).Scan(&status, &homepage); err != nil {
		t.Fatalf("unmapped formula not in the review queue: %v", err)
	}
	if status != "pending" || deref(homepage) != "https://github.com/pat2023-"+sfx+"/"+unmapped {
		t.Fatalf("review row status=%s homepage=%s", status, deref(homepage))
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1`, unmapped); n != 0 {
		t.Fatalf("unmapped formula gained %d mappings with no NVD evidence", n)
	}
	// The global queue carries no tenant or device identifier.
	if n := countRows(t, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'homebrew_cpe_review_queue' AND column_name IN ('tenant_id','device_id')`); n != 0 {
		t.Fatalf("review queue has %d tenant/device columns", n)
	}

	// Portal findings show the Homebrew source and install reason.
	resp := portalDo(t, http.MethodGet, "/v1/portal/findings?limit=500", tn.token, nil)
	var page struct {
		Findings []struct {
			CVEID          string   `json:"cve_id"`
			App            string   `json:"app"`
			FixedVersion   string   `json:"fixed_version"`
			Source         *string  `json:"source"`
			ConfidenceTier *string  `json:"confidence_tier"`
			InstallReasons []string `json:"install_reasons"`
		} `json:"findings"`
	}
	decodeJSON(t, resp, &page)
	var sawCurl bool
	for _, f := range page.Findings {
		if f.CVEID == "CVE-2023-38545" && f.App == "curl (Homebrew formula)" {
			sawCurl = true
			if deref(f.Source) != "homebrew_formula" || deref(f.ConfidenceTier) != "high" ||
				strings.Join(f.InstallReasons, ",") != "dependency" || f.FixedVersion != "8.4.0" {
				t.Fatalf("portal curl finding = %+v", f)
			}
		}
	}
	if !sawCurl {
		t.Fatalf("portal findings lack the curl finding: %+v", page.Findings)
	}

	// Nightly full match reproduces the same findings from scratch.
	if _, err := env.pool.Exec(ctx, `DELETE FROM device_cve_findings WHERE device_id = $1::uuid`, deviceID); err != nil {
		t.Fatal(err)
	}
	res, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, feed)
	if err != nil {
		t.Fatalf("MatchHomebrewFull: %v", err)
	}
	if res.Findings < 2 {
		t.Fatalf("nightly homebrew match wrote %d findings", res.Findings)
	}
	check("nightly path")

	// The lifecycle records Homebrew findings as needing the homebrew scope
	// to close, never the application snapshot.
	cvelifecycleReconcile(t, tn.tenantID, "CVE-2023-0286")
	var evidence string
	if err := env.pool.QueryRow(ctx, `
		SELECT evidence::text FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = 'CVE-2023-0286'
		  AND event_type IN ('first_observed','currently_observed','still_failing','recurred')
		ORDER BY id DESC LIMIT 1
	`, tn.tenantID).Scan(&evidence); err != nil {
		t.Fatalf("lifecycle evidence: %v", err)
	}
	if !strings.Contains(evidence, `"required_scope": "homebrew"`) {
		t.Fatalf("lifecycle evidence lacks required_scope homebrew: %s", evidence)
	}

	// Partial report without openssl@3: it may simply not have been read, so
	// its finding stays.
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "partial", formulae[1:], nil, apps))
	drainCVEQueue(t)
	if _, ok := brewDeviceFindings(t, deviceID)["CVE-2023-0286|openssl@3 (Homebrew formula)"]; !ok {
		t.Fatal("a partial Homebrew report removed the openssl@3 finding")
	}

	// Complete report without openssl@3: authoritative, so the finding goes.
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", formulae[1:], nil, apps))
	drainCVEQueue(t)
	got := brewDeviceFindings(t, deviceID)
	if _, ok := got["CVE-2023-0286|openssl@3 (Homebrew formula)"]; ok {
		t.Fatal("a complete Homebrew report without openssl@3 left its finding")
	}
	if _, ok := got["CVE-2023-38545|curl (Homebrew formula)"]; !ok {
		t.Fatal("the curl finding was lost on an unrelated removal")
	}
}

func cvelifecycleReconcile(t *testing.T, tenantID, cveID string) {
	t.Helper()
	if err := cvelifecycle.ReconcileIdentities(context.Background(), env.pool,
		[]cvelifecycle.Identity{{TenantID: tenantID, CVEID: cveID}}, nil); err != nil {
		t.Fatalf("reconcile %s: %v", cveID, err)
	}
}

// TestHomebrewCVEMatchCaskLinkedToAppYieldsOneFinding: a cask whose app
// bundle is on disk and mapped yields one finding (the app's), not two. With
// the link removed, the cask's own mapping produces its own finding, which is
// what the link is preventing.
func TestHomebrewCVEMatchCaskLinkedToAppYieldsOneFinding(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2023-cask-"+sfx)

	appName := "Pat2023 Browser " + sfx
	token := "pat2023-browser-" + sfx
	product := "browser_" + sfx
	cveID := "CVE-2099-" + sfx
	seedCVEMapping(t, appName, "pat2023", product)
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, 'pat2023', $2, 'PAT-2023 integration test', 'homebrew_cask', 'curated')
	`, token, product); err != nil {
		t.Fatal(err)
	}
	entry := seedRealCVE(t, cveID, 8.8, "HIGH", cvematch.CPERange{Vendor: "pat2023", Product: product, VEndExcl: "150.0"})

	hw := sfx + "-2023-4000-8000-00000000000c"
	apps := []any{map[string]any{"name": appName, "version": "143.0", "bundle_id": "im.patched.pat2023." + sfx,
		"path": "/Applications/" + appName + ".app"}}
	casks := []any{map[string]any{
		"prefix": "/opt/homebrew", "token": token, "version": "143.0", "versions_on_disk": []any{"143.0"},
		"tap": "homebrew/cask", "installed_on_request": true, "installed_at": "2026-09-10T08:00:00Z",
		"receipt_status": "read", "apps": []any{map[string]any{"name": appName + ".app", "path": nil, "exists": nil}},
	}}
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", nil, casks, apps))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)

	count := func() (int, []string) {
		var n int
		var names []string
		for k := range brewDeviceFindings(t, deviceID) {
			if strings.HasPrefix(k, cveID+"|") {
				n++
				names = append(names, strings.TrimPrefix(k, cveID+"|"))
			}
		}
		sort.Strings(names)
		return n, names
	}
	if n, names := count(); n != 1 || names[0] != appName {
		t.Fatalf("cask linked to its app: %d findings %v, want exactly one on %q", n, names, appName)
	}
	// The nightly path agrees.
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, []cvematch.CVEEntry{entry}); err != nil {
		t.Fatal(err)
	}
	if n, names := count(); n != 1 {
		t.Fatalf("after nightly homebrew match: %d findings %v", n, names)
	}

	// Without the link, the cask is its own install and gets its own finding.
	if _, err := env.pool.Exec(ctx, `DELETE FROM homebrew_cask_app_links WHERE device_id = $1::uuid`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.tenantID, deviceID,
		[]string{cvematch.HomebrewDisplayName("cask", token)}, cvepipeline.SourceIngest); err != nil {
		t.Fatal(err)
	}
	drainCVEQueue(t)
	if n, names := count(); n != 2 {
		t.Fatalf("unlinked cask: %d findings %v, want the app's and the cask's", n, names)
	}
}

// TestHomebrewCVEMatchSuggestionIsNeverAMapping (PAT-2023 review, P1 and P2).
// Endpoint-reported homepage and source URLs are attacker-controlled input to
// a global table, so:
//   - an exact NVD key they point at is stored only as suggested_cpe_key on
//     the review row; it never becomes an app_cpe_mappings row and never
//     produces a finding, even with a CVE in range for that key;
//   - a second tenant reporting different metadata for the same formula
//     cannot overwrite the first-seen homepage or suggestion; the row is
//     flagged as contested instead;
//   - a formula with no recorded tap (possibly local or private) is never
//     queued, on either path.
func TestHomebrewCVEMatchSuggestionIsNeverAMapping(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	good := "pat2023good" + sfx
	evil := "pat2023evil" + sfx
	formula := "tool-" + sfx
	private := "private-" + sfx
	goodEntry := seedRealCVE(t, "CVE-2099-G"+sfx, 9.8, "CRITICAL",
		cvematch.CPERange{Vendor: good, Product: "tool", VEndExcl: "9.0"})
	evilEntry := seedRealCVE(t, "CVE-2099-E"+sfx, 9.8, "CRITICAL",
		cvematch.CPERange{Vendor: evil, Product: "log4j", VEndExcl: "9.0"})

	withTap := func(f map[string]any, tap any) map[string]any { f["tap"] = tap; return f }

	tnA := newCVETestTenant(t, "pat2023-sugg-a-"+sfx)
	hwA := sfx + "-2023-4000-8000-0000000000a1"
	postInventoryAs(t, tnA.bearer, tnA.hmacSecret, brewCVEPayload(t, tnA, hwA, "complete", []any{
		brewFormula(formula, "1.0.0", true, nil, "https://github.com/"+good+"/tool"),
		withTap(brewFormula(private, "1.0.0", true, nil, "https://intranet.example.internal/"+private), nil),
	}, nil, nil))
	deviceA := deviceIDByHW(t, tnA.tenantID, hwA)
	drainCVEQueue(t)
	// Review rows are written by the nightly run (PAT-2045).
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, nil); err != nil {
		t.Fatal(err)
	}

	readRow := func() (homepage, suggestion *string, conflict bool, conflicts int) {
		t.Helper()
		if err := env.pool.QueryRow(ctx, `
			SELECT homepage, suggested_cpe_key, metadata_conflict, metadata_conflict_count
			FROM homebrew_cpe_review_queue WHERE package_kind = 'formula' AND name = $1
		`, formula).Scan(&homepage, &suggestion, &conflict, &conflicts); err != nil {
			t.Fatalf("review row for %s: %v", formula, err)
		}
		return
	}
	hp, sug, conflict, conflicts := readRow()
	if deref(sug) != good+":tool" || deref(hp) != "https://github.com/"+good+"/tool" || conflict || conflicts != 0 {
		t.Fatalf("first report: homepage=%s suggestion=%s conflict=%v/%d", deref(hp), deref(sug), conflict, conflicts)
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1`, formula); n != 0 {
		t.Fatalf("a suggestion became %d app_cpe_mappings rows", n)
	}
	for k := range brewDeviceFindings(t, deviceA) {
		t.Fatalf("a suggestion produced a finding: %s", k)
	}

	// Tenant B reports the same formula pointing somewhere else.
	tnB := newCVETestTenant(t, "pat2023-sugg-b-"+sfx)
	hwB := sfx + "-2023-4000-8000-0000000000b1"
	postInventoryAs(t, tnB.bearer, tnB.hmacSecret, brewCVEPayload(t, tnB, hwB, "complete", []any{
		brewFormula(formula, "1.0.0", true, nil, "https://github.com/"+evil+"/log4j"),
	}, nil, nil))
	deviceB := deviceIDByHW(t, tnB.tenantID, hwB)
	drainCVEQueue(t)
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, nil); err != nil {
		t.Fatal(err)
	}
	hp, sug, conflict, conflicts = readRow()
	if deref(sug) != good+":tool" || deref(hp) != "https://github.com/"+good+"/tool" || !conflict || conflicts != 1 {
		t.Fatalf("contested report: homepage=%s suggestion=%s conflict=%v/%d, want first-seen kept and flagged",
			deref(hp), deref(sug), conflict, conflicts)
	}

	// Nightly path: still no mapping, no finding, and the private formula is
	// never queued.
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, []cvematch.CVEEntry{goodEntry, evilEntry}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{deviceA, deviceB} {
		for k := range brewDeviceFindings(t, d) {
			t.Fatalf("nightly: a suggestion produced a finding on %s: %s", d, k)
		}
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1`, formula); n != 0 {
		t.Fatalf("nightly: a suggestion became %d app_cpe_mappings rows", n)
	}
	if n := countRows(t, `SELECT count(*) FROM homebrew_cpe_review_queue WHERE name = $1`, private); n != 0 {
		t.Fatalf("a formula with no recorded tap entered the global review queue")
	}
}

// TestHomebrewCVEMatchOpenssl11LetterRelease (PAT-2044): a Mac with the
// openssl@1.1 formula at 1.1.1s gets CVE-2023-0215, whose NVD range for the
// 1.1.1 branch ends before 1.1.1t, as a confirmed, high-confidence finding
// with fixed version 1.1.1t, through the seeded curated mapping (0170).
// Before PAT-2044 the comparator read 1.1.1s as 1.1.1t and the Homebrew
// path could only report it as low and unverified. Upgrading the formula to
// 1.1.1t, the fixed release, clears it.
func TestHomebrewCVEMatchOpenssl11LetterRelease(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2044-ossl11-"+sfx)

	// CVE-2023-0215 as NVD files it: one range per affected branch.
	ranges := []cvematch.CPERange{
		{Vendor: "openssl", Product: "openssl", VStartIncl: "1.0.2", VEndExcl: "1.0.2zg"},
		{Vendor: "openssl", Product: "openssl", VStartIncl: "1.1.1", VEndExcl: "1.1.1t"},
		{Vendor: "openssl", Product: "openssl", VStartIncl: "3.0.0", VEndExcl: "3.0.8"},
	}
	rangesJSON, _ := json.Marshal(ranges)
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity, cpe_patterns, cpe_ranges)
		VALUES ('CVE-2023-0215', 'PAT-2044 integration test', 'nvd', 7.5, 'HIGH', $1, $2)
		ON CONFLICT (cve_id) DO UPDATE SET cvss_v3_score = EXCLUDED.cvss_v3_score, severity = EXCLUDED.severity,
			cpe_patterns = EXCLUDED.cpe_patterns, cpe_ranges = EXCLUDED.cpe_ranges
	`, []string{"openssl:openssl"}, string(rangesJSON)); err != nil {
		t.Fatalf("seed CVE-2023-0215: %v", err)
	}
	score := 7.5
	feed := []cvematch.CVEEntry{{CVEID: "CVE-2023-0215", Score: &score, Severity: "HIGH",
		Patterns: []string{"openssl:openssl"}, Ranges: ranges}}

	hw := sfx + "-2044-4000-8000-00000000000b"
	vulnerable := []any{brewFormula("openssl@1.1", "1.1.1s", true, nil, "https://openssl-library.org")}
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", vulnerable, nil, nil))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)

	const key = "CVE-2023-0215|openssl@1.1 (Homebrew formula)"
	check := func(stage string) {
		t.Helper()
		got := brewDeviceFindings(t, deviceID)
		f, ok := got[key]
		if !ok {
			t.Fatalf("%s: no CVE-2023-0215 on openssl@1.1 1.1.1s; findings %+v", stage, got)
		}
		if f.Confidence != "version_confirmed" || deref(f.Tier) != "high" || f.Fixed != "1.1.1t" ||
			f.Version != "1.1.1s" || deref(f.Basis) != "curated" || deref(f.Source) != "homebrew_formula" {
			t.Fatalf("%s: finding %+v tier=%s basis=%s, want version_confirmed / high / fixed 1.1.1t",
				stage, f, deref(f.Tier), deref(f.Basis))
		}
	}
	check("ingest path")

	if _, err := env.pool.Exec(ctx, `DELETE FROM device_cve_findings WHERE device_id = $1::uuid`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, feed); err != nil {
		t.Fatalf("MatchHomebrewFull: %v", err)
	}
	check("nightly path")

	// 1.1.1t is the fixed release: a complete report with it clears the finding.
	fixed := []any{brewFormula("openssl@1.1", "1.1.1t", true, nil, "https://openssl-library.org")}
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", fixed, nil, nil))
	drainCVEQueue(t)
	if f, ok := brewDeviceFindings(t, deviceID)[key]; ok {
		t.Fatalf("openssl@1.1 1.1.1t is fixed but still has %+v", f)
	}
}
