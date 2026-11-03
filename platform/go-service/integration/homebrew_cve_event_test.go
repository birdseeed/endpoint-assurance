//go:build integration

package integration

// PAT-2045: Homebrew formulae and casks on the two PAT-2024 event paths that
// used to cover applications only (mapping publish and feed delta), and the
// ingest path no longer routing unmapped packages through cve_match_queue.
// None of these tests runs the nightly full match to get findings; the
// capacity test runs it only to show the review rows it now owns.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
)

func seedHomebrewMapping(t *testing.T, sourceType, name, vendor, product string) int64 {
	t.Helper()
	var id int64
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, $2, $3, 'PAT-2045 integration test', $4, 'curated') RETURNING id
	`, name, vendor, product, sourceType).Scan(&id); err != nil {
		t.Fatalf("seed homebrew mapping %s: %v", name, err)
	}
	return id
}

func brewFindingCount(t *testing.T, deviceID, cveID, app string) int {
	t.Helper()
	return countRows(t, `
		SELECT count(*) FROM device_cve_findings
		WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = $3 AND package_source IS NOT NULL
	`, deviceID, cveID, app)
}

func latestCVELifecycleEvent(t *testing.T, tenantID, cveID string) string {
	t.Helper()
	var ev string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT event_type FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2
		ORDER BY id DESC LIMIT 1
	`, tenantID, cveID).Scan(&ev); err != nil {
		t.Fatalf("latest lifecycle event for %s: %v", cveID, err)
	}
	return ev
}

// Publishing a Homebrew mapping for a formula a device already reports
// produces findings after a drain, with no full match and no new payload.
// The mapping's name differs in case from the formula: Homebrew mappings
// match case-insensitively on every path.
func TestHomebrewCVEEventMappingPublishMatchesExistingInstalls(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2045-publish-"+sfx)
	formula := "pat2045pub-" + sfx
	vendor := "pat2045p" + sfx
	cveID := "CVE-2099-" + sfx + "P"
	seedFeedEntry(t, cveID, vendor, "tool", "2.0", false)

	hw := sfx + "-2045-4000-8000-00000000000a"
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete",
		[]any{brewFormula(formula, "1.5.0", true, nil, nil)}, nil, nil))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)
	display := cvematch.HomebrewDisplayName("formula", formula)
	if n := brewFindingCount(t, deviceID, cveID, display); n != 0 {
		t.Fatalf("unmapped formula has %d findings", n)
	}
	rawPayloads := countRows(t, `SELECT count(*) FROM raw_payloads WHERE device_id = $1::uuid`, deviceID)
	fullRuns := countRows(t, `SELECT count(*) FROM cve_match_runs WHERE run_kind = 'full_match'`)

	seedHomebrewMapping(t, cvematch.HomebrewFormulaSource, strings.ToUpper(formula), vendor, "tool")
	res := drainCVEQueue(t)
	if n := brewFindingCount(t, deviceID, cveID, display); n != 1 {
		t.Fatalf("homebrew mapping publish produced %d findings on %s, want 1", n, display)
	}
	if res.Expanded < 1 {
		t.Fatalf("homebrew mapping publish expanded %d observations, want >= 1", res.Expanded)
	}
	got := brewDeviceFindings(t, deviceID)[cveID+"|"+display]
	if deref(got.Source) != cvematch.HomebrewFormulaSource || deref(got.Tier) != "high" ||
		got.Confidence != "version_confirmed" || got.Version != "1.5.0" {
		t.Fatalf("published finding = %+v tier=%s", got, deref(got.Tier))
	}
	if n := countRows(t, `SELECT count(*) FROM raw_payloads WHERE device_id = $1::uuid`, deviceID); n != rawPayloads {
		t.Fatal("test invalid: a payload was ingested")
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_runs WHERE run_kind = 'full_match'`); n != fullRuns {
		t.Fatal("test invalid: a full match ran")
	}
	// The mapping job went through the Homebrew matcher, not the application
	// word-token matcher: no application observation or assessment exists
	// for the formula name.
	if n := countRows(t, `SELECT count(*) FROM cve_match_assessments WHERE device_id = $1::uuid`, deviceID); n != 0 {
		t.Fatalf("homebrew publish wrote %d application assessments", n)
	}
}

// Removing a Homebrew mapping prunes the findings it produced on every
// device that reports the formula, as the application path does for a
// withdrawn mapping. The formula is still installed at the same version, so
// nothing on the device fixed anything: the lifecycle records withdrawn (a
// matcher correction), never verified_fixed, whether or not a later report
// carries Homebrew authority (PAT-2107). Before PAT-2107 this test asserted
// that the later authoritative report verified the fix, which is exactly the
// false closure withdrawn exists to prevent.
func TestHomebrewCVEEventMappingRemovalWithdrawsRatherThanFixes(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	formula := "pat2045rm-" + sfx
	vendor := "pat2045r" + sfx
	cveID := "CVE-2099-" + sfx + "R"
	seedFeedEntry(t, cveID, vendor, "tool", "2.0", false)
	mappingID := seedHomebrewMapping(t, cvematch.HomebrewFormulaSource, formula, vendor, "tool")
	drainCVEQueue(t) // absorb the publish; no device has the formula yet
	formulae := []any{brewFormula(formula, "1.5.0", true, nil, nil)}
	display := cvematch.HomebrewDisplayName("formula", formula)

	tnA := newCVETestTenant(t, "pat2045-rm-a-"+sfx)
	hwA := sfx + "-2045-4000-8000-0000000000a1"
	postInventoryAs(t, tnA.bearer, tnA.hmacSecret, brewCVEPayload(t, tnA, hwA, "complete", formulae, nil, nil))
	deviceA := deviceIDByHW(t, tnA.tenantID, hwA)
	tnB := newCVETestTenant(t, "pat2045-rm-b-"+sfx)
	hwB := sfx + "-2045-4000-8000-0000000000b1"
	postInventoryAs(t, tnB.bearer, tnB.hmacSecret, brewCVEPayload(t, tnB, hwB, "complete", formulae, nil, nil))
	deviceB := deviceIDByHW(t, tnB.tenantID, hwB)
	drainCVEQueue(t)
	for _, d := range []string{deviceA, deviceB} {
		if n := brewFindingCount(t, d, cveID, display); n != 1 {
			t.Fatalf("device %s has %d findings before removal, want 1", d, n)
		}
	}
	for _, tn := range []cveTestTenant{tnA, tnB} {
		if ev := latestCVELifecycleEvent(t, tn.tenantID, cveID); ev != "first_observed" {
			t.Fatalf("before removal: lifecycle %s, want first_observed", ev)
		}
	}

	if _, err := env.pool.Exec(ctx, `DELETE FROM app_cpe_mappings WHERE id = $1`, mappingID); err != nil {
		t.Fatal(err)
	}
	res := drainCVEQueue(t)
	if res.Expanded < 2 {
		t.Fatalf("mapping removal expanded %d observations, want both devices", res.Expanded)
	}
	for _, d := range []string{deviceA, deviceB} {
		if n := brewFindingCount(t, d, cveID, display); n != 0 {
			t.Fatalf("withdrawn homebrew mapping left %d findings on %s", n, d)
		}
	}
	// The prune reached the lifecycle reducer. The formula is unchanged on
	// both devices, so the CVE is withdrawn, not fixed.
	for _, tn := range []cveTestTenant{tnA, tnB} {
		if ev := latestCVELifecycleEvent(t, tn.tenantID, cveID); ev != "withdrawn" {
			t.Fatalf("mapping removal with the formula unchanged: lifecycle %s, want withdrawn", ev)
		}
	}

	// A reports again with a complete Homebrew block (authority); B's newest
	// report is partial (the formula stays current, no Homebrew authority).
	// collected_at must be strictly newer than the evidence already held.
	later := func(body []byte) []byte {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		m["collected_at"] = time.Now().UTC().Add(2 * time.Second).Format(time.RFC3339)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	postInventoryAs(t, tnA.bearer, tnA.hmacSecret, later(brewCVEPayload(t, tnA, hwA, "complete", formulae, nil, nil)))
	postInventoryAs(t, tnB.bearer, tnB.hmacSecret, later(brewCVEPayload(t, tnB, hwB, "partial", formulae, nil, nil)))
	drainCVEQueue(t)
	cvelifecycleReconcile(t, tnA.tenantID, cveID)
	cvelifecycleReconcile(t, tnB.tenantID, cveID)
	// Neither a fresh complete report (A) nor a partial one (B) turns the
	// withdrawal into a fix, and reconciling again adds nothing.
	for _, tn := range []cveTestTenant{tnA, tnB} {
		if ev := latestCVELifecycleEvent(t, tn.tenantID, cveID); ev != "withdrawn" {
			t.Fatalf("after a later report: lifecycle %s, want withdrawn", ev)
		}
		counts := map[string]int{}
		rows, err := env.pool.Query(ctx, `
			SELECT event_type, count(*) FROM finding_lifecycle_events
			WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2
			GROUP BY event_type`, tn.tenantID, cveID)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var ev string
			var n int
			if err := rows.Scan(&ev, &n); err != nil {
				t.Fatal(err)
			}
			counts[ev] = n
		}
		rows.Close()
		if counts["withdrawn"] != 1 || counts["verified_fixed"] != 0 {
			t.Fatalf("lifecycle events %v, want exactly one withdrawn and no verified_fixed", counts)
		}
	}
}

// A feed delta on openssl:openssl re-matches a device with openssl@3 through
// the curated openssl@3 mapping seeded by 0168, with no full match.
func TestHomebrewCVEEventFeedDeltaRematchesOpenssl(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2045-feed-"+sfx)
	hw := sfx + "-2045-4000-8000-00000000000f"
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", []any{
		brewFormula("openssl@3", "3.0.7", true, nil, "https://openssl-library.org"),
		brewFormula("pat2045other-"+sfx, "1.0.0", true, nil, nil),
	}, nil, nil))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)
	if _, err := env.pool.Exec(ctx, `DELETE FROM cve_feed_delta`); err != nil {
		t.Fatal(err)
	}

	cveID := "CVE-2099-" + sfx + "O"
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM device_cve_findings WHERE cve_id = $1`, cveID)
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM cve_feed_entries WHERE cve_id = $1`, cveID)
	})
	seedFeedEntry(t, cveID, "openssl", "openssl", "3.0.99", true)
	if n := countRows(t, `SELECT count(*) FROM cve_feed_delta WHERE cpe_key = 'openssl:openssl'`); n != 1 {
		t.Fatalf("feed delta recorded %d openssl:openssl keys, want 1", n)
	}
	display := cvematch.HomebrewDisplayName("formula", "openssl@3")
	if n := brewFindingCount(t, deviceID, cveID, display); n != 0 {
		t.Fatal("test invalid: finding present before the feed delta ran")
	}

	res, err := cvepipeline.MatchFeedDelta(ctx, env.pool, nil)
	if err != nil {
		t.Fatalf("MatchFeedDelta: %v", err)
	}
	if n := brewFindingCount(t, deviceID, cveID, display); n != 1 {
		t.Fatalf("feed delta on openssl:openssl left %d findings on openssl@3, want 1", n)
	}
	if res.Mappings < 1 || res.Observations < 1 {
		t.Fatalf("feed delta scope = %d mappings / %d observations, want the openssl@3 mapping and install", res.Mappings, res.Observations)
	}
	got := brewDeviceFindings(t, deviceID)[cveID+"|"+display]
	if deref(got.PkgName) != "openssl@3" || deref(got.Tier) != "high" || got.Fixed != "3.0.99" {
		t.Fatalf("feed delta finding = %+v tier=%s", got, deref(got.Tier))
	}
	if n := countRows(t, `SELECT count(*) FROM cve_feed_delta`); n != 0 {
		t.Fatalf("covered delta keys not cleared: %d left", n)
	}
}

// A Mac's first report of 200 unmapped homebrew/core formulae adds no
// cve_match_queue rows (only its one mapped formula is queued), the drain
// writes no review rows, and the nightly run records all 200 for review.
func TestHomebrewCVEEventFirstReportDoesNotFloodMatchQueue(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2045-cap-"+sfx)
	prefix := "pat2045cap-" + sfx + "-"
	formulae := []any{brewFormula("openssl@3", "3.0.7", true, nil, "https://openssl-library.org")}
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("%s%03d", prefix, i)
		formulae = append(formulae, brewFormula(name, "1.0.0", true, nil, "https://example.com/pat2045/"+name))
	}
	hw := sfx + "-2045-4000-8000-00000000000c"
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete", formulae, nil, nil))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)

	var queued []string
	rows, err := env.pool.Query(ctx, `SELECT app_name FROM cve_match_queue WHERE device_id = $1::uuid ORDER BY app_name`, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		queued = append(queued, n)
	}
	rows.Close()
	if want := cvematch.HomebrewDisplayName("formula", "openssl@3"); len(queued) != 1 || queued[0] != want {
		t.Fatalf("first report queued %d observations %v, want only %q", len(queued), queued, want)
	}

	reviewRows := func() int {
		return countRows(t, `SELECT count(*) FROM homebrew_cpe_review_queue WHERE package_kind = 'formula' AND name LIKE $1`, prefix+"%")
	}
	drainCVEQueue(t)
	if n := reviewRows(); n != 0 {
		t.Fatalf("the drain wrote %d review rows; review recording belongs to the nightly run", n)
	}
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, nil); err != nil {
		t.Fatalf("MatchHomebrewFull: %v", err)
	}
	if n := reviewRows(); n != 200 {
		t.Fatalf("nightly recorded %d review rows, want 200", n)
	}
	if n := countRows(t, `
		SELECT count(*) FROM homebrew_cpe_review_queue
		WHERE name LIKE $1 AND status = 'pending' AND homepage = 'https://example.com/pat2045/' || name
		  AND NOT metadata_conflict
	`, prefix+"%"); n != 200 {
		t.Fatalf("%d of 200 review rows pending with their first-seen homepage", n)
	}
}

// PAT-2045: the nightly batch sees every device at once, so two reports that
// disagree about a new formula's metadata in the same run are flagged as
// contested rather than one silently winning.
func TestHomebrewCVEEventNightlyBatchFlagsDisagreement(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	formula := "pat2045dup-" + sfx
	for i, hp := range []string{"https://one.example/" + formula, "https://two.example/" + formula} {
		tn := newCVETestTenant(t, fmt.Sprintf("pat2045-dup-%d-%s", i, sfx))
		hw := fmt.Sprintf("%s-2045-4000-8000-0000000000d%d", sfx, i)
		postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete",
			[]any{brewFormula(formula, "1.0.0", true, nil, hp)}, nil, nil))
	}
	drainCVEQueue(t)
	if _, err := cvepipeline.MatchHomebrewFull(ctx, env.pool, nil); err != nil {
		t.Fatalf("MatchHomebrewFull: %v", err)
	}
	var conflict bool
	var conflicts int
	var homepage string
	if err := env.pool.QueryRow(ctx, `
		SELECT metadata_conflict, metadata_conflict_count, homepage
		FROM homebrew_cpe_review_queue WHERE package_kind = 'formula' AND name = $1
	`, formula).Scan(&conflict, &conflicts, &homepage); err != nil {
		t.Fatalf("review row for %s: %v", formula, err)
	}
	if !conflict || conflicts != 1 || !strings.HasSuffix(homepage, "/"+formula) {
		t.Fatalf("in-batch disagreement: conflict=%v/%d homepage=%s, want flagged once", conflict, conflicts, homepage)
	}
}
