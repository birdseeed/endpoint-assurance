//go:build integration

package integration

// PAT-2024: event-driven CVE matching. Every test here reaches findings
// without running the nightly patched-cve-sync match: the ingest delta goes
// through the extractor and cvepipeline.Drain, the feed delta through
// cvepipeline.MatchFeedDelta, and a mapping publish through the snapshot diff
// inside Drain. Product names, CPE keys and CVE IDs carry a per-test random
// suffix so the shared integration database cannot cross-contaminate counts.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
	"patched.im/api/internal/extractor"
	"patched.im/api/internal/handlers"

	"github.com/go-chi/chi/v5"
)

type cveTestTenant struct {
	tenantID, bearer, email, token string
	hmacSecret                     []byte
}

func newCVETestTenant(t *testing.T, name string) cveTestTenant {
	t.Helper()
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatalf("create tenant %s: %v", name, err)
	}
	email := strings.ToLower(name) + "@pat2024.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	return cveTestTenant{tenantID: tenantID, bearer: bearer, email: email,
		token: env.idp.token(t, email), hmacSecret: secret}
}

type cveTestApp struct{ name, version, bundle string }

// postAppsPayload posts full.json with its device identity and app list
// replaced, then runs the extractor exactly as production does.
func postAppsPayload(t *testing.T, tn cveTestTenant, hwUUID string, apps []cveTestApp) {
	t.Helper()
	postAppsPayloadAt(t, tn, hwUUID, apps, time.Now())
}

// postAppsPayloadAt is postAppsPayload with an explicit collected_at, for
// tests that need two reports ordered by collection time without sleeping
// across collected_at's one-second resolution.
func postAppsPayloadAt(t *testing.T, tn cveTestTenant, hwUUID string, apps []cveTestApp, collectedAt time.Time) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "full.json"), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tn.tenantID
	p["collected_at"] = collectedAt.UTC().Format(time.RFC3339)
	device := p["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2024" + strings.ToUpper(hwUUID[:8])
	device["hostname"] = "pat2024-" + strings.ToLower(hwUUID[:8])
	list := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		list = append(list, map[string]any{
			"name": a.name, "version": a.version, "bundle_id": a.bundle,
			"path": "/Applications/" + a.name + ".app",
		})
	}
	p["apps"] = list
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, tn.hmacSecret)
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tn.bearer)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", randomHex(16))
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: %d %s", resp.StatusCode, raw)
	}
	var ingest struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingest); err != nil {
		t.Fatal(err)
	}
	if err := extractor.ProcessOnce(context.Background(), env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, ingest.RawPayloadID)
}

func seedCVEMapping(t *testing.T, matchName, vendor, product string) int64 {
	t.Helper()
	var id int64
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes)
		VALUES ('any', $1, $2, $3, 'PAT-2024 integration test') RETURNING id
	`, matchName, vendor, product).Scan(&id); err != nil {
		t.Fatalf("seed mapping %s: %v", matchName, err)
	}
	return id
}

// seedFeedEntry writes one CVE the way a sync page does and records its feed
// delta through the same functions patched-cve-sync's upsertCVEs uses.
func seedFeedEntry(t *testing.T, cveID, vendor, product, vEndExcl string, recordDelta bool) {
	t.Helper()
	ctx := context.Background()
	key := strings.ToLower(vendor + ":" + product)
	ranges := []cvematch.CPERange{{Vendor: vendor, Product: product, VEndExcl: vEndExcl}}
	rangesJSON, _ := json.Marshal(ranges)
	score := 9.8
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	prior, err := cvepipeline.LoadFeedMatchStates(ctx, tx, []string{cveID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity, cpe_patterns, cpe_ranges)
		VALUES ($1, 'PAT-2024 integration test vulnerability', 'nvd', $2, 'CRITICAL', $3, $4)
	`, cveID, score, []string{key}, string(rangesJSON)); err != nil {
		t.Fatalf("seed feed entry %s: %v", cveID, err)
	}
	if recordDelta {
		next := map[string]cvepipeline.FeedMatchState{cveID: {Patterns: []string{key}, Ranges: ranges, Score: &score, Severity: "CRITICAL"}}
		if err := cvepipeline.RecordFeedDelta(ctx, tx, cvepipeline.FeedDeltaKeys(prior, next)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func drainCVEQueue(t *testing.T) cvepipeline.DrainResult {
	t.Helper()
	var total cvepipeline.DrainResult
	for i := 0; i < 20; i++ {
		res, err := cvepipeline.Drain(context.Background(), env.pool, nil, 1000)
		if err != nil {
			t.Fatalf("Drain: %v", err)
		}
		total.Observations += res.Observations
		total.NewFindings += res.NewFindings
		total.Expanded += res.Expanded
		var left int
		if err := env.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM cve_match_queue WHERE attempts < $1`, cvepipeline.MaxAttempts).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left == 0 && res.Observations == 0 && res.Expanded == 0 && res.MappingJobs == 0 {
			return total
		}
	}
	t.Fatal("cve match queue did not drain")
	return total
}

func deviceIDByHW(t *testing.T, tenantID, hwUUID string) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2`, tenantID, hwUUID).Scan(&id); err != nil {
		t.Fatalf("device lookup: %v", err)
	}
	return id
}

func seedCVEDevice(t *testing.T, tenantID, host string, apps []cveTestApp) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $2, 'macOS', '15.5', 'arm64', now())
		RETURNING id::text
	`, tenantID, host).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", host, err)
	}
	for _, a := range apps {
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version) VALUES ($1::uuid, $2, $3, $4)
		`, id, a.name, a.bundle, a.version); err != nil {
			t.Fatalf("seed app %s: %v", a.name, err)
		}
	}
	return id
}

type portalCVEAssessment struct {
	State               string           `json:"state"`
	LastMatchedAt       *time.Time       `json:"last_matched_at"`
	FindingCount        *int             `json:"finding_count"`
	AssessedProducts    int              `json:"assessed_products"`
	PendingProducts     int              `json:"pending_products"`
	NotAssessedProducts int              `json:"not_assessed_products"`
	Products            []map[string]any `json:"products"`
}

func portalDeviceAssessment(t *testing.T, tn cveTestTenant, deviceID string) (portalCVEAssessment, string) {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+deviceID, tn.token, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device detail: %d %s", resp.StatusCode, raw)
	}
	var out struct {
		CVEAssessment portalCVEAssessment `json:"cve_assessment"`
		AppsWithFind  []map[string]any    `json:"apps_with_findings"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.CVEAssessment, string(raw)
}

func productState(t *testing.T, a portalCVEAssessment, app string) (state string, count any, present bool) {
	t.Helper()
	for _, p := range a.Products {
		if p["app"] == app {
			c, has := p["finding_count"]
			if !has {
				t.Fatalf("product %s has no finding_count key at all", app)
			}
			return p["state"].(string), c, true
		}
	}
	return "", nil, false
}

func tenantAssessment(t *testing.T, tn cveTestTenant) map[string]any {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/findings", tn.token, nil)
	var out struct {
		CVEAssessment map[string]any `json:"cve_assessment"`
	}
	decodeJSON(t, resp, &out)
	return out.CVEAssessment
}

func countRows(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}

// A newly reported vulnerable product gets findings through the queue with no
// nightly run; an unmapped product beside it reads not_assessed, never zero;
// re-matching is idempotent; an upgrade to the fixed version clears the
// finding and leaves an honest "assessed, 0".
func TestCVEEventMatchIngestDeltaProducesFindingsWithoutNightlyRun(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-ingest-"+sfx)
	vendor, product := "pat2024v"+sfx, "vulnwidget"
	vulnApp := "Pat2024 Vulnwidget " + sfx
	unmappedApp := "Pat2024 Inhouse " + sfx
	cveID := "CVE-2099-" + sfx + "1"

	seedFeedEntry(t, cveID, vendor, product, "2.0", false)
	seedCVEMapping(t, vulnApp, vendor, product)
	drainCVEQueue(t) // absorb the mapping publish; no observation of it exists yet

	hw := strings.ToUpper(sfx + "-1111-2222-3333-444455556666")
	postAppsPayload(t, tn, hw, []cveTestApp{
		{vulnApp, "1.5", "com.example.pat2024.vuln." + sfx},
		{unmappedApp, "3.1", "com.example.pat2024.inhouse." + sfx},
	})
	deviceID := deviceIDByHW(t, tn.tenantID, hw)

	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid`, deviceID); n != 0 {
		t.Fatalf("findings before any match = %d, want 0", n)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = $2 AND reason = 'ingest'`, deviceID, vulnApp); n != 1 {
		t.Fatalf("ingest delta queued %d rows for the vulnerable product, want 1", n)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = $2`, deviceID, unmappedApp); n != 0 {
		t.Fatalf("unmapped product was queued (%d rows); only mapped products should be", n)
	}

	before, _ := portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, before, vulnApp); st != cvepipeline.StatePending || c != nil {
		t.Fatalf("queued product = %s/%v, want pending/null", st, c)
	}
	if before.State != cvepipeline.StatePending || before.FindingCount != nil {
		t.Fatalf("device before drain = %+v, want pending with null count", before)
	}

	if tenant := tenantAssessment(t, tn); tenant["pending_products"] != float64(1) || tenant["not_assessed_products"] != float64(1) || tenant["assessed_products"] != float64(0) {
		t.Fatalf("tenant aggregate before drain = %v, want pending 1 / not_assessed 1 / assessed 0", tenant)
	}

	res := drainCVEQueue(t)
	if tenant := tenantAssessment(t, tn); tenant["pending_products"] != float64(0) || tenant["not_assessed_products"] != float64(1) || tenant["assessed_products"] != float64(1) {
		t.Fatalf("tenant aggregate after drain = %v, want pending 0 / not_assessed 1 / assessed 1", tenant)
	}
	if res.NewFindings < 1 {
		t.Fatalf("drain reported %d new findings, want >= 1", res.NewFindings)
	}
	var confidence, fixed string
	var firstSeen time.Time
	if err := env.pool.QueryRow(ctx, `
		SELECT match_confidence, fixed_version, first_seen_at FROM device_cve_findings
		WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = $3
	`, deviceID, cveID, vulnApp).Scan(&confidence, &fixed, &firstSeen); err != nil {
		t.Fatalf("queue path produced no finding: %v", err)
	}
	if confidence != "version_confirmed" || fixed != "2.0" {
		t.Fatalf("finding = %s/%s, want version_confirmed/2.0", confidence, fixed)
	}
	lifecycleEvents := countRows(t, `SELECT count(*) FROM finding_lifecycle_events WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2`, tn.tenantID, cveID)
	if lifecycleEvents < 1 {
		t.Fatal("queue match did not reach the lifecycle reducer: no lifecycle event for the new CVE")
	}

	after, raw := portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, after, vulnApp); st != cvepipeline.StateAssessed || c != float64(1) {
		t.Fatalf("vulnerable product = %s/%v, want assessed/1; body %s", st, c, raw)
	}
	if st, c, present := productState(t, after, unmappedApp); !present || st != cvepipeline.StateNotAssessed || c != nil {
		t.Fatalf("unmapped product = %s/%v (present=%v), want not_assessed/null; body %s", st, c, present, raw)
	}
	if after.State != cvepipeline.StateAssessed || after.FindingCount == nil || *after.FindingCount != 1 ||
		after.NotAssessedProducts != 1 || after.LastMatchedAt == nil {
		t.Fatalf("device after drain = %+v", after)
	}

	// Idempotent: the same observation re-matched changes nothing.
	if _, _, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.tenantID, deviceID, []string{vulnApp}, cvepipeline.SourceIngest); err != nil {
		t.Fatal(err)
	}
	again := drainCVEQueue(t)
	if again.NewFindings != 0 {
		t.Fatalf("re-match inserted %d new findings, want 0", again.NewFindings)
	}
	var firstSeenAgain time.Time
	if err := env.pool.QueryRow(ctx, `SELECT first_seen_at FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`,
		deviceID, cveID).Scan(&firstSeenAgain); err != nil || !firstSeenAgain.Equal(firstSeen) {
		t.Fatalf("re-match changed first_seen_at %v -> %v (err %v)", firstSeen, firstSeenAgain, err)
	}
	if n := countRows(t, `SELECT count(*) FROM finding_lifecycle_events WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2`, tn.tenantID, cveID); n != lifecycleEvents {
		t.Fatalf("re-match appended lifecycle events: %d -> %d", lifecycleEvents, n)
	}

	// Upgrade to the fixed version: the finding goes, the product stays
	// assessed with zero known CVEs.
	postAppsPayload(t, tn, hw, []cveTestApp{
		{vulnApp, "2.1", "com.example.pat2024.vuln." + sfx},
		{unmappedApp, "3.1", "com.example.pat2024.inhouse." + sfx},
	})
	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid`, deviceID); n != 0 {
		t.Fatalf("finding survived an upgrade to the fixed version: %d rows", n)
	}
	fixedState, raw := portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, fixedState, vulnApp); st != cvepipeline.StateAssessed || c != float64(0) {
		t.Fatalf("upgraded product = %s/%v, want assessed/0; body %s", st, c, raw)
	}
}

// A feed sync that adds one CVE re-matches only the observations whose
// mapping resolves to that CVE's CPE, asserted by count.
func TestCVEEventMatchFeedDeltaRematchesOnlyAffectedObservations(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-feed-"+sfx)
	affected := "Pat2024 Feedwidget " + sfx
	other := "Pat2024 Otherapp " + sfx
	vendor := "pat2024f" + sfx
	seedCVEMapping(t, affected, vendor, "feedwidget")
	seedCVEMapping(t, other, vendor, "otherapp")

	d1 := seedCVEDevice(t, tn.tenantID, "pat2024-feed-a-"+sfx, []cveTestApp{{affected, "1.0", "com.example.fw." + sfx}, {"Pat2024 Unmapped " + sfx, "1", "com.example.um1." + sfx}})
	d2 := seedCVEDevice(t, tn.tenantID, "pat2024-feed-b-"+sfx, []cveTestApp{{affected, "1.2", "com.example.fw." + sfx}})
	d3 := seedCVEDevice(t, tn.tenantID, "pat2024-feed-c-"+sfx, []cveTestApp{{other, "1.0", "com.example.oa." + sfx}})

	// Absorb the mapping publish: all three observations matched, no CVEs yet.
	drainCVEQueue(t)
	var otherMatchedAt time.Time
	if err := env.pool.QueryRow(ctx, `SELECT last_matched_at FROM cve_match_assessments WHERE device_id = $1::uuid AND app_name = $2`,
		d3, other).Scan(&otherMatchedAt); err != nil {
		t.Fatalf("mapping publish did not assess the unaffected observation: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `DELETE FROM cve_feed_delta`); err != nil {
		t.Fatal(err)
	}

	// The sync: exactly one new CVE, for feedwidget only.
	cveID := "CVE-2099-" + sfx + "2"
	seedFeedEntry(t, cveID, vendor, "feedwidget", "2.0", true)
	if n := countRows(t, `SELECT count(*) FROM cve_feed_delta`); n != 1 {
		t.Fatalf("feed delta recorded %d keys, want 1", n)
	}

	res, err := cvepipeline.MatchFeedDelta(ctx, env.pool, nil)
	if err != nil {
		t.Fatalf("MatchFeedDelta: %v", err)
	}
	if res.Keys != 1 || res.Mappings != 1 {
		t.Fatalf("delta scope = %d keys / %d mappings, want 1/1", res.Keys, res.Mappings)
	}
	if res.Observations != 2 {
		t.Fatalf("feed delta re-matched %d observations, want exactly 2 (the two feedwidget installs)", res.Observations)
	}
	for _, d := range []string{d1, d2} {
		if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, d, cveID); n != 1 {
			t.Fatalf("affected device %s has %d findings for %s, want 1", d, n, cveID)
		}
	}
	var otherAfter time.Time
	if err := env.pool.QueryRow(ctx, `SELECT last_matched_at FROM cve_match_assessments WHERE device_id = $1::uuid AND app_name = $2`,
		d3, other).Scan(&otherAfter); err != nil || !otherAfter.Equal(otherMatchedAt) {
		t.Fatalf("unaffected observation was re-matched: %v -> %v (err %v)", otherMatchedAt, otherAfter, err)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_feed_delta`); n != 0 {
		t.Fatalf("covered delta keys not cleared: %d left", n)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_runs WHERE run_kind = 'delta_match'`); n != 1 {
		t.Fatal("delta match run not recorded")
	}
}

// Publishing a mapping produces findings for existing observations without
// the device reporting again; withdrawing it returns the product to
// not_assessed with a null count.
func TestCVEEventMatchMappingPublishMatchesExistingObservations(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-publish-"+sfx)
	app := "Pat2024 Laterapp " + sfx
	vendor := "pat2024p" + sfx
	cveID := "CVE-2099-" + sfx + "3"
	seedFeedEntry(t, cveID, vendor, "laterapp", "5.0", false)
	deviceID := seedCVEDevice(t, tn.tenantID, "pat2024-publish-"+sfx, []cveTestApp{{app, "4.0", "com.example.la." + sfx}})
	drainCVEQueue(t)

	a, raw := portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, a, app); st != cvepipeline.StateNotAssessed || c != nil {
		t.Fatalf("unmapped product = %s/%v, want not_assessed/null; body %s", st, c, raw)
	}
	if a.State != cvepipeline.StateNotAssessed || a.FindingCount != nil {
		t.Fatalf("device with only unmapped software = %+v, want not_assessed with null count", a)
	}
	if !strings.Contains(raw, `"finding_count":null`) {
		t.Fatalf("not_assessed must serialise finding_count as null: %s", raw)
	}
	rawPayloads := countRows(t, `SELECT count(*) FROM raw_payloads WHERE device_id = $1::uuid`, deviceID)

	mappingID := seedCVEMapping(t, app, vendor, "laterapp")
	res := drainCVEQueue(t)
	if res.Expanded < 1 {
		t.Fatalf("mapping publish expanded %d observations, want >= 1", res.Expanded)
	}
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, deviceID, cveID); n != 1 {
		t.Fatalf("mapping publish produced %d findings, want 1", n)
	}
	if n := countRows(t, `SELECT count(*) FROM raw_payloads WHERE device_id = $1::uuid`, deviceID); n != rawPayloads {
		t.Fatal("test invalid: a payload was ingested")
	}
	a, raw = portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, a, app); st != cvepipeline.StateAssessed || c != float64(1) {
		t.Fatalf("published product = %s/%v, want assessed/1; body %s", st, c, raw)
	}

	if _, err := env.pool.Exec(ctx, `DELETE FROM app_cpe_mappings WHERE id = $1`, mappingID); err != nil {
		t.Fatal(err)
	}
	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid`, deviceID); n != 0 {
		t.Fatalf("withdrawn mapping left %d findings", n)
	}
	a, raw = portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, a, app); st != cvepipeline.StateNotAssessed || c != nil {
		t.Fatalf("withdrawn mapping product = %s/%v, want not_assessed/null; body %s", st, c, raw)
	}

	// Tenant level: freshness fields present, coverage counted.
	resp := portalDo(t, http.MethodGet, "/v1/portal/findings", tn.token, nil)
	var findings struct {
		CVEAssessment map[string]any `json:"cve_assessment"`
	}
	decodeJSON(t, resp, &findings)
	for _, k := range []string{"last_feed_sync_at", "last_full_match_at", "queued_observations", "assessed_products", "pending_products", "not_assessed_products"} {
		if _, ok := findings.CVEAssessment[k]; !ok {
			t.Fatalf("tenant cve_assessment missing %q: %v", k, findings.CVEAssessment)
		}
	}
	if findings.CVEAssessment["not_assessed_products"] != float64(1) {
		t.Fatalf("tenant not_assessed_products = %v, want 1", findings.CVEAssessment["not_assessed_products"])
	}
}

// Closed and accepted findings keep their lifecycle state through repeated
// re-matching: re-matching never reopens them.
func TestCVEEventMatchLifecycleStatesSurviveRematch(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-lifecycle-"+sfx)
	vendor := "pat2024l" + sfx
	acceptedApp := "Pat2024 Acceptedapp " + sfx
	closedApp := "Pat2024 Closedapp " + sfx
	acceptedCVE := "CVE-2099-" + sfx + "4"
	closedCVE := "CVE-2099-" + sfx + "5"
	seedFeedEntry(t, acceptedCVE, vendor, "acceptedapp", "9.0", false)
	seedFeedEntry(t, closedCVE, vendor, "closedapp", "9.0", false)
	seedCVEMapping(t, acceptedApp, vendor, "acceptedapp")
	seedCVEMapping(t, closedApp, vendor, "closedapp")
	drainCVEQueue(t)

	hw := strings.ToUpper(sfx + "-2222-3333-4444-555566667777")
	apps := []cveTestApp{
		{acceptedApp, "1.0", "com.example.acc." + sfx},
		{closedApp, "1.0", "com.example.clo." + sfx},
	}
	postAppsPayload(t, tn, hw, apps)
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)
	for _, cve := range []string{acceptedCVE, closedCVE} {
		if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, deviceID, cve); n != 1 {
			t.Fatalf("setup: %s not matched", cve)
		}
	}

	// The shared test internal router predates PAT-1829's routes, so mount
	// the production disposition handler on its own router here.
	dispositionRouter := chi.NewRouter()
	dispositionRouter.Post("/admin/tenants/{tenantID}/finding-dispositions", handlers.FindingDispositionCreateHandler(env.pool))
	dispositionSrv := httptest.NewServer(dispositionRouter)
	defer dispositionSrv.Close()

	dispose := func(cve, status string) {
		body, _ := json.Marshal(map[string]string{"finding_kind": "cve", "cve_id": cve, "status": status,
			"recorded_by": "analyst@pat2024.example", "reason": "PAT-2024 lifecycle survival test"})
		resp, err := http.Post(fmt.Sprintf("%s/admin/tenants/%s/finding-dispositions", dispositionSrv.URL, tn.tenantID),
			"application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("record %s disposition: %d %s", status, resp.StatusCode, raw)
		}
	}
	dispose(acceptedCVE, "risk_accepted")
	dispose(closedCVE, "closed")

	status := func(cve string) string {
		var s string
		if err := env.pool.QueryRow(ctx, `
			SELECT status FROM finding_lifecycle_current
			WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2
		`, tn.tenantID, cve).Scan(&s); err != nil {
			t.Fatalf("lifecycle status %s: %v", cve, err)
		}
		return s
	}
	activeDisposition := func(cve string) string {
		var s string
		if err := env.pool.QueryRow(ctx, `
			SELECT status FROM finding_dispositions
			WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND cve_id = $2 AND superseded_at IS NULL
		`, tn.tenantID, cve).Scan(&s); err != nil {
			t.Fatalf("active disposition %s: %v", cve, err)
		}
		return s
	}
	acceptedBefore, closedDispositionBefore := status(acceptedCVE), activeDisposition(closedCVE)
	if acceptedBefore != "risk_accepted" {
		t.Fatalf("setup: accepted status = %s", acceptedBefore)
	}

	// Re-match both observations twice through the queue, plus once through
	// a feed delta for the same CPEs.
	for i := 0; i < 2; i++ {
		if _, _, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.tenantID, deviceID,
			[]string{acceptedApp, closedApp}, cvepipeline.SourceIngest); err != nil {
			t.Fatal(err)
		}
		drainCVEQueue(t)
	}
	if err := cvepipeline.RecordFeedDelta(ctx, env.pool, []string{vendor + ":acceptedapp", vendor + ":closedapp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cvepipeline.MatchFeedDelta(ctx, env.pool, nil); err != nil {
		t.Fatal(err)
	}

	if got := status(acceptedCVE); got != "risk_accepted" {
		t.Fatalf("risk-accepted finding changed state on re-match: %s", got)
	}
	if got := activeDisposition(acceptedCVE); got != "risk_accepted" {
		t.Fatalf("risk_accepted disposition changed on re-match: %s", got)
	}
	if got := activeDisposition(closedCVE); got != closedDispositionBefore {
		t.Fatalf("closed disposition changed on re-match: %s -> %s", closedDispositionBefore, got)
	}
	// A closed finding asks for verification. Re-matching the same evidence
	// may record that verification is still unknown, but must never reopen it.
	if got := status(closedCVE); got == "currently_observed" || got == "still_failing" || got == "recurred" || got == "first_observed" {
		t.Fatalf("closed finding reopened by re-match: status %s", got)
	}
	for _, cve := range []string{acceptedCVE, closedCVE} {
		if n := countRows(t, `
			SELECT count(*) FROM finding_lifecycle_events e
			WHERE e.tenant_id = $1::uuid AND e.finding_kind = 'cve' AND e.finding_key = $2
			  AND e.event_type IN ('currently_observed', 'still_failing', 'recurred')
			  AND e.id > (SELECT max(id) FROM finding_lifecycle_events a
			              WHERE a.tenant_id = e.tenant_id AND a.finding_kind = 'cve' AND a.finding_key = e.finding_key
			                AND a.source_type = 'operator_action')
		`, tn.tenantID, cve); n != 0 {
			t.Fatalf("%s: re-match appended %d reopening events after the operator decision", cve, n)
		}
	}
}

// Review round 1, P0: a feed load that fails for one device must not poison
// the batch. Two devices share a product with two current findings; one of
// the product's CVEs is then corrupted so its cpe_ranges cannot be decoded.
// Both devices must keep their findings and assessments and stay queued.
// Before the fix, the first device's failed load cached the key as empty and
// the second device was matched against nothing: findings pruned, assessed 0.
func TestCVEEventMatchFeedLoadFailureNeverPrunesOrAssessesZero(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-poison-"+sfx)
	vendor, product := "pat2024x"+sfx, "poisonapp"
	app := "Pat2024 Poisonapp " + sfx
	cveA, cveB := "CVE-2099-"+sfx+"6", "CVE-2099-"+sfx+"7"
	seedFeedEntry(t, cveA, vendor, product, "9.0", false)
	seedFeedEntry(t, cveB, vendor, product, "9.0", false)
	seedCVEMapping(t, app, vendor, product)
	d1 := seedCVEDevice(t, tn.tenantID, "pat2024-poison-a-"+sfx, []cveTestApp{{app, "1.0", "com.example.px." + sfx}})
	d2 := seedCVEDevice(t, tn.tenantID, "pat2024-poison-b-"+sfx, []cveTestApp{{app, "1.0", "com.example.px." + sfx}})
	drainCVEQueue(t) // mapping publish matches both devices
	for _, d := range []string{d1, d2} {
		if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid`, d); n != 2 {
			t.Fatalf("setup: device %s has %d findings, want 2", d, n)
		}
	}
	var matchedAt time.Time
	if err := env.pool.QueryRow(ctx, `SELECT last_matched_at FROM cve_match_assessments WHERE device_id = $1::uuid`, d2).Scan(&matchedAt); err != nil {
		t.Fatal(err)
	}

	// Corrupt one CVE: valid JSONB, but not a []CPERange.
	if _, err := env.pool.Exec(ctx, `UPDATE cve_feed_entries SET cpe_ranges = '[1]'::jsonb WHERE cve_id = $1`, cveB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM cve_match_queue WHERE tenant_id = $1::uuid`, tn.tenantID)
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM cve_feed_entries WHERE cve_id = $1`, cveB)
	})
	for _, d := range []string{d1, d2} {
		if _, _, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.tenantID, d, []string{app}, cvepipeline.SourceIngest); err != nil {
			t.Fatal(err)
		}
	}
	res, err := cvepipeline.Drain(ctx, env.pool, nil, 1000)
	if err == nil {
		t.Fatal("Drain must report the feed load failure")
	}
	if res.Failed != 2 || res.Observations != 0 {
		t.Fatalf("drain result = %+v, want both observations failed and none matched", res)
	}
	for _, d := range []string{d1, d2} {
		if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid`, d); n != 2 {
			t.Fatalf("device %s: findings pruned after a feed load failure (%d left, want 2)", d, n)
		}
		if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND attempts = 1 AND last_error LIKE '%cpe_ranges%'`, d); n != 1 {
			t.Fatalf("device %s: failed observation not kept queued with its error", d)
		}
	}
	var count int
	var after time.Time
	if err := env.pool.QueryRow(ctx, `SELECT finding_count, last_matched_at FROM cve_match_assessments WHERE device_id = $1::uuid`, d2).Scan(&count, &after); err != nil {
		t.Fatal(err)
	}
	if count != 2 || !after.Equal(matchedAt) {
		t.Fatalf("second device's assessment rewritten after a failed load: count %d at %v, want 2 at %v", count, after, matchedAt)
	}
	a, raw := portalDeviceAssessment(t, tn, d2)
	if st, c, _ := productState(t, a, app); st != cvepipeline.StatePending || c != nil {
		t.Fatalf("product with a failed re-match = %s/%v, want pending/null; body %s", st, c, raw)
	}
}

// Review round 1, P2: OS pseudo-apps belong to the vendor-advisory matcher.
// A queued "macOS" observation must not re-insert an NVD OS finding or touch
// a vendor-confirmed row, and no path may downgrade a vendor-confirmed row.
func TestCVEEventMatchNeverTouchesOSOrVendorConfirmedFindings(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-os-"+sfx)
	osCVE, vendorCVE, nvdOSCVE := "CVE-2099-"+sfx+"8", "CVE-2099-"+sfx+"9", "CVE-2099-"+sfx+"a"
	// apple:macos is covered by the seeded "macOS" mapping.
	seedFeedEntry(t, osCVE, "apple", "macos", "99.0", false)
	seedFeedEntry(t, nvdOSCVE, "apple", "macos", "99.0", false)
	vendor := "pat2024o" + sfx
	app := "Pat2024 Vendorapp " + sfx
	seedFeedEntry(t, vendorCVE, vendor, "vendorapp", "9.0", false)
	seedCVEMapping(t, app, vendor, "vendorapp")
	drainCVEQueue(t)
	d := seedCVEDevice(t, tn.tenantID, "pat2024-os-"+sfx, []cveTestApp{{"macOS", "15.5", "com.apple.macos." + sfx}, {app, "1.0", "com.example.va." + sfx}})
	for _, f := range [][2]string{{osCVE, "macOS"}, {vendorCVE, app}} {
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, severity, match_confidence, fixed_version)
			VALUES ($1::uuid, $2, $3, 'vendor-build', 'CRITICAL', 'version_vendor_confirmed', 'vendor-fix')
		`, d, f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	// Bypass the enqueue filter to prove the matcher itself refuses.
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO cve_match_queue (kind, reason, tenant_id, device_id, app_name)
		VALUES ('observation', 'ingest', $1::uuid, $2::uuid, 'macOS')
	`, tn.tenantID, d); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.tenantID, d, []string{app, "Windows"}, cvepipeline.SourceIngest); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = 'Windows'`, d); n != 0 {
		t.Fatal("an OS pseudo-app was queued")
	}
	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, d, nvdOSCVE); n != 0 {
		t.Fatal("queue path inserted an NVD OS finding")
	}
	for _, f := range [][2]string{{osCVE, "macOS"}, {vendorCVE, app}} {
		var conf, fixed string
		if err := env.pool.QueryRow(ctx, `SELECT match_confidence, fixed_version FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = $3`,
			d, f[0], f[1]).Scan(&conf, &fixed); err != nil {
			t.Fatalf("%s/%s vendor-confirmed row removed: %v", f[0], f[1], err)
		}
		if conf != "version_vendor_confirmed" || fixed != "vendor-fix" {
			t.Fatalf("%s/%s vendor-confirmed row overwritten: %s/%s", f[0], f[1], conf, fixed)
		}
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_assessments WHERE device_id = $1::uuid AND app_name = 'macOS'`, d); n != 0 {
		t.Fatal("queue path assessed an OS pseudo-app")
	}
}

// Review round 1, P2: while the nightly full match holds the match lock, the
// queue drain and the feed-delta match skip their cycle without touching the
// queue or the delta; once released, the queued work is matched.
func TestCVEEventMatchSkipsWhileFullMatchHoldsLock(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-lock-"+sfx)
	vendor := "pat2024k" + sfx
	app := "Pat2024 Lockapp " + sfx
	cveID := "CVE-2099-" + sfx + "b"
	seedFeedEntry(t, cveID, vendor, "lockapp", "9.0", false)
	seedCVEMapping(t, app, vendor, "lockapp")
	drainCVEQueue(t)
	d := seedCVEDevice(t, tn.tenantID, "pat2024-lock-"+sfx, []cveTestApp{{app, "1.0", "com.example.lk." + sfx}})
	if _, _, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.tenantID, d, []string{app}, cvepipeline.SourceIngest); err != nil {
		t.Fatal(err)
	}
	if err := cvepipeline.RecordFeedDelta(ctx, env.pool, []string{vendor + ":lockapp"}); err != nil {
		t.Fatal(err)
	}

	release, err := cvepipeline.AcquireFullMatchLock(ctx, env.pool)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cvepipeline.Drain(ctx, env.pool, nil, 1000)
	if err != nil || !res.SkippedForFullMatch || res.Observations != 0 {
		release()
		t.Fatalf("drain under full-match lock = %+v, err %v; want skipped", res, err)
	}
	fd, err := cvepipeline.MatchFeedDelta(ctx, env.pool, nil)
	if err != nil || !fd.SkippedForFullMatch {
		release()
		t.Fatalf("feed delta under full-match lock = %+v, err %v; want skipped", fd, err)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND attempts = 0`, d); n != 1 {
		release()
		t.Fatal("skipped drain touched the queue")
	}
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid`, d); n != 0 {
		release()
		t.Fatal("drain matched while the full match held the lock")
	}
	release()

	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, d, cveID); n != 1 {
		t.Fatal("queued observation not matched after the full match released the lock")
	}
	if _, err := cvepipeline.MatchFeedDelta(ctx, env.pool, nil); err != nil {
		t.Fatal(err)
	}
}

// Review round 1, P3: a mapping publish that hits the queue cap enqueues only
// the room left, keeps the mapping job, and finishes on a later cycle.
func TestCVEEventMatchMappingExpansionRespectsCapacity(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2024-cap-"+sfx)
	vendor := "pat2024c" + sfx
	app := "Pat2024 Capapp " + sfx
	cveID := "CVE-2099-" + sfx + "c"
	seedFeedEntry(t, cveID, vendor, "capapp", "9.0", false)
	var devices []string
	for i := 0; i < 3; i++ {
		devices = append(devices, seedCVEDevice(t, tn.tenantID, fmt.Sprintf("pat2024-cap-%d-%s", i, sfx),
			[]cveTestApp{{app, "1.0", "com.example.cap." + sfx}}))
	}
	drainCVEQueue(t)
	depth := countRows(t, `SELECT count(*) FROM cve_match_queue`)
	saved := cvepipeline.QueueCapacity
	cvepipeline.QueueCapacity = depth + 2 // room for the mapping job plus one observation
	t.Cleanup(func() { cvepipeline.QueueCapacity = saved })

	seedCVEMapping(t, app, vendor, "capapp")
	if _, err := cvepipeline.Drain(ctx, env.pool, nil, 1000); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'mapping' AND match_name = $1`, app); n != 1 {
		t.Fatalf("mapping job deleted despite dropped observations (%d left, want 1)", n)
	}
	matched := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE cve_id = $1`, cveID)
	if matched >= 3 {
		t.Fatalf("all %d devices matched though the queue had room for fewer", matched)
	}
	a, raw := portalDeviceAssessment(t, tn, devices[2])
	if st, _, _ := productState(t, a, app); st == cvepipeline.StateNotAssessed {
		t.Fatalf("product covered by a pending mapping job read not_assessed: %s", raw)
	}

	cvepipeline.QueueCapacity = saved
	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE cve_id = $1`, cveID); n != 3 {
		t.Fatalf("after capacity returned, %d of 3 devices matched", n)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'mapping' AND match_name = $1`, app); n != 0 {
		t.Fatal("mapping job not cleared once fully expanded")
	}
}

// PAT-2047: 0025_cve_store.sql mapped the app "Git" only to cpe:2.3:a:git:git.
// NVD also files many Git CVEs under the separate cpe:2.3:a:git-scm:git
// identifier, a larger and partly disjoint CVE set, so a Git install checked
// only against git:git has been missing CVEs that only carry the
// git-scm:git key. 0169_app_cpe_mappings_seed_parity.sql adds the
// git-scm:git key alongside the existing row (rescoped from the original
// 0169_git_cpe_vendor_correction.sql once PAT-2051 found patched-api-01's
// app_cpe_mappings held only 9 of 0025's 47 curated rows: 0169 now backfills
// the rest too, asserted below via Adobe Acrobat). This exercises the
// production "Git" match_name and the real migrated rows end to end (normal
// ingest, no test-only mapping seed): an old Git version reaches a finding
// sourced from a git-scm:git feed entry.
func TestCVEEventMatchGitScmCPEMappingProducesFinding(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2047-git-"+sfx)
	cveID := "CVE-2099-" + sfx + "9"
	seedFeedEntry(t, cveID, "git-scm", "git", "2.40.1", false)

	hw := strings.ToUpper(sfx + "-9999-8888-7777-666655554444")
	postAppsPayload(t, tn, hw, []cveTestApp{
		{"Git", "2.39.0", "com.git-scm.git"},
	})
	deviceID := deviceIDByHW(t, tn.tenantID, hw)

	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = 'Git' AND reason = 'ingest'`, deviceID); n != 1 {
		t.Fatalf("ingest delta queued %d rows for Git, want 1 (app_cpe_mappings must map \"Git\")", n)
	}

	res := drainCVEQueue(t)
	if res.NewFindings < 1 {
		t.Fatalf("drain reported %d new findings, want >= 1", res.NewFindings)
	}
	var confidence string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT match_confidence FROM device_cve_findings
		WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = 'Git'
	`, deviceID, cveID).Scan(&confidence); err != nil {
		t.Fatalf("git-scm:git CVE %s produced no finding for an old Git install: %v "+
			"(app_cpe_mappings must carry the git-scm:git key, not only git:git)", cveID, err)
	}
	if confidence != "version_confirmed" {
		t.Fatalf("confidence = %s, want version_confirmed", confidence)
	}

	// PAT-2047 rescope: on patched-api-01, only 9 of 0025's 47 curated rows
	// were ever actually seeded (a pre-merge draft of 0025 ran there
	// instead). 0169_app_cpe_mappings_seed_parity.sql backfills the rest.
	// Adobe Acrobat is one of the 38 missing rows on prod; on this
	// migrations-built test database 0025 already seeded it and 0169 is a
	// no-op for it, but the assertion is the same either way: the row must
	// be present and matching must work.
	acrobatCVE := "CVE-2099-" + sfx + "8"
	seedFeedEntry(t, acrobatCVE, "adobe", "acrobat", "24.0", false)
	sfx2 := randomHex(4)
	hw2 := strings.ToUpper(sfx2 + "-1111-2222-3333-444455556677")
	postAppsPayload(t, tn, hw2, []cveTestApp{
		{"Adobe Acrobat", "23.0", "com.adobe.Acrobat.Pro"},
	})
	device2ID := deviceIDByHW(t, tn.tenantID, hw2)
	drainCVEQueue(t)
	var acrobatConfidence string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT match_confidence FROM device_cve_findings
		WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = 'Adobe Acrobat'
	`, device2ID, acrobatCVE).Scan(&acrobatConfidence); err != nil {
		t.Fatalf("adobe:acrobat CVE %s produced no finding for Adobe Acrobat: %v "+
			"(app_cpe_mappings must carry adobe:acrobat, one of 0169's seed-parity rows)", acrobatCVE, err)
	}
	if acrobatConfidence != "version_confirmed" {
		t.Fatalf("Adobe Acrobat confidence = %s, want version_confirmed", acrobatConfidence)
	}
}

// TestCVEEventMatchGoogleDriveCPEMappingProducesFinding is PAT-2049's version
// of TestCVEEventMatchGitScmCPEMappingProducesFinding: it proves
// 0175_google_drive_cpe_key.sql's google:drive row (added because NVD carries
// real CPE/CVE data there — e.g. CVE-2022-3421 — while the seeded
// google:backup_and_sync_from_google key has zero NVD presence) actually
// reaches a finding for a device running an old Google Drive, not just that
// the migration inserted a row.
func TestCVEEventMatchGoogleDriveCPEMappingProducesFinding(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2049-drive-"+sfx)
	cveID := "CVE-2099-" + sfx + "7"
	seedFeedEntry(t, cveID, "google", "drive", "64.0", false)

	hw := strings.ToUpper(sfx + "-aaaa-bbbb-cccc-ddddeeeeffff")
	postAppsPayload(t, tn, hw, []cveTestApp{
		{"Google Drive", "50.0", "com.google.GoogleDrive"},
	})
	deviceID := deviceIDByHW(t, tn.tenantID, hw)

	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = 'Google Drive' AND reason = 'ingest'`, deviceID); n != 1 {
		t.Fatalf("ingest delta queued %d rows for Google Drive, want 1 (app_cpe_mappings must map \"Google Drive\")", n)
	}

	res := drainCVEQueue(t)
	if res.NewFindings < 1 {
		t.Fatalf("drain reported %d new findings, want >= 1", res.NewFindings)
	}
	var confidence string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT match_confidence FROM device_cve_findings
		WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = 'Google Drive'
	`, deviceID, cveID).Scan(&confidence); err != nil {
		t.Fatalf("google:drive CVE %s produced no finding for an old Google Drive install: %v "+
			"(app_cpe_mappings must carry the google:drive key from 0175, not only the dead "+
			"google:backup_and_sync_from_google key)", cveID, err)
	}
	if confidence != "version_confirmed" {
		t.Fatalf("confidence = %s, want version_confirmed", confidence)
	}
}

// PAT-2107: the event-driven path (cvepipeline.matchDevice) must filter by the
// device's platform and apply the unverified age cut exactly as the nightly
// full match does. One Windows-only CVE (no version data, published recently)
// and one CVE with no platform or version data published in 2018 exist for a
// mapped product installed on a Mac and a Windows device.
func TestCVEEventMatchFiltersByPlatformAndAge(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2107-platform-"+sfx)
	vendor, product := "pat2107v"+sfx, "syncapp"
	app := "Pat2107 Syncapp " + sfx
	windowsCVE, oldCVE := "CVE-2099-"+sfx+"7", "CVE-2018-"+sfx+"8"
	key := vendor + ":" + product

	for _, e := range []struct {
		id        string
		ranges    []cvematch.CPERange
		published time.Time
	}{
		{windowsCVE, []cvematch.CPERange{{Vendor: vendor, Product: product, TargetSW: "windows"}}, time.Now().AddDate(-1, 0, 0)},
		{oldCVE, []cvematch.CPERange{{Vendor: vendor, Product: product}}, time.Date(2018, 6, 1, 0, 0, 0, 0, time.UTC)},
	} {
		rangesJSON, _ := json.Marshal(e.ranges)
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity, cpe_patterns, cpe_ranges, published_at)
			VALUES ($1, 'PAT-2107 integration test vulnerability', 'nvd', 9.8, 'CRITICAL', $2, $3, $4)
		`, e.id, []string{key}, string(rangesJSON), e.published); err != nil {
			t.Fatalf("seed feed entry %s: %v", e.id, err)
		}
	}
	seedCVEMapping(t, app, vendor, product)

	mac := seedCVEDevice(t, tn.tenantID, "pat2107-mac-"+sfx, []cveTestApp{{app, "26.1", "com.example.pat2107." + sfx}})
	var win string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $2, 'Windows', '10.0.26100', 'x64', now())
		RETURNING id::text
	`, tn.tenantID, "pat2107-win-"+sfx).Scan(&win); err != nil {
		t.Fatalf("seed windows device: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO device_apps (device_id, name, identifier, version) VALUES ($1::uuid, $2, '', '26.1')`,
		win, app); err != nil {
		t.Fatalf("seed windows app: %v", err)
	}

	drainCVEQueue(t) // the mapping publish matches both existing observations

	count := func(device, cve string) int {
		return countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, device, cve)
	}
	if n := count(mac, windowsCVE); n != 0 {
		t.Errorf("Mac has %d findings for the Windows-only %s, want 0", n, windowsCVE)
	}
	if n := count(win, windowsCVE); n != 1 {
		t.Errorf("Windows device has %d findings for %s, want 1", n, windowsCVE)
	}
	for _, d := range []string{mac, win} {
		if n := count(d, oldCVE); n != 0 {
			t.Errorf("device %s has %d findings for the 2018 unbounded %s, want 0 (age cut)", d, n, oldCVE)
		}
	}
	// The Mac's product is still assessed, with zero findings: "no CVE
	// applies here" is a real statement, not "not assessed".
	if n := countRows(t, `SELECT count(*) FROM cve_match_assessments WHERE device_id = $1::uuid AND app_name = $2 AND finding_count = 0`,
		mac, app); n != 1 {
		t.Errorf("Mac assessment rows with zero findings = %d, want 1", n)
	}
}
