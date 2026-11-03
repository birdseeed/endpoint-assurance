//go:build integration

package integration

// PAT-2063: absence requires authority for applications. Payloads go through
// POST /v1/inventory and the real extractor; CVE findings are produced and
// re-matched through cvepipeline.Drain exactly as in production, so a kept
// app's finding is proven to survive rather than just its device_apps row.

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
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
)

// appsPost is one inventory report for the apps authority tests.
type appsPost struct {
	schemaV3 bool   // schema_version 3 (macOS); otherwise the v2 full.json shape
	status   string // collection_status.apps; "" leaves the key out
	apps     []cveTestApp
	raw      func(body []byte) []byte // optional last-moment edit of the body
	// PAT-2075: per-user rows (sent with user_account) and the
	// collection_status.apps_users block; nil users leaves the key out.
	userApps []userAppRows
	users    []appsUserStatus
}

type userAppRows struct {
	user string
	apps []cveTestApp
}

type appsUserStatus struct{ user, status string }

// postAppsReport posts full.json with its device identity, app list and
// collection_status replaced, then runs the extractor. It returns the HTTP
// status; on anything but 200 nothing is extracted.
func postAppsReport(t *testing.T, tn cveTestTenant, hwUUID string, r appsPost) int {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "full.json"), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tn.tenantID
	p["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	if r.schemaV3 {
		p["schema_version"] = 3
		p["platform"] = "macos"
	}
	device := p["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2063" + strings.ToUpper(hwUUID[:8])
	device["hostname"] = "pat2063-" + strings.ToLower(hwUUID[:8])
	list := make([]map[string]any, 0, len(r.apps))
	for _, a := range r.apps {
		app := map[string]any{
			"name": a.name, "version": a.version, "bundle_id": a.bundle,
			"path": "/Applications/" + a.name + ".app",
		}
		if r.schemaV3 {
			app["identifier"] = a.bundle
		}
		list = append(list, app)
	}
	for _, ua := range r.userApps {
		for _, a := range ua.apps {
			app := map[string]any{
				"name": a.name, "version": a.version, "bundle_id": a.bundle,
				"path":         "/Users/" + ua.user + "/Applications/" + a.name + ".app",
				"user_account": ua.user,
			}
			if r.schemaV3 {
				app["identifier"] = a.bundle
			}
			list = append(list, app)
		}
	}
	p["apps"] = list
	cs := map[string]any{}
	if r.status != "" {
		cs["apps"] = r.status
	}
	if r.users != nil {
		entries := make([]map[string]any, 0, len(r.users))
		for _, u := range r.users {
			entries = append(entries, map[string]any{"user_account": u.user, "collection_status": u.status})
		}
		cs["apps_users"] = entries
	}
	if len(cs) > 0 {
		p["collection_status"] = cs
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.raw != nil {
		body = r.raw(body)
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
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
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
	return resp.StatusCode
}

func mustPostApps(t *testing.T, tn cveTestTenant, hwUUID string, r appsPost) {
	t.Helper()
	if code := postAppsReport(t, tn, hwUUID, r); code != http.StatusOK {
		t.Fatalf("POST /v1/inventory: %d, want 200", code)
	}
}

// appsFixture is one test's device: a vulnerable, CVE-mapped app plus
// fillers, all with per-test unique names so the shared database cannot
// cross-contaminate.
type appsFixture struct {
	tn       cveTestTenant
	hw       string
	vuln     cveTestApp
	cveID    string
	fillers  []cveTestApp
	deviceID string
}

func newAppsFixture(t *testing.T, label string, fillers int) *appsFixture {
	t.Helper()
	sfx := randomHex(4)
	f := &appsFixture{
		tn:    newCVETestTenant(t, "pat2063-"+label+"-"+sfx),
		hw:    strings.ToUpper(sfx + "-2063-4000-8000-" + randomHex(6)),
		cveID: "CVE-2099-" + sfx + "7",
	}
	vendor, product := "pat2063v"+sfx, "keptwidget"
	f.vuln = cveTestApp{"Pat2063 Keptwidget " + sfx, "1.5", "com.example.pat2063.vuln." + sfx}
	for i := 0; i < fillers; i++ {
		f.fillers = append(f.fillers, cveTestApp{
			fmt.Sprintf("Pat2063 Filler %02d %s", i, sfx), "1.0",
			fmt.Sprintf("com.example.pat2063.filler%02d.%s", i, sfx),
		})
	}
	seedFeedEntry(t, f.cveID, vendor, product, "2.0", false)
	seedCVEMapping(t, f.vuln.name, vendor, product)
	drainCVEQueue(t)
	return f
}

func (f *appsFixture) all() []cveTestApp {
	return append([]cveTestApp{f.vuln}, f.fillers...)
}

// seed posts the full inventory (no status) and drains, so the vulnerable
// app has a real finding and an open installation.
func (f *appsFixture) seed(t *testing.T, schemaV3 bool) {
	t.Helper()
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: schemaV3, apps: f.all()})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	if n := f.appCount(t); n != len(f.all()) {
		t.Fatalf("seeded %d device_apps, want %d", n, len(f.all()))
	}
	if !f.hasFinding(t) {
		t.Fatal("seed produced no CVE finding for the mapped app")
	}
	if f.vulnRemoved(t) {
		t.Fatal("seeded installation already closed")
	}
}

func (f *appsFixture) appCount(t *testing.T) int {
	return countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid`, f.deviceID)
}

func (f *appsFixture) hasApp(t *testing.T, a cveTestApp) bool {
	return countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, a.bundle) > 0
}

func (f *appsFixture) hasFinding(t *testing.T) bool {
	return countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2 AND app_name = $3`,
		f.deviceID, f.cveID, f.vuln.name) == 1
}

func (f *appsFixture) vulnRemoved(t *testing.T) bool {
	return countRows(t, `SELECT count(*) FROM software_installations
		WHERE device_id = $1::uuid AND identity_value_normalized = lower($2) AND removed_at IS NOT NULL`,
		f.deviceID, f.vuln.bundle) > 0
}

// latestRun returns the newest inventory run's scopes and withheld flag.
func (f *appsFixture) latestRun(t *testing.T) (scopes []string, withheld bool) {
	t.Helper()
	if err := env.pool.QueryRow(context.Background(), `
		SELECT authoritative_scopes, COALESCE((coverage->>'apps_absence_withheld')::boolean, false)
		FROM software_inventory_runs WHERE device_id = $1::uuid
		ORDER BY received_at DESC, id DESC LIMIT 1`, f.deviceID).Scan(&scopes, &withheld); err != nil {
		t.Fatalf("latest run: %v", err)
	}
	return scopes, withheld
}

func hasScope(scopes []string, s string) bool {
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

// assertKept checks the device still holds every seeded app, the mapped
// app's finding survived a drain, its installation is still open, and the
// withheld report granted no application absence scope.
func (f *appsFixture) assertKept(t *testing.T, want int) {
	t.Helper()
	queued := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = $2`, f.deviceID, f.vuln.name)
	drainCVEQueue(t)
	if n := f.appCount(t); n != want {
		t.Errorf("device_apps = %d, want %d: unreported apps were pruned without authority", n, want)
	}
	if !f.hasApp(t, f.vuln) {
		t.Error("the unreported vulnerable app was pruned")
	}
	if !f.hasFinding(t) {
		t.Error("the unreported app's CVE finding was pruned")
	}
	if queued != 0 {
		t.Errorf("a withheld report queued the kept app for a removal re-match (%d rows)", queued)
	}
	if f.vulnRemoved(t) {
		t.Error("the unreported app's installation was closed")
	}
	scopes, withheld := f.latestRun(t)
	if hasScope(scopes, "all_software") || !withheld {
		t.Errorf("withheld report run: scopes=%v apps_absence_withheld=%v, want no all_software and withheld", scopes, withheld)
	}
	if t.Failed() {
		t.FailNow()
	}
}

// A short list with no signal (15 of 20 identifiers gone) keeps the
// unreported apps and the mapped app's CVE finding.
func TestAppsShortListWithoutSignalKeepsUnreportedAppsAndFindings(t *testing.T) {
	f := newAppsFixture(t, "short", 19)
	f.seed(t, false)
	mustPostApps(t, f.tn, f.hw, appsPost{apps: f.fillers[:5]})
	f.assertKept(t, 20)
}

// An empty list with no signal never wipes a device, even one with fewer
// apps than the valve's absolute floor.
func TestAppsEmptyListWithoutSignalPrunesNothing(t *testing.T) {
	f := newAppsFixture(t, "empty", 2)
	f.seed(t, false)
	mustPostApps(t, f.tn, f.hw, appsPost{apps: []cveTestApp{}})
	f.assertKept(t, 3)
	var status *string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT collection_status->>'apps' FROM devices WHERE id = $1::uuid`, f.deviceID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != nil {
		t.Fatalf("no-signal report stored an apps status %q", *status)
	}
}

// A genuine small uninstall with no signal (1 of 20) still prunes, and the
// removed app's finding goes with it through the normal re-match.
func TestAppsSmallUninstallWithoutSignalStillPrunes(t *testing.T) {
	f := newAppsFixture(t, "uninstall", 19)
	f.seed(t, false)
	mustPostApps(t, f.tn, f.hw, appsPost{apps: f.fillers})
	drainCVEQueue(t)
	if n := f.appCount(t); n != 19 {
		t.Fatalf("device_apps = %d, want 19", n)
	}
	if f.hasApp(t, f.vuln) || f.hasFinding(t) {
		t.Fatal("a genuine uninstall did not prune the app and its finding")
	}
	if !f.vulnRemoved(t) {
		t.Fatal("a genuine uninstall did not close the installation")
	}
	if scopes, withheld := f.latestRun(t); !hasScope(scopes, "all_software") || withheld {
		t.Fatalf("uninstall run: scopes=%v withheld=%v, want all_software and not withheld", scopes, withheld)
	}
}

// A version upgrade of most of the estate is not a removal and does not trip
// the valve: the superseded version rows are pruned.
func TestAppsMassVersionUpgradeWithoutSignalPrunesOldVersions(t *testing.T) {
	f := newAppsFixture(t, "upgrade", 9)
	f.seed(t, false)
	upgraded := make([]cveTestApp, 0, len(f.all()))
	for _, a := range f.all() {
		a.version = "2.1"
		upgraded = append(upgraded, a)
	}
	mustPostApps(t, f.tn, f.hw, appsPost{apps: upgraded})
	drainCVEQueue(t)
	if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND version <> '2.1'`, f.deviceID); n != 0 {
		t.Fatalf("%d superseded version rows kept after a mass upgrade", n)
	}
	if f.hasFinding(t) {
		t.Fatal("upgrade to the fixed version left the finding")
	}
}

// With the explicit signal: partial and unavailable keep everything, complete
// prunes even a large drop, and the status is stored.
func TestAppsCollectionStatusCompletePrunesPartialDoesNot(t *testing.T) {
	f := newAppsFixture(t, "signal", 19)
	f.seed(t, true)

	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "partial", apps: f.fillers[:5]})
	f.assertKept(t, 20)

	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "unavailable", apps: []cveTestApp{}})
	f.assertKept(t, 20)

	var stored string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT collection_status->>'apps' FROM devices WHERE id = $1::uuid`, f.deviceID).Scan(&stored); err != nil || stored != "unavailable" {
		t.Fatalf("devices.collection_status.apps = %q (err %v), want unavailable", stored, err)
	}

	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers[:5]})
	drainCVEQueue(t)
	if n := f.appCount(t); n != 5 {
		t.Fatalf("complete report left %d device_apps, want 5", n)
	}
	if f.hasFinding(t) {
		t.Fatal("complete report did not prune the removed app's finding")
	}
	if !f.vulnRemoved(t) {
		t.Fatal("complete report did not close the removed installation")
	}
	if scopes, withheld := f.latestRun(t); !hasScope(scopes, "all_software") || withheld {
		t.Fatalf("complete run: scopes=%v withheld=%v", scopes, withheld)
	}

	// complete with an empty array is an authoritative "no apps".
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: []cveTestApp{}})
	if n := f.appCount(t); n != 0 {
		t.Fatalf("complete empty report left %d device_apps, want 0", n)
	}
}

// complete on a legacy schema v2 payload is not authority: it falls back to
// the safety valve.
func TestAppsCollectionStatusCompleteOnV2IsNotAuthority(t *testing.T) {
	f := newAppsFixture(t, "v2complete", 19)
	f.seed(t, false)
	mustPostApps(t, f.tn, f.hw, appsPost{status: "complete", apps: f.fillers[:5]})
	f.assertKept(t, 20)
}

// A well-formed status that contradicts the array is accepted and withholds
// authority; the apps it lists are still upserted.
func TestAppsCollectionStatusInconsistentWithholds(t *testing.T) {
	f := newAppsFixture(t, "inconsistent", 19)
	f.seed(t, true)
	extra := cveTestApp{"Pat2063 Newcomer " + f.hw[:8], "1.0", "com.example.pat2063.newcomer." + strings.ToLower(f.hw[:8])}
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "unavailable",
		apps: append([]cveTestApp{extra}, f.fillers[:5]...)})
	f.assertKept(t, 21)
	if !f.hasApp(t, extra) {
		t.Fatal("an inconsistent report dropped the apps it listed")
	}
}

// Malformed collection_status.apps is refused before storage.
func TestAppsCollectionStatusMalformedRejected(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2063-malformed-"+sfx)
	hw := strings.ToUpper(sfx + "-2063-4000-8000-" + randomHex(6))
	apps := []cveTestApp{{"Pat2063 Bad " + sfx, "1.0", "com.example.pat2063.bad." + sfx}}
	for name, r := range map[string]appsPost{
		"unknown value": {schemaV3: true, status: "done", apps: apps},
		"wrong case":    {schemaV3: true, status: "Complete", apps: apps},
		"not a string": {schemaV3: true, apps: apps, raw: func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"apps":[`), []byte(`"collection_status":{"apps":true},"apps":[`), 1)
		}},
		"case variant key": {schemaV3: true, apps: apps, raw: func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"apps":[`), []byte(`"collection_status":{"APPS":"complete"},"apps":[`), 1)
		}},
		"duplicate collection_status": {schemaV3: true, status: "partial", apps: apps, raw: func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"apps":[`), []byte(`"collection_status":{"apps":"complete"},"apps":[`), 1)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if code := postAppsReport(t, tn, hw, r); code != http.StatusBadRequest {
				t.Fatalf("malformed collection_status.apps: got %d, want 400", code)
			}
		})
	}
}

// backdate moves every device_apps row of one identifier into the past, as
// if the device had last reported it that long ago.
func (f *appsFixture) backdate(t *testing.T, a cveTestApp, by time.Duration) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE device_apps SET last_seen = now() - make_interval(secs => $3) WHERE device_id = $1::uuid AND identifier = $2`,
		f.deviceID, a.bundle, by.Seconds()); err != nil {
		t.Fatalf("backdate %s: %v", a.bundle, err)
	}
}

func (f *appsFixture) hasAppVersion(t *testing.T, a cveTestApp, version string) bool {
	return countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2 AND version = $3`,
		f.deviceID, a.bundle, version) > 0
}

func (f *appsFixture) assertScopesWithheld(t *testing.T) {
	t.Helper()
	if scopes, withheld := f.latestRun(t); hasScope(scopes, "all_software") || !withheld {
		t.Fatalf("held report run: scopes=%v apps_absence_withheld=%v, want no all_software and withheld", scopes, withheld)
	}
}

// While the valve holds, an app reconfirmed at a new version still loses its
// old-version row and that version's CVE finding. Otherwise every upgrade on
// a held device kept the vulnerable row and the nightly sync re-raised it.
func TestAppsValveHeldStillPrunesSupersededVersions(t *testing.T) {
	f := newAppsFixture(t, "heldupgrade", 9)
	f.seed(t, false)
	upgraded := f.vuln
	upgraded.version = "2.1"
	// 6 of 10 identifiers vanish: the valve holds.
	mustPostApps(t, f.tn, f.hw, appsPost{apps: append([]cveTestApp{upgraded}, f.fillers[:3]...)})
	drainCVEQueue(t)
	if f.hasAppVersion(t, f.vuln, "1.5") {
		t.Fatal("held report kept the superseded 1.5 row of a reconfirmed app")
	}
	if !f.hasAppVersion(t, f.vuln, "2.1") {
		t.Fatal("held report lost the reported 2.1 row")
	}
	if f.hasFinding(t) {
		t.Fatal("held report kept the superseded version's CVE finding")
	}
	if n := f.appCount(t); n != 10 {
		t.Fatalf("device_apps = %d, want 10: the unreported apps must stay held", n)
	}
	for _, a := range f.fillers[3:] {
		if !f.hasApp(t, a) {
			t.Fatalf("held report pruned unreported app %s", a.bundle)
		}
	}
	f.assertScopesWithheld(t)
}

// While the valve holds on the ratio and the report reconfirms something, an
// identifier unseen for longer than the release window is pruned; one seen
// recently stays held.
func TestAppsValveHeldTimeReleasesLongUnseenIdentifiers(t *testing.T) {
	f := newAppsFixture(t, "release", 10)
	f.seed(t, false)
	old, recent := f.fillers[8], f.fillers[9]
	f.backdate(t, old, 8*24*time.Hour)
	f.backdate(t, recent, 24*time.Hour)
	// 7 of 11 identifiers vanish: the valve holds, 4 are reconfirmed.
	mustPostApps(t, f.tn, f.hw, appsPost{apps: f.fillers[:4]})
	if f.hasApp(t, old) {
		t.Fatal("identifier unseen for 8 days was not time-released")
	}
	if !f.hasApp(t, recent) {
		t.Fatal("identifier seen 1 day ago was pruned while held")
	}
	f.assertKept(t, 10)
}

// When every vanished identifier is past the release window the report
// holds nothing recent back; it still withholds scopes for that ingest, and
// the next report prunes normally with full authority.
func TestAppsValveHeldReleaseOfEverythingThenPrunesNormally(t *testing.T) {
	f := newAppsFixture(t, "releaseall", 9)
	f.seed(t, false)
	for _, a := range f.all()[4:] {
		f.backdate(t, a, 8*24*time.Hour)
	}
	kept := f.all()[:4]
	mustPostApps(t, f.tn, f.hw, appsPost{apps: kept})
	if n := f.appCount(t); n != 4 {
		t.Fatalf("device_apps = %d, want 4 after releasing 6 long-unseen identifiers", n)
	}
	f.assertScopesWithheld(t)
	mustPostApps(t, f.tn, f.hw, appsPost{apps: kept})
	if scopes, withheld := f.latestRun(t); !hasScope(scopes, "all_software") || withheld {
		t.Fatalf("follow-up run: scopes=%v withheld=%v, want all_software and not withheld", scopes, withheld)
	}
}

// An empty report never deletes anything, however long the device's rows
// have gone unseen: with nothing reconfirmed there is no time release.
func TestAppsEmptyListNeverTimeReleases(t *testing.T) {
	f := newAppsFixture(t, "emptyold", 2)
	f.seed(t, false)
	for _, a := range f.all() {
		f.backdate(t, a, 30*24*time.Hour)
	}
	mustPostApps(t, f.tn, f.hw, appsPost{apps: []cveTestApp{}})
	f.assertKept(t, 3)
}
