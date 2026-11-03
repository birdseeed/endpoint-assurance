//go:build integration

package integration

// PAT-2075: per-user application scopes. A per-user app (Windows HKU, macOS
// ~/Applications) is readable only while its user is logged in, so a report
// that leaves a user out is not evidence of an uninstall. Payloads go
// through POST /v1/inventory and the real extractor, and CVE findings through
// cvepipeline.Drain, as in apps_prune_authority_test.go. The contract is
// platform-neutral; these run on the macOS schema v3 shape because the
// shared fixture and CVE mapping helpers use it.

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	pat2075Alice = "S-1-5-21-1000-1001"
	pat2075Bob   = "S-1-5-21-1000-1002"
)

// perUserSeed posts the fillers machine-wide and the vulnerable app
// per-user for alice, both scopes complete, and drains, so the per-user app
// has a finding and an open installation.
func (f *appsFixture) perUserSeed(t *testing.T) {
	t.Helper()
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		userApps: []userAppRows{{pat2075Alice, []cveTestApp{f.vuln}}},
		users:    []appsUserStatus{{pat2075Alice, "complete"}}})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	if !f.hasApp(t, f.vuln) || !f.hasFinding(t) {
		t.Fatal("seed did not store the per-user app with its CVE finding")
	}
	if f.vulnRemoved(t) {
		t.Fatal("seeded per-user installation already closed")
	}
}

func (f *appsFixture) scopeUsers(t *testing.T, a cveTestApp) int {
	return countRows(t, `SELECT count(*) FROM device_app_user_scopes s
		JOIN device_apps d ON d.id = s.device_app_id
		WHERE d.device_id = $1::uuid AND d.identifier = $2`, f.deviceID, a.bundle)
}

func (f *appsFixture) machineWide(t *testing.T, a cveTestApp) bool {
	t.Helper()
	var mw bool
	if err := env.pool.QueryRow(context.Background(),
		`SELECT machine_wide FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`,
		f.deviceID, a.bundle).Scan(&mw); err != nil {
		t.Fatalf("machine_wide for %s: %v", a.bundle, err)
	}
	return mw
}

// assertPerUserHeld checks the per-user vulnerable app, its finding and its
// installation all survived a report that had no authority over its user,
// and that nothing queued it for a removal re-match.
func (f *appsFixture) assertPerUserHeld(t *testing.T) {
	t.Helper()
	queued := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = $2`, f.deviceID, f.vuln.name)
	drainCVEQueue(t)
	if !f.hasApp(t, f.vuln) {
		t.Error("the held per-user app was pruned")
	}
	if !f.hasFinding(t) {
		t.Error("the held per-user app's CVE finding was pruned")
	}
	if f.vulnRemoved(t) {
		t.Error("the held per-user app's installation was closed")
	}
	if queued != 0 {
		t.Errorf("a held per-user app was queued for a removal re-match (%d rows)", queued)
	}
	if t.Failed() {
		t.FailNow()
	}
}

// A per-user row is stored once in device_apps, not machine-wide, with a
// scope row for its user.
func TestAppsPerUserRowStored(t *testing.T) {
	f := newAppsFixture(t, "peruser", 3)
	f.perUserSeed(t)
	if f.machineWide(t, f.vuln) {
		t.Fatal("per-user row stored as machine-wide")
	}
	if n := countRows(t, `SELECT count(*) FROM device_app_user_scopes s JOIN device_apps d ON d.id = s.device_app_id
		WHERE d.device_id = $1::uuid AND d.identifier = $2 AND s.user_account = $3`, f.deviceID, f.vuln.bundle, pat2075Alice); n != 1 {
		t.Fatalf("scope rows for alice = %d, want 1", n)
	}
	if !f.machineWide(t, f.fillers[0]) || f.scopeUsers(t, f.fillers[0]) != 0 {
		t.Fatal("machine-wide row gained a per-user scope")
	}
}

// A user missing from the next report (logged off) keeps every row, even
// under an authoritative machine-wide complete that grants all_software. The
// machine-wide prune in the same report still works.
func TestAppsPerUserMissingUserKeepsRows(t *testing.T) {
	f := newAppsFixture(t, "loggedoff", 3)
	f.perUserSeed(t)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers[:2],
		users: []appsUserStatus{}})
	f.assertPerUserHeld(t)
	if f.hasApp(t, f.fillers[2]) {
		t.Fatal("machine-wide complete did not prune the unreported machine-wide app")
	}
	if scopes, withheld := f.latestRun(t); !hasScope(scopes, "all_software") || withheld {
		t.Fatalf("run: scopes=%v withheld=%v, want all_software and not withheld", scopes, withheld)
	}
	// With no apps_users block at all, the same holds.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers[:2]})
	f.assertPerUserHeld(t)
}

// A user listed partial or unavailable keeps their rows.
func TestAppsPerUserPartialKeepsRows(t *testing.T) {
	f := newAppsFixture(t, "userpartial", 3)
	f.perUserSeed(t)
	for _, status := range []string{"partial", "unavailable"} {
		mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
			users: []appsUserStatus{{pat2075Alice, status}}})
		f.assertPerUserHeld(t)
	}
	// A duplicated entry merges least authoritative wins.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}, {pat2075Alice, "partial"}}})
	f.assertPerUserHeld(t)
	// complete for a different user is not authority over alice.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Bob, "complete"}}})
	f.assertPerUserHeld(t)
}

// A user listed complete without the app gets it pruned, with its finding
// and installation, even while the machine-wide scope is withheld.
func TestAppsPerUserCompletePrunes(t *testing.T) {
	f := newAppsFixture(t, "usercomplete", 3)
	f.perUserSeed(t)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "partial", apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	drainCVEQueue(t)
	if f.hasApp(t, f.vuln) {
		t.Fatal("alice complete without the app did not prune it")
	}
	if f.hasFinding(t) {
		t.Fatal("alice complete without the app left its CVE finding")
	}
	if f.scopeUsers(t, f.vuln) != 0 {
		t.Fatal("pruned app left a scope row")
	}
	for _, a := range f.fillers {
		if !f.hasApp(t, a) {
			t.Fatalf("a per-user prune touched machine-wide app %s", a.bundle)
		}
	}
	// The installation closes on the next report with application absence
	// authority, since no scope holds it any more.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	if !f.vulnRemoved(t) {
		t.Fatal("the pruned per-user app's installation was not closed")
	}
}

// The same app installed machine-wide and per-user for two users is one
// device_apps row and one CVE finding, and it stays until the last scope
// that holds it lets go.
func TestAppsPerUserAndMachineWideSameAppOneFinding(t *testing.T) {
	f := newAppsFixture(t, "shared", 3)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.all(),
		userApps: []userAppRows{{pat2075Alice, []cveTestApp{f.vuln}}, {pat2075Bob, []cveTestApp{f.vuln}}},
		users:    []appsUserStatus{{pat2075Alice, "complete"}, {pat2075Bob, "complete"}}})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle); n != 1 {
		t.Fatalf("device_apps rows for the shared app = %d, want 1", n)
	}
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, f.deviceID, f.cveID); n != 1 {
		t.Fatalf("CVE findings for the shared app = %d, want 1", n)
	}
	if !f.machineWide(t, f.vuln) || f.scopeUsers(t, f.vuln) != 2 {
		t.Fatal("shared app should be machine-wide with two user scopes")
	}

	// Machine-wide uninstall, both users logged off: still held per-user.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers})
	f.assertPerUserHeld(t)
	if f.machineWide(t, f.vuln) {
		t.Fatal("machine-wide complete without the app kept its machine-wide assertion")
	}

	// Alice uninstalls; bob is logged off and still holds it.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	f.assertPerUserHeld(t)

	// Bob uninstalls: the last scope goes and so does the finding.
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Bob, "complete"}}})
	drainCVEQueue(t)
	if f.hasApp(t, f.vuln) || f.hasFinding(t) {
		t.Fatal("the last scope's uninstall did not remove the app and its finding")
	}
}

// A per-user app that moves machine-wide (or back) is the same row.
func TestAppsPerUserThenMachineWideKeepsOneRow(t *testing.T) {
	f := newAppsFixture(t, "promote", 3)
	f.perUserSeed(t)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.all(),
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	drainCVEQueue(t)
	if !f.machineWide(t, f.vuln) || f.scopeUsers(t, f.vuln) != 0 || !f.hasFinding(t) {
		t.Fatal("app moved machine-wide should be one machine-wide row with its finding")
	}
}

// A legacy payload (no user_account, no apps_users) stores machine-wide rows
// with no scope rows, exactly as before PAT-2075.
func TestAppsLegacyPayloadIsMachineWide(t *testing.T) {
	f := newAppsFixture(t, "legacy2075", 3)
	f.seed(t, false)
	if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND NOT machine_wide`, f.deviceID); n != 0 {
		t.Fatalf("%d legacy rows stored as per-user", n)
	}
	if n := countRows(t, `SELECT count(*) FROM device_app_user_scopes WHERE device_id = $1::uuid`, f.deviceID); n != 0 {
		t.Fatalf("%d scope rows for a legacy payload", n)
	}
}

// apps_users on a schema v2 payload is not authority.
func TestAppsPerUserCompleteOnV2IsNotAuthority(t *testing.T) {
	f := newAppsFixture(t, "v2users", 3)
	mustPostApps(t, f.tn, f.hw, appsPost{apps: f.fillers,
		userApps: []userAppRows{{pat2075Alice, []cveTestApp{f.vuln}}}})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	mustPostApps(t, f.tn, f.hw, appsPost{apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	f.assertPerUserHeld(t)
}

// Malformed per-user fields and case- or fold-variant keys are refused.
func TestAppsPerUserMalformedRejected(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2075-malformed-"+sfx)
	hw := "A" + sfx[1:] + "-2075-4000-8000-" + randomHex(6)
	apps := []cveTestApp{{"Pat2075 Bad " + sfx, "1.0", "com.example.pat2075.bad." + sfx}}
	userRow := []userAppRows{{pat2075Alice, apps}}
	swap := func(from, to string) func([]byte) []byte {
		return func(b []byte) []byte {
			out := bytes.Replace(b, []byte(from), []byte(to), 1)
			if bytes.Equal(out, b) {
				t.Fatalf("test edit %q not applied", from)
			}
			return out
		}
	}
	for name, r := range map[string]appsPost{
		"case variant user_account": {schemaV3: true, userApps: userRow, raw: swap(`"user_account"`, `"User_Account"`)},
		"fold variant user_account": {schemaV3: true, userApps: userRow, raw: swap(`"user_account"`, "\"u\u017fer_account\"")},
		"non-string user_account":   {schemaV3: true, userApps: userRow, raw: swap(`"user_account":"`+pat2075Alice+`"`, `"user_account":7`)},
		"case variant apps_users": {schemaV3: true, apps: apps, users: []appsUserStatus{{pat2075Alice, "complete"}},
			raw: swap(`"apps_users"`, `"Apps_Users"`)},
		"case variant entry key": {schemaV3: true, apps: apps, users: []appsUserStatus{{pat2075Alice, "complete"}},
			raw: swap(`"collection_status":"complete"`, `"Collection_Status":"complete"`)},
		"unknown entry key": {schemaV3: true, apps: apps, users: []appsUserStatus{{pat2075Alice, "complete"}},
			raw: swap(`"collection_status":"complete"`, `"collection_status":"complete","sid":"x"`)},
		"bad entry status": {schemaV3: true, apps: apps, users: []appsUserStatus{{pat2075Alice, "done"}}},
		"not an array": {schemaV3: true, apps: apps, users: []appsUserStatus{},
			raw: swap(`"apps_users":[]`, `"apps_users":{}`)},
		"missing user_account": {schemaV3: true, apps: apps, users: []appsUserStatus{{pat2075Alice, "complete"}},
			raw: swap(`,"user_account":"`+pat2075Alice+`"`, ``)},
	} {
		t.Run(name, func(t *testing.T) {
			if code := postAppsReport(t, tn, hw, r); code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400", code)
			}
		})
	}
}

// An unapproved-present software policy finding on a per-user app is not
// verified fixed by a report that left its logged-off user out, and is by a
// report that read that user in full.
func TestAppsPerUserHeldAppKeepsSoftwarePolicyFinding(t *testing.T) {
	f := newAppsFixture(t, "policy", 3)
	var policyID int64
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, $2, 'any', 'unapproved') RETURNING id`,
		f.tn.tenantID, f.vuln.bundle).Scan(&policyID); err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}
	key := "unapproved_present:" + strconv.FormatInt(policyID, 10)
	fixed := func() int {
		return countRows(t, `SELECT count(*) FROM finding_lifecycle_events
			WHERE tenant_id = $1::uuid AND finding_kind = 'software' AND finding_key = $2 AND event_type = 'verified_fixed'`,
			f.tn.tenantID, key)
	}
	f.perUserSeed(t)
	if n := countRows(t, `SELECT count(*) FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'software' AND finding_key = $2 AND event_type = 'first_observed'`,
		f.tn.tenantID, key); n != 1 {
		t.Fatalf("seed opened %d unapproved-present findings, want 1", n)
	}
	// The lifecycle only takes evidence strictly newer than the last, and
	// collected_at has one-second resolution. Without the pause the next
	// report would be ignored as stale and this check could not fail.
	time.Sleep(1100 * time.Millisecond)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers})
	if n := countRows(t, `SELECT count(*) FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'software' AND finding_key = $2 AND event_type = 'currently_observed'`,
		f.tn.tenantID, key); n != 1 {
		t.Fatalf("report without the logged-off user recorded %d currently_observed events, want 1", n)
	}
	if n := fixed(); n != 0 {
		t.Fatal("a report without the logged-off user verified the unapproved app fixed")
	}
	time.Sleep(1100 * time.Millisecond)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	if n := fixed(); n != 1 {
		t.Fatalf("alice complete without the app: %d verified_fixed events, want 1", n)
	}
}

// Two users whose user_account values share a 128-character prefix never
// collapse into one scope: a complete report for the longer one (which is
// over the bound, so its rows are dropped and its entry grants nothing)
// cannot prune the other's rows.
func TestAppsPerUserSharedPrefixNeverCrossPrunes(t *testing.T) {
	f := newAppsFixture(t, "prefix", 3)
	prefix := strings.Repeat("p", 128)
	longer := prefix + "X"
	extra := cveTestApp{"Pat2075 Longuser " + f.hw[:8], "1.0", "com.example.pat2075.longuser." + strings.ToLower(f.hw[:8])}
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		userApps: []userAppRows{{prefix, []cveTestApp{f.vuln}}},
		users:    []appsUserStatus{{prefix, "complete"}}})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	if !f.hasApp(t, f.vuln) || !f.hasFinding(t) {
		t.Fatal("seed did not store the 128-character user's app with its finding")
	}
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		userApps: []userAppRows{{longer, []cveTestApp{extra}}},
		users:    []appsUserStatus{{longer, "complete"}}})
	f.assertPerUserHeld(t)
	if f.hasApp(t, extra) {
		t.Fatal("a row with an over-long user_account was stored")
	}
	for _, a := range f.fillers {
		if !f.hasApp(t, a) {
			t.Fatalf("the rest of the report was lost: %s missing", a.bundle)
		}
	}
	if n := countRows(t, `SELECT count(*) FROM device_app_user_scopes WHERE device_id = $1::uuid AND user_account <> $2`, f.deviceID, prefix); n != 0 {
		t.Fatalf("%d scope rows under a key other than the 128-character user", n)
	}
}

// Per-user scopes are held or pruned by whether this report listed them,
// not by comparing last_seen with the ingest time: a scope stamped in the
// future (a stepped or skewed clock) is still held for a logged-off user and
// still pruned by that user's complete report.
func TestAppsPerUserScopeJudgedBySetNotClock(t *testing.T) {
	f := newAppsFixture(t, "clock", 3)
	var policyID int64
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, $2, 'any', 'unapproved') RETURNING id`,
		f.tn.tenantID, f.vuln.bundle).Scan(&policyID); err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}
	key := "unapproved_present:" + strconv.FormatInt(policyID, 10)
	events := func(kind string) int {
		return countRows(t, `SELECT count(*) FROM finding_lifecycle_events
			WHERE tenant_id = $1::uuid AND finding_kind = 'software' AND finding_key = $2 AND event_type = $3`,
			f.tn.tenantID, key, kind)
	}
	f.perUserSeed(t)
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE device_app_user_scopes SET last_seen = now() + interval '1 day' WHERE device_id = $1::uuid`,
		f.deviceID); err != nil {
		t.Fatalf("future-date scopes: %v", err)
	}

	// Alice logged off: held, so the unapproved app is still observed.
	time.Sleep(1100 * time.Millisecond)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers})
	if events("currently_observed") != 1 || events("verified_fixed") != 0 {
		t.Fatalf("future-dated scope of a logged-off user was not held: currently_observed=%d verified_fixed=%d",
			events("currently_observed"), events("verified_fixed"))
	}
	f.assertPerUserHeld(t)

	// Alice complete without it: pruned, although last_seen is in the future.
	time.Sleep(1100 * time.Millisecond)
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{pat2075Alice, "complete"}}})
	drainCVEQueue(t)
	if f.hasApp(t, f.vuln) || f.hasFinding(t) || f.scopeUsers(t, f.vuln) != 0 {
		t.Fatal("alice complete did not prune a future-dated scope")
	}
	if events("verified_fixed") != 1 {
		t.Fatalf("verified_fixed = %d, want 1", events("verified_fixed"))
	}
}
