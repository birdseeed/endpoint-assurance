//go:build integration

package integration

// PAT-2075 Phase B: the rulings added after apps_legacy_user_located_test.go
// was frozen. Same fixture, same route through POST /v1/inventory and the
// real extractor.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// The same installation upgraded: the legacy row is at one version, and the
// user scope lists another version at the row's stored path. That is positive
// evidence. One row remains, at the new version, owned by the user, carrying
// the legacy row's history.
func TestLegacyUserAppRehomedAcrossVersionChange(t *testing.T) {
	f := newLegacyFixture(t, "version", "")
	f.seedLegacy(t, nil)
	upgraded := f.vuln
	upgraded.version = "1.6" // still below the fixed version, so the finding stays
	paths := map[string]string{f.vuln.bundle: f.in(legacyAliceHome, f.vuln)}
	f.mustPost(t, legacyPost{machine: f.fillers, paths: paths,
		userApps: []userAppRows{{legacyAlice, []cveTestApp{upgraded}}},
		users:    []legacyUser{{legacyAlice, "partial", nil}}})
	drainCVEQueue(t)

	var id int64
	var version, path string
	var machineWide bool
	var firstSeen time.Time
	if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle); n != 1 {
		t.Fatalf("device_apps rows = %d, want 1: the old version must be released, not held beside the new one", n)
	}
	if err := env.pool.QueryRow(context.Background(), `
		SELECT id, version, COALESCE(path, ''), machine_wide, first_seen FROM device_apps
		WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle).
		Scan(&id, &version, &path, &machineWide, &firstSeen); err != nil {
		t.Fatal(err)
	}
	if version != "1.6" || machineWide || path != f.in(legacyAliceHome, f.vuln) {
		t.Fatalf("row: version=%q machine_wide=%v path=%q", version, machineWide, path)
	}
	if !firstSeen.Equal(f.firstSeen) {
		t.Fatalf("first_seen = %v, want the legacy row's %v: history was lost", firstSeen, f.firstSeen)
	}
	if n := countRows(t, `SELECT count(*) FROM device_app_user_scopes WHERE device_app_id = $1 AND user_account = $2`, id, legacyAlice); n != 1 {
		t.Fatalf("scope rows for alice = %d, want 1", n)
	}
	if n := countRows(t, `SELECT count(*) FROM software_installations
		WHERE device_id = $1::uuid AND identity_value_normalized = lower($2)`, f.deviceID, f.vuln.bundle); n != 1 || f.vulnRemoved(t) {
		t.Fatalf("installations = %d removed=%v, want one open installation", n, f.vulnRemoved(t))
	}
	if !f.hasFinding(t) {
		t.Fatal("the still-vulnerable upgraded version lost its CVE finding")
	}
	if n := f.heldCount(t); n != 0 {
		t.Fatalf("held count = %d, want 0", n)
	}
}

// Another version listed somewhere else, by a user whose home is unknown, is
// not evidence about the legacy row's path: both rows stay.
func TestLegacyUserAppOtherVersionElsewhereIsNotEvidence(t *testing.T) {
	f := newLegacyFixture(t, "versionelsewhere", "")
	f.seedLegacy(t, nil)
	upgraded := f.vuln
	upgraded.version = "1.6"
	f.mustPost(t, legacyPost{machine: f.fillers,
		paths:    map[string]string{f.vuln.bundle: f.in(legacyBobHome, f.vuln)},
		userApps: []userAppRows{{legacyBob, []cveTestApp{upgraded}}},
		users:    []legacyUser{{legacyBob, "complete", legacyBobHome}}})
	if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle); n != 2 {
		t.Fatalf("device_apps rows = %d, want the held legacy row and bob's new one", n)
	}
	if !f.hasAppVersion(t, f.vuln, f.vuln.version) || f.heldCount(t) != 1 {
		t.Fatalf("the legacy row was released on another user's listing (held count %d)", f.heldCount(t))
	}
}

// Two users. Bob has the same app, same version, in his own home, so his row
// collapses onto the legacy row in alice's home. That is not evidence about
// alice's copy: the row keeps its machine-wide assertion and its stored path,
// and survives bob letting go. Alice listing it re-homes it.
func TestLegacyUserAppSameIdentityUnderAnotherUserDoesNotRehome(t *testing.T) {
	f := newLegacyFixture(t, "twousers", "unapproved")
	f.seedLegacy(t, nil)
	bobCopy := map[string]string{f.vuln.bundle: f.in(legacyBobHome, f.vuln)}
	f.mustPost(t, legacyPost{machine: f.fillers, paths: bobCopy,
		userApps: []userAppRows{{legacyBob, []cveTestApp{f.vuln}}},
		users:    []legacyUser{{legacyBob, "complete", legacyBobHome}}})
	f.assertHeld(t, "bob lists the same app in his own home")
	if !f.machineWide(t, f.vuln) {
		t.Fatal("bob's listing released the machine-wide assertion on alice's copy")
	}
	if n := countRows(t, `SELECT count(*) FROM device_app_user_scopes WHERE device_app_id = $1 AND user_account = $2`, f.rowID, legacyBob); n != 1 {
		t.Fatalf("scope rows for bob = %d, want 1", n)
	}
	if n := f.heldCount(t); n != 1 {
		t.Fatalf("held count = %d, want 1", n)
	}

	// Bob uninstalls his copy. Alice's is still held.
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyBob, "complete", legacyBobHome}}})
	f.assertHeld(t, "bob complete without it")
	if f.scopeUsers(t, f.vuln) != 0 {
		t.Fatal("bob's scope row was not pruned by his own complete report")
	}

	// Alice is read: her home equals the row's home, the app is listed at
	// another path inside it. Re-homed.
	moved := legacyAliceHome + "/Applications/Moved/" + f.vuln.name + ".app"
	f.mustPost(t, legacyPost{machine: f.fillers, paths: map[string]string{f.vuln.bundle: moved},
		userApps: []userAppRows{{legacyAlice, []cveTestApp{f.vuln}}},
		users:    []legacyUser{{legacyAlice, "partial", legacyAliceHome}}})
	if f.machineWide(t, f.vuln) || f.scopeUsers(t, f.vuln) != 1 || f.heldCount(t) != 0 {
		t.Fatalf("alice's listing did not re-home the row: machine_wide=%v scopes=%d held=%d",
			f.machineWide(t, f.vuln), f.scopeUsers(t, f.vuln), f.heldCount(t))
	}
	if !f.hasFinding(t) || f.vulnRemoved(t) {
		t.Fatal("the re-homed row lost its finding or installation")
	}
}

// With both users listing the app in one report, the row is re-homed and
// both scopes hold it.
func TestLegacyUserAppBothUsersListIt(t *testing.T) {
	f := newLegacyFixture(t, "bothusers", "")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers,
		userApps: []userAppRows{{legacyBob, []cveTestApp{f.vuln}}, {legacyAlice, []cveTestApp{f.vuln}}},
		users:    []legacyUser{{legacyBob, "complete", legacyBobHome}, {legacyAlice, "complete", legacyAliceHome}}})
	if f.machineWide(t, f.vuln) || f.scopeUsers(t, f.vuln) != 2 {
		t.Fatalf("machine_wide=%v scopes=%d, want a row held by both users only", f.machineWide(t, f.vuln), f.scopeUsers(t, f.vuln))
	}
}

// The owner's complete report releases only the machine-wide assertion when
// another user's scope still holds the row.
func TestLegacyUserAppOwnerPruneKeepsOtherUsersScope(t *testing.T) {
	f := newLegacyFixture(t, "ownerother", "")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers,
		paths:    map[string]string{f.vuln.bundle: f.in(legacyBobHome, f.vuln)},
		userApps: []userAppRows{{legacyBob, []cveTestApp{f.vuln}}},
		users:    []legacyUser{{legacyBob, "complete", legacyBobHome}, {legacyAlice, "complete", legacyAliceHome}}})
	drainCVEQueue(t)
	if !f.hasApp(t, f.vuln) || f.machineWide(t, f.vuln) || f.scopeUsers(t, f.vuln) != 1 || !f.hasFinding(t) {
		t.Fatal("alice's prune should leave the row to bob's scope, with its finding")
	}
}

// A non-string home is a malformed report: 400 and nothing is extracted. Any
// string is accepted.
func TestLegacyUserAppHomeValidation(t *testing.T) {
	f := newLegacyFixture(t, "validation", "")
	f.seedLegacy(t, nil)
	for _, home := range []any{7, true, []any{legacyAliceHome}, map[string]any{"path": legacyAliceHome}} {
		if code := f.post(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", home}}}); code != http.StatusBadRequest {
			t.Fatalf("home %#v: POST = %d, want 400", home, code)
		}
	}
	for _, home := range []any{"", "/", "relative", "/Users/profile-alias/", "/Users/profile-alias/.."} {
		if code := f.post(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", home}}}); code != http.StatusOK {
			t.Fatalf("home %#v: POST = %d, want 200", home, code)
		}
		if !f.hasApp(t, f.vuln) {
			t.Fatalf("home %#v pruned the row", home)
		}
	}
	// A case- or fold-variant key is refused by the key walk.
	edit := func(body []byte) []byte {
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		p["collection_status"].(map[string]any)["apps_users"].([]any)[0].(map[string]any)["Home"] = legacyAliceHome
		out, _ := json.Marshal(p)
		return out
	}
	if code := postAppsReport(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		users: []appsUserStatus{{legacyAlice, "complete"}}, raw: edit}); code != http.StatusBadRequest {
		t.Fatalf("key Home: POST = %d, want 400", code)
	}
}

// A held row is not refreshed by the report, so its usage evidence must not
// keep supporting an unused-software conclusion: usage_evidence_complete is
// cleared while it is held and comes back when its owner reports it.
func TestLegacyUserAppHeldRowUsageEvidenceIsNotComplete(t *testing.T) {
	f := newLegacyFixture(t, "usage", "")
	path := f.in(legacyAliceHome, f.vuln)
	withUsage := func(body []byte) []byte {
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		for _, raw := range p["apps"].([]any) {
			app := raw.(map[string]any)
			if app["bundle_id"] == f.vuln.bundle {
				app["path"] = path
				app["usage_evidence"] = "recorded"
				app["last_used_at"] = "2026-07-02T03:04:05Z"
				app["launch_count"] = 3
			}
		}
		out, _ := json.Marshal(p)
		return out
	}
	complete := func() *bool {
		var c *bool
		if err := env.pool.QueryRow(context.Background(), `
			SELECT usage_evidence_complete FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`,
			f.deviceID, f.vuln.bundle).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.all(), raw: withUsage})
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	if c := complete(); c == nil || !*c {
		t.Fatal("seed: a complete legacy report did not store complete usage evidence")
	}
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers, users: []appsUserStatus{}})
	if !f.hasApp(t, f.vuln) {
		t.Fatal("the legacy row was not held")
	}
	if c := complete(); c == nil || *c {
		t.Fatal("a held row still claims complete usage evidence")
	}
	// The controls keep theirs.
	if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier <> $2
		AND usage_evidence_complete IS FALSE AND usage_evidence = 'recorded'`, f.deviceID, f.vuln.bundle); n != 0 {
		t.Fatalf("%d other rows lost usage authority", n)
	}
	mustPostApps(t, f.tn, f.hw, appsPost{schemaV3: true, status: "complete", apps: f.fillers,
		userApps: []userAppRows{{legacyAlice, []cveTestApp{f.vuln}}},
		users:    []appsUserStatus{{legacyAlice, "complete"}}, raw: withUsage})
	if c := complete(); c == nil || !*c || f.machineWide(t, f.vuln) {
		t.Fatal("the re-homed row, read in full with usage, did not regain complete usage evidence")
	}
}

// A valve-held report (no collection_status.apps, but apps_users present)
// must not time-release or supersede a held legacy row either.
func TestLegacyUserAppHeldThroughValveReleases(t *testing.T) {
	f := newLegacyFixture(t, "valve", "")
	f.seedLegacy(t, nil)
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE device_apps SET last_seen = now() - interval '400 days' WHERE id = $1`, f.rowID); err != nil {
		t.Fatal(err)
	}
	// No machine-wide signal, one of four identifiers unreported: the
	// valve does not hold and the ordinary prune runs.
	if code := postAppsReport(t, f.tn, f.hw, appsPost{schemaV3: true, apps: f.fillers, users: []appsUserStatus{}}); code != http.StatusOK {
		t.Fatalf("POST = %d", code)
	}
	if !f.hasApp(t, f.vuln) {
		t.Fatal("a no-signal prune removed the legacy user-located row")
	}
	if n := f.heldCount(t); n != 1 {
		t.Fatalf("held count = %d, want 1", n)
	}
}
