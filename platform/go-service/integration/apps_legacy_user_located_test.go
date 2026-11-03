//go:build integration

package integration

// PAT-2075 (platform prerequisite for the agent release): legacy user-located
// machine-scope rows.
//
// A macOS agent before PAT-2075 walked /Users/*/Applications as part of its
// machine-wide scan, so an app in a user's ~/Applications is stored as an
// ordinary machine_wide device_apps row whose path lies under that user's
// home. The PAT-2075 agent reports the same app under a per-user scope
// instead, and its collection_status.apps = complete covers /Applications
// only. A machine-wide complete from that agent therefore has no authority
// over a stored row located in a user's home: it must not prune the row and
// must not let any absence consumer (CVE finding, installation closure,
// software policy lifecycle, unapproved alert) read it as gone.
//
// Such a row is resolved only by positive evidence (the same app listed under
// a user scope re-homes it) or by its owner's authority (apps_users lists the
// user complete AND carries a `home` equal to the row's home directory).
// Otherwise it is held, and the run's coverage counts it.
//
// These go through POST /v1/inventory and the real extractor, like
// apps_per_user_scope_test.go. Fixture names follow the agent handoff: the
// account synthetic_alice lives in /Users/profile-alias, so nothing here can
// pass by inferring an owner from a path basename.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"
)

const (
	legacyAlice     = "synthetic_alice"
	legacyAliceHome = "/Users/profile-alias"
	legacyBob       = "synthetic_bob"
	legacyBobHome   = "/Users/bob-home"
	// legacyHeldCoverageKey is where a run reports how many legacy
	// user-located rows it held: software_inventory_runs.coverage.
	legacyHeldCoverageKey = "apps_legacy_user_held"
	// legacyNoPath removes the path key from a row.
	legacyNoPath = "\x00none"
)

// legacyUser is one collection_status.apps_users entry. home nil leaves the
// key out; anything else is sent as given (a non-string on purpose in the
// hostile cases).
type legacyUser struct {
	user, status string
	home         any
}

// legacyPost is one report. users nil sends no apps_users key at all, which
// is what every agent before PAT-2075 does; an empty non-nil slice sends [].
type legacyPost struct {
	status   string // collection_status.apps, default complete
	machine  []cveTestApp
	userApps []userAppRows
	users    []legacyUser
	// paths overrides a row's path by identifier, for both scopes.
	paths map[string]string
}

type legacyFixture struct {
	*appsFixture
	policy    string // "", "unapproved" or "mandatory" on the vulnerable app
	policyKey string
	posted    bool
	rowID     int64
	firstSeen time.Time
}

func newLegacyFixture(t *testing.T, label, policy string) *legacyFixture {
	t.Helper()
	f := &legacyFixture{appsFixture: newAppsFixture(t, "legacy-"+label, 3), policy: policy}
	if policy != "" {
		var id int64
		if err := env.pool.QueryRow(context.Background(), `
			INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
			VALUES ($1::uuid, $2, 'macos', $3, 'report') RETURNING id`,
			f.tn.tenantID, f.vuln.bundle, policy).Scan(&id); err != nil {
			t.Fatalf("seed %s policy: %v", policy, err)
		}
		drift := "unapproved_present:"
		if policy == "mandatory" {
			drift = "mandatory_missing:"
		}
		f.policyKey = drift + strconv.FormatInt(id, 10)
	}
	return f
}

func (f *legacyFixture) in(home string, a cveTestApp) string {
	return home + "/Applications/" + a.name + ".app"
}

// post sends one report and returns the HTTP status. Every report after the
// first waits out the lifecycle's one-second evidence resolution: without
// the pause a report would be ignored as stale and the "not verified fixed"
// checks could not fail.
func (f *legacyFixture) post(t *testing.T, r legacyPost) int {
	t.Helper()
	if f.posted {
		time.Sleep(1100 * time.Millisecond)
	}
	f.posted = true
	status := r.status
	if status == "" {
		status = "complete"
	}
	var users []appsUserStatus
	if r.users != nil {
		users = []appsUserStatus{}
		for _, u := range r.users {
			users = append(users, appsUserStatus{u.user, u.status})
		}
	}
	edit := func(body []byte) []byte {
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		for _, raw := range p["apps"].([]any) {
			app := raw.(map[string]any)
			path, ok := r.paths[app["bundle_id"].(string)]
			if !ok {
				continue
			}
			if path == legacyNoPath {
				delete(app, "path")
			} else {
				app["path"] = path
			}
		}
		if r.users != nil {
			entries := p["collection_status"].(map[string]any)["apps_users"].([]any)
			if len(entries) != len(r.users) {
				t.Fatalf("apps_users has %d entries, want %d", len(entries), len(r.users))
			}
			for i, u := range r.users {
				if u.home != nil {
					entries[i].(map[string]any)["home"] = u.home
				}
			}
		}
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	return postAppsReport(t, f.tn, f.hw, appsPost{schemaV3: true, status: status,
		apps: r.machine, userApps: r.userApps, users: users, raw: edit})
}

func (f *legacyFixture) mustPost(t *testing.T, r legacyPost) {
	t.Helper()
	if code := f.post(t, r); code != http.StatusOK {
		t.Fatalf("POST /v1/inventory = %d, want 200 (a well-formed apps_users[].home must be accepted)", code)
	}
}

// seedLegacy stores the vulnerable app as an agent before PAT-2075 reports
// it: a machine-wide row in alice's home, under a complete report with no
// apps_users key. extra places further apps by identifier.
func (f *legacyFixture) seedLegacy(t *testing.T, extra map[string]string) {
	t.Helper()
	paths := map[string]string{f.vuln.bundle: f.in(legacyAliceHome, f.vuln)}
	for k, v := range extra {
		paths[k] = v
	}
	f.mustPost(t, legacyPost{machine: f.all(), paths: paths})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	var path string
	var machineWide bool
	if err := env.pool.QueryRow(context.Background(), `
		SELECT id, first_seen, COALESCE(path, ''), machine_wide FROM device_apps
		WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle).
		Scan(&f.rowID, &f.firstSeen, &path, &machineWide); err != nil {
		t.Fatalf("seeded legacy row: %v", err)
	}
	if !machineWide || path != paths[f.vuln.bundle] {
		t.Fatalf("seed: machine_wide=%v path=%q, want a machine-wide row at %s", machineWide, path, paths[f.vuln.bundle])
	}
	if f.scopeUsers(t, f.vuln) != 0 {
		t.Fatal("seed: a legacy report created a per-user scope row")
	}
	if !f.hasFinding(t) || f.vulnRemoved(t) {
		t.Fatal("seed: the legacy row has no CVE finding or its installation is closed")
	}
	switch f.policy {
	case "unapproved":
		if f.events(t, "first_observed") != 1 {
			t.Fatal("seed: no unapproved-present finding was opened")
		}
		if _, status, _, _, _ := lcRow(t, f.tn.tenantID, f.deviceID); status != "open" {
			t.Fatalf("seed: unapproved alert is %s, want open", status)
		}
	case "mandatory":
		if n := f.events(t, "first_observed"); n != 0 {
			t.Fatalf("seed: mandatory-missing opened %d times with the app installed", n)
		}
	}
}

func (f *legacyFixture) events(t *testing.T, eventType string) int {
	t.Helper()
	return countRows(t, `SELECT count(*) FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'software' AND finding_key = $2 AND event_type = $3`,
		f.tn.tenantID, f.policyKey, eventType)
}

// heldCount is the newest run's count of held legacy user-located rows, or
// -1 when the run does not report one.
func (f *legacyFixture) heldCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT COALESCE((coverage->>'`+legacyHeldCoverageKey+`')::int, -1)
		FROM software_inventory_runs WHERE device_id = $1::uuid
		ORDER BY received_at DESC, id DESC LIMIT 1`, f.deviceID).Scan(&n); err != nil {
		t.Fatalf("latest run coverage: %v", err)
	}
	return n
}

// assertHeld checks the legacy row survived as the same row and that no
// absence consumer treated it as gone: no CVE removal re-match and the
// finding kept, the installation open, the software policy finding not
// verified fixed, and the unapproved alert not resolved.
func (f *legacyFixture) assertHeld(t *testing.T, when string) {
	t.Helper()
	queued := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE device_id = $1::uuid AND app_name = $2`, f.deviceID, f.vuln.name)
	drainCVEQueue(t)
	var id int64
	var firstSeen time.Time
	var path string
	err := env.pool.QueryRow(context.Background(), `
		SELECT id, first_seen, COALESCE(path, '') FROM device_apps
		WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle).Scan(&id, &firstSeen, &path)
	if err != nil {
		t.Fatalf("%s: the legacy user-located row was pruned by a report with no authority over %s (%v)", when, legacyAliceHome, err)
	}
	if id != f.rowID || !firstSeen.Equal(f.firstSeen) || path != f.in(legacyAliceHome, f.vuln) {
		t.Errorf("%s: held row changed: id %d->%d first_seen %v->%v path %q", when, f.rowID, id, f.firstSeen, firstSeen, path)
	}
	if queued != 0 {
		t.Errorf("%s: the held row was queued for a CVE removal re-match (%d rows)", when, queued)
	}
	if !f.hasFinding(t) {
		t.Errorf("%s: the held row's CVE finding was pruned", when)
	}
	if f.vulnRemoved(t) {
		t.Errorf("%s: the held row's installation was closed", when)
	}
	switch f.policy {
	case "unapproved":
		if n := f.events(t, "verified_fixed"); n != 0 {
			t.Errorf("%s: the unapproved-present finding was verified fixed (%d events)", when, n)
		}
		if _, status, reason, _, _ := lcRow(t, f.tn.tenantID, f.deviceID); status != "open" {
			got := ""
			if reason != nil {
				got = *reason
			}
			t.Errorf("%s: the unapproved alert is %s/%q, want open", when, status, got)
		}
	case "mandatory":
		if n := f.events(t, "first_observed"); n != 0 {
			t.Errorf("%s: a mandatory-missing finding was opened for an app that is still installed", when)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}

// assertPruned checks the row left with everything that hangs off it.
func (f *legacyFixture) assertPruned(t *testing.T, when string) {
	t.Helper()
	drainCVEQueue(t)
	if f.hasApp(t, f.vuln) {
		t.Fatalf("%s: the row was not pruned", when)
	}
	if f.hasFinding(t) {
		t.Errorf("%s: the pruned row left its CVE finding", when)
	}
	if !f.vulnRemoved(t) {
		t.Errorf("%s: the pruned row's installation was not closed", when)
	}
	if f.policy == "unapproved" {
		if n := f.events(t, "verified_fixed"); n != 1 {
			t.Errorf("%s: verified_fixed = %d, want 1", when, n)
		}
		if _, status, reason, _, _ := lcRow(t, f.tn.tenantID, f.deviceID); status != "resolved" || reason == nil || *reason != "not_observed" {
			t.Errorf("%s: the unapproved alert is %s, want resolved/not_observed", when, status)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}

// The handoff's after_denied report: machine-wide complete, the owning user
// partial. Nothing had authority over alice's home.
func TestLegacyUserAppHeldWhenUserPartial(t *testing.T) {
	f := newLegacyFixture(t, "partial", "unapproved")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "partial", nil}}})
	f.assertHeld(t, "alice partial")
	if scopes, withheld := f.latestRun(t); !hasScope(scopes, "all_software") || withheld {
		t.Fatalf("run: scopes=%v withheld=%v: the hold must not withhold the machine-wide scope", scopes, withheld)
	}
	// A home on a partial or unavailable entry is not authority either.
	for _, status := range []string{"partial", "unavailable"} {
		f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, status, legacyAliceHome}}})
		f.assertHeld(t, "alice "+status+" with home")
	}
}

// The handoff's after_unresolved report: machine-wide complete and an
// apps_users block that lists nobody.
func TestLegacyUserAppHeldWhenUserNotListed(t *testing.T) {
	f := newLegacyFixture(t, "unlisted", "unapproved")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{}})
	f.assertHeld(t, "apps_users empty")
	// Another user's complete report, with that user's own home, is not
	// authority over alice's home.
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyBob, "complete", legacyBobHome}}})
	f.assertHeld(t, "only bob complete")
}

// The machine-wide prune in a holding report still works, and the hold has
// no timer: a row unseen for a year is still held.
func TestLegacyUserAppHoldIsNarrowAndHasNoTimer(t *testing.T) {
	f := newLegacyFixture(t, "narrow", "")
	f.seedLegacy(t, nil)
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE device_apps SET last_seen = now() - interval '400 days' WHERE id = $1`, f.rowID); err != nil {
		t.Fatal(err)
	}
	f.mustPost(t, legacyPost{machine: f.fillers[:2], users: []legacyUser{}})
	if f.hasApp(t, f.fillers[2]) {
		t.Fatal("machine-wide complete did not prune the unreported /Applications row")
	}
	f.assertHeld(t, "row unseen for 400 days")
}

// A held legacy row is still installed as far as anything knows, so a
// mandatory policy on it is not reported missing.
func TestLegacyUserAppHeldDoesNotOpenMandatoryMissing(t *testing.T) {
	f := newLegacyFixture(t, "mandatory", "mandatory")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "partial", nil}}})
	f.assertHeld(t, "alice partial")
}

// The owner's authority: alice complete, her home matching the row's, the
// app not listed. Pruned, with everything downstream.
func TestLegacyUserAppPrunedByOwnerCompleteWithHome(t *testing.T) {
	f := newLegacyFixture(t, "owner", "unapproved")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", legacyAliceHome}}})
	f.assertPruned(t, "alice complete with her home")
	for _, a := range f.fillers {
		if !f.hasApp(t, a) {
			t.Fatalf("the owner's prune touched machine-wide app %s", a.bundle)
		}
	}
	if n := f.heldCount(t); n > 0 {
		t.Fatalf("held count = %d after the only legacy row was pruned", n)
	}
}

// The owner's authority reaches the row even while the machine-wide scope is
// withheld, like any per-user prune.
func TestLegacyUserAppPrunedByOwnerWhileMachinePartial(t *testing.T) {
	f := newLegacyFixture(t, "ownerpartial", "")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{status: "partial", machine: f.fillers[:1],
		users: []legacyUser{{legacyAlice, "complete", legacyAliceHome}}})
	drainCVEQueue(t)
	if f.hasApp(t, f.vuln) || f.hasFinding(t) {
		t.Fatal("alice complete with her home did not prune her legacy row under a partial machine-wide report")
	}
	for _, a := range f.fillers {
		if !f.hasApp(t, a) {
			t.Fatalf("a partial machine-wide report pruned %s", a.bundle)
		}
	}
}

// Complete alone is not ownership. With no home, or a well-formed home that
// is not the row's, the row is held.
func TestLegacyUserAppHeldWhenCompleteWithoutMatchingHome(t *testing.T) {
	t.Run("no home", func(t *testing.T) {
		f := newLegacyFixture(t, "nohome", "unapproved")
		f.seedLegacy(t, nil)
		f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", nil}}})
		f.assertHeld(t, "alice complete, no home")
	})
	t.Run("home elsewhere", func(t *testing.T) {
		f := newLegacyFixture(t, "otherhome", "unapproved")
		f.seedLegacy(t, nil)
		f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", "/Users/" + legacyAlice}}})
		f.assertHeld(t, "alice complete, home /Users/"+legacyAlice)
	})
}

// The owner is established from `home`, never from the path's basename: a
// user account named exactly like the home directory gets nothing from the
// name, and the account whose name differs from the directory owns the row
// through its home.
func TestLegacyUserAppOwnerOnlyThroughHome(t *testing.T) {
	f := newLegacyFixture(t, "basename", "unapproved")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{"profile-alias", "complete", nil}}})
	f.assertHeld(t, "an account named like the home directory, no home")
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{"profile-alias", "complete", "/Users/elsewhere"}}})
	f.assertHeld(t, "an account named like the home directory, home elsewhere")
	f.mustPost(t, legacyPost{machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", legacyAliceHome}}})
	f.assertPruned(t, "synthetic_alice with home "+legacyAliceHome)
}

// Positive evidence: the same app at the same path listed under a user scope
// re-homes the row. One row, the same row, owned by the user, with its
// finding, installation and history.
func TestLegacyUserAppRehomedWhenListedUnderUser(t *testing.T) {
	for _, machine := range []string{"complete", "partial"} {
		t.Run("machine "+machine, func(t *testing.T) {
			f := newLegacyFixture(t, "rehome"+machine, "unapproved")
			f.seedLegacy(t, nil)
			paths := map[string]string{f.vuln.bundle: f.in(legacyAliceHome, f.vuln)}
			f.mustPost(t, legacyPost{status: machine, machine: f.fillers, paths: paths,
				userApps: []userAppRows{{legacyAlice, []cveTestApp{f.vuln}}},
				users:    []legacyUser{{legacyAlice, "partial", nil}}})
			f.assertHeld(t, "listed under alice")
			if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.deviceID, f.vuln.bundle); n != 1 {
				t.Fatalf("device_apps rows = %d, want 1: re-homing duplicated the row", n)
			}
			if n := countRows(t, `SELECT count(*) FROM software_installations
				WHERE device_id = $1::uuid AND identity_value_normalized = lower($2)`, f.deviceID, f.vuln.bundle); n != 1 {
				t.Fatalf("installations = %d, want 1", n)
			}
			if n := countRows(t, `SELECT count(*) FROM device_app_user_scopes
				WHERE device_app_id = $1 AND user_account = $2`, f.rowID, legacyAlice); n != 1 || f.scopeUsers(t, f.vuln) != 1 {
				t.Fatalf("scope rows for alice on the original row = %d (total %d), want 1", n, f.scopeUsers(t, f.vuln))
			}
			if f.machineWide(t, f.vuln) {
				t.Fatal("the re-homed row is still asserted machine-wide: it would be held for ever once alice lets go of it")
			}
			if n := f.heldCount(t); n > 0 {
				t.Fatalf("held count = %d for a re-homed row", n)
			}
			// It is now an ordinary per-user row: alice's complete report
			// prunes it with no home needed.
			f.mustPost(t, legacyPost{status: machine, machine: f.fillers, users: []legacyUser{{legacyAlice, "complete", nil}}})
			drainCVEQueue(t)
			if f.hasApp(t, f.vuln) || f.hasFinding(t) {
				t.Fatal("alice complete did not prune the re-homed row")
			}
		})
	}
}

// /Users/Shared is nobody's home, and a path outside any /Users/<name>/
// directory is not user-located: both are ordinary machine-wide rows, pruned
// by a machine-wide complete exactly as on main. Passes before the hold.
func TestLegacyUserAppSharedAndNonHomePathsStayMachineScope(t *testing.T) {
	f := newLegacyFixture(t, "shared", "unapproved")
	f.seedLegacy(t, map[string]string{
		f.vuln.bundle:       "/Users/Shared/Applications/" + f.vuln.name + ".app",
		f.fillers[0].bundle: "/Users/" + f.fillers[0].name + ".app",
		f.fillers[1].bundle: legacyNoPath,
	})
	f.mustPost(t, legacyPost{machine: f.fillers[2:], users: []legacyUser{{legacyAlice, "partial", nil}}})
	f.assertPruned(t, "/Users/Shared row under machine-wide complete")
	if f.hasApp(t, f.fillers[0]) {
		t.Fatal("a row directly under /Users was held as if it were in a home")
	}
	if f.hasApp(t, f.fillers[1]) {
		t.Fatal("a row with no path was held")
	}
	if !f.hasApp(t, f.fillers[2]) {
		t.Fatal("the reconfirmed machine-wide row was pruned")
	}
	if n := f.heldCount(t); n > 0 {
		t.Fatalf("held count = %d with no user-located row", n)
	}
}

func (f *legacyFixture) seedTwoHomes(t *testing.T) {
	t.Helper()
	f.seedLegacy(t, map[string]string{f.fillers[0].bundle: f.in(legacyBobHome, f.fillers[0])})
}

// A hostile or malformed home never widens what a user can prune. Each value
// is sent on alice's complete entry beside a legacy row in bob's home. The
// platform may refuse the report (400) or ignore the home; either way no
// row leaves. Guard: passes before the hold, while every home is refused.
func TestLegacyUserAppHostileHomeNeverWidens(t *testing.T) {
	f := newLegacyFixture(t, "hostile", "")
	f.seedTwoHomes(t)
	send := func(home any) {
		t.Helper()
		if code := f.post(t, legacyPost{machine: f.fillers[1:], users: []legacyUser{{legacyAlice, "complete", home}}}); code != http.StatusOK && code != http.StatusBadRequest {
			t.Fatalf("home %#v: POST = %d, want 200 or 400", home, code)
		}
		if !f.hasApp(t, f.fillers[0]) {
			t.Fatalf("home %#v let alice prune the row in %s", home, legacyBobHome)
		}
	}
	// None of these is alice's home: her row stays too.
	for _, home := range []any{
		"/", "/Users", "/Users/", "", " ", "~", "~/", ".",
		"Users/profile-alias", "profile-alias",
		"/Users/profile-alias/..", "/Users/profile-alias/../bob-home",
		"/Users/prof", "/Users/profile-alia", "/Users/profile-alias-2",
		"/Users/%", "/Users/_rofile-alias", "/Users/*", "/Users/profile-alias%",
		"/Users/Shared", "/private/Users/profile-alias",
		7, true, []any{legacyAliceHome}, map[string]any{"path": legacyAliceHome},
	} {
		send(home)
		if !f.hasApp(t, f.vuln) {
			t.Fatalf("home %#v is not %s but pruned the row there", home, legacyAliceHome)
		}
	}
	// Two users claiming one home, one of them not complete: least
	// authority wins, whichever order they come in.
	for _, users := range [][]legacyUser{
		{{legacyAlice, "complete", legacyBobHome}, {legacyBob, "partial", legacyBobHome}},
		{{legacyBob, "partial", legacyBobHome}, {legacyAlice, "complete", legacyBobHome}},
		{{legacyAlice, "complete", legacyBobHome}, {legacyBob, "unavailable", legacyBobHome}},
	} {
		if code := f.post(t, legacyPost{machine: f.fillers[1:], users: users}); code != http.StatusOK && code != http.StatusBadRequest {
			t.Fatalf("contested home: POST = %d", code)
		}
		if !f.hasApp(t, f.fillers[0]) {
			t.Fatal("a home also claimed by a partial user was pruned")
		}
	}
	// One user sent twice with two homes owns neither with certainty.
	if code := f.post(t, legacyPost{machine: f.fillers[1:], users: []legacyUser{
		{legacyAlice, "complete", legacyAliceHome}, {legacyAlice, "complete", legacyBobHome}}}); code != http.StatusOK && code != http.StatusBadRequest {
		t.Fatalf("two homes: POST = %d", code)
	}
	if !f.hasApp(t, f.fillers[0]) {
		t.Fatal("a second home on a duplicate entry widened alice's prune to bob's home")
	}
	// Variants that do name alice's home, non-canonically. Whether they
	// are honoured is the platform's choice; they must not reach bob's row.
	for _, home := range []any{
		"/Users/profile-alias/", "//Users/profile-alias", "/Users/./profile-alias",
		"/Users/bob-home/../profile-alias", "/users/profile-alias", "/Users/profile-alias/Applications",
	} {
		send(home)
	}
}

// A device stuck holding legacy rows is visible: the run's coverage counts
// them.
func TestLegacyUserAppHeldCountReported(t *testing.T) {
	f := newLegacyFixture(t, "count", "")
	f.seedTwoHomes(t)
	if n := f.heldCount(t); n > 0 {
		t.Fatalf("held count = %d on the legacy report that listed both rows", n)
	}
	f.mustPost(t, legacyPost{machine: f.fillers[1:], users: []legacyUser{}})
	if !f.hasApp(t, f.vuln) || !f.hasApp(t, f.fillers[0]) {
		t.Fatal("the two legacy user-located rows were not both held")
	}
	if n := f.heldCount(t); n != 2 {
		t.Fatalf("coverage.%s = %d, want 2", legacyHeldCoverageKey, n)
	}
	// Bob's authority releases his; alice's is still held and counted.
	f.mustPost(t, legacyPost{machine: f.fillers[1:], users: []legacyUser{{legacyBob, "complete", legacyBobHome}}})
	if f.hasApp(t, f.fillers[0]) || !f.hasApp(t, f.vuln) {
		t.Fatal("bob complete with his home should prune his row and only his")
	}
	if n := f.heldCount(t); n != 1 {
		t.Fatalf("coverage.%s = %d, want 1", legacyHeldCoverageKey, n)
	}
}

// Control, passes before the hold. An agent before PAT-2075 sends no
// apps_users key and its complete does cover /Users/*/Applications, so its
// report prunes a user-located row exactly as on main. The hold applies only
// to a report that carries apps_users, i.e. one that scopes users itself.
func TestLegacyUserAppOldAgentCompleteStillPrunes(t *testing.T) {
	f := newLegacyFixture(t, "oldagent", "unapproved")
	f.seedLegacy(t, nil)
	f.mustPost(t, legacyPost{machine: f.fillers})
	f.assertPruned(t, "old agent complete without the app")
}

// Control, passes before the hold. An ordinary per-user scope row whose path
// is in a home keeps the 0180 rules: held while its user is missing, pruned
// by its user's complete with no home needed. Machine-wide /Applications
// rows prune as before in the same reports.
func TestLegacyUserAppPerUserScopeRulesUnchanged(t *testing.T) {
	f := newLegacyFixture(t, "scopes", "")
	paths := map[string]string{f.vuln.bundle: f.in(legacyAliceHome, f.vuln)}
	f.mustPost(t, legacyPost{machine: f.fillers, paths: paths,
		userApps: []userAppRows{{legacyAlice, []cveTestApp{f.vuln}}},
		users:    []legacyUser{{legacyAlice, "complete", nil}}})
	drainCVEQueue(t)
	f.deviceID = deviceIDByHW(t, f.tn.tenantID, f.hw)
	if f.machineWide(t, f.vuln) || f.scopeUsers(t, f.vuln) != 1 || !f.hasFinding(t) {
		t.Fatal("seed: want one per-user row for alice with its finding")
	}
	f.mustPost(t, legacyPost{machine: f.fillers[:2], users: []legacyUser{}})
	drainCVEQueue(t)
	if !f.hasApp(t, f.vuln) || !f.hasFinding(t) || f.vulnRemoved(t) {
		t.Fatal("a per-user row of a missing user was not held")
	}
	if f.hasApp(t, f.fillers[2]) {
		t.Fatal("machine-wide complete did not prune the unreported machine-wide row")
	}
	if n := f.heldCount(t); n > 0 {
		t.Fatalf("held count = %d: a per-user scope row is not a legacy row", n)
	}
	f.mustPost(t, legacyPost{machine: f.fillers[:2], users: []legacyUser{{legacyAlice, "complete", nil}}})
	drainCVEQueue(t)
	if f.hasApp(t, f.vuln) || f.hasFinding(t) || f.scopeUsers(t, f.vuln) != 0 {
		t.Fatal("alice complete did not prune her per-user row")
	}
}
