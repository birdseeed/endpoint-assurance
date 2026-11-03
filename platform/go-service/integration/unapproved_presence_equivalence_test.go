//go:build integration

package integration

// PAT-2095: the Unapproved-present summary must answer exactly what the full
// computation answers. These tests build randomised estates, mutate them the
// ways ingest, policy writes and retirement do, bring the summary up to date
// by every route (ingest refresh, dirty sweep, full rebuild, or nothing at
// all, leaving devices dirty), and compare the summary against the full
// computation, which stays in the code as the oracle.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/softwaregov"
)

type equivEstate struct {
	t        *testing.T
	rng      *rand.Rand
	tenantID string
	bearer   string
	secret   []byte
	devices  []string
	version  int
}

func TestUnapprovedSummaryDeviceCountWithDirtyOverlay(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "devicecount", "")
	clean := govDevice(t, g.id, "devicecount-clean", "macOS", time.Now())
	dirty := govDevice(t, g.id, "devicecount-dirty", "macOS", time.Now())
	for _, ident := range []string{"com.devicecount.one", "com.devicecount.two"} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
			VALUES ($1::uuid, $2, 'any', 'unapproved')`, g.id, ident); err != nil {
			t.Fatal(err)
		}
		for _, dev := range []string{clean, dirty} {
			govApp(t, dev, ident, ident, "COUNTTEAM1")
		}
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	assertCounts := func(label string, wantDevices int) {
		t.Helper()
		got, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, g.id, time.Now(), 0)
		if err != nil || got.Devices != wantDevices || got.Products != 2 {
			t.Fatalf("%s: overview=%+v err=%v", label, got, err)
		}
		assertSummaryMatchesFull(t, g.id, label)
	}
	assertCounts("multiple products count each clean device once", 2)
	// The old derived rows still contain this device, but a live dirty read
	// must exclude it when its inventory no longer contains either product.
	if _, err := env.pool.Exec(ctx, `DELETE FROM device_apps WHERE device_id = $1::uuid`, dirty); err != nil {
		t.Fatal(err)
	}
	assertCounts("dirty absence excludes old derived rows", 1)
	govApp(t, dirty, "Returned App", "com.devicecount.one", "COUNTTEAM1")
	assertCounts("dirty presence overlays one device once", 2)
}

var (
	equivTeams = []string{"EQTEAMAAA1", "EQTEAMBBB2", "EQTEAMCCC3"}
	equivExts  = []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc",
		"dddddddddddddddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	equivBrowsers = []string{"chrome", "edge", "firefox"}
)

// equivProduct is one application identity the generator draws from.
type equivProduct struct {
	ident string
	team  string
	names []string
	win   bool // a Windows winget-style identifier
}

var equivApps = func() []equivProduct {
	var out []equivProduct
	for i := 0; i < 14; i++ {
		p := equivProduct{ident: fmt.Sprintf("com.eq.app%d", i),
			names: []string{fmt.Sprintf("Eq App %d", i), fmt.Sprintf("eq app %d", i), fmt.Sprintf("Eq App %d Pro", i)}}
		if i%3 == 0 {
			p.team = equivTeams[i%len(equivTeams)]
		}
		if i%5 == 4 {
			p.ident = fmt.Sprintf("EqVendor.App%d", i)
			p.win = true
		}
		out = append(out, p)
	}
	return out
}()

func newEquivEstate(t *testing.T, seed int64) *equivEstate {
	t.Helper()
	suffix := randomHex(4)
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, "pat2095-equiv-"+suffix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return &equivEstate{t: t, rng: rand.New(rand.NewSource(seed)), tenantID: tenantID, bearer: bearer, secret: secret}
}

func (e *equivEstate) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := env.pool.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("%s: %v", strings.Fields(sql)[0], err)
	}
}

func (e *equivEstate) pick(n int) int { return e.rng.Intn(n) }

func (e *equivEstate) randomDevice() string {
	if len(e.devices) == 0 {
		return ""
	}
	return e.devices[e.pick(len(e.devices))]
}

func (e *equivEstate) addDevice() {
	osName := "macOS"
	if e.pick(3) == 0 {
		osName = "Windows"
	}
	// Some devices are stale: last report older than StaleAfter.
	lastSeen := time.Now().Add(-time.Duration(e.pick(30*24)) * time.Hour)
	e.devices = append(e.devices, govDevice(e.t, e.tenantID, fmt.Sprintf("eq-%02d-%s", len(e.devices), randomHex(2)), osName, lastSeen))
}

func (e *equivEstate) addApp(dev string) {
	p := equivApps[e.pick(len(equivApps))]
	e.version++
	var team any
	if p.team != "" && e.pick(4) != 0 {
		team = p.team
	}
	kind := "native"
	if p.win {
		kind = "winget"
	}
	firstSeen := time.Now().Add(-time.Duration(e.pick(90*24)) * time.Hour)
	e.exec(`INSERT INTO device_apps (device_id, name, identifier, version, team_id, identifier_kind, first_seen)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)`,
		dev, p.names[e.pick(len(p.names))], p.ident, "1."+strconv.Itoa(e.version), team, kind, firstSeen)
}

func (e *equivEstate) addExtension(dev string) {
	e.exec(`INSERT INTO device_browser_extensions (device_id, browser, user_account, profile, extension_id, name, first_seen)
		VALUES ($1::uuid, $2, $3, 'Default', $4, $5, $6) ON CONFLICT DO NOTHING`,
		dev, equivBrowsers[e.pick(len(equivBrowsers))], "user"+strconv.Itoa(e.pick(3)), equivExts[e.pick(len(equivExts))],
		"Eq Ext "+strconv.Itoa(e.pick(3)), time.Now().Add(-time.Duration(e.pick(60*24))*time.Hour))
}

var equivAppPolicies = []string{"unapproved", "unapproved", "approved", "unmanaged", "mandatory"}

func (e *equivEstate) setAppPolicy() {
	p := equivApps[e.pick(len(equivApps))]
	platform := []string{"any", "macos", "windows"}[e.pick(3)]
	policy := equivAppPolicies[e.pick(len(equivAppPolicies))]
	var team, bundle, winget, name any
	switch e.pick(5) {
	case 0: // by identifier
		if p.win {
			winget = p.ident
		} else {
			bundle = p.ident
		}
	case 1: // identifier and team
		bundle = p.ident
		if p.team != "" {
			team = p.team
		}
	case 2: // name only
		name = p.names[e.pick(len(p.names))]
	case 3: // team only: every product of the vendor
		team = equivTeams[e.pick(len(equivTeams))]
	default: // identifier, lower-cased differently
		bundle = strings.ToUpper(p.ident)
	}
	e.exec(`INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, winget_id, name, platform, policy)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`,
		e.tenantID, team, bundle, winget, name, platform, policy)
}

func (e *equivEstate) setExtensionPolicy() {
	browser := append([]string{"any"}, equivBrowsers...)[e.pick(len(equivBrowsers)+1)]
	policy := []string{"unapproved", "unapproved", "approved", "ignored"}[e.pick(4)]
	e.exec(`INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, policy)
		VALUES ($1::uuid, $2, $3, $4)
		ON CONFLICT (tenant_id, browser, extension_id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()`,
		e.tenantID, browser, equivExts[e.pick(len(equivExts))], policy)
}

// postHomebrew ingests the Homebrew fixture for a new device through
// POST /v1/inventory and the extractor, the real ingest path, including the
// post-commit summary refresh.
func (e *equivEstate) postHomebrew() {
	serial := "PAT2095-" + randomHex(4)
	postInventoryAs(e.t, e.bearer, e.secret, homebrewPayload(e.t, serial, "eq-brew-"+serial, nil))
	var id string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND serial = $2`, e.tenantID, serial).Scan(&id); err != nil {
		e.t.Fatalf("homebrew device: %v", err)
	}
	e.devices = append(e.devices, id)
}

func (e *equivEstate) setHomebrewPolicy() {
	kind, name := "formula", "openssl@3"
	if e.pick(2) == 0 {
		kind, name = "cask", "firefox"
	}
	policy := []string{"unapproved", "approved", "unmanaged"}[e.pick(3)]
	e.exec(`INSERT INTO tenant_homebrew_policies (tenant_id, kind, name, tap, policy)
		VALUES ($1::uuid, $2, $3, '', $4)
		ON CONFLICT DO NOTHING`, e.tenantID, kind, name, policy)
	e.exec(`UPDATE tenant_homebrew_policies SET policy = $4, updated_at = now()
		WHERE tenant_id = $1::uuid AND kind = $2 AND name = $3`, e.tenantID, kind, name, policy)
}

// mutate applies one random change of the kinds the estate sees in life.
func (e *equivEstate) mutate() string {
	dev := e.randomDevice()
	switch op := e.pick(16); {
	case op == 0 || dev == "":
		e.addDevice()
		return "add device"
	case op <= 3:
		e.addApp(dev)
		return "add app"
	case op == 4:
		e.exec(`DELETE FROM device_apps WHERE id = (SELECT id FROM device_apps WHERE device_id = $1::uuid ORDER BY random() LIMIT 1)`, dev)
		return "remove app"
	case op == 5:
		e.exec(`UPDATE device_apps SET name = name || ' X' WHERE id = (SELECT id FROM device_apps WHERE device_id = $1::uuid ORDER BY id LIMIT 1)`, dev)
		return "rename app"
	case op == 6:
		e.exec(`UPDATE device_apps SET first_seen = first_seen - interval '3 days' WHERE device_id = $1::uuid`, dev)
		return "backdate first_seen"
	case op == 7:
		e.addExtension(dev)
		return "add extension"
	case op == 8:
		e.exec(`DELETE FROM device_browser_extensions WHERE id = (SELECT id FROM device_browser_extensions WHERE device_id = $1::uuid ORDER BY id LIMIT 1)`, dev)
		return "remove extension"
	case op == 9:
		e.setAppPolicy()
		return "app policy"
	case op == 10:
		e.exec(`UPDATE tenant_app_policies SET policy = $2, updated_at = now()
			WHERE id = (SELECT id FROM tenant_app_policies WHERE tenant_id = $1::uuid ORDER BY random() LIMIT 1)`,
			e.tenantID, equivAppPolicies[e.pick(len(equivAppPolicies))])
		return "flip app policy"
	case op == 11:
		e.exec(`DELETE FROM tenant_app_policies WHERE id = (SELECT id FROM tenant_app_policies WHERE tenant_id = $1::uuid ORDER BY random() LIMIT 1)`, e.tenantID)
		return "delete app policy"
	case op == 12:
		e.setExtensionPolicy()
		return "extension policy"
	case op == 13:
		// PAT-2135 retirement: a decision, not an inventory change.
		e.exec(`INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
			VALUES ($1::uuid, $2::uuid, $3, 'admin@equiv.example')`, e.tenantID, dev, []string{"retire", "unretire"}[e.pick(2)])
		return "retire/unretire"
	case op == 14:
		switch e.pick(3) {
		case 0:
			e.exec(`UPDATE devices SET os = CASE WHEN os = 'Windows' THEN 'macOS' ELSE 'Windows' END WHERE id = $1::uuid`, dev)
			return "flip os"
		case 1:
			e.exec(`UPDATE devices SET last_seen = now() - interval '20 days', hostname = hostname || 'z' WHERE id = $1::uuid`, dev)
			return "go stale"
		default:
			e.exec(`DELETE FROM devices WHERE id = $1::uuid`, dev)
			for i, d := range e.devices {
				if d == dev {
					e.devices = append(e.devices[:i], e.devices[i+1:]...)
					break
				}
			}
			return "delete device"
		}
	default:
		e.setHomebrewPolicy()
		return "homebrew policy"
	}
}

// catchUp brings the summary partly or wholly up to date, at random, the way
// production does: nothing (devices stay dirty), an ingest refresh of some
// devices, the runner's dirty sweep, or a full rebuild.
func (e *equivEstate) catchUp() string {
	ctx := context.Background()
	switch e.pick(4) {
	case 0:
		return "none"
	case 1:
		for i := 0; i < 3 && len(e.devices) > 0; i++ {
			if err := softwaregov.RefreshDevice(ctx, env.pool, e.tenantID, e.randomDevice(), time.Now()); err != nil {
				e.t.Fatalf("refresh device: %v", err)
			}
		}
		return "ingest refresh"
	case 2:
		if _, err := softwaregov.RefreshTenantDirty(ctx, env.pool, e.tenantID, time.Now()); err != nil {
			e.t.Fatalf("refresh dirty: %v", err)
		}
		return "dirty sweep"
	default:
		if err := softwaregov.ReconcileTenant(ctx, env.pool, e.tenantID, time.Now()); err != nil {
			e.t.Fatalf("reconcile: %v", err)
		}
		return "rebuild"
	}
}

func overviewString(o softwaregov.OverviewSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "products=%d devices=%d\n", o.Products, o.Devices)
	for _, it := range o.Items {
		fmt.Fprintf(&b, "  %s|%s|%q|%s|%s|%d|%s\n", it.Type, it.ProductKey, it.Name, it.Platform, it.Browser,
			it.DeviceCount, it.Since.UTC().Format(time.RFC3339Nano))
	}
	return b.String()
}

func assessmentsString(as []softwaregov.Assessment) string {
	var lines []string
	for _, a := range as {
		updated := "nil"
		if a.PolicyUpdatedAt != nil {
			updated = a.PolicyUpdatedAt.UTC().Format(time.RFC3339Nano)
		}
		var devs []string
		for _, d := range a.Devices {
			devs = append(devs, fmt.Sprintf("%s/%s/%s/%s/%s/%t", d.DeviceID, d.Hostname, d.Platform,
				d.ObservedSince.UTC().Format(time.RFC3339Nano), d.LastSeen.UTC().Format(time.RFC3339Nano), d.Stale))
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%q|%s|%s|%s|%s|%s|%s|%d|%s [%s]", a.Type, a.ProductKey, a.Name, a.Platform,
			a.TeamID, a.Browser, a.ExtensionID, a.Tap, a.State, a.PolicyID, updated, strings.Join(devs, " ")))
	}
	return strings.Join(lines, "\n")
}

// compare checks the summary against the full computation at one instant:
// the overview at two list lengths, and the per-policy device lists the
// marked alert reads, for every Unapproved policy row.
func (e *equivEstate) compare(step string) (usable bool) {
	e.t.Helper()
	ctx := context.Background()
	asOf := time.Now()
	for _, limit := range []int{0, 5} {
		full, err := softwaregov.UnapprovedOverviewFull(ctx, env.pool, e.tenantID, asOf, limit)
		if err != nil {
			e.t.Fatalf("%s: full overview: %v", step, err)
		}
		sum, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, e.tenantID, asOf, limit)
		if errors.Is(err, softwaregov.ErrSummaryUnusable) {
			return false
		}
		if err != nil {
			e.t.Fatalf("%s: summary overview: %v", step, err)
		}
		if a, b := overviewString(full), overviewString(sum); a != b {
			e.t.Fatalf("%s: overview (limit %d) differs\nfull:\n%s\nsummary:\n%s", step, limit, a, b)
		}
		// The public entry point answers the same, whichever path it takes.
		pub, err := softwaregov.UnapprovedOverview(ctx, env.pool, e.tenantID, asOf, limit)
		if err != nil {
			e.t.Fatalf("%s: overview: %v", step, err)
		}
		if a, b := overviewString(full), overviewString(pub); a != b {
			e.t.Fatalf("%s: UnapprovedOverview differs\nfull:\n%s\npublic:\n%s", step, a, b)
		}
	}
	type pol struct {
		kind string
		id   int64
	}
	var pols []pol
	rows, err := env.pool.Query(ctx, `
		SELECT 'application', id FROM tenant_app_policies WHERE tenant_id = $1::uuid
		UNION ALL SELECT 'browser_extension', id FROM tenant_extension_policies WHERE tenant_id = $1::uuid
		UNION ALL SELECT 'homebrew_' || kind, id FROM tenant_homebrew_policies WHERE tenant_id = $1::uuid`, e.tenantID)
	if err != nil {
		e.t.Fatal(err)
	}
	for rows.Next() {
		var p pol
		if err := rows.Scan(&p.kind, &p.id); err != nil {
			e.t.Fatal(err)
		}
		pols = append(pols, p)
	}
	rows.Close()
	for _, p := range pols {
		full, err := softwaregov.PolicyPresenceFull(ctx, env.pool, e.tenantID, p.kind, p.id, asOf)
		if err != nil {
			e.t.Fatalf("%s: full presence: %v", step, err)
		}
		sum, err := softwaregov.PolicyPresence(ctx, env.pool, e.tenantID, p.kind, p.id, asOf)
		if err != nil {
			e.t.Fatalf("%s: summary presence: %v", step, err)
		}
		if a, b := assessmentsString(full), assessmentsString(sum); a != b {
			e.t.Fatalf("%s: presence for %s %d differs\nfull:\n%s\nsummary:\n%s", step, p.kind, p.id, a, b)
		}
	}
	return true
}

func equivSeeds() []int64 {
	n := 8
	if v, err := strconv.Atoi(os.Getenv("PATCHED_EQUIV_SEEDS")); err == nil && v > 0 {
		n = v
	}
	seeds := make([]int64, n)
	base := time.Now().UnixNano()
	if v, err := strconv.ParseInt(os.Getenv("PATCHED_EQUIV_SEED"), 10, 64); err == nil {
		base = v
	}
	for i := range seeds {
		seeds[i] = base + int64(i)
	}
	// Keep the disclosed zero-app initial-coverage seed in ordinary runs,
	// while preserving explicit single-seed reproduction and random coverage.
	if os.Getenv("PATCHED_EQUIV_SEED") == "" {
		seeds[0] = 1790455257233084001
	}
	return seeds
}

func TestUnapprovedPresenceSummaryEquivalence(t *testing.T) {
	for _, seed := range equivSeeds() {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			t.Logf("reproduce with PATCHED_EQUIV_SEED=%d PATCHED_EQUIV_SEEDS=1", seed)
			e := newEquivEstate(t, seed)
			// Pre-seed a realistic estate, then rebuild once so the summary
			// starts usable.
			for i := 0; i < 12; i++ {
				e.addDevice()
			}
			for i := 0; i < 2; i++ {
				e.postHomebrew()
			}
			for _, d := range e.devices {
				for j := 0; j < 1+e.pick(8); j++ {
					e.addApp(d)
				}
				for j := 0; j < e.pick(3); j++ {
					e.addExtension(d)
				}
			}
			// Guarantee at least one Unapproved app and extension policy so
			// the overview reads the inventory at all.
			e.exec(`INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy) VALUES ($1::uuid, 'com.eq.app1', 'any', 'unapproved')`, e.tenantID)
			e.exec(`INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, policy) VALUES ($1::uuid, 'any', $2, 'unapproved')`, e.tenantID, equivExts[0])
			e.exec(`INSERT INTO tenant_homebrew_policies (tenant_id, kind, name, tap, policy) VALUES ($1::uuid, 'formula', 'openssl@3', '', 'unapproved')`, e.tenantID)
			for i := 0; i < 8; i++ {
				e.setAppPolicy()
			}
			// Random policies can approve/remove every initially Unapproved
			// app. Anchor coverage only after that setup, using an identity
			// outside the random policy catalogue. Keep the device mutable so
			// later deletions/retirement can still exercise empty presence.
			anchor := govDevice(t, e.tenantID, "equiv-initial-anchor", "macOS", time.Now())
			e.devices = append(e.devices, anchor)
			govApp(t, anchor, "Equivalence Anchor", "com.eq.initialanchor", "")
			e.exec(`INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
				VALUES ($1::uuid, 'com.eq.initialanchor', 'any', 'unapproved')`, e.tenantID)
			if err := softwaregov.ReconcileTenant(context.Background(), env.pool, e.tenantID, time.Now()); err != nil {
				t.Fatal(err)
			}
			if !e.compare("initial") {
				t.Fatal("summary unusable right after a rebuild")
			}
			// The generator must actually exercise every product type.
			var apps, exts, brews int
			if err := env.pool.QueryRow(context.Background(), `
				SELECT count(*) FILTER (WHERE policy_kind = 'application'),
				       count(*) FILTER (WHERE policy_kind = 'browser_extension'),
				       count(*) FILTER (WHERE policy_kind LIKE 'homebrew%')
				FROM software_unapproved_presence WHERE tenant_id = $1::uuid`, e.tenantID).Scan(&apps, &exts, &brews); err != nil {
				t.Fatal(err)
			}
			if apps == 0 || brews == 0 {
				t.Fatalf("initial estate has no Unapproved presence to compare: apps=%d exts=%d homebrew=%d", apps, exts, brews)
			}
			compared, unusable := 0, 0
			for step := 0; step < 60; step++ {
				var ops []string
				for k := 0; k < 1+e.pick(3); k++ {
					ops = append(ops, e.mutate())
				}
				catch := e.catchUp()
				label := fmt.Sprintf("step %d [%s] then %s", step, strings.Join(ops, ", "), catch)
				if e.compare(label) {
					compared++
					continue
				}
				unusable++
				// Unusable only while a policy change is unreconciled; a
				// rebuild always makes it usable and equal.
				if err := softwaregov.ReconcileTenant(context.Background(), env.pool, e.tenantID, time.Now()); err != nil {
					t.Fatal(err)
				}
				if !e.compare(label + " + rebuild") {
					t.Fatalf("%s: summary unusable after a rebuild", label)
				}
				compared++
			}
			t.Logf("compared %d states (%d needed a rebuild first)", compared, unusable)
		})
	}
}

// TestUnapprovedPresenceDirtyTracking proves the triggers mark exactly the
// writes that can change an answer, and that an ingest-shaped write landing
// after a refresh read its dirty mark keeps the device dirty.
func TestUnapprovedPresenceDirtyTracking(t *testing.T) {
	ctx := context.Background()
	g := newGovTenant(t, "dirty", "")
	dev := govDevice(t, g.id, "dirty-mac", "macOS", time.Now())
	dirty := func() bool {
		var ok bool
		if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_presence_dirty WHERE device_id = $1::uuid)`, dev).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	govApp(t, dev, "Dirty App", "com.eq.dirty", "")
	if !dirty() {
		t.Fatal("an app insert did not dirty the device")
	}
	if err := softwaregov.RefreshDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
		t.Fatal(err)
	}
	if dirty() {
		t.Fatal("a refresh left the device dirty")
	}
	// last_seen, version-only touches do not change an answer.
	if _, err := env.pool.Exec(ctx, `UPDATE device_apps SET last_seen = now(), launch_count = 3 WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE devices SET last_seen = now() WHERE id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	if dirty() {
		t.Fatal("a last_seen touch dirtied the device")
	}
	if _, err := env.pool.Exec(ctx, `UPDATE device_apps SET name = 'Dirty App 2' WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	if !dirty() {
		t.Fatal("a rename did not dirty the device")
	}

	// A write that lands between the refresh's read of the mark and its
	// clear keeps the device dirty: simulate by re-marking in a transaction
	// that commits after the refresh read the old mark value.
	var seq int64
	if err := env.pool.QueryRow(ctx, `SELECT seq FROM software_unapproved_presence_dirty WHERE device_id = $1::uuid`, dev).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE device_apps SET name = 'Dirty App 3' WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `DELETE FROM software_unapproved_presence_dirty WHERE device_id = $1::uuid AND seq = $2`, dev, seq); err != nil {
		t.Fatal(err)
	}
	if !dirty() {
		t.Fatal("a clear keyed on a stale mark removed a newer mark")
	}

	// Policy writes bump the version; an unrelated column does not.
	version := func() int64 {
		var v int64
		_ = env.pool.QueryRow(ctx, `SELECT policy_version FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid`, g.id).Scan(&v)
		return v
	}
	v0 := version()
	var pid int64
	if err := env.pool.QueryRow(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.eq.dirty', 'any', 'unapproved') RETURNING id`, g.id).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	v1 := version()
	if v1 <= v0 {
		t.Fatalf("policy insert did not bump the version: %d -> %d", v0, v1)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenant_app_policies SET notes = 'n', updated_at = now() WHERE id = $1`, pid); err != nil {
		t.Fatal(err)
	}
	if version() != v1 {
		t.Fatal("a notes-only edit bumped the policy version")
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenant_app_policies SET policy = 'approved' WHERE id = $1`, pid); err != nil {
		t.Fatal(err)
	}
	if version() <= v1 {
		t.Fatal("a policy value change did not bump the version")
	}
	if _, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, g.id, time.Now(), 5); err != nil && !errors.Is(err, softwaregov.ErrSummaryUnusable) {
		t.Fatal(err)
	}
}
