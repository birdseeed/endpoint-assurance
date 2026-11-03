//go:build integration

package integration

// PAT-2095 latency test: a synthetic 10,000-device estate, the portal
// overview, and a 500-product bulk mark, with ingest running throughout.
//
// Opt-in: it builds 200,000 inventory rows and takes a minute or two, so it
// runs only with PATCHED_PERF_TESTS=1. CI runs it in its own step of
// go-integration-test.yml (see that file); locally:
//
//	PATCHED_PERF_TESTS=1 go test -tags=integration -run TestUnapprovedPresenceLatency -v ./integration/
//
// Budgets asserted (chosen with headroom over what a laptop PG16 and the CI
// runner measure; see the PAT-2095 report for the numbers):
//
//	overview p95 (median of round p95s)   < 200ms (summary current)
//	bulk mark PUT (500 products)          < perfMarkBudget
//	ingest post-commit hook, max          < 1s while the marked alert is raised
//	ingest inventory write, max           < 250ms while the marked alert is raised

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/report"
	"patched.im/api/internal/softwaregov"
)

const (
	perfDevices        = 10000
	perfAppsPerDevice  = 20
	perfProducts       = 600
	perfMarked         = 500
	perfOverviewBudget = 200 * time.Millisecond
	perfMarkBudget     = 3 * time.Second
	perfIngestBudget   = time.Second
	// PAT-2235: the write budget has two parts. p99 stays at 250ms, so a
	// systematic slowdown during the raise fails. A single worst write may
	// reach 2s, because one ~270ms outlier among ~2,000 writes is runner
	// jitter on shared CI, while a write blocked on a lock the raise holds
	// stalls for seconds (the raise runs for about a minute) and still fails.
	perfWriteBudget    = 250 * time.Millisecond
	perfWriteMaxBudget = 2 * time.Second

	// PAT-2296: the overview gate is the median of perfOverviewRounds round p95s,
	// each taken over perfOverviewSamplesPerRound samples (200 in all).
	perfOverviewRounds          = 5
	perfOverviewSamplesPerRound = 40
)

func perfPercentile(ds []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s) == 0 {
		return 0
	}
	i := int(float64(len(s)-1) * p)
	return s[i]
}

func perfTeam(p int) string { return fmt.Sprintf("PT%08d", p%50) }

func TestUnapprovedPresenceLatency(t *testing.T) {
	if os.Getenv("PATCHED_PERF_TESTS") != "1" {
		t.Skip("PATCHED_PERF_TESTS=1 runs the 10k-device latency test")
	}
	ctx := context.Background()
	g := newGovTenant(t, "perf", "it@perf.example")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := env.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(sql)[0], err)
		}
	}

	start := time.Now()
	exec(`INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, last_seen)
		SELECT $1::uuid, 'PERF-' || i, gen_random_uuid(), 'perf-' || lpad(i::text, 5, '0'), 'macOS', '15.1',
		       now() - make_interval(days => (i % 20)::int)
		FROM generate_series(1, $2) i`, g.id, perfDevices)
	exec(`INSERT INTO device_apps (device_id, name, identifier, version, team_id, identifier_kind, first_seen)
		SELECT d.id, 'Perf App ' || p, 'com.perf.app' || lpad(p::text, 3, '0'), '1.0',
		       'PT' || lpad((p % 50)::text, 8, '0'), 'native', now() - make_interval(days => ((p + n) % 90)::int)
		FROM (SELECT id, row_number() OVER (ORDER BY id) AS n FROM devices WHERE tenant_id = $1::uuid) d
		CROSS JOIN LATERAL (SELECT DISTINCT ((d.n * 7 + j * 31) % $3)::int AS p FROM generate_series(1, $2) j) x`,
		g.id, perfAppsPerDevice, perfProducts)
	exec(`INSERT INTO device_browser_extensions (device_id, browser, user_account, profile, extension_id, name)
		SELECT d.id, 'chrome', 'user', 'Default', translate(md5(((d.n + j) % 50)::text), '0123456789', 'ghijklmnop'), 'Perf Ext'
		FROM (SELECT id, row_number() OVER (ORDER BY id) AS n FROM devices WHERE tenant_id = $1::uuid) d
		CROSS JOIN generate_series(1, 2) j`, g.id)
	// Standing policies: 20 Unapproved, 30 Approved, one Unapproved extension.
	exec(`INSERT INTO tenant_app_policies (tenant_id, bundle_id, team_id, platform, policy)
		SELECT $1::uuid, 'com.perf.app' || lpad(p::text, 3, '0'), 'PT' || lpad((p % 50)::text, 8, '0'), 'macos',
		       CASE WHEN p < 20 THEN 'unapproved' ELSE 'approved' END
		FROM generate_series(0, 49) p`, g.id)
	exec(`INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, policy)
		VALUES ($1::uuid, 'any', translate(md5('3'), '0123456789', 'ghijklmnop'), 'unapproved')`, g.id)
	exec(`ANALYZE devices`)
	exec(`ANALYZE device_apps`)
	exec(`ANALYZE device_browser_extensions`)
	var rows int
	_ = env.pool.QueryRow(ctx, `SELECT count(*) FROM device_apps da JOIN devices d ON d.id = da.device_id WHERE d.tenant_id = $1::uuid`, g.id).Scan(&rows)
	t.Logf("estate: %d devices, %d application rows, built in %s", perfDevices, rows, time.Since(start).Round(time.Millisecond))

	// Before: the full computation every overview request used to run.
	var full []time.Duration
	for i := 0; i < 5; i++ {
		s := time.Now()
		if _, err := softwaregov.UnapprovedOverviewFull(ctx, env.pool, g.id, time.Now(), 5); err != nil {
			t.Fatalf("full overview: %v", err)
		}
		full = append(full, time.Since(s))
	}
	t.Logf("BEFORE overview (full computation): p50 %s max %s", perfPercentile(full, .5), perfPercentile(full, 1))

	s := time.Now()
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Logf("initial summary rebuild: %s", time.Since(s).Round(time.Millisecond))
	// Exercise the production plan after autoanalyze, not an optimistic plan
	// based on an empty table's statistics. Keep maintenance outside timings.
	if _, err := env.pool.Exec(ctx, `ANALYZE software_unapproved_presence`); err != nil {
		t.Fatal(err)
	}

	overview := func(label string) {
		t.Helper()
		var ds, roundP95s []time.Duration
		for round := 0; round < perfOverviewRounds; round++ {
			var rd []time.Duration
			for i := 0; i < perfOverviewSamplesPerRound; i++ {
				s := time.Now()
				if _, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, g.id, time.Now(), 5); err != nil {
					t.Fatalf("%s overview: %v", label, err)
				}
				rd = append(rd, time.Since(s))
			}
			ds = append(ds, rd...)
			roundP95s = append(roundP95s, perfPercentile(rd, .95))
		}
		// The whole handler, over HTTP, as the portal calls it.
		var hs []time.Duration
		for i := 0; i < 10; i++ {
			s := time.Now()
			resp := portalDo(t, http.MethodGet, "/v1/portal/overview", g.adminToken, nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /v1/portal/overview = %d", resp.StatusCode)
			}
			hs = append(hs, time.Since(s))
		}
		// The other figures on the same overview response, for context:
		// they are outside PAT-2095 and not asserted.
		timeIt := func(fn func() error) time.Duration {
			s := time.Now()
			if err := fn(); err != nil {
				t.Fatalf("%s overview component: %v", label, err)
			}
			return time.Since(s)
		}
		base := timeIt(func() error { _, err := report.FetchPortalOverview(ctx, env.pool, g.id); return err })
		counts := timeIt(func() error { _, _, err := softwaregov.ActiveAlertCounts(ctx, env.pool, g.id); return err })
		newSW := timeIt(func() error {
			_, err := softwaregov.FetchNewSoftwareUrgency(ctx, env.pool, g.id, time.Now())
			return err
		})
		t.Logf("%s other overview components: FetchPortalOverview %s, ActiveAlertCounts %s, FetchNewSoftwareUrgency %s",
			label, base.Round(time.Millisecond), counts.Round(time.Millisecond), newSW.Round(time.Millisecond))
		// PAT-2296: gate on the median of the round p95s, not on one p95. The
		// perfPercentile p95 of 40 samples is the third-worst sample, so a single
		// noisy scheduling hiccup on a shared CI runner trips it: one run logged
		// 205ms on a commit that touched none of these queries and the re-run of
		// that same commit passed at 162ms. The median of several round p95s
		// tolerates one or two noisy rounds, while a genuine regression (a dropped
		// index, a plan change) lifts every round and still fails. The 200ms
		// budget was deliberately NOT raised. All the round p95s are logged, so a
		// failing log shows whether it was noise (one or two rounds high) or a
		// consistent shift (all of them high).
		medianP95 := perfPercentile(roundP95s, .5)
		t.Logf("%s overview (summary): round p95s %v, median of round p95s %s; all %d samples p50 %s max %s; GET /v1/portal/overview p50 %s max %s",
			label, roundP95s, medianP95, len(ds), perfPercentile(ds, .5), perfPercentile(ds, 1), perfPercentile(hs, .5), perfPercentile(hs, 1))
		if medianP95 > perfOverviewBudget {
			t.Errorf("%s overview: median of %d round p95s %s over the %s budget (round p95s %v)",
				label, perfOverviewRounds, medianP95, perfOverviewBudget, roundP95s)
		}
	}
	overview("AFTER")
	assertOverviewEquivalent(t, g.id)

	// The bulk mark: 500 products, each on about 333 devices.
	items := make([]string, 0, perfMarked)
	for p := perfProducts - perfMarked; p < perfProducts; p++ {
		items = append(items, macApp(fmt.Sprintf("com.perf.app%03d", p), perfTeam(p)))
	}
	s = time.Now()
	status, body := putApprovals(t, g.adminToken, approvalBody("unapproved", "", items...))
	markTook := time.Since(s)
	if status != http.StatusOK {
		t.Fatalf("bulk mark = %d: %s", status, body)
	}
	t.Logf("bulk mark PUT (%d products): %s", perfMarked, markTook.Round(time.Millisecond))
	if markTook > perfMarkBudget {
		t.Errorf("bulk mark took %s, over the %s budget", markTook, perfMarkBudget)
	}
	if n := len(govAlerts(t, g.id)); n != 0 {
		t.Fatalf("the PUT raised %d alerts on the request path", n)
	}

	// The runner's raise (summary rebuild, then one transaction per
	// episode), with ingest running against random devices the whole time.
	var wg sync.WaitGroup
	raiseDone := make(chan struct{})
	var raiseErr error
	var raiseTook time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(raiseDone)
		s := time.Now()
		raiseErr = softwaregov.RaiseUnraised(ctx, env.pool, time.Now())
		raiseTook = time.Since(s)
	}()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var devIDs []string
	r, err := env.pool.Query(ctx, `SELECT id::text FROM devices WHERE tenant_id = $1::uuid`, g.id)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var id string
		_ = r.Scan(&id)
		devIDs = append(devIDs, id)
	}
	r.Close()
	var writes, hooks []time.Duration
	for n := 0; ; n++ {
		select {
		case <-raiseDone:
		default:
			dev := devIDs[rng.Intn(len(devIDs))]
			p := rng.Intn(perfProducts)
			s := time.Now()
			// The extractor's inventory transaction, as far as this feature
			// touches it: an app row plus the dirty-marking trigger.
			exec(`INSERT INTO device_apps (device_id, name, identifier, version, team_id, identifier_kind)
				VALUES ($1::uuid, $2, $3, $4, $5, 'native') ON CONFLICT DO NOTHING`,
				dev, fmt.Sprintf("Perf App %d", p), fmt.Sprintf("com.perf.app%03d", p), fmt.Sprintf("2.%d", n), perfTeam(p))
			writes = append(writes, time.Since(s))
			s = time.Now()
			// The post-commit hook: summary refresh, then DetectOnDevice.
			if err := softwaregov.RefreshDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
				t.Fatalf("ingest refresh: %v", err)
			}
			if _, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
				t.Fatalf("ingest detect: %v", err)
			}
			hooks = append(hooks, time.Since(s))
			continue
		}
		break
	}
	wg.Wait()
	if raiseErr != nil {
		t.Fatalf("raise: %v", raiseErr)
	}
	var alerts, ledger int
	_ = env.pool.QueryRow(ctx, `SELECT count(*) FROM software_unapproved_alerts WHERE tenant_id = $1::uuid AND trigger = 'marked'`, g.id).Scan(&alerts)
	_ = env.pool.QueryRow(ctx, `SELECT count(*) FROM software_unapproved_alerted_devices WHERE tenant_id = $1::uuid`, g.id).Scan(&ledger)
	t.Logf("runner raise: %s for %d marked alerts, %d tracked (episode, device) pairs", raiseTook.Round(time.Millisecond), alerts, ledger)
	t.Logf("ingest during the raise (%d reports): inventory write p50 %s max %s; post-commit hook p50 %s p95 %s max %s",
		len(hooks), perfPercentile(writes, .5), perfPercentile(writes, 1),
		perfPercentile(hooks, .5), perfPercentile(hooks, .95), perfPercentile(hooks, 1))
	if alerts != perfMarked {
		t.Errorf("marked alerts = %d, want %d", alerts, perfMarked)
	}
	if len(hooks) == 0 {
		t.Error("no ingest ran during the raise")
	}
	if m := perfPercentile(hooks, 1); m > perfIngestBudget {
		t.Errorf("an ingest post-commit hook took %s during the raise, over %s", m, perfIngestBudget)
	}
	if m := perfPercentile(writes, .99); m > perfWriteBudget {
		t.Errorf("ingest inventory writes during the raise: p99 %s, over %s", m, perfWriteBudget)
	}
	if m := perfPercentile(writes, 1); m > perfWriteMaxBudget {
		t.Errorf("an ingest inventory write took %s during the raise, over %s: something blocked it", m, perfWriteMaxBudget)
	}

	if _, err := softwaregov.RefreshTenantDirty(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `ANALYZE software_unapproved_presence`); err != nil {
		t.Fatal(err)
	}
	overview("AFTER MARK")
	assertOverviewEquivalent(t, g.id)
}

// assertOverviewEquivalent compares the summary against the full computation
// on the same estate.
func assertOverviewEquivalent(t *testing.T, tenantID string) {
	t.Helper()
	ctx := context.Background()
	asOf := time.Now()
	full, err := softwaregov.UnapprovedOverviewFull(ctx, env.pool, tenantID, asOf, 5)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, tenantID, asOf, 5)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := overviewString(full), overviewString(sum); a != b {
		t.Fatalf("summary differs from the full computation\nfull:\n%s\nsummary:\n%s", a, b)
	}
}
