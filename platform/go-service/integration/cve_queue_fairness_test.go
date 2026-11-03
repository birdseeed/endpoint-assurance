//go:build integration

package integration

// PAT-2030: cve_match_queue fairness across tenants. The queue used to have
// one global soft cap and an oldest-first drain, so one tenant with a large
// backlog (a big estate onboarding, or a mapping change fanning out across a
// large tenant) could fill the queue and hold every other tenant's change
// back: refused at the cap, or waiting behind the backlog, until the nightly
// full match.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/cvepipeline"
	"patched.im/api/internal/metrics"
)

type fairnessTenant struct {
	id      string
	devices []string
}

// fairnessFixture seeds one mapped, vulnerable product and settles the
// shared queue, so the mapping publish is expanded before any test device
// exists and the queue then holds only what the test itself enqueues (plus
// whatever stuck rows earlier tests left, counted in baseline).
type fairnessFixture struct {
	app, vendor, cveID string
	baseline           int
}

func newFairnessFixture(t *testing.T, tag string) fairnessFixture {
	t.Helper()
	sfx := randomHex(4)
	f := fairnessFixture{
		app:    "Pat2030 Fairapp " + tag + " " + sfx,
		vendor: "pat2030" + tag + sfx,
		cveID:  "CVE-2099-" + sfx + tag,
	}
	seedFeedEntry(t, f.cveID, f.vendor, "fairapp", "9.0", false)
	seedCVEMapping(t, f.app, f.vendor, "fairapp")
	drainCVEQueue(t)
	f.baseline = countRows(t, `SELECT count(*) FROM cve_match_queue`)
	return f
}

func newFairnessTenant(t *testing.T, app, name string, devices int) fairnessTenant {
	t.Helper()
	return newFairnessTenantWithIDPrefix(t, app, name, devices, "")
}

// newFairnessTenantWithIDPrefix seeds devices whose UUIDs start with
// idPrefix (two hex digits), so a test can control how the tenants' devices
// interleave in device_id order. An empty prefix leaves the IDs random.
func newFairnessTenantWithIDPrefix(t *testing.T, app, name string, devices int, idPrefix string) fairnessTenant {
	t.Helper()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatalf("create tenant %s: %v", name, err)
	}
	tn := fairnessTenant{id: tenantID}
	for i := 0; i < devices; i++ {
		host := fmt.Sprintf("%s-%d", name, i)
		if idPrefix == "" {
			tn.devices = append(tn.devices, seedCVEDevice(t, tenantID, host,
				[]cveTestApp{{app, "1.0", "com.example.pat2030"}}))
			continue
		}
		h := idPrefix + randomHex(15)[:30]
		id := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
		ctx := context.Background()
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO devices (id, tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen)
			VALUES ($1::uuid, $2::uuid, $3, gen_random_uuid(), $3, 'macOS', '15.5', 'arm64', now())
		`, id, tenantID, host); err != nil {
			t.Fatalf("seed device %s: %v", host, err)
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version) VALUES ($1::uuid, $2, 'com.example.pat2030', '1.0')
		`, id, app); err != nil {
			t.Fatalf("seed app on %s: %v", host, err)
		}
		tn.devices = append(tn.devices, id)
	}
	return tn
}

// enqueueEach queues the app on each device in turn, one statement each, so
// the rows' queue order is the device order.
func enqueueEach(t *testing.T, tn fairnessTenant, app string) (enqueued, dropped int) {
	t.Helper()
	for _, d := range tn.devices {
		e, dr, err := cvepipeline.EnqueueObservations(context.Background(), env.pool, tn.id, d, []string{app}, cvepipeline.SourceIngest)
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		enqueued += e
		dropped += dr
	}
	return enqueued, dropped
}

// setQueueCaps lowers the global and per-tenant caps for one test.
func setQueueCaps(t *testing.T, global, perTenant int) {
	t.Helper()
	savedGlobal, savedTenant := cvepipeline.QueueCapacity, cvepipeline.TenantQueueCapacity
	t.Cleanup(func() {
		cvepipeline.QueueCapacity, cvepipeline.TenantQueueCapacity = savedGlobal, savedTenant
	})
	cvepipeline.QueueCapacity, cvepipeline.TenantQueueCapacity = global, perTenant
}

// matchedDevices returns which of devices have the fixture's finding, in
// the order given.
func matchedDevices(t *testing.T, f fairnessFixture, devices []string) []string {
	t.Helper()
	var out []string
	for _, d := range devices {
		if countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, d, f.cveID) == 1 {
			out = append(out, d)
		}
	}
	return out
}

func queuedFor(t *testing.T, tenantID string) int {
	t.Helper()
	return countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'observation' AND tenant_id = $1::uuid`, tenantID)
}

func drainOnce(t *testing.T, batch int) cvepipeline.DrainResult {
	t.Helper()
	res, err := cvepipeline.Drain(context.Background(), env.pool, nil, batch)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if res.SkippedForFullMatch {
		t.Fatal("Drain skipped for the full match; the cycle under test never ran")
	}
	return res
}

// Done-when for PAT-2030: tenant A fills the queue to its cap with changes
// older than tenant B's, and B's one change is still matched in the very
// next drain cycle, even though that cycle has room for only a third of A's
// backlog.
func TestCVEQueueTenantAtCapCannotBlockAnotherTenant(t *testing.T) {
	f := newFairnessFixture(t, "cap")
	const capA, batch = 30, 10
	setQueueCaps(t, f.baseline+capA+5, capA)

	a := newFairnessTenant(t, f.app, "pat2030-noisy-"+randomHex(4), capA+10)
	b := newFairnessTenant(t, f.app, "pat2030-quiet-"+randomHex(4), 1)

	aIn, aDropped := enqueueEach(t, a, f.app)
	if aIn < capA || aDropped == 0 {
		t.Fatalf("tenant A: enqueued %d dropped %d, want at least %d enqueued and some dropped (A at its cap)", aIn, aDropped, capA)
	}
	bIn, bDropped := enqueueEach(t, b, f.app)

	drainOnce(t, batch)

	matched := len(matchedDevices(t, f, b.devices))
	stillQueued := queuedFor(t, b.id)
	if matched != 1 || stillQueued != 0 {
		t.Fatalf("tenant B's change was not matched within one drain cycle while tenant A sat at its cap: "+
			"B enqueue (enqueued=%d dropped=%d), B finding rows=%d, B rows still queued=%d",
			bIn, bDropped, matched, stillQueued)
	}
	// A kept exactly its share: capped at capA, and matched only what the
	// batch had left after B.
	if aIn != capA || aDropped != 10 {
		t.Fatalf("tenant A: enqueued %d dropped %d, want %d and 10 at its per-tenant cap", aIn, aDropped, capA)
	}
	if got := queuedFor(t, a.id); got != capA-(batch-1) {
		t.Fatalf("tenant A rows left after one cycle = %d, want %d", got, capA-(batch-1))
	}
}

// PAT-2169: cap refusals retain the global counter used by existing alerts,
// and add only the affected tenant as attribution. Device and product never
// appear in metric labels.
func TestCVEQueueTenantDroppedMetric(t *testing.T) {
	f := newFairnessFixture(t, "dropped")
	tn := newFairnessTenant(t, f.app, "pat2169-dropped-"+randomHex(4), 1)
	setQueueCaps(t, 1<<30, 0)

	globalBefore := testutil.ToFloat64(metrics.CVEMatchQueueDropped)
	tenantBefore := testutil.ToFloat64(metrics.CVEMatchQueueTenantDropped.WithLabelValues(tn.id))
	enqueued, dropped := enqueueEach(t, tn, f.app)
	if enqueued != 0 || dropped != 1 {
		t.Fatalf("cap refusal enqueued=%d dropped=%d, want 0 and 1", enqueued, dropped)
	}
	if got := testutil.ToFloat64(metrics.CVEMatchQueueDropped) - globalBefore; got != 1 {
		t.Fatalf("global dropped counter increment = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.CVEMatchQueueTenantDropped.WithLabelValues(tn.id)) - tenantBefore; got != 1 {
		t.Fatalf("tenant dropped counter increment = %v, want 1", got)
	}
}

// The drain half on its own: no cap is anywhere near binding, but A's
// backlog is older than B's change and larger than one batch. Oldest-first
// would spend the whole batch on A.
func TestCVEQueueDrainIsRoundRobinAcrossTenants(t *testing.T) {
	f := newFairnessFixture(t, "rr")
	const batch = 10
	a := newFairnessTenant(t, f.app, "pat2030-rr-a-"+randomHex(4), 3*batch)
	b := newFairnessTenant(t, f.app, "pat2030-rr-b-"+randomHex(4), 1)
	enqueueEach(t, a, f.app)
	enqueueEach(t, b, f.app)

	drainOnce(t, batch)

	if got := matchedDevices(t, f, b.devices); len(got) != 1 {
		t.Fatalf("tenant B's change waited behind tenant A's older backlog: B matched %d of 1", len(got))
	}
	if got := len(matchedDevices(t, f, a.devices)); got != batch-1 {
		t.Fatalf("tenant A matched %d, want the rest of the batch (%d)", got, batch-1)
	}
}

// Within a tenant the drain is still oldest first, and two tenants with
// equal backlogs share one batch evenly: A1 B1 A2 B2 A3 B3.
func TestCVEQueueDrainKeepsOldestFirstWithinTenant(t *testing.T) {
	f := newFairnessFixture(t, "ord")
	const perTenant, batch = 6, 6
	a := newFairnessTenant(t, f.app, "pat2030-ord-a-"+randomHex(4), perTenant)
	b := newFairnessTenant(t, f.app, "pat2030-ord-b-"+randomHex(4), perTenant)
	// All of A's rows are older than all of B's.
	enqueueEach(t, a, f.app)
	enqueueEach(t, b, f.app)

	drainOnce(t, batch)

	for _, tn := range []struct {
		name string
		t    fairnessTenant
	}{{"A", a}, {"B", b}} {
		got := matchedDevices(t, f, tn.t.devices)
		want := tn.t.devices[:batch/2]
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("tenant %s matched %v, want its %d oldest in queue order %v", tn.name, got, batch/2, want)
		}
	}
}

// QueueCapacity is still a hard-as-before bound on the total even when no
// tenant is near its own cap.
func TestCVEQueueGlobalCapStillBoundsTotal(t *testing.T) {
	f := newFairnessFixture(t, "glob")
	const room = 8
	setQueueCaps(t, f.baseline+room, 1000)
	var total, dropped int
	for i := 0; i < 3; i++ {
		tn := newFairnessTenant(t, f.app, fmt.Sprintf("pat2030-glob-%d-%s", i, randomHex(4)), 5)
		in, dr := enqueueEach(t, tn, f.app)
		total += in
		dropped += dr
	}
	if total != room || dropped != 15-room {
		t.Fatalf("enqueued %d dropped %d across three tenants, want %d and %d under the global cap", total, dropped, room, 15-room)
	}
	if depth := countRows(t, `SELECT count(*) FROM cve_match_queue`); depth != f.baseline+room {
		t.Fatalf("queue depth %d exceeds the global cap %d", depth, f.baseline+room)
	}
}

// A mapping publish expands across tenants in one statement. When the global
// room is short, it is shared round-robin across those tenants (not handed
// out in device_id order), each tenant is still bounded by its own cap, and
// the mapping job is kept for the next cycle as before.
func TestCVEQueueMappingExpansionSharesGlobalRoomAcrossTenants(t *testing.T) {
	sfx := randomHex(4)
	app := "Pat2030 Expandapp " + sfx
	vendor := "pat2030x" + sfx
	cveID := "CVE-2099-" + sfx + "x"
	seedFeedEntry(t, cveID, vendor, "expandapp", "9.0", false)
	drainCVEQueue(t)
	// Every device of A sorts before every device of B, so handing the room
	// out in device_id order would give it all to A.
	a := newFairnessTenantWithIDPrefix(t, app, "pat2030-x-a-"+sfx, 8, "00")
	b := newFairnessTenantWithIDPrefix(t, app, "pat2030-x-b-"+sfx, 8, "ff")
	baseline := countRows(t, `SELECT count(*) FROM cve_match_queue`)
	// Room for the mapping job plus 6 observations.
	setQueueCaps(t, baseline+1+6, 1000)

	seedCVEMapping(t, app, vendor, "expandapp")
	drainOnce(t, 1000)

	f := fairnessFixture{app: app, cveID: cveID}
	gotA, gotB := len(matchedDevices(t, f, a.devices)), len(matchedDevices(t, f, b.devices))
	if gotA != 3 || gotB != 3 {
		t.Fatalf("global room of 6 split A=%d B=%d, want 3 each", gotA, gotB)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'mapping' AND match_name = $1`, app); n != 1 {
		t.Fatalf("mapping job not kept for retry after dropped observations (%d left)", n)
	}

	// Now the per-tenant cap binds in the same expansion: the kept mapping
	// job re-expands to all 8 devices of each tenant, and each tenant is
	// allowed only 2 queued, so this cycle matches exactly 2 per tenant.
	setQueueCaps(t, 1<<30, 2)
	var since time.Time
	if err := env.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&since); err != nil {
		t.Fatal(err)
	}
	drainOnce(t, 1000)
	for _, tn := range []fairnessTenant{a, b} {
		n := countRows(t, `SELECT count(*) FROM cve_match_assessments
			WHERE tenant_id = $1::uuid AND app_name = $2 AND last_matched_at >= $3`, tn.id, app, since)
		if n != 2 {
			t.Fatalf("tenant %s: %d observations matched in a per-tenant-capped expansion, want 2", tn.id, n)
		}
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'mapping' AND match_name = $1`, app); n != 1 {
		t.Fatalf("mapping job not kept after the per-tenant cap dropped observations (%d left)", n)
	}

	setQueueCaps(t, 1<<30, 1<<30)
	drainCVEQueue(t)
	if gotA, gotB := len(matchedDevices(t, f, a.devices)), len(matchedDevices(t, f, b.devices)); gotA != 8 || gotB != 8 {
		t.Fatalf("once caps lifted A=%d B=%d matched, want all 8 each", gotA, gotB)
	}
}

// PAT-2169: a retained mapping job re-expands every extractor cycle while a
// tenant is at its cap. That retry is not new device evidence, so it must not
// reset a stuck observation's attempts or last_error and let it evade
// MaxAttempts. A direct ingest refresh is new evidence and still resets both.
func TestCVEQueueMappingReexpansionPreservesRetryState(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	app := "Pat2169 Retryapp " + sfx
	vendor := "pat2169r" + sfx
	cveID := "CVE-2099-" + sfx + "r"
	seedFeedEntry(t, cveID, vendor, "retryapp", "9.0", false)
	tn := newFairnessTenant(t, app, "pat2169-retry-"+sfx, 2)
	setQueueCaps(t, 1<<30, 1)
	t.Cleanup(func() {
		if _, err := env.pool.Exec(ctx, `DELETE FROM cve_match_queue
			WHERE device_id = $1::uuid OR (kind = 'mapping' AND match_name = $2)`, tn.devices[0], app); err != nil {
			t.Errorf("clean retry queue rows: %v", err)
		}
	})

	seedCVEMapping(t, app, vendor, "retryapp")
	drainOnce(t, 1000) // one observation matches; the cap keeps the mapping job.
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'mapping' AND match_name = $1`, app); n != 1 {
		t.Fatalf("mapping job after first capped expansion = %d, want 1", n)
	}
	if enqueued, dropped, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.id, tn.devices[0], []string{app}, cvepipeline.SourceIngest); err != nil || enqueued != 1 || dropped != 0 {
		t.Fatalf("enqueue stuck observation = (%d, %d, %v), want (1, 0, nil)", enqueued, dropped, err)
	}
	const lastError = "forced matcher failure"
	if _, err := env.pool.Exec(ctx, `UPDATE cve_match_queue
		SET attempts = $1, last_error = $2
		WHERE kind = 'observation' AND device_id = $3::uuid AND app_name = $4`, cvepipeline.MaxAttempts, lastError, tn.devices[0], app); err != nil {
		t.Fatal(err)
	}

	// A one-observation drain still expands mapping work before it claims any
	// observation. With the stuck row occupying this tenant's share, the
	// second device remains refused.
	res := drainOnce(t, 1)
	if res.Expanded < 2 {
		t.Fatalf("capped re-expansion did not include both tenant observations: %+v", res)
	}
	var attempts int
	var gotError *string
	if err := env.pool.QueryRow(ctx, `SELECT attempts, last_error FROM cve_match_queue
		WHERE kind = 'observation' AND device_id = $1::uuid AND app_name = $2`, tn.devices[0], app).Scan(&attempts, &gotError); err != nil {
		t.Fatal(err)
	}
	if attempts != cvepipeline.MaxAttempts || gotError == nil || *gotError != lastError {
		t.Fatalf("mapping re-expansion changed stuck retry state to attempts=%d last_error=%v, want %d and %q", attempts, gotError, cvepipeline.MaxAttempts, lastError)
	}
	if attempts < cvepipeline.MaxAttempts {
		t.Fatalf("stuck row became claimable after mapping re-expansion: attempts=%d, max=%d", attempts, cvepipeline.MaxAttempts)
	}
	if n := countRows(t, `SELECT count(*) FROM cve_match_queue WHERE kind = 'mapping' AND match_name = $1`, app); n != 1 {
		t.Fatalf("mapping job was removed despite the capped second observation (%d left)", n)
	}

	// A direct inventory change remains a legitimate refresh of this queued
	// observation and restores it to the retryable state.
	if enqueued, dropped, err := cvepipeline.EnqueueObservations(ctx, env.pool, tn.id, tn.devices[0], []string{app}, cvepipeline.SourceIngest); err != nil || enqueued != 1 || dropped != 0 {
		t.Fatalf("ingest refresh = (%d, %d, %v), want (1, 0, nil)", enqueued, dropped, err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT attempts, last_error FROM cve_match_queue
		WHERE kind = 'observation' AND device_id = $1::uuid AND app_name = $2`, tn.devices[0], app).Scan(&attempts, &gotError); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || gotError != nil {
		t.Fatalf("ingest refresh retry state attempts=%d last_error=%v, want 0 and NULL", attempts, gotError)
	}
}

// PAT-2169: migration 0203 drops 0161's redundant tenant-only index only
// because 0194's partial composite index covers every former tenant-prefix
// access: capacity counts, tenant enumeration, the ordered drain prefix, and
// queue metrics aggregation. The pending-assessment lookup instead has the
// existing device_id/app_name unique index as its narrower surviving path.
// Disable scans that cannot prove index capability; this is a shape
// regression, not a fragile local-cardinality cost benchmark.
func TestCVEQueueTenantIndexesCoverAllAccessPaths(t *testing.T) {
	ctx := context.Background()
	const tenants, observationsPerTenant = 21, 100
	app := "Pat2169 Planner " + randomHex(4)
	var tenantIDs []string
	var plannerTenant, plannerDevice string
	for i := 0; i < tenants; i++ {
		tenantID, _, _, err := createTestTenant(env.internalSrv.URL, fmt.Sprintf("pat2169-plan-%02d-%s", i, randomHex(3)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO devices (id, tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen)
			SELECT gen_random_uuid(), $1::uuid, $2 || '-' || n, gen_random_uuid(), $2 || '-' || n,
			       'macOS', '15.5', 'arm64', now()
			FROM generate_series(1, $3) AS n
		`, tenantID, fmt.Sprintf("pat2169-plan-device-%02d", i), observationsPerTenant); err != nil {
			t.Fatal(err)
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO cve_match_queue (kind, reason, tenant_id, device_id, app_name, enqueued_at)
			SELECT 'observation', 'ingest', tenant_id, id, $2, now() - random() * interval '100 seconds'
			FROM devices WHERE tenant_id = $1::uuid
		`, tenantID, app); err != nil {
			t.Fatal(err)
		}
		tenantIDs = append(tenantIDs, tenantID)
		if i == 0 {
			plannerTenant = tenantID
			if err := env.pool.QueryRow(ctx, `SELECT id::text FROM devices WHERE tenant_id = $1::uuid ORDER BY id LIMIT 1`, tenantID).Scan(&plannerDevice); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := env.pool.Exec(ctx, `ANALYZE cve_match_queue`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.pool.Exec(ctx, `DELETE FROM cve_match_queue WHERE tenant_id = ANY($1::uuid[])`, tenantIDs); err != nil {
			t.Errorf("clean planner queue rows: %v", err)
		}
	})
	conn, err := env.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	// Run the EXPLAINs inside a rolled-back transaction with SET LOCAL, not a
	// session-level SET on the pooled connection: SET here would otherwise
	// leak enable_seqscan/enable_hashagg=off back into the pool for whatever
	// test acquires this connection next.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// enable_seqscan/enable_bitmapscan off rules out a full scan of the
	// table. That alone isn't enough to make the plan deterministic: the
	// tenant-metrics query has no tenant_id filter, so the composite
	// (tenant_id, enqueued_at, id) index and the unrelated
	// uq_cve_match_queue_observation (device_id, app_name) index are both
	// full-index-scan candidates for kind = 'observation', and on a table
	// this size their estimated costs are close enough that physical index
	// size (itself sensitive to prior tests' churn in the shared queue
	// table) can tip the planner either way, with HashAggregate absorbing
	// whichever one it picks. enable_hashagg off removes that escape hatch:
	// GroupAggregate needs input already sorted by tenant_id, which only the
	// composite index provides, so it wins on cost without needing a sort.
	if _, err := tx.Exec(ctx, `
		SET LOCAL enable_seqscan = off;
		SET LOCAL enable_bitmapscan = off;
		SET LOCAL enable_hashagg = off;
	`); err != nil {
		t.Fatal(err)
	}
	explain := func(name string, requireComposite bool, query string, args ...any) {
		t.Helper()
		rows, err := tx.Query(ctx, "EXPLAIN (COSTS OFF) "+query, args...)
		if err != nil {
			t.Fatalf("explain %s: %v", name, err)
		}
		defer rows.Close()
		var plan []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, line)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate %s plan: %v", name, err)
		}
		got := strings.Join(plan, "\n")
		t.Logf("%s plan:\n%s", name, got)
		if strings.Contains(got, "idx_cve_match_queue_tenant_order") {
			return
		}
		// The pending-assessment query is keyed by device_id and app_name,
		// so its existing partial unique index is more selective than either
		// tenant prefix. It remains indexed after 0203 removes 0161.
		if !requireComposite && name == "pending assessment" && strings.Contains(got, "uq_cve_match_queue_observation") {
			return
		}
		if requireComposite {
			t.Fatalf("%s did not use the tenant-prefix composite index:\n%s", name, got)
		}
		t.Fatalf("%s did not use a surviving queue index:\n%s", name, got)
	}
	explain("tenant capacity", true, `
		SELECT count(*)::int FROM cve_match_queue
		WHERE kind = 'observation' AND tenant_id = $1::uuid`, plannerTenant)
	explain("tenant metrics", true, `
		SELECT tenant_id::text, count(*)::int,
		       GREATEST(EXTRACT(EPOCH FROM now() - min(enqueued_at)), 0)::float8
		FROM cve_match_queue
		WHERE kind = 'observation'
		GROUP BY tenant_id
		ORDER BY tenant_id`)
	explain("tenant walk", true, `
		SELECT tenant_id FROM cve_match_queue
		WHERE kind = 'observation' AND tenant_id > $1::uuid
		ORDER BY tenant_id LIMIT 1`, plannerTenant)
	explain("drain prefix", true, `
		SELECT q.id, q.device_id::text, q.app_name
		FROM cve_match_queue q
		WHERE q.kind = 'observation' AND q.tenant_id = $1::uuid AND q.attempts < $2
		ORDER BY q.enqueued_at, q.id
		LIMIT $3`, plannerTenant, cvepipeline.MaxAttempts, 500)
	explain("pending assessment", false, `
		SELECT device_id::text, app_name FROM cve_match_queue
		WHERE kind = 'observation' AND tenant_id = $1::uuid AND device_id = ANY($2::uuid[])`, plannerTenant, []string{plannerDevice})
	var oldIndex, compositeIndex *string
	if err := conn.QueryRow(ctx, `SELECT to_regclass('idx_cve_match_queue_tenant')::text,
		to_regclass('idx_cve_match_queue_tenant_order')::text`).Scan(&oldIndex, &compositeIndex); err != nil {
		t.Fatal(err)
	}
	if oldIndex != nil || compositeIndex == nil {
		t.Fatalf("index migration state old=%v composite=%v, want old absent and composite present", oldIndex, compositeIndex)
	}
}

// The forward and rollback scripts run against the same migrated database:
// rollback restores the former index and receipt, then forward returns the
// schema to its deployed shape. This proves 0203 is reversible without
// touching queue rows or CVE evidence.
func TestCVEQueueTenantIndexMigrationRollbackRestoresOldIndex(t *testing.T) {
	ctx := context.Background()
	for _, file := range []string{
		"0203_drop_redundant_cve_match_queue_tenant_index_rollback.sql",
		"0203_drop_redundant_cve_match_queue_tenant_index.sql",
	} {
		sql, err := os.ReadFile(filepath.Join("..", "migrations", file))
		if err != nil {
			t.Fatal(err)
		}
		if err := execMigration(ctx, env.pool, string(sql)); err != nil {
			t.Fatalf("execute %s: %v", file, err)
		}
		var oldIndex *string
		if err := env.pool.QueryRow(ctx, `SELECT to_regclass('idx_cve_match_queue_tenant')::text`).Scan(&oldIndex); err != nil {
			t.Fatal(err)
		}
		wantOld := strings.Contains(file, "rollback")
		if (oldIndex != nil) != wantOld {
			t.Fatalf("after %s old index = %v, want present=%t", file, oldIndex, wantOld)
		}
		if wantOld {
			var definition, predicate string
			if err := env.pool.QueryRow(ctx, `SELECT pg_get_indexdef(indexrelid), pg_get_expr(indpred, indrelid)
				FROM pg_index WHERE indexrelid = 'idx_cve_match_queue_tenant'::regclass`).Scan(&definition, &predicate); err != nil {
				t.Fatal(err)
			}
			definition = strings.Join(strings.Fields(definition), " ")
			if !strings.HasSuffix(definition, "USING btree (tenant_id) WHERE (kind = 'observation'::text)") || predicate != "(kind = 'observation'::text)" {
				t.Fatalf("rollback restored the wrong 0161 index definition: definition=%q predicate=%q", definition, predicate)
			}
		}
	}
}

// tenantSeries lists the tenant_id label values a per-tenant gauge vec
// currently exports.
func tenantSeries(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "tenant_id" {
					out[lp.GetValue()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	return out
}

// The per-tenant depth and oldest-age gauges report each tenant's backlog,
// and a tenant's series disappears once its backlog is gone.
func TestCVEQueueTenantMetrics(t *testing.T) {
	ctx := context.Background()
	f := newFairnessFixture(t, "met")
	a := newFairnessTenant(t, f.app, "pat2030-met-a-"+randomHex(4), 4)
	b := newFairnessTenant(t, f.app, "pat2030-met-b-"+randomHex(4), 1)
	enqueueEach(t, a, f.app)
	if _, err := env.pool.Exec(ctx, `UPDATE cve_match_queue SET enqueued_at = now() - interval '2 hours'
		WHERE kind = 'observation' AND tenant_id = $1::uuid`, a.id); err != nil {
		t.Fatal(err)
	}
	enqueueEach(t, b, f.app)

	stats, err := cvepipeline.RefreshQueueMetrics(ctx, env.pool)
	if err != nil {
		t.Fatal(err)
	}
	byTenant := map[string]cvepipeline.TenantQueueStats{}
	for _, ts := range stats.Tenants {
		byTenant[ts.TenantID] = ts
	}
	if !sort.SliceIsSorted(stats.Tenants, func(i, j int) bool { return stats.Tenants[i].TenantID < stats.Tenants[j].TenantID }) {
		t.Fatal("tenant stats not sorted by tenant ID")
	}
	sa, sb := byTenant[a.id], byTenant[b.id]
	if sa.Depth != 4 || sb.Depth != 1 {
		t.Fatalf("tenant depths A=%d B=%d, want 4 and 1", sa.Depth, sb.Depth)
	}
	if sa.OldestAgeSeconds < 7190 || sa.OldestAgeSeconds > 7300 {
		t.Fatalf("tenant A oldest age %.0fs, want about 7200", sa.OldestAgeSeconds)
	}
	if sb.OldestAgeSeconds < 0 || sb.OldestAgeSeconds > 60 {
		t.Fatalf("tenant B oldest age %.0fs, want under a minute", sb.OldestAgeSeconds)
	}
	if got := testutil.ToFloat64(metrics.CVEMatchQueueTenantDepth.WithLabelValues(a.id)); got != 4 {
		t.Fatalf("patched_cve_match_queue_tenant_depth{tenant_id=A} = %v, want 4", got)
	}
	if got := testutil.ToFloat64(metrics.CVEMatchQueueTenantOldestAge.WithLabelValues(a.id)); got != sa.OldestAgeSeconds {
		t.Fatalf("patched_cve_match_queue_tenant_oldest_age_seconds{tenant_id=A} = %v, want %v", got, sa.OldestAgeSeconds)
	}
	if got := testutil.ToFloat64(metrics.CVEMatchQueueTenantDepth.WithLabelValues(b.id)); got != 1 {
		t.Fatalf("patched_cve_match_queue_tenant_depth{tenant_id=B} = %v, want 1", got)
	}

	drainCVEQueue(t)
	if _, err := cvepipeline.RefreshQueueMetrics(ctx, env.pool); err != nil {
		t.Fatal(err)
	}
	for _, c := range []prometheus.Collector{metrics.CVEMatchQueueTenantDepth, metrics.CVEMatchQueueTenantOldestAge} {
		series := tenantSeries(t, c)
		if _, ok := series[a.id]; ok {
			t.Fatalf("tenant A's series still exported after its backlog drained: %v", series)
		}
		if _, ok := series[b.id]; ok {
			t.Fatalf("tenant B's series still exported after its backlog drained: %v", series)
		}
	}
}
