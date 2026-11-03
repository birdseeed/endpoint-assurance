//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/softwaregov"
)

func TestUnapprovedRunnerMarkedLockTimeoutDoesNotStarve(t *testing.T) {
	ctx := presenceTestContext(t, 25*time.Second)
	drainUnapprovedRaises(t)
	bad := newGovTenant(t, "markedtimeout", "")
	good := newGovTenant(t, "markedaftertimeout", "")
	for _, g := range []*govTenant{bad, good} {
		dev := govDevice(t, g.id, "markedtimeout-"+g.id, "macOS", time.Now())
		govApp(t, dev, "Timed App", "com.markedtimeout.app", "TIMEDTEAM1")
		if status, body := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.markedtimeout.app", "TIMEDTEAM1"))); status != http.StatusOK {
			t.Fatalf("mark: %d %s", status, body)
		}
		if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_episodes SET created_at = '1900-01-01' WHERE tenant_id = $1::uuid`, bad.id); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, bad.id); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- softwaregov.RaiseUnraised(ctx, env.pool, time.Now()) }()
	waitForPresenceAlertLock(t, ctx, blocker)
	if err := <-errc; !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), bad.id) {
		t.Fatalf("blocked batch did not time out: %v", err)
	}
	if ctx.Err() != nil || len(govAlerts(t, good.id)) != 1 || len(govAlerts(t, bad.id)) != 0 {
		t.Fatal("blocked marked batch exhausted the parent or starved the healthy batch")
	}
	var pending, attempted bool
	if err := env.pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM software_unapproved_episodes WHERE tenant_id = $1::uuid AND raised_at IS NULL),
		EXISTS (SELECT 1 FROM software_unapproved_runner_attempts WHERE tenant_id = $1::uuid AND work_kind = 'marked')`, bad.id).Scan(&pending, &attempted); err != nil || !pending || !attempted {
		t.Fatalf("timeout lost durable work/rotation: pending=%v attempted=%v err=%v", pending, attempted, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertPresenceAlertUnlocked(t, bad.id)
	if err := softwaregov.RaiseUnraised(ctx, env.pool, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(govAlerts(t, bad.id)) != 1 || len(govAlerts(t, good.id)) != 1 {
		t.Fatal("retry lost or duplicated a marked alert")
	}
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_runner_attempts WHERE tenant_id = $1::uuid AND work_kind = 'marked')`, bad.id).Scan(&attempted); err != nil || attempted {
		t.Fatalf("completed batch retained attempt metadata: attempted=%v err=%v", attempted, err)
	}
}

func TestUnapprovedRunnerSummaryPreparationTimeout(t *testing.T) {
	ctx := presenceTestContext(t, 45*time.Second)
	g := newGovTenant(t, "summarytimeout", "")
	dev := govDevice(t, g.id, "summarytimeout", "macOS", time.Now())
	govApp(t, dev, "Prepared App", "com.summarytimeout.app", "PREPTEAM01")
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if status, body := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.summarytimeout.app", "PREPTEAM01"))); status != http.StatusOK {
		t.Fatalf("mark: %d %s", status, body)
	}
	var id int64
	if err := env.pool.QueryRow(ctx, `SELECT id FROM software_unapproved_episodes WHERE tenant_id = $1::uuid AND raised_at IS NULL`, g.id).Scan(&id); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM software_unapproved_presence_devices WHERE device_id = $1::uuid FOR UPDATE`, dev); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	// An earlier caller deadline must cap the larger production preparation
	// budget. Keep a real row-lock timeout/retry regression without making CI
	// wait out the full 90-second allowance; unit tests cover budget nesting.
	raiseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	go func() {
		_, err := softwaregov.RaiseEpisodes(raiseCtx, env.pool, g.id, []int64{id}, time.Now())
		errc <- err
	}()
	waitForPresenceTransactionWait(t, ctx, blocker)
	if err := <-errc; !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("summary preparation did not respect the caller budget: %v parent=%v", err, ctx.Err())
	}
	var pending bool
	if err := env.pool.QueryRow(ctx, `SELECT raised_at IS NULL FROM software_unapproved_episodes WHERE id = $1`, id).Scan(&pending); err != nil || !pending {
		t.Fatalf("summary timeout lost its episode: pending=%v err=%v", pending, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := softwaregov.RaiseEpisodes(ctx, env.pool, g.id, []int64{id}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(govAlerts(t, g.id)) != 1 {
		t.Fatal("unblocked summary preparation did not raise exactly once")
	}
}

func TestUnapprovedDeferredRevokedTenantResumesAfterRestore(t *testing.T) {
	ctx := presenceTestContext(t, 15*time.Second)
	g := newGovTenant(t, "deferredrestore", "")
	dev := govDevice(t, g.id, "deferredrestore", "macOS", time.Now())
	if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.deferredrestore.app', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	govApp(t, dev, "Restored App", "com.deferredrestore.app", "RESTORETEAM")
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, g.id); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_detection_queue SET queued_at = '1800-01-01' WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	for _, check := range []func() (softwaregov.RaiseResult, error){
		func() (softwaregov.RaiseResult, error) {
			return softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now())
		},
		func() (softwaregov.RaiseResult, error) {
			res, _, err := softwaregov.ProcessDeviceCheck(ctx, env.pool, g.id, dev, softwaregov.DeviceAuthority{}, time.Now())
			return res, err
		},
	} {
		if res, err := check(); err != nil || res.Skipped != "tenant_inactive" {
			t.Fatalf("revoked check: %+v %v", res, err)
		}
	}
	// A revoked check cannot consume the one available selection slot.
	healthy := newGovTenant(t, "deferredrestorehealthy", "")
	good := govDevice(t, healthy.id, "deferredrestorehealthy", "macOS", time.Now())
	govApp(t, good, "Healthy App", "com.deferredrestore.healthy", "RESTORETEAM")
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_detection_queue SET queued_at = '1801-01-01' WHERE device_id = $1::uuid`, good); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	var retained, healthyDrained bool
	if err := env.pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid),
		NOT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $2::uuid)`, dev, good).Scan(&retained, &healthyDrained); err != nil || !retained || !healthyDrained {
		t.Fatalf("revoked work lost or consumed active selection: retained=%v healthyDrained=%v err=%v", retained, healthyDrained, err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET revoked_at = NULL WHERE id = $1::uuid`, g.id); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid)`, dev).Scan(&retained); err != nil || retained || len(govAlerts(t, g.id)) != 1 {
		t.Fatalf("restored work did not resume: retained=%v err=%v", retained, err)
	}
}

func TestUnapprovedRunnerPoisonWindowsRotateAcrossRestart(t *testing.T) {
	ctx := presenceTestContext(t, 45*time.Second)
	drainUnapprovedRaises(t)
	// Flush prior suite fixtures before constructing deliberately older work.
	for i := 0; i < 20; i++ {
		stale, err := softwaregov.StaleSummaryTenants(ctx, env.pool, 20)
		if err != nil {
			t.Fatal(err)
		}
		if len(stale) == 0 {
			break
		}
		if err := softwaregov.NewRunner(env.pool, nil).RunMarked(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var poisonIDs []string
	var markedPoison *govTenant
	var markedPolicy int64
	for i := 0; i < 21; i++ {
		g := newGovTenant(t, "fairpoison", "")
		poisonIDs = append(poisonIDs, g.id)
		dev := govDevice(t, g.id, "fairpoison-"+g.id, "macOS", time.Now())
		govApp(t, dev, "Poison App", "com.fairpoison.app", "FAIRTEAM")
		var policyID int64
		if err := env.pool.QueryRow(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
			VALUES ($1::uuid, 'com.fairpoison.app', 'any', 'unapproved') RETURNING id`, g.id).Scan(&policyID); err != nil {
			t.Fatal(err)
		}
		if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_presence_state SET policy_changed_at = $2 WHERE tenant_id = $1::uuid`,
			g.id, time.Date(1800, 1, 1, 0, 0, i, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			markedPoison, markedPolicy = g, policyID
		}
	}
	good := newGovTenant(t, "fairhealthy", "")
	dev := govDevice(t, good.id, "fairhealthy", "macOS", time.Now())
	govApp(t, dev, "Healthy App", "com.fairhealthy.app", "FAIRTEAM")
	var goodPolicy int64
	if err := env.pool.QueryRow(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.fairhealthy.app', 'any', 'unapproved') RETURNING id`, good.id).Scan(&goodPolicy); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_presence_state SET policy_changed_at = '1801-01-01' WHERE tenant_id = $1::uuid`, good.id); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO software_unapproved_episodes
		(tenant_id, policy_kind, policy_id, source, marked_at, created_at, batch_id)
		SELECT $1::uuid, 'application', $2, 'operator', now(), '1800-01-01'::timestamptz + n * interval '1 second', gen_random_uuid()
		FROM generate_series(1, 51) n`, markedPoison.id, markedPolicy); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO software_unapproved_episodes
		(tenant_id, policy_kind, policy_id, source, marked_at, created_at, batch_id)
		VALUES ($1::uuid, 'application', $2, 'operator', now(), '1801-01-01', gen_random_uuid())`, good.id, goodPolicy); err != nil {
		t.Fatal(err)
	}
	// Leave only the healthy fixture dirty. Failed full rebuilds must not
	// prevent the subsequent dirty sweep from repairing its inventory rows.
	if _, err := env.pool.Exec(ctx, `DELETE FROM software_unapproved_presence_dirty dd USING devices d
		WHERE dd.device_id = d.id AND d.tenant_id = ANY($1::uuid[])`, poisonIDs); err != nil {
		t.Fatal(err)
	}
	name := "pat2095_runner_poison_" + randomHex(4)
	ident := pgx.Identifier{name}.Sanitize()
	// Presence insert failure poisons rebuilds independently of their policy
	// rows. Episode failure also exercises selected-batch error isolation.
	ddl := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF TG_TABLE_NAME = 'software_unapproved_presence_devices' THEN
		IF EXISTS (SELECT 1 FROM devices d JOIN tenants t ON t.id = d.tenant_id
		WHERE d.id = NEW.device_id AND t.name LIKE 'pat2009-fairpoison-%%') THEN
		RAISE EXCEPTION 'test poison summary'; END IF;
		ELSIF NEW.tenant_id = '%s'::uuid AND NEW.raised_at IS NOT NULL THEN
		RAISE EXCEPTION 'test poison marked batch'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER %s BEFORE INSERT OR UPDATE ON software_unapproved_presence_devices FOR EACH ROW EXECUTE FUNCTION %s();
		CREATE TRIGGER %s BEFORE UPDATE ON software_unapproved_episodes FOR EACH ROW EXECUTE FUNCTION %s()`,
		ident, markedPoison.id, ident, ident, ident, ident)
	if _, err := env.pool.Exec(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := env.pool.Exec(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON software_unapproved_presence_devices;
		DROP TRIGGER IF EXISTS %s ON software_unapproved_episodes; DROP FUNCTION IF EXISTS %s()`, ident, ident, ident))
		return err
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("poison trigger cleanup: %v", err)
		}
	})
	if err := softwaregov.NewRunner(env.pool, nil).RunMarked(ctx); err == nil {
		t.Fatal("poison work was not reported")
	}
	var current bool
	if err := env.pool.QueryRow(ctx, `SELECT summary_version >= policy_version FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid`, good.id).Scan(&current); err != nil || current || len(govAlerts(t, good.id)) != 0 {
		t.Fatalf("healthy work was not beyond both selector windows: current=%v err=%v", current, err)
	}
	if presenceDirty(t, dev) {
		t.Fatal("failed summary rebuilds prevented the independent dirty sweep")
	}
	// Fresh Runner has no process cursor: only durable attempt ordering can
	// move the healthy tenant/batch into its bounded second selection.
	if err := softwaregov.NewRunner(env.pool, nil).RunMarked(ctx); err == nil {
		t.Fatal("remaining poison work was not reported")
	}
	if err := env.pool.QueryRow(ctx, `SELECT summary_version >= policy_version FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid`, good.id).Scan(&current); err != nil || !current || len(govAlerts(t, good.id)) != 1 {
		t.Fatalf("poison windows starved healthy work after restart: current=%v err=%v", current, err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	// Repair all injected poison and prove completion removes scheduler rows.
	for i := 0; i < 4; i++ {
		if err := softwaregov.NewRunner(env.pool, nil).RunMarked(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var attempts int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM software_unapproved_runner_attempts WHERE tenant_id = ANY($1::uuid[])`, append(poisonIDs, good.id)).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatalf("completed work leaked scheduling rows: attempts=%d err=%v", attempts, err)
	}
}
