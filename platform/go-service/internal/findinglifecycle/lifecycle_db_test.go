package findinglifecycle

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const lifecycleTestSchema = "pat1878_lifecycle_test"

func lifecycleTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping finding lifecycle DB test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = lifecycleTestSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	statements := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`DROP SCHEMA IF EXISTS ` + lifecycleTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + lifecycleTestSchema,
		`CREATE TABLE ` + lifecycleTestSchema + `.tenants (id UUID PRIMARY KEY DEFAULT gen_random_uuid())`,
		`CREATE TABLE ` + lifecycleTestSchema + `.devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL,
			UNIQUE (id, tenant_id), FOREIGN KEY (tenant_id) REFERENCES ` + lifecycleTestSchema + `.tenants(id)
		)`,
		`CREATE TABLE ` + lifecycleTestSchema + `.finding_lifecycle_events (
			id BIGSERIAL PRIMARY KEY, tenant_id UUID NOT NULL, finding_kind TEXT NOT NULL,
			device_id UUID, finding_key TEXT NOT NULL, event_type TEXT NOT NULL,
			source_type TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '',
			observed_at TIMESTAMPTZ, authoritative BOOLEAN NOT NULL DEFAULT false,
			evidence JSONB NOT NULL DEFAULT '{}'::jsonb, recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			FOREIGN KEY (tenant_id) REFERENCES ` + lifecycleTestSchema + `.tenants(id),
			FOREIGN KEY (device_id, tenant_id) REFERENCES ` + lifecycleTestSchema + `.devices(id, tenant_id)
		)`,
		`CREATE FUNCTION ` + lifecycleTestSchema + `.reject_lifecycle_mutation() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'append-only'; END; $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER trg_lifecycle_append_only BEFORE UPDATE OR DELETE
			ON ` + lifecycleTestSchema + `.finding_lifecycle_events
			FOR EACH ROW EXECUTE FUNCTION ` + lifecycleTestSchema + `.reject_lifecycle_mutation()`,
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("setup lifecycle DB test: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+lifecycleTestSchema+` CASCADE`)
	})
	return pool
}

func TestLifecycleDBAppendOnlyTenantIsolationAndRecurrence(t *testing.T) {
	pool := lifecycleTestPool(t)
	ctx := context.Background()
	var tenantA, tenantB, deviceA string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantB); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantA).Scan(&deviceA); err != nil {
		t.Fatal(err)
	}
	identity := Identity{TenantID: tenantA, Kind: KindCIS, DeviceID: &deviceA, FindingKey: "cis_test_rule"}
	t0 := time.Now().UTC().Add(-time.Hour)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := RecordObservation(ctx, tx, Observation{Identity: identity, Outcome: OutcomeFailing, ObservedAt: t0, ReceivedAt: t0, Authoritative: true}); err != nil || got != EventFirstObserved {
		t.Fatalf("first observation: event=%q err=%v", got, err)
	}
	if err := RecordAction(ctx, tx, Action{Identity: identity, Type: EventPendingVerification, Actor: "operator@example.test"}); err != nil {
		t.Fatal(err)
	}
	fixedAt := time.Now().UTC().Add(time.Hour)
	if got, err := RecordObservation(ctx, tx, Observation{Identity: identity, Outcome: OutcomePassing, ObservedAt: fixedAt, ReceivedAt: fixedAt, Authoritative: true}); err != nil || got != EventVerifiedFixed {
		t.Fatalf("verified closure: event=%q err=%v", got, err)
	}
	recurredAt := time.Now().UTC().Add(2 * time.Hour)
	if got, err := RecordObservation(ctx, tx, Observation{Identity: identity, Outcome: OutcomeFailing, ObservedAt: recurredAt, ReceivedAt: recurredAt, Authoritative: true}); err != nil || got != EventRecurred {
		t.Fatalf("recurrence: event=%q err=%v", got, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var tenantACount, tenantBCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM finding_lifecycle_events WHERE tenant_id=$1::uuid`, tenantA).Scan(&tenantACount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM finding_lifecycle_events WHERE tenant_id=$1::uuid`, tenantB).Scan(&tenantBCount); err != nil {
		t.Fatal(err)
	}
	if tenantACount != 4 || tenantBCount != 0 {
		t.Fatalf("tenant isolation counts A=%d B=%d, want 4/0", tenantACount, tenantBCount)
	}

	if _, err := pool.Exec(ctx, `UPDATE finding_lifecycle_events SET reason='rewritten' WHERE tenant_id=$1::uuid`, tenantA); err == nil {
		t.Fatal("append-only guard allowed UPDATE")
	}
}

func TestLifecycleDBActionAndObservationShareIdentityLock(t *testing.T) {
	pool := lifecycleTestPool(t)
	ctx := context.Background()
	var tenantID, deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	identity := Identity{TenantID: tenantID, Kind: KindCIS, DeviceID: &deviceID, FindingKey: "cis_lock_test"}
	firstAt := time.Now().UTC().Add(-time.Hour)
	seedTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordObservation(ctx, seedTx, Observation{
		Identity: identity, Outcome: OutcomeFailing,
		ObservedAt: firstAt, ReceivedAt: firstAt, Authoritative: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := seedTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	actionTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var actionPID int
	if err := actionTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&actionPID); err != nil {
		t.Fatal(err)
	}
	if err := RecordAction(ctx, actionTx, Action{
		Identity: identity, Type: EventPendingVerification, Actor: "operator@example.test",
	}); err != nil {
		t.Fatal(err)
	}
	var actionLockHeld bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM pg_locks
			WHERE pid=$1 AND locktype='advisory' AND mode='ExclusiveLock' AND granted
		)
	`, actionPID).Scan(&actionLockHeld); err != nil {
		t.Fatal(err)
	}
	if !actionLockHeld {
		t.Fatal("RecordAction did not hold the shared identity advisory lock")
	}

	type observationResult struct {
		event string
		err   error
	}
	observationPID := make(chan int, 1)
	result := make(chan observationResult, 1)
	go func() {
		observationTx, beginErr := pool.Begin(ctx)
		if beginErr != nil {
			result <- observationResult{err: beginErr}
			return
		}
		defer func() { _ = observationTx.Rollback(ctx) }()
		var pid int
		if pidErr := observationTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); pidErr != nil {
			result <- observationResult{err: pidErr}
			return
		}
		observationPID <- pid
		observedAt := time.Now().UTC().Add(time.Hour)
		eventType, recordErr := RecordObservation(ctx, observationTx, Observation{
			Identity: identity, Outcome: OutcomePassing,
			ObservedAt: observedAt, ReceivedAt: observedAt, Authoritative: true,
		})
		if recordErr == nil {
			recordErr = observationTx.Commit(ctx)
		}
		result <- observationResult{event: eventType, err: recordErr}
	}()
	var observationBackendPID int
	select {
	case observationBackendPID = <-observationPID:
	case early := <-result:
		t.Fatalf("observation failed before attempting identity lock: event=%q err=%v", early.event, early.err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for observation backend PID")
	}

	lockDeadline := time.NewTimer(2 * time.Second)
	defer lockDeadline.Stop()
	lockPoll := time.NewTicker(10 * time.Millisecond)
	defer lockPoll.Stop()
	queuedOnActionLock := false
	for !queuedOnActionLock {
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1
				FROM pg_locks waiting
				JOIN pg_locks held
				  ON held.locktype = waiting.locktype
				 AND held.database IS NOT DISTINCT FROM waiting.database
				 AND held.classid = waiting.classid
				 AND held.objid = waiting.objid
				 AND held.objsubid = waiting.objsubid
				WHERE waiting.pid = $1 AND held.pid = $2
				  AND waiting.locktype = 'advisory'
				  AND NOT waiting.granted AND held.granted
			)
		`, observationBackendPID, actionPID).Scan(&queuedOnActionLock); err != nil {
			t.Fatal(err)
		}
		if queuedOnActionLock {
			break
		}
		select {
		case early := <-result:
			t.Fatalf("observation bypassed uncommitted action lock: event=%q err=%v", early.event, early.err)
		case <-lockPoll.C:
		case <-lockDeadline.C:
			t.Fatal("observation did not queue on the action transaction's identity lock")
		}
	}
	if err := actionTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-result:
		if completed.err != nil || completed.event != EventVerifiedFixed {
			t.Fatalf("observation after action commit: event=%q err=%v", completed.event, completed.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observation remained blocked after action commit")
	}

	rows, err := pool.Query(ctx, `
		SELECT event_type FROM finding_lifecycle_events
		WHERE tenant_id=$1::uuid AND finding_kind='cis' AND device_id=$2::uuid AND finding_key=$3
		ORDER BY id
	`, tenantID, deviceID, identity.FindingKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []string
	for rows.Next() {
		var eventType string
		if err := rows.Scan(&eventType); err != nil {
			t.Fatal(err)
		}
		events = append(events, eventType)
	}
	want := []string{EventFirstObserved, EventPendingVerification, EventVerifiedFixed}
	if len(events) != len(want) {
		t.Fatalf("events=%v, want %v", events, want)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events=%v, want %v", events, want)
		}
	}
}
