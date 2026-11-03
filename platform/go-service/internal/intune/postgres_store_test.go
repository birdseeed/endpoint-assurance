package intune

// DB-backed test for PostgresStore, gated behind TEST_DATABASE_URL — same
// convention as internal/rings/advance_db_test.go and
// internal/auth/bearer_db_test.go. The pool's search_path is pinned to an
// isolated schema mirroring migrations/0124_intune_config_snapshots.sql, so
// no real data is touched; the schema is dropped on cleanup.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pgTestSchema = "pat1662_test"

func pgPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed intune store test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pgTestSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pgTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pgTestSchema,
		`CREATE TABLE ` + pgTestSchema + `.tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid()
		)`,
		// Mirrors migrations/0124_intune_config_snapshots.sql (superset in
		// production; this is the minimal shape PostgresStore touches).
		`CREATE TABLE ` + pgTestSchema + `.intune_config_snapshots (
			id            BIGSERIAL   PRIMARY KEY,
			tenant_id     UUID        NOT NULL REFERENCES ` + pgTestSchema + `.tenants(id) ON DELETE CASCADE,
			object_type   TEXT        NOT NULL CHECK (object_type IN ('compliance_policy')),
			api_version   TEXT        NOT NULL CHECK (api_version IN ('v1.0', 'beta')),
			started_at    TIMESTAMPTZ NOT NULL,
			completed_at  TIMESTAMPTZ NOT NULL,
			status        TEXT        NOT NULL CHECK (status IN ('complete', 'partial')),
			error         TEXT,
			object_count  INTEGER     NOT NULL DEFAULT 0,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pgTestSchema + `.intune_config_objects (
			id                      BIGSERIAL   PRIMARY KEY,
			snapshot_id             BIGINT      NOT NULL REFERENCES ` + pgTestSchema + `.intune_config_snapshots(id) ON DELETE CASCADE,
			graph_object_id         TEXT        NOT NULL,
			last_modified_date_time TIMESTAMPTZ,
			change_kind             TEXT        NOT NULL CHECK (change_kind IN (
			                          'appeared', 'unchanged', 'refreshed', 'disappeared')),
			body_changed            BOOLEAN     NOT NULL DEFAULT false,
			assignments_changed     BOOLEAN     NOT NULL DEFAULT false,
			raw_body                JSONB,
			raw_assignments         JSONB,
			created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (snapshot_id, graph_object_id)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup exec %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pgTestSchema+` CASCADE`)
	})
	return pool
}

func pgSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}

// TestPostgresStore_WriteThenReadBack_RoundTrips verifies the store writes
// a complete snapshot atomically and PriorObjects reads it back verbatim,
// including raw JSON bodies.
func TestPostgresStore_WriteThenReadBack_RoundTrips(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(t)
	tenantID := pgSeedTenant(t, ctx, pool)
	store := NewPostgresStore(pool)

	now := time.Now().UTC().Truncate(time.Millisecond)
	snap := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   now,
		CompletedAt: now.Add(time.Second),
		Status:      StatusComplete,
		Objects: []ObjectRecord{
			{
				GraphObjectID:        "p1",
				LastModifiedDateTime: now,
				ChangeKind:           ChangeAppeared,
				BodyChanged:          true,
				AssignmentsChanged:   true,
				RawBody:              json.RawMessage(`{"id":"p1","displayName":"Policy One"}`),
				RawAssignments:       json.RawMessage(`[{"id":"a1"}]`),
			},
		},
	}

	if _, err := store.WriteSnapshot(ctx, snap); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	prior, err := store.PriorObjects(ctx, tenantID, ObjectTypeCompliancePolicy)
	if err != nil {
		t.Fatalf("PriorObjects: %v", err)
	}
	got, ok := prior["p1"]
	if !ok {
		t.Fatalf("p1 not found in PriorObjects result")
	}
	if !jsonEqual(got.RawBody, snap.Objects[0].RawBody) {
		t.Errorf("RawBody = %s, want %s", got.RawBody, snap.Objects[0].RawBody)
	}
	if !jsonEqual(got.RawAssignments, snap.Objects[0].RawAssignments) {
		t.Errorf("RawAssignments = %s, want %s", got.RawAssignments, snap.Objects[0].RawAssignments)
	}
	if !got.LastModifiedDateTime.Equal(now) {
		t.Errorf("LastModifiedDateTime = %v, want %v", got.LastModifiedDateTime, now)
	}
}

// TestPostgresStore_PartialSnapshot_NeverUsedAsBaseline is the DB-level
// enforcement of "a partial pull must be unusable as a diff input": once a
// partial snapshot is written after a complete one, PriorObjects must keep
// returning the complete snapshot's data, not the partial one's.
func TestPostgresStore_PartialSnapshot_NeverUsedAsBaseline(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(t)
	tenantID := pgSeedTenant(t, ctx, pool)
	store := NewPostgresStore(pool)

	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	complete := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   t0,
		CompletedAt: t0.Add(time.Second),
		Status:      StatusComplete,
		Objects: []ObjectRecord{
			{
				GraphObjectID:        "p1",
				LastModifiedDateTime: t0,
				ChangeKind:           ChangeAppeared,
				RawBody:              json.RawMessage(`{"id":"p1","displayName":"v1"}`),
				RawAssignments:       json.RawMessage(`[]`),
			},
		},
	}
	if _, err := store.WriteSnapshot(ctx, complete); err != nil {
		t.Fatalf("WriteSnapshot(complete): %v", err)
	}

	t1 := t0.Add(time.Minute)
	partial := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   t1,
		CompletedAt: t1.Add(time.Second),
		Status:      StatusPartial,
		Error:       "simulated mid-pull failure",
		// Empty Objects: nothing was successfully captured before failing.
	}
	if _, err := store.WriteSnapshot(ctx, partial); err != nil {
		t.Fatalf("WriteSnapshot(partial): %v", err)
	}

	prior, err := store.PriorObjects(ctx, tenantID, ObjectTypeCompliancePolicy)
	if err != nil {
		t.Fatalf("PriorObjects: %v", err)
	}
	got, ok := prior["p1"]
	if !ok {
		t.Fatalf("p1 missing from PriorObjects after a partial snapshot was written; the partial snapshot must not have replaced the baseline")
	}
	if !got.LastModifiedDateTime.Equal(t0) {
		t.Errorf("baseline LastModifiedDateTime = %v, want the complete snapshot's %v (partial snapshot must be ignored)", got.LastModifiedDateTime, t0)
	}
}

// TestPostgresStore_LatestCompletePair_FewerThanTwoComplete proves ok is
// false (not an error) when a tenant/objectType has zero or one complete
// snapshot on record — PAT-1684's handler reads this as "nothing to diff
// yet", not a failure.
func TestPostgresStore_LatestCompletePair_FewerThanTwoComplete(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(t)
	tenantID := pgSeedTenant(t, ctx, pool)
	store := NewPostgresStore(pool)

	if _, _, ok, err := store.LatestCompletePair(ctx, tenantID, ObjectTypeCompliancePolicy); err != nil || ok {
		t.Fatalf("zero snapshots: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	only := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   now,
		CompletedAt: now.Add(time.Second),
		Status:      StatusComplete,
		Objects: []ObjectRecord{
			{GraphObjectID: "p1", LastModifiedDateTime: now, ChangeKind: ChangeAppeared,
				RawBody: json.RawMessage(`{"id":"p1","displayName":"v1"}`), RawAssignments: json.RawMessage(`[]`)},
		},
	}
	if _, err := store.WriteSnapshot(ctx, only); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	if _, _, ok, err := store.LatestCompletePair(ctx, tenantID, ObjectTypeCompliancePolicy); err != nil || ok {
		t.Fatalf("one snapshot: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// TestPostgresStore_LatestCompletePair_TwoComplete proves the two most
// recent complete snapshots come back ordered prior (older) then current
// (newer), with a partial snapshot written in between ignored entirely (it
// is neither returned as a pair member nor able to hide the complete
// snapshot beneath it), and with a disappeared row excluded from the alive
// object set the same way PriorObjects excludes it.
func TestPostgresStore_LatestCompletePair_TwoComplete(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(t)
	tenantID := pgSeedTenant(t, ctx, pool)
	store := NewPostgresStore(pool)

	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	first := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   t0,
		CompletedAt: t0.Add(time.Second),
		Status:      StatusComplete,
		Objects: []ObjectRecord{
			{GraphObjectID: "p1", LastModifiedDateTime: t0, ChangeKind: ChangeAppeared,
				RawBody: json.RawMessage(`{"id":"p1","displayName":"Policy One v1"}`), RawAssignments: json.RawMessage(`[]`)},
			{GraphObjectID: "p2", LastModifiedDateTime: t0, ChangeKind: ChangeAppeared,
				RawBody: json.RawMessage(`{"id":"p2","displayName":"Policy Two"}`), RawAssignments: json.RawMessage(`[]`)},
		},
	}
	if _, err := store.WriteSnapshot(ctx, first); err != nil {
		t.Fatalf("WriteSnapshot(first): %v", err)
	}

	t1 := t0.Add(30 * time.Minute)
	partial := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   t1,
		CompletedAt: t1.Add(time.Second),
		Status:      StatusPartial,
		Error:       "simulated mid-pull failure",
	}
	if _, err := store.WriteSnapshot(ctx, partial); err != nil {
		t.Fatalf("WriteSnapshot(partial): %v", err)
	}

	t2 := t0.Add(time.Hour)
	second := Snapshot{
		TenantID:    tenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   t2,
		CompletedAt: t2.Add(time.Second),
		Status:      StatusComplete,
		Objects: []ObjectRecord{
			{GraphObjectID: "p1", LastModifiedDateTime: t2, ChangeKind: ChangeRefreshed, BodyChanged: true,
				RawBody: json.RawMessage(`{"id":"p1","displayName":"Policy One v2"}`), RawAssignments: json.RawMessage(`[]`)},
			{GraphObjectID: "p2", LastModifiedDateTime: t0, ChangeKind: ChangeDisappeared},
		},
	}
	if _, err := store.WriteSnapshot(ctx, second); err != nil {
		t.Fatalf("WriteSnapshot(second): %v", err)
	}

	prior, current, ok, err := store.LatestCompletePair(ctx, tenantID, ObjectTypeCompliancePolicy)
	if err != nil {
		t.Fatalf("LatestCompletePair: %v", err)
	}
	if !ok {
		t.Fatalf("ok = false, want true with two complete snapshots on record")
	}
	if !prior.CompletedAt.Equal(first.CompletedAt) {
		t.Errorf("prior.CompletedAt = %v, want %v (the older complete snapshot, partial skipped)", prior.CompletedAt, first.CompletedAt)
	}
	if !current.CompletedAt.Equal(second.CompletedAt) {
		t.Errorf("current.CompletedAt = %v, want %v", current.CompletedAt, second.CompletedAt)
	}
	if len(prior.Objects) != 2 {
		t.Fatalf("prior.Objects = %d entries, want 2", len(prior.Objects))
	}
	// p2 is ChangeDisappeared in `second` — must not appear in current.Objects.
	if _, found := objectByID(current.Objects, "p2"); found {
		t.Errorf("current.Objects contains disappeared object p2; LatestCompletePair must exclude tombstone rows")
	}
	p1After, found := objectByID(current.Objects, "p1")
	if !found {
		t.Fatalf("current.Objects missing p1")
	}
	if !jsonEqual(p1After.RawBody, second.Objects[0].RawBody) {
		t.Errorf("current p1 RawBody = %s, want %s", p1After.RawBody, second.Objects[0].RawBody)
	}

	// Diff can be called directly on the returned pair — the whole point of
	// this store method (see its doc comment: "ready to pass straight to
	// Diff").
	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff(prior, current): %v", err)
	}
	if len(cl.Entries) != 2 {
		t.Fatalf("Diff produced %d entries, want 2 (p1 settings_changed, p2 deleted): %+v", len(cl.Entries), cl.Entries)
	}
}
