package mdmsync

// Skipped unless TEST_DATABASE_URL points at a scratch database (same
// convention as internal/rings/advance_db_test.go and
// internal/auth/bearer_db_test.go). The pool's search_path is pinned to an
// isolated schema so the tables created here never touch real data, and
// the schema is dropped on cleanup.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const mdmsyncTestSchema = "pat1654_test"

func mdmsyncDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed mdmsync test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = mdmsyncTestSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + mdmsyncTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + mdmsyncTestSchema,
		// Mirrors migrations/0123_msgraph_device_snapshots.sql.
		`CREATE TABLE ` + mdmsyncTestSchema + `.msgraph_device_snapshots (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id    TEXT NOT NULL,
			collection   TEXT NOT NULL CHECK (collection IN ('entra_devices', 'intune_managed_devices')),
			pulled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			record_count INTEGER NOT NULL,
			raw_body     JSONB NOT NULL
		)`,
		`CREATE TABLE ` + mdmsyncTestSchema + `.msgraph_entra_devices (
			id                                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			snapshot_id                        UUID NOT NULL REFERENCES ` + mdmsyncTestSchema + `.msgraph_device_snapshots(id) ON DELETE CASCADE,
			tenant_id                          TEXT NOT NULL,
			device_id                          TEXT NOT NULL,
			display_name                       TEXT,
			operating_system                   TEXT,
			operating_system_version           TEXT,
			approximate_last_sign_in_date_time TIMESTAMPTZ,
			account_enabled                    BOOLEAN,
			trust_type                         TEXT,
			is_managed                         BOOLEAN
		)`,
		`CREATE TABLE ` + mdmsyncTestSchema + `.msgraph_intune_managed_devices (
			id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			snapshot_id               UUID NOT NULL REFERENCES ` + mdmsyncTestSchema + `.msgraph_device_snapshots(id) ON DELETE CASCADE,
			tenant_id                 TEXT NOT NULL,
			managed_device_id         TEXT NOT NULL,
			azure_ad_device_id        TEXT,
			device_name               TEXT,
			operating_system          TEXT,
			os_version                TEXT,
			last_sync_date_time       TIMESTAMPTZ,
			enrolled_date_time        TIMESTAMPTZ,
			compliance_state          TEXT,
			managed_device_owner_type TEXT,
			management_agent          TEXT,
			device_registration_state TEXT
		)`,
		`CREATE TABLE ` + mdmsyncTestSchema + `.msgraph_device_join_results (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          TEXT NOT NULL,
			entra_snapshot_id  UUID REFERENCES ` + mdmsyncTestSchema + `.msgraph_device_snapshots(id) ON DELETE SET NULL,
			intune_snapshot_id UUID REFERENCES ` + mdmsyncTestSchema + `.msgraph_device_snapshots(id) ON DELETE SET NULL,
			computed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
			status             TEXT NOT NULL CHECK (status IN ('joined', 'entra_only', 'intune_only', 'unjoinable')),
			join_key           TEXT,
			entra_device_id    TEXT,
			managed_device_id  TEXT
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup exec %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+mdmsyncTestSchema+` CASCADE`)
	})
	return pool
}

// TestSaveEntraSnapshot_RoundTrip verifies the raw body and parsed rows both
// land, and that record_count matches.
func TestSaveEntraSnapshot_RoundTrip(t *testing.T) {
	pool := mdmsyncDBPool(t)
	ctx := context.Background()

	raw := []json.RawMessage{json.RawMessage(`{"deviceId":"d1","displayName":"WKS-01"}`)}
	devices := []EntraDevice{{DeviceID: "d1", DisplayName: "WKS-01"}}

	snapshotID, err := SaveEntraSnapshot(ctx, pool, "tenant-a", raw, devices)
	if err != nil {
		t.Fatalf("SaveEntraSnapshot: %v", err)
	}
	if snapshotID == "" {
		t.Fatal("SaveEntraSnapshot returned empty snapshot id")
	}

	var recordCount int
	var rawBody []byte
	if err := pool.QueryRow(ctx,
		`SELECT record_count, raw_body FROM msgraph_device_snapshots WHERE id = $1`, snapshotID,
	).Scan(&recordCount, &rawBody); err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	if recordCount != 1 {
		t.Errorf("record_count = %d, want 1", recordCount)
	}

	var deviceCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM msgraph_entra_devices WHERE snapshot_id = $1`, snapshotID,
	).Scan(&deviceCount); err != nil {
		t.Fatalf("query entra devices: %v", err)
	}
	if deviceCount != 1 {
		t.Errorf("device row count = %d, want 1", deviceCount)
	}
}

// TestSaveEntraSnapshot_ReRunIsIdempotentViaNewSnapshot is the PAT-1654
// idempotency acceptance criterion: re-running the pull with unchanged data
// must insert a NEW snapshot row, never update the previous one. Both
// snapshots must remain queryable afterward (history retained).
func TestSaveEntraSnapshot_ReRunIsIdempotentViaNewSnapshot(t *testing.T) {
	pool := mdmsyncDBPool(t)
	ctx := context.Background()

	raw := []json.RawMessage{json.RawMessage(`{"deviceId":"d1","displayName":"WKS-01"}`)}
	devices := []EntraDevice{{DeviceID: "d1", DisplayName: "WKS-01"}}

	firstID, err := SaveEntraSnapshot(ctx, pool, "tenant-a", raw, devices)
	if err != nil {
		t.Fatalf("first SaveEntraSnapshot: %v", err)
	}
	secondID, err := SaveEntraSnapshot(ctx, pool, "tenant-a", raw, devices)
	if err != nil {
		t.Fatalf("second SaveEntraSnapshot: %v", err)
	}

	if firstID == secondID {
		t.Fatalf("re-running the pull reused snapshot id %q instead of creating a new one", firstID)
	}

	var totalSnapshots int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM msgraph_device_snapshots WHERE tenant_id = 'tenant-a' AND collection = 'entra_devices'`,
	).Scan(&totalSnapshots); err != nil {
		t.Fatalf("count snapshots: %v", err)
	}
	if totalSnapshots != 2 {
		t.Fatalf("got %d snapshots after two identical pulls, want 2 (append-only, no mutation of the previous run)", totalSnapshots)
	}

	// The first snapshot's own rows must be untouched, not merged/overwritten.
	var firstStillHasRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM msgraph_entra_devices WHERE snapshot_id = $1`, firstID,
	).Scan(&firstStillHasRows); err != nil {
		t.Fatalf("query first snapshot rows: %v", err)
	}
	if firstStillHasRows != 1 {
		t.Errorf("first snapshot device rows = %d, want 1 (still intact after the second pull)", firstStillHasRows)
	}
}

// TestSaveManagedSnapshotAndJoinResults_RoundTrip exercises the full
// managed-device + join persistence path, including an unjoinable record.
func TestSaveManagedSnapshotAndJoinResults_RoundTrip(t *testing.T) {
	pool := mdmsyncDBPool(t)
	ctx := context.Background()

	entraRaw := []json.RawMessage{json.RawMessage(`{"deviceId":"d1"}`)}
	entraDevices := []EntraDevice{{DeviceID: "d1", DisplayName: "WKS-01"}}
	entraSnapshotID, err := SaveEntraSnapshot(ctx, pool, "tenant-a", entraRaw, entraDevices)
	if err != nil {
		t.Fatalf("SaveEntraSnapshot: %v", err)
	}

	managedRaw := []json.RawMessage{
		json.RawMessage(`{"id":"m1","azureADDeviceId":"d1"}`),
		json.RawMessage(`{"id":"m2","azureADDeviceId":"00000000-0000-0000-0000-000000000000"}`),
	}
	managedDevices := []ManagedDevice{
		{ID: "m1", AzureADDeviceID: "d1"},
		{ID: "m2", AzureADDeviceID: "00000000-0000-0000-0000-000000000000"},
	}
	intuneSnapshotID, err := SaveManagedSnapshot(ctx, pool, "tenant-a", managedRaw, managedDevices)
	if err != nil {
		t.Fatalf("SaveManagedSnapshot: %v", err)
	}

	joined := JoinDevices(entraDevices, managedDevices)
	if err := SaveJoinResults(ctx, pool, "tenant-a", entraSnapshotID, intuneSnapshotID, joined); err != nil {
		t.Fatalf("SaveJoinResults: %v", err)
	}

	var unjoinableCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM msgraph_device_join_results WHERE status = 'unjoinable' AND managed_device_id = 'm2'`,
	).Scan(&unjoinableCount); err != nil {
		t.Fatalf("query unjoinable rows: %v", err)
	}
	if unjoinableCount != 1 {
		t.Errorf("unjoinable rows for m2 = %d, want 1 (must be persisted, not dropped)", unjoinableCount)
	}

	var joinedCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM msgraph_device_join_results WHERE status = 'joined' AND managed_device_id = 'm1' AND entra_device_id = 'd1'`,
	).Scan(&joinedCount); err != nil {
		t.Fatalf("query joined rows: %v", err)
	}
	if joinedCount != 1 {
		t.Errorf("joined rows for m1/d1 = %d, want 1", joinedCount)
	}
}
