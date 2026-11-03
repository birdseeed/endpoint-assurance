package extractor

// DB-backed tests for PAT-1825's automatic reappearance rule
// (checkAndSupersedeReappearedDisposition, disposition_reappearance.go).
// Same isolated-schema convention as applied_config_db_test.go: schema
// mirrors migrations/0143_device_dispositions.sql by hand, gated behind
// TEST_DATABASE_URL, dropped on cleanup.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1825ExtractorSchema = "pat1825_extractor_test"

func pat1825ExtractorPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed reappearance test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1825ExtractorSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1825ExtractorSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1825ExtractorSchema,
		`CREATE TABLE ` + pat1825ExtractorSchema + `.tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid()
		)`,
		`CREATE TABLE ` + pat1825ExtractorSchema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1825ExtractorSchema + `.tenants(id)
		)`,
		// Mirrors migrations/0143_device_dispositions.sql.
		`CREATE TABLE ` + pat1825ExtractorSchema + `.device_dispositions (
			id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id           UUID         NOT NULL REFERENCES ` + pat1825ExtractorSchema + `.tenants(id),
			device_id           UUID         NOT NULL REFERENCES ` + pat1825ExtractorSchema + `.devices(id),
			category            TEXT         NOT NULL CHECK (category IN ('decommissioned', 'on-leave', 'lost', 'unaccounted')),
			reported_by         TEXT         NOT NULL DEFAULT '',
			reported_by_role    TEXT         NOT NULL DEFAULT '',
			channel             TEXT         NOT NULL DEFAULT '',
			note                TEXT         NOT NULL DEFAULT '',
			recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
			cohort_id           UUID,
			supersedes_id       UUID         REFERENCES ` + pat1825ExtractorSchema + `.device_dispositions(id),
			superseded_at       TIMESTAMPTZ,
			superseded_reason   TEXT
		)`,
		`CREATE TABLE ` + pat1825ExtractorSchema + `.device_lifecycle_findings (
			id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id      UUID        NOT NULL REFERENCES ` + pat1825ExtractorSchema + `.tenants(id),
			device_id      UUID        NOT NULL REFERENCES ` + pat1825ExtractorSchema + `.devices(id),
			disposition_id UUID        NOT NULL REFERENCES ` + pat1825ExtractorSchema + `.device_dispositions(id),
			kind           TEXT        NOT NULL CHECK (kind IN ('reappeared_after_disposition')),
			detail         TEXT        NOT NULL DEFAULT '',
			raised_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1825ExtractorSchema+` CASCADE`)
	})
	return pool
}

func pat1825ExtractorSeedTenantDevice(t *testing.T, pool *pgxpool.Pool) (tenantID, deviceID string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return tenantID, deviceID
}

func TestCheckAndSupersedeReappearedDisposition_ActiveDisposition_SupersedesAndRaisesFinding(t *testing.T) {
	pool := pat1825ExtractorPool(t)
	tenantID, deviceID := pat1825ExtractorSeedTenantDevice(t, pool)
	ctx := context.Background()

	// Disposition recorded an hour ago — well before "now".
	var dispositionID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO device_dispositions (tenant_id, device_id, category, reported_by, recorded_at)
		VALUES ($1::uuid, $2::uuid, 'decommissioned', 'jane@customer.com', now() - interval '1 hour')
		RETURNING id::text
	`, tenantID, deviceID).Scan(&dispositionID); err != nil {
		t.Fatalf("seed disposition: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	findingID, err := checkAndSupersedeReappearedDisposition(ctx, tx, tenantID, deviceID, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("checkAndSupersedeReappearedDisposition: %v", err)
	}
	if findingID == "" {
		t.Fatal("expected a finding to be raised for a device with an active disposition that reappeared")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var supersededReason string
	var supersededAt *string
	if err := pool.QueryRow(ctx,
		`SELECT superseded_reason, superseded_at::text FROM device_dispositions WHERE id = $1::uuid`, dispositionID,
	).Scan(&supersededReason, &supersededAt); err != nil {
		t.Fatal(err)
	}
	if supersededReason != "reappeared" || supersededAt == nil {
		t.Fatalf("disposition not auto-superseded correctly: reason=%q at=%v", supersededReason, supersededAt)
	}

	var findingCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM device_lifecycle_findings WHERE device_id = $1::uuid AND kind = 'reappeared_after_disposition'`,
		deviceID,
	).Scan(&findingCount); err != nil {
		t.Fatal(err)
	}
	if findingCount != 1 {
		t.Fatalf("expected exactly 1 reappearance finding, got %d", findingCount)
	}
}

func TestCheckAndSupersedeReappearedDisposition_NoActiveDisposition_NoOp(t *testing.T) {
	pool := pat1825ExtractorPool(t)
	tenantID, deviceID := pat1825ExtractorSeedTenantDevice(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	findingID, err := checkAndSupersedeReappearedDisposition(ctx, tx, tenantID, deviceID, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("checkAndSupersedeReappearedDisposition: %v", err)
	}
	if findingID != "" {
		t.Fatalf("expected no finding for a device with no disposition at all, got %q", findingID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var findingCount, dispositionCount int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM device_lifecycle_findings WHERE device_id = $1::uuid`, deviceID).Scan(&findingCount)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM device_dispositions WHERE device_id = $1::uuid`, deviceID).Scan(&dispositionCount)
	if findingCount != 0 || dispositionCount != 0 {
		t.Fatalf("no-disposition device should have zero rows written, got findings=%d dispositions=%d", findingCount, dispositionCount)
	}
}

// A superseded (already-resolved) disposition must never be found "active"
// again — the reappearance check is scoped to superseded_at IS NULL, so a
// second ingest after the first reappearance already resolved things must
// also no-op.
func TestCheckAndSupersedeReappearedDisposition_AlreadySuperseded_NoOp(t *testing.T) {
	pool := pat1825ExtractorPool(t)
	tenantID, deviceID := pat1825ExtractorSeedTenantDevice(t, pool)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO device_dispositions (tenant_id, device_id, category, reported_by, recorded_at, superseded_at, superseded_reason)
		VALUES ($1::uuid, $2::uuid, 'lost', 'jane@customer.com', now() - interval '2 hour', now() - interval '1 hour', 'reappeared')
	`, tenantID, deviceID); err != nil {
		t.Fatalf("seed superseded disposition: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	findingID, err := checkAndSupersedeReappearedDisposition(ctx, tx, tenantID, deviceID, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("checkAndSupersedeReappearedDisposition: %v", err)
	}
	if findingID != "" {
		t.Fatalf("an already-superseded disposition must not raise another finding, got %q", findingID)
	}
}
