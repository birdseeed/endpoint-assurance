package extractor

// PAT-2015: category tag evaluation runs inside the ingest transaction and
// must never fail or abort it. This drives a failing evaluator through the
// real savepoint guard and proves the transaction is still usable and keeps
// the work done before it. Requires TEST_DATABASE_URL; all writes roll back.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/categorytag"
)

func TestCategoryTagEvaluationFailureNeverAbortsIngest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping category tag savepoint test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID, deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat2015-savepoint', '\x00', '\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hostname, os) VALUES ($1::uuid, 'PAT2015SP', 'pat2015-sp', 'macOS')
		RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	orig := categoryTagEvaluator
	t.Cleanup(func() { categoryTagEvaluator = orig })
	called := false
	categoryTagEvaluator = func(ctx context.Context, sp pgx.Tx, tenant, device string) (categorytag.Result, error) {
		called = true
		// A write, then a statement error: both must roll back to the
		// savepoint and leave the outer transaction healthy.
		if _, err := sp.Exec(ctx, `UPDATE devices SET hostname = 'clobbered' WHERE id = $1::uuid`, device); err != nil {
			return categorytag.Result{}, err
		}
		_, err := sp.Exec(ctx, `SELECT 1/0`)
		return categorytag.Result{}, err
	}

	evaluateCategoryTags(ctx, tx, tenantID, deviceID, nil)
	if !called {
		t.Fatal("evaluator was not called")
	}

	var hostname string
	if err := tx.QueryRow(ctx, `SELECT hostname FROM devices WHERE id = $1::uuid`, deviceID).Scan(&hostname); err != nil {
		t.Fatalf("outer transaction unusable after a failed evaluation: %v", err)
	}
	if hostname != "pat2015-sp" {
		t.Fatalf("hostname = %q: the failed evaluation's write leaked past its savepoint", hostname)
	}

	// And the real evaluator runs cleanly against a device with no inventory.
	categoryTagEvaluator = orig
	evaluateCategoryTags(ctx, tx, tenantID, deviceID, nil)
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatalf("outer transaction unusable after the real evaluator: %v", err)
	}
}
