package categorytag

// PAT-2015: when the reconcile after a published edit fails, the edit is
// saved, the error says to run the backfill, and ReconcileAll finishes the
// job. Requires TEST_DATABASE_URL with migrations applied.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEditReconcileFailureIsFinishedByBackfill(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	sfx := hex.EncodeToString(b)
	bundleA, bundleB := "com.pat2015.edit.a."+sfx, "com.pat2015.edit.b."+sfx

	var tenantID, deviceID, runID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat2015-edit-'||$1, '\x00', '\x00') RETURNING id::text`, sfx).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id, serial, hostname, os)
		VALUES ($1::uuid, 'PAT2015E'||$2, 'pat2015-edit', 'macOS') RETURNING id::text`, tenantID, sfx).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO software_inventory_runs (tenant_id, device_id, platform, received_at, provenance)
		VALUES ($1::uuid, $2::uuid, 'macos', now(), 'backfill_current_snapshot') RETURNING id::text`, tenantID, deviceID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	for i, bundle := range []string{bundleA, bundleB} {
		sum := sha256.Sum256([]byte(bundle))
		fp := hex.EncodeToString(sum[:])
		var obsID int64
		if err := pool.QueryRow(ctx, `INSERT INTO software_observations (inventory_run_id, tenant_id, device_id, ordinal,
			platform, observed_name, observed_identifier, identity_kind, identity_value_normalized,
			identity_confidence, identity_fingerprint, observed_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'macos', $5, $5, 'macos_bundle', $5, 'medium', $6, now())
			RETURNING id`, runID, tenantID, deviceID, i, bundle, fp).Scan(&obsID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO software_installations (tenant_id, device_id, platform, identity_kind,
			identity_value_normalized, identity_fingerprint, current_name, first_seen_at, last_seen_at,
			latest_observation_id, provenance)
			VALUES ($1::uuid, $2::uuid, 'macos', 'macos_bundle', $3, $4, $3, now(), now(), $5, 'backfill_current_snapshot')`,
			tenantID, deviceID, bundle, fp, obsID); err != nil {
			t.Fatal(err)
		}
	}
	actor := Actor{Actor: "test"}
	var rule Rule
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rule, err = CreateRule(ctx, tx, RuleSpec{IdentifierType: TypeMacOSBundleID, IdentifierValue: bundleA,
			CategoryKey: "ai_tooling", SubtypeKey: "desktop_app"}, actor)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { _, _, err := RetireRule(ctx, tx, rule.ID, actor); return err })
	})
	if _, _, err := PublishRule(ctx, pool, rule.ID, actor); err != nil {
		t.Fatal(err)
	}
	live := func(bundle string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM software_category_tags t
			JOIN software_installations si ON si.id = t.installation_id
			WHERE t.rule_id = $1 AND t.retired_at IS NULL AND si.identity_value_normalized = $2`, rule.ID, bundle).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if live(bundleA) != 1 {
		t.Fatal("publish did not tag bundle A")
	}

	orig := reconcileAfterEdit
	reconcileAfterEdit = func(context.Context, *pgxpool.Pool, int64, string, int) (Result, error) {
		return Result{}, errors.New("injected reconcile failure")
	}
	_, _, err = UpdateRule(ctx, pool, rule.ID, RuleSpec{IdentifierType: TypeMacOSBundleID, IdentifierValue: bundleB,
		CategoryKey: "ai_tooling", SubtypeKey: "desktop_app"}, actor)
	reconcileAfterEdit = orig
	if !errors.Is(err, ErrReconcileIncomplete) || !strings.Contains(err.Error(), "POST /admin/software-categories/backfill") {
		t.Fatalf("edit error = %v, want ErrReconcileIncomplete naming the backfill", err)
	}
	if got, _ := GetRule(ctx, pool, rule.ID); got.IdentifierValue != bundleB || got.Version != 2 {
		t.Fatalf("edit not saved: %+v", got)
	}
	if live(bundleA) != 1 || live(bundleB) != 0 {
		t.Fatal("tags changed although the reconcile failed")
	}

	if _, err := ReconcileAll(ctx, pool); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if live(bundleA) != 0 || live(bundleB) != 1 {
		t.Fatalf("after backfill: A live %d, B live %d; want 0 and 1", live(bundleA), live(bundleB))
	}
}
