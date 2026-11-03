package healthsignals

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

// -- recomputeOne DB round-trip tests (PAT-872) ------------------------------
//
// These tests require a live Postgres with all migrations applied (see
// docs/TESTING.md). They are skipped when TEST_DATABASE_URL is unset, matching
// the pattern used by internal/handlers/health_signals_test.go.

// dbOrSkip connects using TEST_DATABASE_URL, or skips the test when it is unset.
func dbOrSkip(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping healthsignals rotation DB tests")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, ctx
}

// insertRotationTenant creates a tenant row with directly-controlled
// health-signal state so the 30-day rotation gate can be exercised without
// waiting real wall-clock time, and registers cleanup. lastRotatedAt may be
// nil to exercise the created_at fallback path (a brand new tenant that has
// never rotated).
func insertRotationTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, createdAt time.Time, lastRotatedAt *time.Time, currentScore *int, score30dAgo *int, dashLogins int) string {
	t.Helper()
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (
			name, bearer_token_hash, hmac_secret, created_at, updated_at,
			health_signals_last_rotated_at,
			compliance_score_current, compliance_score_30d_ago,
			dashboard_logins_last_30d
		)
		VALUES ($1, '\x00'::bytea, '\x00'::bytea, $2, $2, $3, $4, $5, $6)
		RETURNING id::text
	`, name, createdAt, lastRotatedAt, currentScore, score30dAgo, dashLogins).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}

func intPtr(v int) *int { return &v }

func TestRecomputeOne_NoRotationWithinWindow(t *testing.T) {
	pool, ctx := dbOrSkip(t)

	rotatedAt := time.Now().Add(-40 * 24 * time.Hour) // 40 days ago -> eligible
	createdAt := time.Now().Add(-100 * 24 * time.Hour)
	tenantID := insertRotationTenant(t, ctx, pool, "pat872-no-rerotate", createdAt, &rotatedAt, intPtr(50), nil, 5)

	// First run: rotation is eligible (40 days since last rotation) and
	// should fire.
	if err := recomputeOne(ctx, pool, tenantID); err != nil {
		t.Fatalf("recomputeOne (first run): %v", err)
	}

	var score30dAgo *int
	var lastRotatedAt time.Time
	var dashLogins int
	if err := pool.QueryRow(ctx, `
		SELECT compliance_score_30d_ago, health_signals_last_rotated_at, dashboard_logins_last_30d
		FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&score30dAgo, &lastRotatedAt, &dashLogins); err != nil {
		t.Fatalf("query after first run: %v", err)
	}
	if score30dAgo == nil || *score30dAgo != 50 {
		t.Fatalf("want compliance_score_30d_ago=50 after first rotation, got %v", score30dAgo)
	}
	if dashLogins != 0 {
		t.Fatalf("want dashboard_logins_last_30d reset to 0 after rotation, got %d", dashLogins)
	}
	if time.Since(lastRotatedAt) > time.Minute {
		t.Fatalf("want health_signals_last_rotated_at freshly stamped, got %v ago", time.Since(lastRotatedAt))
	}

	// Simulate a new compliance score and a login recorded just after
	// rotation. Mimics handlers/health_signals.go incrementing the counter.
	if _, err := pool.Exec(ctx, `
		UPDATE tenants SET compliance_score_current = 80, dashboard_logins_last_30d = 3
		WHERE id = $1::uuid
	`, tenantID); err != nil {
		t.Fatalf("simulate post-rotation login: %v", err)
	}

	// Second run happens seconds later (well within 30 days of the rotation
	// that just fired). This must NOT rotate again.
	if err := recomputeOne(ctx, pool, tenantID); err != nil {
		t.Fatalf("recomputeOne (second run): %v", err)
	}

	var score30dAgoAfter *int
	var dashLoginsAfter int
	if err := pool.QueryRow(ctx, `
		SELECT compliance_score_30d_ago, dashboard_logins_last_30d
		FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&score30dAgoAfter, &dashLoginsAfter); err != nil {
		t.Fatalf("query after second run: %v", err)
	}
	if score30dAgoAfter == nil || *score30dAgoAfter != 50 {
		t.Fatalf("want compliance_score_30d_ago to remain 50 (no re-rotation within 30 days), got %v", score30dAgoAfter)
	}
	if dashLoginsAfter != 3 {
		t.Fatalf("want dashboard_logins_last_30d to remain 3 (not reset outside rotation), got %d", dashLoginsAfter)
	}
}

func TestRecomputeOne_RotatesAfter30DaysElapsed(t *testing.T) {
	pool, ctx := dbOrSkip(t)

	rotatedAt := time.Now().Add(-31 * 24 * time.Hour) // just over 30 days ago
	createdAt := time.Now().Add(-200 * 24 * time.Hour)
	tenantID := insertRotationTenant(t, ctx, pool, "pat872-rotates-after-30d", createdAt, &rotatedAt, intPtr(80), intPtr(40), 7)

	beforeRun := time.Now()
	if err := recomputeOne(ctx, pool, tenantID); err != nil {
		t.Fatalf("recomputeOne: %v", err)
	}

	var score30dAgo *int
	var lastRotatedAt time.Time
	var dashLogins int
	if err := pool.QueryRow(ctx, `
		SELECT compliance_score_30d_ago, health_signals_last_rotated_at, dashboard_logins_last_30d
		FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&score30dAgo, &lastRotatedAt, &dashLogins); err != nil {
		t.Fatalf("query: %v", err)
	}
	if score30dAgo == nil || *score30dAgo != 80 {
		t.Fatalf("want compliance_score_30d_ago rotated to 80, got %v", score30dAgo)
	}
	if lastRotatedAt.Before(beforeRun) {
		t.Fatalf("want health_signals_last_rotated_at to advance to now, got %v (before run started at %v)", lastRotatedAt, beforeRun)
	}
	if dashLogins != 0 {
		t.Fatalf("want dashboard_logins_last_30d reset to 0 on rotation, got %d", dashLogins)
	}

	// Running again immediately must not fire a second rotation. This is
	// the "fires exactly once" half of the requirement.
	if _, err := pool.Exec(ctx, `UPDATE tenants SET compliance_score_current = 55 WHERE id = $1::uuid`, tenantID); err != nil {
		t.Fatalf("simulate new score: %v", err)
	}
	if err := recomputeOne(ctx, pool, tenantID); err != nil {
		t.Fatalf("recomputeOne (immediate rerun): %v", err)
	}
	var score30dAgoAfter *int
	if err := pool.QueryRow(ctx, `
		SELECT compliance_score_30d_ago FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&score30dAgoAfter); err != nil {
		t.Fatalf("query after rerun: %v", err)
	}
	if score30dAgoAfter == nil || *score30dAgoAfter != 80 {
		t.Fatalf("want compliance_score_30d_ago to stay 80 (no second rotation), got %v", score30dAgoAfter)
	}
}

func TestRecomputeOne_LoginCounterWindowsOnRotation(t *testing.T) {
	pool, ctx := dbOrSkip(t)

	rotatedAt := time.Now().Add(-45 * 24 * time.Hour)
	createdAt := time.Now().Add(-300 * 24 * time.Hour)
	tenantID := insertRotationTenant(t, ctx, pool, "pat872-login-window", createdAt, &rotatedAt, intPtr(60), nil, 12)

	// Pre-condition: a tenant that logged in 12 times would never trip the
	// "no logins in 30 days" penalty under the old, never-reset counter.
	var before int
	if err := pool.QueryRow(ctx, `SELECT dashboard_logins_last_30d FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&before); err != nil {
		t.Fatalf("query before: %v", err)
	}
	if before != 12 {
		t.Fatalf("setup: want dashboard_logins_last_30d=12, got %d", before)
	}

	if err := recomputeOne(ctx, pool, tenantID); err != nil {
		t.Fatalf("recomputeOne: %v", err)
	}

	var after int
	if err := pool.QueryRow(ctx, `SELECT dashboard_logins_last_30d FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&after); err != nil {
		t.Fatalf("query after: %v", err)
	}
	if after != 0 {
		t.Fatalf("want dashboard_logins_last_30d to window/reset to 0 on rotation, got %d", after)
	}

	// A subsequent login (simulating handlers/health_signals.go) must still
	// increment correctly from the fresh window.
	if _, err := pool.Exec(ctx, `
		UPDATE tenants SET dashboard_logins_last_30d = dashboard_logins_last_30d + 1
		WHERE id = $1::uuid
	`, tenantID); err != nil {
		t.Fatalf("simulate increment: %v", err)
	}
	var afterLogin int
	if err := pool.QueryRow(ctx, `SELECT dashboard_logins_last_30d FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&afterLogin); err != nil {
		t.Fatalf("query after login: %v", err)
	}
	if afterLogin != 1 {
		t.Fatalf("want dashboard_logins_last_30d=1 after a fresh-window login, got %d", afterLogin)
	}
}

// TestRecomputeOne_NullLastRotatedAtFallsBackToCreatedAt exercises the
// never-rotated path (health_signals_last_rotated_at IS NULL), which real
// new tenants hit. The rotation baseline must fall back to created_at, not
// treat NULL as "always eligible" or "never eligible".
func TestRecomputeOne_NullLastRotatedAtFallsBackToCreatedAt(t *testing.T) {
	pool, ctx := dbOrSkip(t)

	// Tenant created 10 days ago, never rotated (NULL). Not yet eligible:
	// created_at fallback baseline is only 10 days old, well short of 30.
	recentCreatedAt := time.Now().Add(-10 * 24 * time.Hour)
	youngTenant := insertRotationTenant(t, ctx, pool, "pat872-null-baseline-young", recentCreatedAt, nil, intPtr(70), nil, 2)

	if err := recomputeOne(ctx, pool, youngTenant); err != nil {
		t.Fatalf("recomputeOne (young tenant): %v", err)
	}
	var score30dAgo *int
	var lastRotatedAt *time.Time
	var dashLogins int
	if err := pool.QueryRow(ctx, `
		SELECT compliance_score_30d_ago, health_signals_last_rotated_at, dashboard_logins_last_30d
		FROM tenants WHERE id = $1::uuid
	`, youngTenant).Scan(&score30dAgo, &lastRotatedAt, &dashLogins); err != nil {
		t.Fatalf("query young tenant: %v", err)
	}
	if score30dAgo != nil {
		t.Fatalf("want compliance_score_30d_ago to stay NULL (tenant only 10 days old), got %v", *score30dAgo)
	}
	if lastRotatedAt != nil {
		t.Fatalf("want health_signals_last_rotated_at to stay NULL (no rotation fired), got %v", *lastRotatedAt)
	}
	if dashLogins != 2 {
		t.Fatalf("want dashboard_logins_last_30d unchanged at 2 (no rotation fired), got %d", dashLogins)
	}

	// Tenant created 40 days ago, never rotated (NULL). Eligible: created_at
	// fallback baseline is > 30 days old.
	oldCreatedAt := time.Now().Add(-40 * 24 * time.Hour)
	oldTenant := insertRotationTenant(t, ctx, pool, "pat872-null-baseline-old", oldCreatedAt, nil, intPtr(70), nil, 2)

	if err := recomputeOne(ctx, pool, oldTenant); err != nil {
		t.Fatalf("recomputeOne (old tenant): %v", err)
	}
	var score30dAgoOld *int
	var lastRotatedAtOld *time.Time
	var dashLoginsOld int
	if err := pool.QueryRow(ctx, `
		SELECT compliance_score_30d_ago, health_signals_last_rotated_at, dashboard_logins_last_30d
		FROM tenants WHERE id = $1::uuid
	`, oldTenant).Scan(&score30dAgoOld, &lastRotatedAtOld, &dashLoginsOld); err != nil {
		t.Fatalf("query old tenant: %v", err)
	}
	if score30dAgoOld == nil || *score30dAgoOld != 70 {
		t.Fatalf("want compliance_score_30d_ago rotated to 70 (tenant older than 30 days), got %v", score30dAgoOld)
	}
	if lastRotatedAtOld == nil {
		t.Fatalf("want health_signals_last_rotated_at stamped after rotation, got nil")
	}
	if dashLoginsOld != 0 {
		t.Fatalf("want dashboard_logins_last_30d reset to 0 on rotation, got %d", dashLoginsOld)
	}
}
