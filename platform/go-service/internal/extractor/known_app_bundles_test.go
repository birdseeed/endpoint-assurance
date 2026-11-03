package extractor

// Tests for known_app_bundles upsert semantics (PAT-806): auto-populated,
// tenant-agnostic (name, platform) -> app_path mapping fed from every
// inventory ingest, distinct from the manually-curated EULA/mirror Catalogue.
//
// DB-backed: require TEST_DATABASE_URL and are skipped otherwise, matching the
// pattern used by internal/handlers/device_removals_test.go.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

func kabConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping known_app_bundles DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

func kabCleanup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM known_app_bundles WHERE name = $1`, name)
	})
}

// TestUpsertKnownAppBundle_FirstSeenPreserved covers: first_seen_at is set on
// first insert and does NOT move on a later re-sighting, while last_seen_at
// and app_path do refresh.
//
// Each "sighting" runs in and commits its own transaction -- mirroring real
// usage, where upsertKnownAppBundle is called once per ingest transaction.
// Postgres now() is fixed for the lifetime of a transaction (same caveat
// documented on the device_apps prune in upsertApps), so two calls inside one
// shared tx would incorrectly see identical timestamps.
func TestUpsertKnownAppBundle_FirstSeenPreserved(t *testing.T) {
	pool := kabConnectOrSkip(t)
	// t.Cleanup (not a plain defer): a bare `defer pool.Close()` runs at
	// function-return time, which is BEFORE the testing package invokes
	// t.Cleanup callbacks -- so the seed helpers' DELETE-on-cleanup below
	// would silently fail against an already-closed pool (found in PAT-806
	// review; this exact ordering bug also exists in device_removals_test.go's
	// `defer pool.Close()` -- left alone there as pre-existing/out of scope).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	name := "PAT806-TestApp-FirstSeen"
	kabCleanup(t, ctx, pool, name)

	runUpsert := func(path string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := upsertKnownAppBundle(ctx, tx, name, "macos", path); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	querySnapshot := func() (firstSeen, lastSeen time.Time, path string) {
		t.Helper()
		if err := pool.QueryRow(ctx,
			`SELECT first_seen_at, last_seen_at, app_path FROM known_app_bundles WHERE name = $1 AND platform = 'macos'`,
			name,
		).Scan(&firstSeen, &lastSeen, &path); err != nil {
			t.Fatalf("scan: %v", err)
		}
		return
	}

	runUpsert("/Applications/PAT806TestApp.app")
	firstSeen1, lastSeen1, path1 := querySnapshot()
	if path1 != "/Applications/PAT806TestApp.app" {
		t.Errorf("app_path after first upsert = %q, want /Applications/PAT806TestApp.app", path1)
	}

	// Sleep past typical timestamp precision so last_seen_at visibly moves if
	// refreshed.
	time.Sleep(10 * time.Millisecond)

	// Re-sighting with a DIFFERENT path (simulating a vendor bundle rename) --
	// app_path should update, first_seen_at must NOT move, last_seen_at must
	// advance.
	runUpsert("/Applications/PAT806TestApp-v2.app")
	firstSeen2, lastSeen2, path2 := querySnapshot()

	if !firstSeen1.Equal(firstSeen2) {
		t.Errorf("first_seen_at changed across re-sighting: %v -> %v", firstSeen1, firstSeen2)
	}
	if !lastSeen2.After(lastSeen1) {
		t.Errorf("last_seen_at did not advance: %v -> %v", lastSeen1, lastSeen2)
	}
	if path2 != "/Applications/PAT806TestApp-v2.app" {
		t.Errorf("app_path after second upsert = %q, want /Applications/PAT806TestApp-v2.app", path2)
	}

	// Exactly one row for this name+platform -- conflict target worked as an
	// update, not a duplicate insert.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM known_app_bundles WHERE name = $1 AND platform = 'macos'`, name,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("row count for name+platform = %d, want 1", count)
	}

	// Rows were committed above (not rolled back), so clean up explicitly
	// rather than relying on kabCleanup's t.Cleanup (which only fires once,
	// after this func returns -- fine here, but the explicit delete makes the
	// commit-vs-rollback distinction from the other tests in this file obvious).
	_, _ = pool.Exec(ctx, `DELETE FROM known_app_bundles WHERE name = $1`, name)
}

// TestUpsertKnownAppBundle_CaseInsensitiveDedup covers: two sightings of the
// same app whose reported display-name casing differs (e.g. "Zoom" vs
// "zoom") collapse to ONE row, not two. This matters because the reader
// (GET /v1/allowlist/pending-removals) joins known_app_bundles against
// tenant_allowlists.name case-insensitively (LOWER() on both sides) -- if
// the write side used a case-SENSITIVE key, two differently-cased rows for
// the same app could both satisfy that join and the endpoint would return
// duplicate items for a single queued removal.
func TestUpsertKnownAppBundle_CaseInsensitiveDedup(t *testing.T) {
	pool := kabConnectOrSkip(t)
	// t.Cleanup (not a plain defer): a bare `defer pool.Close()` runs at
	// function-return time, which is BEFORE the testing package invokes
	// t.Cleanup callbacks -- so the seed helpers' DELETE-on-cleanup below
	// would silently fail against an already-closed pool (found in PAT-806
	// review; this exact ordering bug also exists in device_removals_test.go's
	// `defer pool.Close()` -- left alone there as pre-existing/out of scope).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	name := "PAT806-CaseDedup"
	altCaseName := "pat806-casededup"
	kabCleanup(t, ctx, pool, name)
	kabCleanup(t, ctx, pool, altCaseName)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := upsertKnownAppBundle(ctx, tx, name, "macos", "/Applications/PAT806CaseDedup.app"); err != nil {
		t.Fatalf("first upsert (title case): %v", err)
	}
	if err := upsertKnownAppBundle(ctx, tx, altCaseName, "macos", "/Applications/PAT806CaseDedupAlt.app"); err != nil {
		t.Fatalf("second upsert (lowercase): %v", err)
	}

	var count int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM known_app_bundles WHERE LOWER(name) = LOWER($1) AND platform = 'macos'`, name,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count across case variants = %d, want 1 (case-insensitive collapse)", count)
	}

	var path string
	if err := tx.QueryRow(ctx,
		`SELECT app_path FROM known_app_bundles WHERE LOWER(name) = LOWER($1) AND platform = 'macos'`, name,
	).Scan(&path); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if path != "/Applications/PAT806CaseDedupAlt.app" {
		t.Errorf("app_path = %q, want the second (latest) sighting's path", path)
	}
}

// TestUpsertKnownAppBundle_PlatformKeyIsolation covers: the same app name on
// both platforms does not collide — (name, platform) is a compound key, and
// each platform keeps an independent app_path/first_seen_at/last_seen_at.
func TestUpsertKnownAppBundle_PlatformKeyIsolation(t *testing.T) {
	pool := kabConnectOrSkip(t)
	// t.Cleanup (not a plain defer): a bare `defer pool.Close()` runs at
	// function-return time, which is BEFORE the testing package invokes
	// t.Cleanup callbacks -- so the seed helpers' DELETE-on-cleanup below
	// would silently fail against an already-closed pool (found in PAT-806
	// review; this exact ordering bug also exists in device_removals_test.go's
	// `defer pool.Close()` -- left alone there as pre-existing/out of scope).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	name := "PAT806-TestApp-PlatformIsolation"
	kabCleanup(t, ctx, pool, name)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := upsertKnownAppBundle(ctx, tx, name, "macos", "/Applications/PAT806TestApp.app"); err != nil {
		t.Fatalf("macos upsert: %v", err)
	}
	if err := upsertKnownAppBundle(ctx, tx, name, "windows", `C:\Program Files\PAT806TestApp\app.exe`); err != nil {
		t.Fatalf("windows upsert: %v", err)
	}

	var count int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM known_app_bundles WHERE name = $1`, name,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("row count for name across platforms = %d, want 2 (macos + windows independent rows)", count)
	}

	var macPath, winPath string
	if err := tx.QueryRow(ctx,
		`SELECT app_path FROM known_app_bundles WHERE name = $1 AND platform = 'macos'`, name,
	).Scan(&macPath); err != nil {
		t.Fatalf("scan macos row: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`SELECT app_path FROM known_app_bundles WHERE name = $1 AND platform = 'windows'`, name,
	).Scan(&winPath); err != nil {
		t.Fatalf("scan windows row: %v", err)
	}
	if macPath != "/Applications/PAT806TestApp.app" {
		t.Errorf("macos app_path = %q, want /Applications/PAT806TestApp.app", macPath)
	}
	if winPath != `C:\Program Files\PAT806TestApp\app.exe` {
		t.Errorf("windows app_path = %q, want C:\\Program Files\\PAT806TestApp\\app.exe", winPath)
	}
}

// TestUpsertApps_FeedsKnownAppBundles covers the integration point (PAT-806):
// upsertApps itself must feed known_app_bundles for apps carrying a path, and
// must skip apps with an empty path (nothing useful to record).
func TestUpsertApps_FeedsKnownAppBundles(t *testing.T) {
	pool := kabConnectOrSkip(t)
	// t.Cleanup (not a plain defer): a bare `defer pool.Close()` runs at
	// function-return time, which is BEFORE the testing package invokes
	// t.Cleanup callbacks -- so the seed helpers' DELETE-on-cleanup below
	// would silently fail against an already-closed pool (found in PAT-806
	// review; this exact ordering bug also exists in device_removals_test.go's
	// `defer pool.Close()` -- left alone there as pre-existing/out of scope).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	nameWithPath := "PAT806-UpsertApps-WithPath"
	nameNoPath := "PAT806-UpsertApps-NoPath"
	kabCleanup(t, ctx, pool, nameWithPath)
	kabCleanup(t, ctx, pool, nameNoPath)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('PAT806-known-app-bundles-test', '\x00'::bytea, '\x00'::bytea)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os) VALUES ($1::uuid, 'macOS') RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	apps := []appPart{
		{Name: nameWithPath, Identifier: "com.patched.pat806.withpath", Path: "/Applications/PAT806WithPath.app"},
		{Name: nameNoPath, Identifier: "com.patched.pat806.nopath", Path: ""},
	}

	if _, _, err := upsertApps(ctx, tx, deviceID, time.Now(), apps, nil, "macos", appsSignalComplete, "", nil, legacyUserHold{}); err != nil {
		t.Fatalf("upsertApps: %v", err)
	}

	var withPathCount int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM known_app_bundles WHERE name = $1 AND platform = 'macos'`, nameWithPath,
	).Scan(&withPathCount); err != nil {
		t.Fatalf("count withPath: %v", err)
	}
	if withPathCount != 1 {
		t.Errorf("known_app_bundles row for app with path: got count %d, want 1", withPathCount)
	}

	var noPathCount int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM known_app_bundles WHERE name = $1 AND platform = 'macos'`, nameNoPath,
	).Scan(&noPathCount); err != nil {
		t.Fatalf("count noPath: %v", err)
	}
	if noPathCount != 0 {
		t.Errorf("known_app_bundles row for app with empty path: got count %d, want 0 (should be skipped)", noPathCount)
	}
}
