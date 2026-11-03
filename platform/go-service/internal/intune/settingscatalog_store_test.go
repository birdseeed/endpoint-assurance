package intune

// DB-backed test for PostgresDefinitionStore, gated behind TEST_DATABASE_URL
// — same convention as postgres_store_test.go (PAT-1662) and
// internal/rings/advance_db_test.go / internal/auth/bearer_db_test.go. The
// pool's search_path is pinned to an isolated schema mirroring
// migrations/0125_settings_catalog_definitions.sql, so no real data is
// touched; the schema is dropped on cleanup.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pgSettingsCatalogTestSchema = "pat1663_test"

func pgSettingsCatalogPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed setting-definition store test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pgSettingsCatalogTestSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`DROP SCHEMA IF EXISTS ` + pgSettingsCatalogTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pgSettingsCatalogTestSchema,
		// Mirrors migrations/0125_settings_catalog_definitions.sql (this is
		// the full shape; the production table has no columns PostgresDefinitionStore
		// doesn't already use, unlike the intune_config_* tables' test mirror).
		`CREATE TABLE ` + pgSettingsCatalogTestSchema + `.intune_setting_definitions (
			id            BIGSERIAL   PRIMARY KEY,
			definition_id TEXT        NOT NULL,
			version       TEXT        NOT NULL,
			display_name  TEXT        NOT NULL,
			description   TEXT        NOT NULL DEFAULT '',
			options       JSONB       NOT NULL DEFAULT '[]'::jsonb,
			fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (definition_id, version)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup exec %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pgSettingsCatalogTestSchema+` CASCADE`)
	})
	return pool
}

// TestPostgresDefinitionStore_PutAllThenGet_RoundTrips proves a definition
// written via PutAll (the refresh path) reads back byte-for-byte via Get
// (the resolution path), options included.
func TestPostgresDefinitionStore_PutAllThenGet_RoundTrips(t *testing.T) {
	ctx := context.Background()
	pool := pgSettingsCatalogPool(t)
	store := NewPostgresDefinitionStore(pool)

	def := bitlockerFixture()
	if err := store.PutAll(ctx, []SettingDefinition{def}); err != nil {
		t.Fatalf("PutAll: %v", err)
	}

	got, found, err := store.Get(ctx, def.ID, def.Version)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatalf("Get: not found after PutAll")
	}
	if got.DisplayName != def.DisplayName || got.Description != def.Description {
		t.Errorf("got %+v, want name/description from %+v", got, def)
	}
	if len(got.Options) != len(def.Options) {
		t.Fatalf("got %d options, want %d", len(got.Options), len(def.Options))
	}
	if got.Options[0] != def.Options[0] {
		t.Errorf("Options[0] = %+v, want %+v", got.Options[0], def.Options[0])
	}
}

// TestPostgresDefinitionStore_OlderVersionNotAppliedToNewerLookup is the
// DB-level version of TestResolve_VersionMismatch_DoesNotApplyStaleCachedName
// in settingscatalog_test.go: writing a newer version must not overwrite or
// shadow the older version's row, and a lookup at the newer version that
// was never written must miss (not fall back to the old version).
func TestPostgresDefinitionStore_OlderVersionNotAppliedToNewerLookup(t *testing.T) {
	ctx := context.Background()
	pool := pgSettingsCatalogPool(t)
	store := NewPostgresDefinitionStore(pool)

	v1 := bitlockerFixture() // Version "1"
	if err := store.PutAll(ctx, []SettingDefinition{v1}); err != nil {
		t.Fatalf("PutAll(v1): %v", err)
	}

	// A policy citing version "2" (never fetched) must miss, not silently
	// receive the v1 row.
	_, found, err := store.Get(ctx, v1.ID, "2")
	if err != nil {
		t.Fatalf("Get(v2): %v", err)
	}
	if found {
		t.Fatalf("Get(v2) found a definition; the v1 row must not satisfy a v2 lookup")
	}

	// CachedVersion should still report v1 is on file, for a useful
	// unresolved reason upstream.
	cachedVersion, cvFound, err := store.CachedVersion(ctx, v1.ID)
	if err != nil {
		t.Fatalf("CachedVersion: %v", err)
	}
	if !cvFound || cachedVersion != v1.Version {
		t.Errorf("CachedVersion = (%q, %v), want (%q, true)", cachedVersion, cvFound, v1.Version)
	}

	// Now fetch v2 for real (simulating a later refresh). v1 must remain
	// queryable — an older version is never deleted.
	v2 := v1
	v2.Version = "2"
	v2.DisplayName = "Require device encryption (v2 wording)"
	if err := store.PutAll(ctx, []SettingDefinition{v2}); err != nil {
		t.Fatalf("PutAll(v2): %v", err)
	}

	gotV1, foundV1, err := store.Get(ctx, v1.ID, v1.Version)
	if err != nil {
		t.Fatalf("Get(v1) after v2 written: %v", err)
	}
	if !foundV1 {
		t.Fatalf("v1 row disappeared after v2 was written; older versions must never be deleted")
	}
	if gotV1.DisplayName == v2.DisplayName {
		t.Fatalf("Get(v1) returned the v2 display name; version rows bled into each other")
	}

	gotV2, foundV2, err := store.Get(ctx, v2.ID, v2.Version)
	if err != nil {
		t.Fatalf("Get(v2): %v", err)
	}
	if !foundV2 || gotV2.DisplayName != v2.DisplayName {
		t.Errorf("Get(v2) = (%+v, %v), want display name %q", gotV2, foundV2, v2.DisplayName)
	}
}
