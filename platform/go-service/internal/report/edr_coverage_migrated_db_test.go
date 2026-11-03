package report

// PAT-2226: every other test in this package (edr_coverage_db_test.go)
// builds its own hand-copied schema mirroring migrations/0139_protected_
// software.sql's columns — the established internal/report db-test
// convention (pat1758Pool etc.), chosen so a full migration run isn't
// required. A hand copy can drift from the real migration without anyone
// noticing, so this file runs the same "Sophos is covered" assertion
// against a REAL, fully-migrated schema instead: the actual
// protected_software table as migration 0139 creates it, with its actual
// seeded baseline Sophos row, not a row this suite inserted.
//
// Convention: same as internal/handlers' parConnectOrSkip/parSeedTenant
// (see allowlist_agent_known_path_test.go) — connect to TEST_DATABASE_URL
// directly with no search_path override, on the assumption the target
// database is already fully migrated (true in CI: go-integration-test.yml
// runs integration/'s TestMain, which applies every migrations/*.sql file,
// before any *_db_test.go in this package runs against the same
// TEST_DATABASE_URL). Locally, point TEST_DATABASE_URL at a database that
// has had every migrations/*.sql file applied — e.g. build one the way
// integration/'s TestMain does:
//
//	createdb -h <host> -U <user> patched_migrated_test
//	TEST_DATABASE_URL=postgres://<user>@<host>/patched_migrated_test?sslmode=disable \
//	  go test -tags=integration -run TestMain ./integration/ -v
//
// then point this test's TEST_DATABASE_URL at that same database. Skips
// (rather than erroring) when TEST_DATABASE_URL is unset or the target
// database hasn't reached migration 0139 yet, so a plain `go test ./...`
// against an empty/unmigrated database degrades to a skip, not a false red.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

// pat2226MigratedConnectOrSkip connects to TEST_DATABASE_URL's public
// schema and skips (with a clear reason) unless migration
// 0139_protected_software has actually been applied there.
func pat2226MigratedConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping migrated-schema EDR coverage test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var applied bool
	err = pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0139_protected_software')`,
	).Scan(&applied)
	if err != nil {
		pool.Close()
		t.Skipf("TEST_DATABASE_URL does not look like a fully-migrated schema (schema_migrations query failed: %v) — "+
			"point it at a database with every migrations/*.sql file applied, see this file's header comment", err)
	}
	if !applied {
		pool.Close()
		t.Skip("TEST_DATABASE_URL is missing migration 0139_protected_software — " +
			"point it at a database with every migrations/*.sql file applied, see this file's header comment")
	}
	return pool
}

// pat2226MigratedSeedTenant inserts a real tenants row satisfying every
// NOT NULL column migration 0001+ actually requires (bearer_token_hash,
// hmac_secret — the hand-copied schema in edr_coverage_db_test.go doesn't
// carry these because its tenants table only needs `name`), and registers
// cleanup. FetchEDRCoverageReport never reads bearer_token_hash/hmac_secret
// itself, but a real tenants row can't be inserted without them.
func pat2226MigratedSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	tokenHash := sha256.Sum256([]byte("pat2226-migrated-" + name))
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, $2, $3)
		RETURNING id::text
	`, name, tokenHash[:], []byte("pat2226-migrated-hmac-secret-32b!")).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}

// TestFetchEDRCoverageReport_RealMigratedSchema_SophosBaselineCovered is the
// requirement-2 check: prove FetchEDRCoverageReport reports a Sophos-only
// device as covered against the REAL protected_software table (migration
// 0139) and its REAL seeded baseline row, not the hand-copied schema every
// other test in this package uses. No protected_software row is inserted by
// this test — the baseline row this asserts against is whatever migration
// 0139 itself seeded.
func TestFetchEDRCoverageReport_RealMigratedSchema_SophosBaselineCovered(t *testing.T) {
	pool := pat2226MigratedConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	// Confirm the real baseline row this test relies on is actually there —
	// fail with a clear message rather than a confusing "unrecognised"
	// assertion failure if migration 0139's seed ever changes shape.
	var baselineCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM protected_software
		WHERE tenant_id IS NULL AND category = 'edr' AND lower(vendor) = 'sophos'
	`).Scan(&baselineCount); err != nil {
		t.Fatalf("check sophos baseline row: %v", err)
	}
	if baselineCount == 0 {
		t.Skip("no shared-baseline Sophos protected_software row found (migration 0139 seed) — " +
			"is TEST_DATABASE_URL pointed at a database with 0139 actually applied?")
	}

	tenantID := pat2226MigratedSeedTenant(t, ctx, pool, "pat2226-migrated-sophos-tenant")

	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, security_inventory)
		VALUES ($1::uuid, 'sophos-real-schema', 'macOS 15.5', $2::jsonb)
	`, tenantID, `{"security_tools":[{"id":"sophos-endpoint","name":"Sophos Intercept X"}]}`); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}

	dev := pat2226DeviceByHostname(t, r, "sophos-real-schema")
	if dev.State != EDRStateCovered {
		t.Fatalf("real-schema Sophos device state = %q, want %q (baseline row: %d matching)", dev.State, EDRStateCovered, baselineCount)
	}
	if len(dev.Tools) != 1 || dev.Tools[0] != "Sophos Intercept X" {
		t.Fatalf("real-schema Sophos device tools = %v, want [\"Sophos Intercept X\"]", dev.Tools)
	}
	if r.Covered != 1 || r.TotalDevices != 1 {
		t.Fatalf("real-schema counts = covered=%d total=%d, want covered=1 total=1", r.Covered, r.TotalDevices)
	}
}

// TestFetchEDRCoverageReport_RealMigratedSchema_BitdefenderBaselineCovered
// (PAT-2234) proves the baseline row migration 0212 seeds covers the exact
// security_tools entry both agents send for Bitdefender, {"id":
// "bitdefender", "name": "Bitdefender"}, and that the row carries the Team ID
// the macOS agent's seed table (updater macos/lib/sectools.sh,
// _sectools_team_ids) reports on. If either side changes the name or the
// Team ID, this and updater's test-sectools.zsh are the two places that say
// so. No protected_software row is inserted by this test.
func TestFetchEDRCoverageReport_RealMigratedSchema_BitdefenderBaselineCovered(t *testing.T) {
	pool := pat2226MigratedConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	var applied bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0212_protected_software_bitdefender')`,
	).Scan(&applied); err != nil {
		t.Fatalf("check 0212 applied: %v", err)
	}
	if !applied {
		t.Skip("TEST_DATABASE_URL is missing migration 0212_protected_software_bitdefender — " +
			"point it at a database with every migrations/*.sql file applied, see this file's header comment")
	}

	var category, productName string
	var teamID *string
	if err := pool.QueryRow(ctx, `
		SELECT category, product_name, team_id FROM protected_software
		WHERE tenant_id IS NULL AND lower(vendor) = 'bitdefender'
	`).Scan(&category, &productName, &teamID); err != nil {
		t.Fatalf("read bitdefender baseline row (want exactly one): %v", err)
	}
	if teamID == nil || *teamID != "GUNFMW623Y" {
		t.Fatalf("bitdefender baseline team_id = %v, want GUNFMW623Y (aligned with the macOS agent's seed table)", teamID)
	}
	if productName != "Bitdefender" || !edrCategories[category] {
		t.Fatalf("bitdefender baseline row = (%q, %q), want product_name \"Bitdefender\" in an EDR category", category, productName)
	}

	tenantID := pat2226MigratedSeedTenant(t, ctx, pool, "pat2234-migrated-bitdefender-tenant")
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, security_inventory)
		VALUES ($1::uuid, 'bitdefender-real-schema', 'macOS 26.0', $2::jsonb)
	`, tenantID, `{"security_tools":[{"id":"bitdefender","name":"Bitdefender"}]}`); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}
	dev := pat2226DeviceByHostname(t, r, "bitdefender-real-schema")
	if dev.State != EDRStateCovered {
		t.Fatalf("real-schema Bitdefender device state = %q, want %q", dev.State, EDRStateCovered)
	}
}

// TestFetchEDRCoverageReport_RealMigratedSchema_AgentEmittedIDsMapToBaseline
// (PAT-2268) is the requirement check for the id-first matcher, against the
// REAL protected_software table (migrations 0139 + 0212). It feeds each
// device the exact {id, name} pair the macOS/Windows agents themselves emit
// (updater/macos/lib/sectools.sh, updater/windows/src/Service/
// SecurityToolDetector.cs) — not the baseline's own product_name.
//
// Before PAT-2268, crowdstrike-falcon ("CrowdStrike Falcon" vs baseline
// "CrowdStrike Falcon Sensor"), sentinelone ("SentinelOne" vs "SentinelOne
// Agent") and sophos-endpoint ("Sophos Endpoint" vs "Sophos Intercept X")
// all read unrecognised despite running a baseline-covered EDR — the exact
// defect this ticket fixes. bitdefender and defender-for-endpoint already
// matched by coincidence (the agent's display name equals the baseline's
// product_name) but are pinned here too so the id-first path is exercised
// for all five baseline-mapped ids, not just the three that were broken.
//
// microsoft-defender-antivirus (built-in Defender Antivirus, the id
// PAT-2267's in-flight Windows detector uses — distinct from the EDR
// defender-for-endpoint) must resolve to NO baseline row: mapping it would
// mark every Windows device EDR-covered whether or not Defender for
// Endpoint is actually onboarded.
func TestFetchEDRCoverageReport_RealMigratedSchema_AgentEmittedIDsMapToBaseline(t *testing.T) {
	pool := pat2226MigratedConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	var applied bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0212_protected_software_bitdefender')`,
	).Scan(&applied); err != nil {
		t.Fatalf("check 0212 applied: %v", err)
	}
	if !applied {
		t.Skip("TEST_DATABASE_URL is missing migration 0212_protected_software_bitdefender — " +
			"point it at a database with every migrations/*.sql file applied, see this file's header comment")
	}

	tenantID := pat2226MigratedSeedTenant(t, ctx, pool, "pat2268-agent-ids-tenant")

	cases := []struct {
		hostname, id, name string
		wantCovered        bool
	}{
		// Agent-emitted name differs from the baseline product_name — the
		// bug this ticket fixes.
		{"crowdstrike-mac", "crowdstrike-falcon", "CrowdStrike Falcon", true},
		{"sentinelone-mac", "sentinelone", "SentinelOne", true},
		{"sophos-mac", "sophos-endpoint", "Sophos Endpoint", true},
		// Agent-emitted name happens to equal the baseline product_name —
		// pinned so the id-first path is exercised here too.
		{"bitdefender-mac", "bitdefender", "Bitdefender", true},
		{"defender-endpoint-win", "defender-for-endpoint", "Microsoft Defender for Endpoint", true},
		// Built-in Defender AV must never resolve to the MDE baseline row.
		{"defender-av-win", "microsoft-defender-antivirus", "Microsoft Defender Antivirus", false},
	}
	for _, c := range cases {
		secInv := fmt.Sprintf(`{"security_tools":[{"id":%q,"name":%q}]}`, c.id, c.name)
		if _, err := pool.Exec(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, security_inventory)
			VALUES ($1::uuid, $2, 'macOS 15.5', $3::jsonb)
		`, tenantID, c.hostname, secInv); err != nil {
			t.Fatalf("insert device %s: %v", c.hostname, err)
		}
	}

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}
	for _, c := range cases {
		dev := pat2226DeviceByHostname(t, r, c.hostname)
		wantState := EDRStateUnrecognised
		if c.wantCovered {
			wantState = EDRStateCovered
		}
		if dev.State != wantState {
			t.Errorf("device %s (id=%q name=%q) state = %q, want %q", c.hostname, c.id, c.name, dev.State, wantState)
		}
	}
}
