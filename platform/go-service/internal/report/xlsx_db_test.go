package report

// PAT-732 regression: FetchXLSXData used to select devices.created_at, which
// does not exist in the current schema. This DB-backed test exercises the full
// fetch path against a scratch schema that matches the live devices table
// shape closely enough to catch that regression.
//
// PAT-861: the scratch `devices` table below previously declared an
// `os_platform` column that has never existed in production — see
// migrations/0001_initial.sql, where the real column is `os`. That divergence
// let FetchXLSXData's `os_platform` queries pass here while 500ing against the
// real schema. The columns below are bound to migrations/0001_initial.sql
// (devices, lines ~38-54); keep this table in sync with that file rather than
// letting it drift again.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat732Schema = "pat732_test"

func pat732Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed XLSX test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat732Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat732Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat732Schema,
		`CREATE TABLE ` + pat732Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		// Column set mirrors migrations/0001_initial.sql's devices table
		// (id, tenant_id, os, os_version, first_seen, last_seen, ...) plus
		// migration 0004's pending_updates and the agent_version column the
		// extractor writes. Deliberately named `os`, not `os_platform` — the
		// bug this test guards against (PAT-861) was exactly this scratch
		// schema having a column production doesn't.
		`CREATE TABLE ` + pat732Schema + `.devices (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id       UUID NOT NULL REFERENCES ` + pat732Schema + `.tenants(id),
			hostname        TEXT,
			os              TEXT NOT NULL,
			os_version      TEXT,
			agent_version   TEXT,
			first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
			pending_updates JSONB,
			device_class    TEXT NOT NULL DEFAULT 'unknown'
			                CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat732Schema + `.device_cve_findings (
			device_id        UUID NOT NULL,
			cve_id           TEXT NOT NULL,
			app_name         TEXT,
			app_version      TEXT,
			first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
			match_confidence TEXT NOT NULL DEFAULT 'version_unverified'
		)`,
		`CREATE TABLE ` + pat732Schema + `.cve_feed_entries (
			cve_id         TEXT PRIMARY KEY,
			description    TEXT NOT NULL DEFAULT '',
			description_source TEXT NOT NULL DEFAULT '',
			severity       TEXT,
			cvss_v3_score  NUMERIC
		)`,
		`CREATE TABLE ` + pat732Schema + `.compliance_rules (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key     TEXT NOT NULL,
			title        TEXT NOT NULL,
			severity     TEXT NOT NULL DEFAULT 'low',
			enabled      BOOLEAN NOT NULL DEFAULT TRUE,
			platform     TEXT NOT NULL DEFAULT 'macos',
			device_class TEXT[]
		)`,
		`CREATE TABLE ` + pat732Schema + `.compliance_evaluations (
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat732Schema+` CASCADE`)
	})
	return pool
}

func TestFetchXLSXDataUsesRealDeviceColumns(t *testing.T) {
	pool := pat732Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-732 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	firstSeen := time.Date(2026, 7, 6, 11, 22, 33, 0, time.UTC)
	lastSeen := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (
			tenant_id, hostname, os, os_version, agent_version, first_seen, last_seen
		)
		VALUES ($1::uuid, 'XLSX-Device', 'macOS', '15.0', '1.2.3', $2, $3)
	`, tenantID, firstSeen, lastSeen); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	data, err := FetchXLSXData(ctx, pool, tenantID, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("FetchXLSXData: %v", err)
	}
	if got, want := len(data.Devices), 1; got != want {
		t.Fatalf("len(data.Devices) = %d, want %d", got, want)
	}
	if got, want := data.Devices[0].Hostname, "XLSX-Device"; got != want {
		t.Fatalf("Hostname = %q, want %q", got, want)
	}
	if got, want := data.Devices[0].Platform, "macOS"; got != want {
		t.Fatalf("Platform = %q, want %q (devices.os column)", got, want)
	}
	if got, want := data.Devices[0].EnrolledAt.UTC(), firstSeen; !got.Equal(want) {
		t.Fatalf("EnrolledAt = %s, want %s", got, want)
	}
	if got, want := data.Devices[0].LastCheckIn.UTC(), lastSeen; !got.Equal(want) {
		t.Fatalf("LastCheckIn = %s, want %s", got, want)
	}
}
