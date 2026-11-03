package report

// PAT-2226 regression: the EDR Coverage report used to call a device
// "WithoutEDR" whenever none of its security_tools[].name entries contained
// one of three hardcoded substrings (crowdstrike/sentinelone/defender). A
// device running Sophos, Bitdefender, ESET, Jamf Protect or Huntress was
// therefore told it had no EDR, even though security_tools carries no
// completeness marker at all — an absent or empty list proves nothing about
// the device, only about what the collector happened to detect. That is
// exactly the "Absence requires authority" hard constraint in root
// AGENTS.md: incomplete inventory must never close a finding or prove a
// control healthy (or, here, unhealthy).
//
// The fix gives every device exactly one of three states instead of a
// binary has/hasn't:
//   - covered: a reported tool matches a protected_software row (category
//     edr or security) visible to this tenant — the shared baseline plus
//     the tenant's own additions.
//   - unrecognised: tools were reported, but none matched. The customer
//     sees what was found so they can add it themselves.
//   - unknown: no security_tools evidence at all (null, missing or empty).
//
// This file pins:
//   - a baseline-recognised tool (Sophos, seeded by migration 0139) reports
//     covered;
//   - an unrecognised tool (no protected_software row at all) reports
//     unrecognised, never "without EDR";
//   - no security_tools evidence reports unknown, not "without EDR";
//   - protected_software tenant scoping: a tenant's own addition only
//     covers that tenant's devices, never another tenant's;
//   - the aggregate counts and coverage-percentage maths.
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as pat1758_unknown_evidence_db_test.go (pat1758Pool) one
// function over. The pool's search_path is pinned to an isolated schema
// mirroring only the columns FetchEDRCoverageReport and
// protectedsoftware.Check actually read — protected_software_overrides is
// included because protectedsoftware.Check's scopeClause always references
// it, even when a test never populates an override row. No full migration
// run is required.

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat2226Schema = "pat2226_test"

func pat2226Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat2226Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat2226Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat2226Schema,
		`CREATE TABLE ` + pat2226Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat2226Schema + `.devices (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          UUID NOT NULL REFERENCES ` + pat2226Schema + `.tenants(id),
			hostname           TEXT,
			os                 TEXT,
			security_inventory JSONB
		)`,
		// Mirrors migrations/0139_protected_software.sql, trimmed to the
		// columns protectedsoftware.Check reads/writes.
		`CREATE TABLE ` + pat2226Schema + `.protected_software (
			id               BIGSERIAL    PRIMARY KEY,
			tenant_id        UUID         REFERENCES ` + pat2226Schema + `.tenants(id) ON DELETE CASCADE,
			category         TEXT         NOT NULL
			                      CHECK (category IN ('edr', 'mdm', 'backup', 'security', 'patched_agent', 'customer_defined')),
			vendor           TEXT         NOT NULL,
			product_name     TEXT         NOT NULL,
			bundle_id        TEXT,
			team_id          TEXT,
			signer           TEXT,
			win_publisher    TEXT,
			win_product_code TEXT,
			process_name     TEXT,
			reason           TEXT         NOT NULL DEFAULT '',
			added_by         TEXT         NOT NULL DEFAULT '',
			added_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat2226Schema + `.protected_software_overrides (
			id           BIGSERIAL    PRIMARY KEY,
			tenant_id    UUID         NOT NULL REFERENCES ` + pat2226Schema + `.tenants(id) ON DELETE CASCADE,
			baseline_id  BIGINT       NOT NULL REFERENCES ` + pat2226Schema + `.protected_software(id) ON DELETE CASCADE,
			reason       TEXT         NOT NULL,
			removed_by   TEXT         NOT NULL,
			removed_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, baseline_id)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat2226Schema+` CASCADE`)
	})
	return pool
}

func pat2226Tenant(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (name) VALUES ($1) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return id
}

// pat2226Device inserts a device with the given raw security_inventory JSON
// (already-marshalled text, or "" for a NULL column — the null/missing/empty
// three-way the unknown-state test cares about).
func pat2226Device(t *testing.T, pool *pgxpool.Pool, tenantID, hostname, secInvJSON string) {
	t.Helper()
	var arg any
	if secInvJSON != "" {
		arg = secInvJSON
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO devices (tenant_id, hostname, os, security_inventory) VALUES ($1, $2, 'macOS 15.5', $3)`,
		tenantID, hostname, arg); err != nil {
		t.Fatalf("insert device %s: %v", hostname, err)
	}
}

// pat2226BaselineSophos seeds the one baseline row these tests rely on —
// the real migrations/0139_protected_software.sql Sophos row, reproduced
// here rather than sourced from the migration file so this suite stays
// independent of migration drift (same reasoning as pat1758Pool's comment
// on not requiring a full migration run).
func pat2226BaselineSophos(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO protected_software (tenant_id, category, vendor, product_name, win_publisher, process_name, reason, added_by)
		VALUES (NULL, 'edr', 'Sophos', 'Sophos Intercept X', 'Sophos Limited', 'SAVService.exe',
		        'EDR agent baseline seed', 'PAT-1801 baseline seed')
	`); err != nil {
		t.Fatalf("seed sophos baseline: %v", err)
	}
}

func pat2226TenantEDRRow(t *testing.T, pool *pgxpool.Pool, tenantID, productName string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO protected_software (tenant_id, category, vendor, product_name, process_name, reason, added_by)
		VALUES ($1, 'edr', 'Acme', $2, $2, 'tenant-added EDR', 'test')
	`, tenantID, productName); err != nil {
		t.Fatalf("insert tenant EDR row: %v", err)
	}
}

func pat2226DeviceByHostname(t *testing.T, r EDRCoverageReport, hostname string) EDRDevice {
	t.Helper()
	for _, d := range r.Devices {
		if d.Hostname == hostname {
			return d
		}
	}
	t.Fatalf("no device with hostname %q in report (devices: %+v)", hostname, r.Devices)
	return EDRDevice{}
}

// TestFetchEDRCoverageReport_BaselineToolIsCovered proves a Sophos-only
// device — recognised by the shared protected_software baseline, never
// matched by the old crowdstrike/sentinelone/defender substring list — is
// reported covered, not "without EDR".
func TestFetchEDRCoverageReport_BaselineToolIsCovered(t *testing.T) {
	pool := pat2226Pool(t)
	ctx := context.Background()
	tenantID := pat2226Tenant(t, pool, "Sophos Co")
	pat2226BaselineSophos(t, pool)
	pat2226Device(t, pool, tenantID, "sophos-mac", `{"security_tools":[{"id":"sophos-endpoint","name":"Sophos Intercept X"}]}`)

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}

	dev := pat2226DeviceByHostname(t, r, "sophos-mac")
	if dev.State != EDRStateCovered {
		t.Fatalf("Sophos device state = %q, want %q", dev.State, EDRStateCovered)
	}
	if len(dev.Tools) != 1 || dev.Tools[0] != "Sophos Intercept X" {
		t.Fatalf("Sophos device tools = %v, want [\"Sophos Intercept X\"]", dev.Tools)
	}
}

// TestFetchEDRCoverageReport_UnmatchedToolIsUnrecognisedNeverWithoutEDR
// proves a device reporting a real security tool that has no
// protected_software row (this suite seeds no Bitdefender row) is
// unrecognised — the report must never claim the device lacks EDR, because
// no authoritative source exists for that claim (Hard Constraint: "Absence
// requires authority").
func TestFetchEDRCoverageReport_UnmatchedToolIsUnrecognisedNeverWithoutEDR(t *testing.T) {
	pool := pat2226Pool(t)
	ctx := context.Background()
	tenantID := pat2226Tenant(t, pool, "Bitdefender Co")
	pat2226Device(t, pool, tenantID, "bitdefender-mac", `{"security_tools":[{"id":"bitdefender-endpoint","name":"Bitdefender Endpoint Security"}]}`)

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}

	dev := pat2226DeviceByHostname(t, r, "bitdefender-mac")
	if dev.State != EDRStateUnrecognised {
		t.Fatalf("Bitdefender device state = %q, want %q", dev.State, EDRStateUnrecognised)
	}
	if len(dev.Tools) != 1 || dev.Tools[0] != "Bitdefender Endpoint Security" {
		t.Fatalf("Bitdefender device tools = %v, want [\"Bitdefender Endpoint Security\"]", dev.Tools)
	}
	if r.Unrecognised != 1 || r.Covered != 0 {
		t.Fatalf("counts = covered=%d unrecognised=%d, want covered=0 unrecognised=1", r.Covered, r.Unrecognised)
	}
}

// TestFetchEDRCoverageReport_NoSecurityToolsIsUnknown proves a device with
// no security_tools evidence at all is unknown, distinct from both covered
// and unrecognised, across all three absent shapes: a NULL
// security_inventory column, an object with no security_tools key, and an
// explicit empty security_tools array.
func TestFetchEDRCoverageReport_NoSecurityToolsIsUnknown(t *testing.T) {
	pool := pat2226Pool(t)
	ctx := context.Background()
	tenantID := pat2226Tenant(t, pool, "No Evidence Co")
	pat2226Device(t, pool, tenantID, "null-inventory", "")
	pat2226Device(t, pool, tenantID, "no-key", `{}`)
	pat2226Device(t, pool, tenantID, "empty-array", `{"security_tools":[]}`)

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}

	for _, hostname := range []string{"null-inventory", "no-key", "empty-array"} {
		dev := pat2226DeviceByHostname(t, r, hostname)
		if dev.State != EDRStateUnknown {
			t.Fatalf("%s state = %q, want %q", hostname, dev.State, EDRStateUnknown)
		}
		if len(dev.Tools) != 0 {
			t.Fatalf("%s tools = %v, want none", hostname, dev.Tools)
		}
	}
	if r.Unknown != 3 {
		t.Fatalf("r.Unknown = %d, want 3", r.Unknown)
	}
}

// TestFetchEDRCoverageReport_TenantScoping proves a tenant-added EDR row
// only covers that tenant's own devices — the same product name reported by
// another tenant, with no visibility into the first tenant's addition, must
// stay unrecognised. Regression target: protected_software's tenant_id
// scoping (protectedsoftware.Check's scopeClause) must be honoured by the
// EDR coverage fetch, not bypassed by a global name lookup.
func TestFetchEDRCoverageReport_TenantScoping(t *testing.T) {
	pool := pat2226Pool(t)
	ctx := context.Background()
	tenantA := pat2226Tenant(t, pool, "Tenant A")
	tenantB := pat2226Tenant(t, pool, "Tenant B")

	pat2226TenantEDRRow(t, pool, tenantB, "Acme Tenant EDR")

	pat2226Device(t, pool, tenantB, "b-covered", `{"security_tools":[{"id":"acme-edr","name":"Acme Tenant EDR"}]}`)
	pat2226Device(t, pool, tenantA, "a-not-covered", `{"security_tools":[{"id":"acme-edr","name":"Acme Tenant EDR"}]}`)

	rB, err := FetchEDRCoverageReport(ctx, pool, tenantB)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport(tenantB): %v", err)
	}
	devB := pat2226DeviceByHostname(t, rB, "b-covered")
	if devB.State != EDRStateCovered {
		t.Fatalf("tenant B device state = %q, want %q (own tenant-added row)", devB.State, EDRStateCovered)
	}

	rA, err := FetchEDRCoverageReport(ctx, pool, tenantA)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport(tenantA): %v", err)
	}
	devA := pat2226DeviceByHostname(t, rA, "a-not-covered")
	if devA.State != EDRStateUnrecognised {
		t.Fatalf("tenant A device state = %q, want %q (tenant B's row must not leak)", devA.State, EDRStateUnrecognised)
	}
}

// TestFetchEDRCoverageReport_CountsAndPercentage pins the aggregate maths:
// coverage % = covered / total * 100, with unrecognised and unknown counted
// but not folded into a "without EDR" figure anywhere.
func TestFetchEDRCoverageReport_CountsAndPercentage(t *testing.T) {
	pool := pat2226Pool(t)
	ctx := context.Background()
	tenantID := pat2226Tenant(t, pool, "Mixed Estate Co")
	pat2226BaselineSophos(t, pool)

	pat2226Device(t, pool, tenantID, "covered-1", `{"security_tools":[{"id":"sophos-endpoint","name":"Sophos Intercept X"}]}`)
	pat2226Device(t, pool, tenantID, "covered-2", `{"security_tools":[{"id":"sophos-endpoint","name":"Sophos Intercept X"}]}`)
	pat2226Device(t, pool, tenantID, "unrecognised-1", `{"security_tools":[{"id":"bitdefender-endpoint","name":"Bitdefender Endpoint Security"}]}`)
	pat2226Device(t, pool, tenantID, "unknown-1", `{}`)

	r, err := FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}

	if r.TotalDevices != 4 {
		t.Fatalf("TotalDevices = %d, want 4", r.TotalDevices)
	}
	if r.Covered != 2 {
		t.Fatalf("Covered = %d, want 2", r.Covered)
	}
	if r.Unrecognised != 1 {
		t.Fatalf("Unrecognised = %d, want 1", r.Unrecognised)
	}
	if r.Unknown != 1 {
		t.Fatalf("Unknown = %d, want 1", r.Unknown)
	}
	if r.CoveragePct != 50.0 {
		t.Fatalf("CoveragePct = %v, want 50.0", r.CoveragePct)
	}

	// Sanity: every device landed in exactly one state, and the three
	// counts sum to the total — no device is silently dropped or
	// double-counted across states.
	states := make([]string, 0, len(r.Devices))
	for _, d := range r.Devices {
		states = append(states, string(d.State))
	}
	sort.Strings(states)
	if got, want := r.Covered+r.Unrecognised+r.Unknown, r.TotalDevices; got != want {
		t.Fatalf("state counts sum to %d, want %d (states: %v)", got, want, states)
	}
}
