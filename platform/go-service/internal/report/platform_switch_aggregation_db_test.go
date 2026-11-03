package report

// PAT-862 regression: two bugs in the same aggregation family.
//
// (a) FetchCISComplianceReport fetched the tenant's real platform switches
// (macos_enabled/windows_enabled) and then discarded them, overwriting sw
// with {true, true} before calling its section fetchers. Any tenant with a
// disabled platform got a CIS Compliance Report that counted devices from
// that platform, disagreeing with the Executive Summary for the same tenant.
//
// (b) fetchPatchingStats, unlike its four sibling fetchers in executive.go
// (fetchEstateStats, fetchComplianceStats, fetchTopFailingControls,
// fetchWorstDevices), never took or applied platformSwitches/enabledOSFilter.
// So within a single Executive Summary / Portal Overview PDF, the Estate and
// Compliance bands excluded a disabled platform's devices while the
// Patching KPI band still counted them.
//
// These tests build a tenant with windows_enabled = false and devices on
// both platforms, then assert every band (from both FetchCISComplianceReport
// and FetchExecutiveSummary) excludes the Windows devices, and that the two
// reports' Estate/Compliance figures are identical for the same tenant.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as admin_devices_db_test.go (pat745Pool) and xlsx_db_test.go
// (pat732Pool). The pool's search_path is pinned to an isolated schema so no
// real data is touched.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat862Schema = "pat862_test"

func pat862Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat862Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat862Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat862Schema,
		`CREATE TABLE ` + pat862Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat862Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat862Schema + `.tenants(id),
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat862Schema + `.compliance_rules (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key        TEXT NOT NULL,
			benchmark       TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version TEXT NOT NULL DEFAULT 'v1',
			title           TEXT NOT NULL,
			severity        TEXT NOT NULL DEFAULT 'low',
			platform        TEXT NOT NULL DEFAULT 'macos',
			collection_tier TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled         BOOLEAN NOT NULL DEFAULT true,
			device_class    TEXT[]
		)`,
		// tenant_rules (PAT-1794): fetchControlCoverage joins this to count
		// T2 rules actively enabled for a tenant. No rows are seeded in
		// this suite's fixtures — PAT-862's tenant only ever seeds T1-tier
		// rules — but the table must exist for the JOIN to plan.
		`CREATE TABLE ` + pat862Schema + `.tenant_rules (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id        UUID NOT NULL REFERENCES ` + pat862Schema + `.tenants(id),
			rule_id          UUID NOT NULL REFERENCES ` + pat862Schema + `.compliance_rules(id),
			enabled          BOOLEAN NOT NULL DEFAULT true,
			suppressed_until TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + pat862Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat862Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// agent_config is queried (best-effort, non-fatal on error) by
		// FetchExecutiveSummary for the report_user_attribution toggle.
		// Omit the table entirely: the query errors and is discarded, and the
		// toggle defaults to "off" — the same behavior seen with tenants
		// that have no agent_config row.
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat862Schema+` CASCADE`)
	})
	return pool
}

// seedPAT862Tenant creates a tenant with windows_enabled=false and one
// macOS + one Windows device, each with a critical-fail evaluation and a
// pending update, so every aggregate band has something to (wrongly) count
// from the disabled platform if the switch is ignored.
func seedPAT862Tenant(t *testing.T, pool *pgxpool.Pool) (tenantID, macDeviceID, winDeviceID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-862 Test Tenant', true, false)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version, pending_updates)
		VALUES ($1::uuid, 'mac-01', 'macOS', '15.0', '[{"name":"Chrome"}]'::jsonb)
		RETURNING id::text
	`, tenantID).Scan(&macDeviceID); err != nil {
		t.Fatalf("insert macOS device: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version, pending_updates)
		VALUES ($1::uuid, 'win-01', 'Windows', '11', '[{"name":"Edge"}]'::jsonb)
		RETURNING id::text
	`, tenantID).Scan(&winDeviceID); err != nil {
		t.Fatalf("insert Windows device: %v", err)
	}

	var ruleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat862_test_rule', 'PAT-862 Test Rule', 'critical')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	// observed_value is set to a real (non-NULL) value: this is a genuine,
	// evidenced fail for the purposes of this test, which is about
	// platform-switch filtering, not PAT-1758's undetermined-evidence
	// exclusion (see pat1758_unknown_evidence_db_test.go for that).
	for _, deviceID := range []string{macDeviceID, winDeviceID} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
			VALUES ($1::uuid, $2::uuid, 'fail', 'Off', 'critical')
		`, deviceID, ruleID); err != nil {
			t.Fatalf("insert evaluation for %s: %v", deviceID, err)
		}
	}

	return tenantID, macDeviceID, winDeviceID
}

// TestFetchCISComplianceReport_ExcludesDisabledPlatformDevices is the
// cis_compliance.go half of the PAT-862 regression: before the fix, the
// hardcoded `sw = platformSwitches{true, true}` overwrite meant this report
// always behaved as if both platforms were enabled, regardless of what the
// tenant actually had configured.
func TestFetchCISComplianceReport_ExcludesDisabledPlatformDevices(t *testing.T) {
	pool := pat862Pool(t)
	tenantID, macDeviceID, winDeviceID := seedPAT862Tenant(t, pool)

	rep, err := FetchCISComplianceReport(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchCISComplianceReport: %v", err)
	}

	if rep.Estate.TotalDevices != 1 {
		t.Errorf("Estate.TotalDevices = %d, want 1 (Windows device must be excluded; windows_enabled=false)", rep.Estate.TotalDevices)
	}
	if rep.Estate.WindowsDevices != 0 {
		t.Errorf("Estate.WindowsDevices = %d, want 0", rep.Estate.WindowsDevices)
	}
	if rep.Estate.MacOSDevices != 1 {
		t.Errorf("Estate.MacOSDevices = %d, want 1", rep.Estate.MacOSDevices)
	}

	if len(rep.WorstDevices) != 1 {
		t.Fatalf("len(WorstDevices) = %d, want 1 (only the macOS device)", len(rep.WorstDevices))
	}
	if rep.WorstDevices[0].DeviceID != macDeviceID {
		t.Errorf("WorstDevices[0].DeviceID = %s, want the macOS device %s (Windows device %s must not appear)", rep.WorstDevices[0].DeviceID, macDeviceID, winDeviceID)
	}

	if len(rep.TopFailing) != 1 {
		t.Fatalf("len(TopFailing) = %d, want 1", len(rep.TopFailing))
	}
	if rep.TopFailing[0].DevicesAffected != 1 {
		t.Errorf("TopFailing[0].DevicesAffected = %d, want 1 (Windows device's fail must not be counted)", rep.TopFailing[0].DevicesAffected)
	}

	if rep.Compliance.CriticalFails != 1 {
		t.Errorf("Compliance.CriticalFails = %d, want 1 (only the macOS device's fail)", rep.Compliance.CriticalFails)
	}
}

// TestFetchExecutiveSummary_PatchingStatsExcludesDisabledPlatformDevices is
// the executive.go half of PAT-862: fetchPatchingStats was the only
// aggregate fetcher that ignored platformSwitches, so the Patching KPI band
// disagreed with the Estate/Compliance bands in the same PDF.
func TestFetchExecutiveSummary_PatchingStatsExcludesDisabledPlatformDevices(t *testing.T) {
	pool := pat862Pool(t)
	tenantID, _, _ := seedPAT862Tenant(t, pool)

	summary, err := FetchExecutiveSummary(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	total := summary.Patching.DevicesUpToDate + summary.Patching.DevicesPendingUpdates
	if total != 1 {
		t.Errorf("Patching devices counted = %d, want 1 (Windows device must be excluded; windows_enabled=false)", total)
	}
	if summary.Patching.DevicesPendingUpdates != 1 {
		t.Errorf("Patching.DevicesPendingUpdates = %d, want 1 (only the macOS device's pending update)", summary.Patching.DevicesPendingUpdates)
	}

	// Cross-check against the Estate band computed by the same call: both
	// must agree there's exactly one in-scope device, or the Patching KPI
	// band would once again silently disagree with Estate within one PDF.
	if summary.Estate.TotalDevices != total {
		t.Errorf("Estate.TotalDevices = %d but Patching bands counted %d devices; the Patching KPI band must reconcile with Estate", summary.Estate.TotalDevices, total)
	}
}

// TestCISComplianceReport_MatchesExecutiveSummary_ForSameTenant is the
// cross-report regression PAT-862 asks for directly: for the same tenant,
// the CIS Compliance Report and Executive Summary must produce identical
// Estate/Compliance figures. Before the fix, cis_compliance.go's overwrite
// bug made the two reports diverge for any tenant with a disabled platform.
func TestCISComplianceReport_MatchesExecutiveSummary_ForSameTenant(t *testing.T) {
	pool := pat862Pool(t)
	tenantID, _, _ := seedPAT862Tenant(t, pool)
	ctx := context.Background()

	cisRep, err := FetchCISComplianceReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchCISComplianceReport: %v", err)
	}
	summary, err := FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	if cisRep.Estate != summary.Estate {
		t.Errorf("Estate mismatch between CIS Compliance Report and Executive Summary for the same tenant:\n  CIS:  %+v\n  Exec: %+v", cisRep.Estate, summary.Estate)
	}
	if cisRep.Compliance != summary.Compliance {
		t.Errorf("Compliance mismatch between CIS Compliance Report and Executive Summary for the same tenant:\n  CIS:  %+v\n  Exec: %+v", cisRep.Compliance, summary.Compliance)
	}
}

// TestFetchPatchStatusReport_MatchesExecutiveSummary_ForSameTenant is the
// PAT-915 regression: FetchPatchStatusReport passed a hardcoded
// platformSwitches{true, true} to fetchPatchingStats instead of the
// tenant's real switches, so the Patch Status report counted a disabled
// platform's devices while the Executive Summary (fixed by PAT-862) did
// not. For the same tenant, both reports' patching counts must agree.
//
// This also covers the per-device list (r.Devices): it feeds the same PDF
// as the Patching KPI band (patch_status_pdf.go renderPatchStatusKPIBand /
// renderPatchStatusDevices), so leaving it unfiltered while the KPI band
// respects platform switches would just move PAT-862's disagreement bug
// inside a single report instead of fixing it.
func TestFetchPatchStatusReport_MatchesExecutiveSummary_ForSameTenant(t *testing.T) {
	pool := pat862Pool(t)
	tenantID, _, _ := seedPAT862Tenant(t, pool)
	ctx := context.Background()

	patchRep, err := FetchPatchStatusReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchPatchStatusReport: %v", err)
	}
	summary, err := FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	if patchRep.Patching != summary.Patching {
		t.Errorf("Patching mismatch between Patch Status Report and Executive Summary for the same tenant:\n  PatchStatus: %+v\n  Exec:        %+v", patchRep.Patching, summary.Patching)
	}

	total := patchRep.Patching.DevicesUpToDate + patchRep.Patching.DevicesPendingUpdates
	if total != 1 {
		t.Errorf("Patch Status devices counted = %d, want 1 (Windows device must be excluded; windows_enabled=false)", total)
	}

	if len(patchRep.Devices) != 1 {
		t.Errorf("len(PatchStatusReport.Devices) = %d, want 1 (Windows device must be excluded from the pending-updates table too, not just the KPI band)", len(patchRep.Devices))
	} else if patchRep.Devices[0].Hostname != "mac-01" {
		t.Errorf("PatchStatusReport.Devices[0].Hostname = %q, want mac-01 (the Windows device win-01 must not appear)", patchRep.Devices[0].Hostname)
	}
}

// TestFetchCISComplianceReport_AllPlatformsEnabled is a control case: with
// both switches on, the Windows device must be included everywhere.
func TestFetchCISComplianceReport_AllPlatformsEnabled(t *testing.T) {
	pool := pat862Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-862 Control Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, 'win-02', 'Windows', '11')
	`, tenantID); err != nil {
		t.Fatalf("insert Windows device: %v", err)
	}

	rep, err := FetchCISComplianceReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchCISComplianceReport: %v", err)
	}
	if rep.Estate.TotalDevices != 1 || rep.Estate.WindowsDevices != 1 {
		t.Errorf("Estate = %+v, want TotalDevices=1 WindowsDevices=1 (both platforms enabled)", rep.Estate)
	}
}
