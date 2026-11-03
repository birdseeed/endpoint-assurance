package handlers

// PAT-1147 DB-backed regression tests for fetchAppPolicy's mandatory_missing
// determination (posture.go). Drives the real function against a live
// Postgres schema — not just the extracted mandatoryPolicySatisfied unit in
// posture_test.go — so the exact reported bug (Opera showing both
// "Installed / Approved" and "required app missing" on Self Service) is
// covered end to end: two overlapping tenant_app_policies rows for the same
// installed app must no longer produce a false mandatory_missing finding,
// while a mandatory policy for an app that is genuinely absent still must.
//
// DB-backed: requires TEST_DATABASE_URL and is skipped otherwise, same convention
// as parConnectOrSkip/parSeedTenant/rrInsertDeviceOS (allowlist_agent_known_path_test.go,
// ring_rollout_db_test.go) reused here rather than inventing new helpers.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// pat1147BoundedPool is parConnectOrSkip with a small, bounded MaxConns.
// parConnectOrSkip's pgxpool defaults to MaxConns ≈ NumCPU (~10) per pool;
// four new DB-backed tests in this package each opening their own
// default-sized pool tipped the whole package over Postgres's connection
// limit under `go test`'s parallelism, producing intermittent "connection
// reset by peer" failures in unrelated tests (e.g. needs_attention) that had
// nothing to do with this change. These PAT-1147 tests only ever need one or
// two connections at a time, so cap the pool instead of widening Postgres's
// limit.
func pat1147BoundedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-1147 app-policy DB tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.MaxConns = 2
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

func TestPostureFetchAppPolicy_OverlappingPolicyOnSameApp_NoFalseMandatoryMissing(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1147-overlap-tenant", "pat1147-overlap-token", "pat1147-overlap-hmac-secret-32b!!")

	deviceID := rrInsertDeviceOS(t, pool, tenantID, "11111111-2222-3333-4444-555555555501", 0, "macOS")

	// Row 1: approved, keyed by bundle_id.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.operasoftware.Opera', 'macos', 'approved', 'report')
	`, tenantID); err != nil {
		t.Fatalf("insert approved policy: %v", err)
	}
	// Row 2: mandatory, keyed by name only (no bundle_id) — the same app also
	// satisfies this one, but only by a different key.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'Opera', 'macos', 'mandatory', 'app_management')
	`, tenantID); err != nil {
		t.Fatalf("insert mandatory policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	rep := report.Report{
		Device: report.Device{ID: deviceID, OS: "macOS"},
		Apps: []report.App{
			{Name: "Opera", BundleID: "com.operasoftware.Opera"},
		},
	}

	ap, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, rep)
	if err != nil {
		t.Fatalf("fetchAppPolicy: %v", err)
	}

	for _, d := range ap.Drift {
		if d.DriftType == "mandatory_missing" {
			t.Errorf("unexpected mandatory_missing finding: %+v", d)
		}
	}

	if len(ap.Apps) != 1 {
		t.Fatalf("apps: want 1 entry, got %d: %+v", len(ap.Apps), ap.Apps)
	}
	if ap.Apps[0].AppName != "Opera" || ap.Apps[0].Policy != "approved" {
		t.Errorf("apps[0]: want Opera/approved, got %+v", ap.Apps[0])
	}
}

// TestFetchAppPolicy_GenuinelyMissingMandatoryStillFlagged is the control:
// a mandatory policy for an app that is NOT installed on the device must
// still produce a mandatory_missing finding. Guards against over-correcting
// the PAT-1147 fix into never flagging mandatory_missing at all.
func TestPostureFetchAppPolicy_GenuinelyMissingMandatoryStillFlagged(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1147-missing-tenant", "pat1147-missing-token", "pat1147-missing-hmac-secret-32b!!")

	deviceID := rrInsertDeviceOS(t, pool, tenantID, "11111111-2222-3333-4444-555555555502", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.crowdstrike.falcon', 'CrowdStrike Falcon', 'macos', 'mandatory', 'app_management')
	`, tenantID); err != nil {
		t.Fatalf("insert mandatory policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	rep := report.Report{
		Device: report.Device{ID: deviceID, OS: "macOS"},
		Apps: []report.App{
			{Name: "Opera", BundleID: "com.operasoftware.Opera"}, // unrelated app, present
		},
	}

	ap, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, rep)
	if err != nil {
		t.Fatalf("fetchAppPolicy: %v", err)
	}

	found := false
	for _, d := range ap.Drift {
		if d.DriftType == "mandatory_missing" && d.AppName == "CrowdStrike Falcon" {
			found = true
		}
	}
	if !found {
		t.Errorf("want mandatory_missing for CrowdStrike Falcon (genuinely absent), got drift: %+v", ap.Drift)
	}
}

// TestPostureFetchAppPolicy_AllowlistFallbackEmitsCanonicalTier is a PAT-1250
// regression test for the allowlist-fallback branch of resolvePolicy
// (posture.go): an app with no explicit tenant_app_policies row, approved
// only via a tenant_allowlists 'allowed' entry, synthesises its own
// tenantPolicy rather than loading one from the DB. That synthesised row must
// carry the canonical "report_deploy" tier — never the legacy "report" — in
// the app_policy.apps entry this ends up in, since that entry is embedded
// in the signed GET /v1/posture payload agents consume.
func TestPostureFetchAppPolicy_AllowlistFallbackEmitsCanonicalTier(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1250-allowlist-fallback-tenant", "pat1250-allowlist-fallback-token", "pat1250-allowlist-fallback-hmac-32b!")

	deviceID := rrInsertDeviceOS(t, pool, tenantID, "11111111-2222-3333-4444-555555555503", 0, "macOS")

	// No tenant_app_policies row for this app at all — only an allowlist
	// 'allowed' entry, which is what routes resolvePolicy through the
	// synthesised-fallback branch instead of a DB-loaded tenantPolicy.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_allowlists (tenant_id, platform, name, match_mode, enforcement)
		VALUES ($1::uuid, 'macos', 'slack', 'exact_name', 'allowed')
	`, tenantID); err != nil {
		t.Fatalf("insert allowlist entry: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_allowlists WHERE tenant_id = $1::uuid`, tenantID)
	})

	rep := report.Report{
		Device: report.Device{ID: deviceID, OS: "macOS"},
		Apps: []report.App{
			{Name: "Slack", BundleID: "com.tinyspeck.slackmacgap"},
		},
	}

	ap, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, rep)
	if err != nil {
		t.Fatalf("fetchAppPolicy: %v", err)
	}

	if len(ap.Apps) != 1 {
		t.Fatalf("apps: want 1 entry, got %d: %+v", len(ap.Apps), ap.Apps)
	}
	if ap.Apps[0].EnforcementTier != "report_deploy" {
		t.Errorf("allowlist-fallback enforcement_tier = %q, want canonical %q", ap.Apps[0].EnforcementTier, "report_deploy")
	}
}

func TestPostureFetchAppPolicy_EffectivePolicyIsTenantAndPlatformScoped(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-posture-effective-tenant", "pat1481-posture-effective-token", "pat1481-posture-effective-hmac!")
	otherTenantID := parSeedTenant(t, ctx, pool,
		"pat1481-posture-other-tenant", "pat1481-posture-other-token", "pat1481-posture-other-hmac-32b")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "11111111-2222-3333-4444-555555555504", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies
			(tenant_id, team_id, bundle_id, platform, policy, enforcement_tier)
		VALUES
			($1::uuid, NULL, 'com.example.required', 'any', 'mandatory', 'report'),
			($1::uuid, NULL, 'com.example.required', 'macos', 'unmanaged', 'report'),
			($1::uuid, 'TEAM-EXAMPLE', NULL, 'any', 'unapproved', 'report'),
			($1::uuid, 'TEAM-EXAMPLE', NULL, 'macos', 'unmanaged', 'report'),
			($2::uuid, NULL, 'com.example.required', 'windows', 'unmanaged', 'report'),
			($2::uuid, 'TEAM-EXAMPLE', NULL, 'windows', 'unmanaged', 'report')
	`, tenantID, otherTenantID); err != nil {
		t.Fatalf("insert effective policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = ANY($1::uuid[])`, []string{tenantID, otherTenantID})
	})

	rep := report.Report{
		Device: report.Device{ID: deviceID, OS: "macOS"},
		Apps: []report.App{
			{Name: "Example App", BundleID: "com.example.app", TeamID: "TEAM-EXAMPLE"},
		},
	}

	macPolicy, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, rep)
	if err != nil {
		t.Fatalf("fetch macOS app policy: %v", err)
	}
	if len(macPolicy.Apps) != 1 || macPolicy.Apps[0].Policy != "unmanaged" {
		t.Fatalf("macOS exact unmanaged policy must win for the installed app, got %+v", macPolicy.Apps)
	}
	if len(macPolicy.Drift) != 0 {
		t.Fatalf("macOS exact unmanaged policies must suppress inherited drift, got %+v", macPolicy.Drift)
	}

	rep.Device.OS = "Windows"
	windowsPolicy, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, rep)
	if err != nil {
		t.Fatalf("fetch Windows app policy: %v", err)
	}
	if len(windowsPolicy.Apps) != 1 || windowsPolicy.Apps[0].Policy != "unapproved" {
		t.Fatalf("Windows must inherit this tenant's any-platform unapproved policy, got %+v", windowsPolicy.Apps)
	}
	if len(windowsPolicy.Drift) != 2 {
		t.Fatalf("Windows must retain inherited unapproved-present and mandatory-missing drift, got %+v", windowsPolicy.Drift)
	}
	driftTypes := map[string]bool{}
	for _, finding := range windowsPolicy.Drift {
		driftTypes[finding.DriftType] = true
	}
	if !driftTypes["unapproved_present"] || !driftTypes["mandatory_missing"] {
		t.Fatalf("Windows drift types = %+v, want unapproved_present and mandatory_missing", driftTypes)
	}
}

func TestPostureFetchAppPolicy_SharedTeamIDKeepsMandatoryBundleBWithEmptyInventory(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-posture-shared-team-tenant", "pat1481-posture-shared-team-token", "pat1481-posture-shared-team-hmac!")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "11111111-2222-3333-4444-555555555505", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies
			(tenant_id, team_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES
			($1::uuid, 'TEAM-SHARED', 'com.example.bundle-a', 'Bundle A', 'any', 'mandatory', 'report'),
			($1::uuid, 'TEAM-SHARED', 'com.example.bundle-a', 'Bundle A', 'macos', 'approved', 'report'),
			($1::uuid, 'TEAM-SHARED', 'com.example.bundle-b', 'Bundle B', 'any', 'mandatory', 'report')
	`, tenantID); err != nil {
		t.Fatalf("insert shared-Team-ID policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	ap, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, report.Report{
		Device: report.Device{ID: deviceID, OS: "macOS"},
		Apps:   []report.App{},
	})
	if err != nil {
		t.Fatalf("fetchAppPolicy: %v", err)
	}
	if len(ap.Apps) != 0 {
		t.Fatalf("empty inventory produced installed policy entries: %+v", ap.Apps)
	}
	if len(ap.Drift) != 1 || ap.Drift[0].DriftType != "mandatory_missing" || ap.Drift[0].Identifier != "com.example.bundle-b" || ap.Drift[0].AppName != "Bundle B" {
		t.Fatalf("want only mandatory Bundle B missing after exact Bundle A approval, got %+v", ap.Drift)
	}
}

func TestPostureFetchAppPolicy_SharedTeamIDDoesNotCrossApplyBundleAPolicyToBundleB(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-posture-shared-team-match-tenant", "pat1481-posture-shared-team-match-token", "pat1481-posture-shared-team-match-hmac")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "11111111-2222-3333-4444-555555555506", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies
			(tenant_id, team_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES
			($1::uuid, 'TEAM-SHARED', 'com.example.bundle-a', 'Bundle A', 'macos', 'approved', 'report'),
			($1::uuid, 'TEAM-SHARED', 'com.example.bundle-b', 'Bundle B', 'any', 'unapproved', 'report')
	`, tenantID); err != nil {
		t.Fatalf("insert shared-Team-ID policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	ap, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, report.Report{
		Device: report.Device{ID: deviceID, OS: "macOS"},
		Apps: []report.App{{
			Name: "Bundle B", BundleID: "com.example.bundle-b", TeamID: "TEAM-SHARED",
		}},
	})
	if err != nil {
		t.Fatalf("fetchAppPolicy: %v", err)
	}
	if len(ap.Apps) != 1 || ap.Apps[0].AppName != "Bundle B" || ap.Apps[0].Policy != "unapproved" {
		t.Fatalf("Bundle B must retain its own unapproved policy, got %+v", ap.Apps)
	}
	if len(ap.Drift) != 1 || ap.Drift[0].DriftType != "unapproved_present" || ap.Drift[0].AppName != "Bundle B" {
		t.Fatalf("Bundle B must produce its own unapproved-present finding, got %+v", ap.Drift)
	}
}
