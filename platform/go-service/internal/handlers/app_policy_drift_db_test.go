package handlers

// PAT-1147 DB-backed regression tests for TenantAppPolicyDriftHandler's
// mandatory_missing count (app_policy_drift.go) — the sibling of the
// posture.go fetchAppPolicy bug, feeding the admin drift report/PDF. Drives
// the real handler over HTTP against a live Postgres schema (not just the
// extracted mandatoryPolicySatisfiedDrift unit in app_policy_drift_test.go):
// two overlapping tenant_app_policies rows matching the same installed app
// must not produce a false mandatory_missing finding, while a mandatory
// policy for an app genuinely absent from the device still must.
//
// DB-backed: requires TEST_DATABASE_URL and is skipped otherwise, reusing
// parSeedTenant/rrInsertDeviceOS and taWithTenantID (tenant_apps_test.go)
// rather than inventing new helpers. Uses pat1147BoundedPool (defined in
// posture_app_policy_db_test.go), not parConnectOrSkip — see that helper's
// doc comment for why: parConnectOrSkip's default-sized pgxpool per test
// tipped the package over Postgres's connection limit under `go test`'s
// parallelism.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTenantAppPolicyDriftHandler_WingetPolicyRequiresTypedInventory(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-winget-kind-tenant", "pat1481-winget-kind-token", "pat1481-winget-kind-hmac-secret-32b")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666609", 0, "Windows")
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, winget_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'example.package', 'windows', 'mandatory', 'patch')
	`, tenantID); err != nil {
		t.Fatalf("insert Winget mandatory policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, identifier_kind, version)
		VALUES ($1::uuid, 'Example Package', 'Example.Package', 'native', '1.0')
	`, deviceID); err != nil {
		t.Fatalf("insert native device app: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	get := func() struct {
		Findings         []appPolicyDriftFinding `json:"findings"`
		MandatoryMissing int                     `json:"mandatory_missing"`
	} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
		req = taWithTenantID(req, tenantID)
		rr := httptest.NewRecorder()
		TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Findings         []appPolicyDriftFinding `json:"findings"`
			MandatoryMissing int                     `json:"mandatory_missing"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return resp
	}

	if got := get(); got.MandatoryMissing != 1 {
		t.Fatalf("native identifier satisfied mandatory Winget policy: %+v", got)
	}
	if _, err := pool.Exec(ctx, `UPDATE device_apps SET identifier_kind='winget' WHERE device_id=$1::uuid`, deviceID); err != nil {
		t.Fatalf("mark device app as Winget: %v", err)
	}
	if got := get(); got.MandatoryMissing != 0 {
		t.Fatalf("typed canonical Winget identifier did not satisfy mandatory policy: %+v", got)
	}
}

func TestTenantAppPolicyDriftHandler_OverlappingPolicyOnSameApp_NoFalseMandatoryMissing(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1147-drift-overlap-tenant", "pat1147-drift-overlap-token", "pat1147-drift-overlap-hmac-32b!!")

	deviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666601", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'Opera', 'com.operasoftware.Opera', '100.0')
	`, deviceID); err != nil {
		t.Fatalf("insert device app: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.operasoftware.Opera', 'macos', 'approved', 'report')
	`, tenantID); err != nil {
		t.Fatalf("insert approved policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'Opera', 'macos', 'mandatory', 'app_management')
	`, tenantID); err != nil {
		t.Fatalf("insert mandatory policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings          []appPolicyDriftFinding `json:"findings"`
		MandatoryMissing  int                     `json:"mandatory_missing"`
		UnapprovedPresent int                     `json:"unapproved_present"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MandatoryMissing != 0 {
		t.Errorf("mandatory_missing: want 0, got %d: findings=%+v", resp.MandatoryMissing, resp.Findings)
	}
}

func TestTenantAppPolicyDriftHandler_OverlappingUnmanagedDoesNotSuppressDistinctMandatoryVersionFloor(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-drift-version-overlap-tenant", "pat1481-drift-version-overlap-token", "pat1481-drift-version-overlap-hmac")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666610", 0, "macOS")
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'Example App', 'com.example.app', '1.0')
	`, deviceID); err != nil {
		t.Fatalf("insert device app: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier, min_version)
		VALUES
			($1::uuid, 'com.example.app', NULL, 'any', 'mandatory', 'patch', '3.0'),
			($1::uuid, 'com.example.app', NULL, 'macos', 'unmanaged', 'report', NULL),
			($1::uuid, NULL, 'Example App', 'any', 'mandatory', 'patch', '2.0')
	`, tenantID); err != nil {
		t.Fatalf("insert overlapping policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings          []appPolicyDriftFinding `json:"findings"`
		VersionBelowMin   int                     `json:"version_below_minimum"`
		UnapprovedPresent int                     `json:"unapproved_present"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.VersionBelowMin != 1 || len(resp.Findings) != 1 {
		t.Fatalf("want one distinct mandatory version-floor finding, got count=%d findings=%+v", resp.VersionBelowMin, resp.Findings)
	}
	finding := resp.Findings[0]
	if finding.DeviceID != deviceID || finding.DriftType != "version_below_minimum" || finding.MinVersion != "2.0" || finding.InstalledVersion != "1.0" {
		t.Fatalf("unexpected version-floor finding: %+v", finding)
	}
	if resp.UnapprovedPresent != 0 {
		t.Fatalf("exact unmanaged policy must not produce inherited unapproved drift: %+v", resp.Findings)
	}
}

// TestTenantAppPolicyDriftHandler_GenuinelyMissingMandatoryStillFlagged is
// the control: a mandatory policy for an app that is NOT installed on any
// device must still be counted in mandatory_missing.
func TestTenantAppPolicyDriftHandler_GenuinelyMissingMandatoryStillFlagged(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1147-drift-missing-tenant", "pat1147-drift-missing-token", "pat1147-drift-missing-hmac-32b!")

	deviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666602", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'Opera', 'com.operasoftware.Opera', '100.0')
	`, deviceID); err != nil {
		t.Fatalf("insert device app: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.crowdstrike.falcon', 'CrowdStrike Falcon', 'macos', 'mandatory', 'app_management')
	`, tenantID); err != nil {
		t.Fatalf("insert mandatory policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings         []appPolicyDriftFinding `json:"findings"`
		MandatoryMissing int                     `json:"mandatory_missing"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MandatoryMissing != 1 {
		t.Errorf("mandatory_missing: want 1 (CrowdStrike Falcon genuinely absent), got %d: findings=%+v", resp.MandatoryMissing, resp.Findings)
	}
}

// TestTenantAppPolicyDriftHandler_PlatformMismatchedPolicySkippedNotFlagged
// is the regression for a bug review caught in the first PAT-1147 fix: the
// mandatory_missing loop had collapsed "policy doesn't apply to this
// device's OS" and "policy applies but no app matches" into a single
// mandatoryPolicySatisfiedDrift(p, apps, dev.OS) call, so a windows-only
// mandatory policy was falsely reported mandatory_missing on a macOS device
// (and vice versa) — those policies must be SKIPPED as not applicable, not
// flagged as missing. A device-level HTTP test is what actually exercises
// this: a unit test on mandatoryPolicySatisfiedDrift alone can't distinguish
// "the function correctly says false" from "the loop correctly skips it",
// since both look identical from inside the function.
func TestTenantAppPolicyDriftHandler_PlatformMismatchedPolicySkippedNotFlagged(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1147-drift-platform-tenant", "pat1147-drift-platform-token", "pat1147-drift-platform-hmac-32b!")

	// macOS device with no apps installed at all.
	rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666603", 0, "macOS")

	// A mandatory policy scoped to windows only — must not apply to the
	// macOS device above, regardless of whether any app matches it.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'Windows Defender ATP', 'windows', 'mandatory', 'app_management')
	`, tenantID); err != nil {
		t.Fatalf("insert windows-only mandatory policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings         []appPolicyDriftFinding `json:"findings"`
		MandatoryMissing int                     `json:"mandatory_missing"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MandatoryMissing != 0 {
		t.Errorf("mandatory_missing: want 0 (windows-only policy does not apply to a macOS device, so must be skipped not flagged), got %d: findings=%+v", resp.MandatoryMissing, resp.Findings)
	}
}

func TestTenantAppPolicyDriftHandler_ExactApprovalOverrideIsTenantAndPlatformScoped(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-drift-override-tenant", "pat1481-drift-override-token", "pat1481-drift-override-hmac!")
	otherTenantID := parSeedTenant(t, ctx, pool,
		"pat1481-drift-other-tenant", "pat1481-drift-other-token", "pat1481-drift-other-hmac-32b")

	macDeviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666604", 0, "macOS")
	windowsDeviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666605", 0, "Windows")
	for _, deviceID := range []string{macDeviceID, windowsDeviceID} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, team_id, version)
			VALUES ($1::uuid, 'Example App', 'com.example.app', 'TEAM-EXAMPLE', '1.0')
		`, deviceID); err != nil {
			t.Fatalf("insert device app for %s: %v", deviceID, err)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, team_id, platform, policy, enforcement_tier)
		VALUES
			($1::uuid, 'TEAM-EXAMPLE', 'any', 'unapproved', 'report'),
			($1::uuid, 'TEAM-EXAMPLE', 'macos', 'approved', 'report'),
			($2::uuid, 'TEAM-EXAMPLE', 'macos', 'unapproved', 'report')
	`, tenantID, otherTenantID); err != nil {
		t.Fatalf("insert override policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = ANY($1::uuid[])`, []string{tenantID, otherTenantID})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings          []appPolicyDriftFinding `json:"findings"`
		UnapprovedPresent int                     `json:"unapproved_present"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.UnapprovedPresent != 1 || len(resp.Findings) != 1 {
		t.Fatalf("want only the Windows any-platform finding, got count=%d findings=%+v", resp.UnapprovedPresent, resp.Findings)
	}
	if resp.Findings[0].DeviceID != windowsDeviceID || resp.Findings[0].Policy != "unapproved" {
		t.Fatalf("unexpected finding: %+v", resp.Findings[0])
	}
}

func TestTenantAppPolicyDriftHandler_ExactUnmanagedSuppressesInheritedDrift(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-drift-unmanaged-tenant", "pat1481-drift-unmanaged-token", "pat1481-drift-unmanaged-hmac!")
	otherTenantID := parSeedTenant(t, ctx, pool,
		"pat1481-drift-unmanaged-other", "pat1481-drift-unmanaged-other-token", "pat1481-drift-other-hmac-32b")

	macDeviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666606", 0, "macOS")
	windowsDeviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666607", 0, "Windows")
	for _, deviceID := range []string{macDeviceID, windowsDeviceID} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, team_id, version)
			VALUES ($1::uuid, 'Example App', 'com.example.app', 'TEAM-EXAMPLE', '1.0')
		`, deviceID); err != nil {
			t.Fatalf("insert device app for %s: %v", deviceID, err)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies
			(tenant_id, team_id, bundle_id, platform, policy, enforcement_tier)
		VALUES
			($1::uuid, 'TEAM-EXAMPLE', NULL, 'any', 'unapproved', 'report'),
			($1::uuid, 'TEAM-EXAMPLE', NULL, 'macos', 'unmanaged', 'report'),
			($1::uuid, NULL, 'com.example.required', 'any', 'mandatory', 'report'),
			($1::uuid, NULL, 'com.example.required', 'macos', 'unmanaged', 'report'),
			($2::uuid, 'TEAM-EXAMPLE', NULL, 'windows', 'unmanaged', 'report'),
			($2::uuid, NULL, 'com.example.required', 'windows', 'unmanaged', 'report')
	`, tenantID, otherTenantID); err != nil {
		t.Fatalf("insert effective policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_app_policies WHERE tenant_id = ANY($1::uuid[])`, []string{tenantID, otherTenantID})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings          []appPolicyDriftFinding `json:"findings"`
		MandatoryMissing  int                     `json:"mandatory_missing"`
		UnapprovedPresent int                     `json:"unapproved_present"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MandatoryMissing != 1 || resp.UnapprovedPresent != 1 || len(resp.Findings) != 2 {
		t.Fatalf("want only two Windows inherited findings, got mandatory=%d unapproved=%d findings=%+v", resp.MandatoryMissing, resp.UnapprovedPresent, resp.Findings)
	}
	for _, finding := range resp.Findings {
		if finding.DeviceID != windowsDeviceID {
			t.Fatalf("exact macOS unmanaged and other-tenant Windows policies must not emit/suppress cross-scope drift, got %+v", finding)
		}
	}
}

func TestTenantAppPolicyDriftHandler_SharedTeamIDKeepsMandatoryBundleBWithEmptyInventory(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-drift-shared-team-tenant", "pat1481-drift-shared-team-token", "pat1481-drift-shared-team-hmac-32b")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666608", 0, "macOS")

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

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/app-policy-drift", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAppPolicyDriftHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings         []appPolicyDriftFinding `json:"findings"`
		MandatoryMissing int                     `json:"mandatory_missing"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MandatoryMissing != 1 || len(resp.Findings) != 1 {
		t.Fatalf("want one missing obligation for empty inventory, got count=%d findings=%+v", resp.MandatoryMissing, resp.Findings)
	}
	if resp.Findings[0].DeviceID != deviceID || resp.Findings[0].Identifier != "com.example.bundle-b" || resp.Findings[0].AppName != "Bundle B" {
		t.Fatalf("exact Bundle A approval suppressed or replaced the wrong full identity tuple: %+v", resp.Findings[0])
	}
}
