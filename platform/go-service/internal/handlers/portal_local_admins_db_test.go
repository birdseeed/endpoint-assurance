package handlers

// PAT-2215: GET /v1/portal/local-admins against the real, fully-migrated
// schema (see docs/TESTING.md — run `go test -tags=integration ./integration/`
// first against the same TEST_DATABASE_URL to apply migrations, then this
// package's DB-gated tests reuse that schema). Skipped without
// TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"patched.im/api/internal/portalauth"
)

// TestPortalLocalAdminsHandlerAdminSeesRoster: an admin identity gets the
// full roster, with principal types, the built-in Administrator's disabled
// state excluded from the assessed count, and the estate summary figures.
func TestPortalLocalAdminsHandlerAdminSeesRoster(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2215")

	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, collection_status)
		VALUES ($1::uuid, 'DC-2215', 'Windows', '{"local_admins": "complete"}'::jsonb)
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, 'local_admin_count', '3')`,
		deviceID,
	); err != nil {
		t.Fatalf("seed compliance_signals: %v", err)
	}
	for _, a := range []struct {
		name, principalType, sid, accountState string
		builtin                                bool
	}{
		{"CONTOSO\\Domain Admins", "group", "S-1-5-21-1-2-3-512", "", false},
		{"S-1-5-21-1-2-3-9999", "unresolved", "S-1-5-21-1-2-3-9999", "", false},
		{"DC-2215\\Administrator", "user", "S-1-5-21-1-2-3-500", "disabled", true},
	} {
		var accountState any
		if a.accountState != "" {
			accountState = a.accountState
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin, sid, account_state)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
			deviceID, a.name, a.principalType, a.builtin, a.sid, accountState,
		); err != nil {
			t.Fatalf("seed local_admin_accounts %q: %v", a.name, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/local-admins", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: adminEmail, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	PortalLocalAdminsHandler(pool).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var resp portalLocalAdminsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rec.Body.String())
	}
	if resp.Threshold != 2 {
		t.Errorf("Threshold: got %d, want 2", resp.Threshold)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("Devices: got %d, want 1", len(resp.Devices))
	}
	dev := resp.Devices[0]
	if dev.DeviceID != deviceID {
		t.Errorf("DeviceID: got %q, want %q", dev.DeviceID, deviceID)
	}
	if dev.Platform != "windows" {
		t.Errorf("Platform: got %q, want %q", dev.Platform, "windows")
	}
	if !dev.MembershipReadable {
		t.Errorf("MembershipReadable: got false, want true")
	}
	if dev.ReportedAdminCount == nil || *dev.ReportedAdminCount != 3 {
		t.Errorf("ReportedAdminCount: got %v, want 3", dev.ReportedAdminCount)
	}
	// The built-in Administrator is disabled, so it is excluded: assessed
	// count is 2, which passes the lte-2 threshold.
	if dev.AssessedAdminCount == nil || *dev.AssessedAdminCount != 2 {
		t.Errorf("AssessedAdminCount: got %v, want 2", dev.AssessedAdminCount)
	}
	if dev.Pass == nil || !*dev.Pass {
		t.Errorf("Pass: got %v, want true", dev.Pass)
	}
	if len(dev.Principals) != 3 {
		t.Fatalf("Principals: got %d, want 3: %+v", len(dev.Principals), dev.Principals)
	}
	byName := map[string]portalLocalAdminPrincipal{}
	for _, p := range dev.Principals {
		byName[p.Name] = p
	}
	if got := byName["CONTOSO\\Domain Admins"].PrincipalType; got != "group" {
		t.Errorf("Domain Admins principal_type: got %q, want %q", got, "group")
	}
	if got := byName["S-1-5-21-1-2-3-9999"].PrincipalType; got != "unresolved" {
		t.Errorf("unresolved SID principal_type: got %q, want %q", got, "unresolved")
	}
	builtin := byName["DC-2215\\Administrator"]
	if !builtin.Builtin {
		t.Errorf("built-in account Builtin: got false, want true")
	}
	if builtin.AccountState == nil || *builtin.AccountState != "disabled" {
		t.Errorf("built-in account AccountState: got %v, want %q", builtin.AccountState, "disabled")
	}

	if resp.OverLimitDevices != 0 {
		t.Errorf("OverLimitDevices: got %d, want 0 (the one device passes)", resp.OverLimitDevices)
	}
	if resp.DistinctAccounts != 3 {
		t.Errorf("DistinctAccounts: got %d, want 3", resp.DistinctAccounts)
	}
	if resp.UnreadableDevices != 0 {
		t.Errorf("UnreadableDevices: got %d, want 0", resp.UnreadableDevices)
	}
}

// TestPortalLocalAdminsHandlerUnreadableAndUnknownDevices: a device whose
// roster collection failed and a device with no local_admin_count signal at
// all must never render as a device with zero admins.
func TestPortalLocalAdminsHandlerUnreadableAndUnknownDevices(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2215-unreadable")

	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, collection_status)
		VALUES ($1::uuid, 'FAILED-READ', 'Windows', '{"local_admins": "unavailable"}'::jsonb)
	`, tenantID); err != nil {
		t.Fatalf("seed failed-read device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'NEVER-REPORTED', 'macOS')
	`, tenantID); err != nil {
		t.Fatalf("seed never-reported device: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/local-admins", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: adminEmail, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	PortalLocalAdminsHandler(pool).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp portalLocalAdminsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rec.Body.String())
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("Devices: got %d, want 2", len(resp.Devices))
	}
	if resp.UnreadableDevices != 2 {
		t.Errorf("UnreadableDevices: got %d, want 2", resp.UnreadableDevices)
	}
	for _, dev := range resp.Devices {
		if dev.MembershipReadable {
			t.Errorf("device %s: MembershipReadable got true, want false", dev.Hostname)
		}
		if dev.ReportedAdminCount != nil {
			t.Errorf("device %s: ReportedAdminCount got %v, want nil (no signal)", dev.Hostname, dev.ReportedAdminCount)
		}
		if dev.Pass != nil {
			t.Errorf("device %s: Pass got %v, want nil (unknown, not false)", dev.Hostname, dev.Pass)
		}
	}
	if resp.OverLimitDevices != 0 {
		t.Errorf("OverLimitDevices: got %d, want 0 (unknown is not over-limit)", resp.OverLimitDevices)
	}
}

// TestPortalLocalAdminsHandlerViewerForbidden: account names are personal
// data, so a viewer identity (no portal_users row — resolves to the least
// privileged role) must be refused, never served the roster.
func TestPortalLocalAdminsHandlerViewerForbidden(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat2215-viewer")
	viewerEmail := "viewer-" + tenantID[:8] + "@pat2215.example"

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/local-admins", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: viewerEmail, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	PortalLocalAdminsHandler(pool).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
	var errResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error response: %v; body: %s", err, rec.Body.String())
	}
	if errResp["error"] != "admin_role_required" {
		t.Errorf(`error field: got %v, want "admin_role_required"`, errResp["error"])
	}
}
