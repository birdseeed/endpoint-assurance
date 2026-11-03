package handlers

// Tests for parseInt64Param (shared by allowlist.go, extension_policies.go,
// and extension_removals.go entryID/requestID path params).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestParseInt64Param covers valid input, the trailing-garbage regression
// ("123abc" silently truncated to 123 by fmt.Sscan), and other malformed
// shapes. Regression test for the bug where fmt.Sscan stopped at the first
// non-numeric rune and reported no error, so "123abc" scanned as 123 with
// err == nil.
func TestParseInt64Param(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{"valid positive", "123", 123, false},
		{"valid zero", "0", 0, false},
		{"valid negative", "-42", -42, false},
		{"trailing garbage", "123abc", 0, true},
		{"leading garbage", "abc123", 0, true},
		{"purely alphabetic", "notint", 0, true},
		{"single letter", "x", 0, true},
		{"empty string", "", 0, true},
		{"whitespace suffix", "123 ", 0, true},
		{"decimal point", "123.5", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseInt64Param(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseInt64Param(%q) = (%d, nil), want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInt64Param(%q) returned unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseInt64Param(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestAllowlistInstalledAppIdentityPrecedence(t *testing.T) {
	tests := []struct {
		name                string
		teamID, bundle, app string
		want                string
	}{
		{"team ID wins", " EQHXZ8M8AV ", "com.google.Chrome", "Google Chrome", "team:eqhxz8m8av"},
		{"bundle fallback", "Unknown", " com.google.Chrome ", "Google Chrome", "bundle:com.google.chrome"},
		{"name fallback", "", "Unknown", " Google Chrome ", "name:google chrome"},
		{"no evidence", "", "", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowlistInstalledAppIdentity(tc.teamID, tc.bundle, "", tc.app, "macos"); got != tc.want {
				t.Fatalf("allowlistInstalledAppIdentity() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAllowlistInstalledWingetID(t *testing.T) {
	tests := []struct {
		name, identifier, identifierKind, platform, want string
	}{
		{"typed valid Windows PackageIdentifier", "Microsoft.VisualStudioCode", "winget", "windows", "Microsoft.VisualStudioCode"},
		{"native Windows identifier is not Winget authority", "Microsoft.VisualStudioCode", "native", "windows", ""},
		{"untyped Windows identifier is not Winget authority", "Microsoft.VisualStudioCode", "", "windows", ""},
		{"malformed typed identifier is not Winget authority", "bad..identifier", "winget", "windows", ""},
		{"macOS bundle identifier is not Winget authority", "com.microsoft.VSCode", "winget", "macos", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowlistInstalledWingetID(tc.identifier, tc.identifierKind, tc.platform); got != tc.want {
				t.Fatalf("allowlistInstalledWingetID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAllowlistInstalledAppIdentityPreservesTypedWindowsWinget(t *testing.T) {
	got := allowlistInstalledAppIdentity(
		"", "Microsoft.VisualStudioCode", "Microsoft.VisualStudioCode",
		"Visual Studio Code", "windows",
	)
	if got != "winget:microsoft.visualstudiocode" {
		t.Fatalf("typed Windows Winget identity = %q, want winget identity", got)
	}
}

func TestAllowlistGroupKeySeparatesWindowsIdentifierKinds(t *testing.T) {
	const identifier = "Microsoft.VisualStudio.Code"
	if got := allowlistGroupKey(identifier, "winget", "windows"); got != "winget:Microsoft.VisualStudio" {
		t.Fatalf("Winget group key = %q", got)
	}
	if got := allowlistGroupKey(identifier, "native", "windows"); got != "native:Microsoft.VisualStudio" {
		t.Fatalf("native group key = %q", got)
	}
	if got := allowlistGroupKey(identifier, "", "windows"); got != "untyped:Microsoft.VisualStudio" {
		t.Fatalf("untyped group key = %q", got)
	}
	if got := allowlistGroupKey("com.microsoft.VSCode", "", "macos"); got != "com.microsoft" {
		t.Fatalf("macOS compatibility group key = %q", got)
	}
}

// TestTenantAllowlistScanReturnsInstalledIdentityEvidence drives the real
// query and response contract against the migrated schema. It proves the
// dashboard receives the installed Team ID and bundle ID separately, while
// app_identity follows Team ID > bundle ID > name.
func TestTenantAllowlistScanReturnsInstalledIdentityEvidence(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-allowlist-identity", "pat1481-allowlist-token", "pat1481-allowlist-hmac-secret-32b")
	deviceID := rrInsertDeviceOS(t, pool, tenantID,
		"14810000-0000-4000-8000-000000000001", 0, "macOS")

	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id, publisher)
		VALUES ($1::uuid, 'PAT-1481 Signed App', 'im.patched.identity-test', '1.0',
		        'TEAM1481ID', 'Publisher text must not define Team ID')
	`, deviceID); err != nil {
		t.Fatalf("insert device app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/allowlist/scan", nil)
	req = alwWithParams(req, map[string]string{"tenantID": tenantID})
	rr := httptest.NewRecorder()
	TenantAllowlistScanHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("allowlist scan: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got allowlistScanResp
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode allowlist scan: %v", err)
	}
	if len(got.Apps) != 1 {
		t.Fatalf("apps: want 1, got %d: %+v", len(got.Apps), got.Apps)
	}
	app := got.Apps[0]
	if app.TeamID != "TEAM1481ID" || app.BundleID != "im.patched.identity-test" || app.AppIdentity != "team:team1481id" {
		t.Fatalf("unexpected installed identity contract: %+v", app)
	}
}

// TestTenantAllowlistScanPreservesWindowsIdentifierKinds drives the handler's
// aggregation query. The same installed identifier must remain three rows
// when the authenticated evidence says Winget, native, or legacy/untyped.
func TestTenantAllowlistScanPreservesWindowsIdentifierKinds(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-allowlist-winget-kind", "pat1481-allowlist-winget-token", "pat1481-allowlist-winget-hmac-secret-32b")

	identifiers := []struct {
		hwUUID, kind string
	}{
		{"14810000-0000-4000-8000-000000000011", "winget"},
		{"14810000-0000-4000-8000-000000000012", "native"},
		{"14810000-0000-4000-8000-000000000013", ""},
	}
	for _, row := range identifiers {
		deviceID := rrInsertDeviceOS(t, pool, tenantID, row.hwUUID, 0, "Windows 11")
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, identifier_kind, version)
			VALUES ($1::uuid, 'PAT-1481 Windows Identity', 'Microsoft.VisualStudio.Code', NULLIF($2, ''), '1.0')
		`, deviceID, row.kind); err != nil {
			t.Fatalf("insert %q device app: %v", row.kind, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/allowlist/scan", nil)
	req = alwWithParams(req, map[string]string{"tenantID": tenantID})
	rr := httptest.NewRecorder()
	TenantAllowlistScanHandler(pool).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("allowlist scan: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got allowlistScanResp
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode allowlist scan: %v", err)
	}
	if len(got.Apps) != len(identifiers) {
		t.Fatalf("apps: want %d independently aggregated rows, got %d: %+v", len(identifiers), len(got.Apps), got.Apps)
	}
	byKind := make(map[string]allowlistScanAppJSON, len(got.Apps))
	for _, app := range got.Apps {
		if app.DeviceCount != 1 {
			t.Fatalf("identifier kind %q was aggregated across evidence kinds: %+v", app.IdentifierKind, app)
		}
		byKind[app.IdentifierKind] = app
	}
	if app := byKind["winget"]; app.WingetID != "Microsoft.VisualStudio.Code" || app.BundleID != "Microsoft.VisualStudio.Code" || app.AppIdentity != "winget:microsoft.visualstudio.code" || app.GroupKey != "winget:Microsoft.VisualStudio" {
		t.Fatalf("typed Winget response lost identity evidence: %+v", app)
	}
	for _, kind := range []string{"native", ""} {
		app, ok := byKind[kind]
		if !ok || app.WingetID != "" {
			t.Fatalf("%q identifier incorrectly became Winget authority: %+v", kind, app)
		}
	}
	if byKind["native"].GroupKey == byKind[""].GroupKey || byKind["native"].GroupKey == byKind["winget"].GroupKey {
		t.Fatalf("Windows identity kinds share a dashboard group: %+v", byKind)
	}
}

const alwTestTenantID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

func alwWithParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestTenantAllowlistUpdate_TrailingGarbageEntryID400 is the handler-level
// regression test: an entryID of "123abc" must be rejected with 400, not
// silently parsed as 123 and passed through to the DB layer. Before the fix,
// parseInt64Param("123abc") returned (123, nil), so this request would have
// sailed past entryID validation. The body carries a well-formed, valid
// request so that a stray 400 from JSON parsing or enforcement validation
// can't masquerade as the entryID guard working — if entryID validation is
// bypassed, this reaches the nil-pool DB call and panics instead of 400ing.
func TestTenantAllowlistUpdate_TrailingGarbageEntryID400(t *testing.T) {
	handler := TenantAllowlistUpdateHandler(nil, nil)
	body := strings.NewReader(`{"enforcement":"flagged","notes":"test"}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+alwTestTenantID+"/allowlist/123abc", body)
	req = alwWithParams(req, map[string]string{"tenantID": alwTestTenantID, "entryID": "123abc"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for entryID with trailing garbage, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTenantAllowlistDelete_TrailingGarbageEntryID400 mirrors the update case
// for the delete handler.
func TestTenantAllowlistDelete_TrailingGarbageEntryID400(t *testing.T) {
	handler := TenantAllowlistDeleteHandler(nil)
	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+alwTestTenantID+"/allowlist/7xyz", nil)
	req = alwWithParams(req, map[string]string{"tenantID": alwTestTenantID, "entryID": "7xyz"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for entryID with trailing garbage, got %d: %s", rr.Code, rr.Body.String())
	}
}
