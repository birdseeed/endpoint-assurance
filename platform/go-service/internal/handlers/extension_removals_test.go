package handlers

// Tests for the per-tenant browser-extension removal request queue (PAT-832).
//
// Pure-logic (nil-pool) tests cover the scope/context validation branches, which
// run before any DB access — the load-bearing guard against a malformed request
// silently widening removal blast radius. No database is required.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func erWithTenantID(r *http.Request, tenantID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

const erTestTenantID = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"

// TestValidateExtensionRemoval exercises the scope/context matrix directly.
func TestValidateExtensionRemoval(t *testing.T) {
	tests := []struct {
		name        string
		req         extensionRemovalCreateReq
		wantErr     bool
		wantUserNil bool // expected user_account == nil after normalisation
		wantProfNil bool // expected profile == nil after normalisation
	}{
		{
			name:    "one_profile with full context",
			req:     extensionRemovalCreateReq{Browser: "chrome", ExtensionID: "x", Scope: "one_profile", UserAccount: strPtr("alice"), Profile: strPtr("Default")},
			wantErr: false,
		},
		{
			name:    "one_profile missing profile",
			req:     extensionRemovalCreateReq{Browser: "chrome", ExtensionID: "x", Scope: "one_profile", UserAccount: strPtr("alice")},
			wantErr: true,
		},
		{
			name:    "one_profile missing user_account",
			req:     extensionRemovalCreateReq{Browser: "chrome", ExtensionID: "x", Scope: "one_profile", Profile: strPtr("Default")},
			wantErr: true,
		},
		{
			name:    "one_profile blank profile treated as missing",
			req:     extensionRemovalCreateReq{Browser: "chrome", ExtensionID: "x", Scope: "one_profile", UserAccount: strPtr("alice"), Profile: strPtr("   ")},
			wantErr: true,
		},
		{
			name:    "one_user with user_account",
			req:     extensionRemovalCreateReq{Browser: "edge", ExtensionID: "x", Scope: "one_user", UserAccount: strPtr("alice")},
			wantErr: false, wantProfNil: true,
		},
		{
			name:    "one_user drops any supplied profile",
			req:     extensionRemovalCreateReq{Browser: "edge", ExtensionID: "x", Scope: "one_user", UserAccount: strPtr("alice"), Profile: strPtr("Default")},
			wantErr: false, wantProfNil: true,
		},
		{
			name:    "one_user missing user_account",
			req:     extensionRemovalCreateReq{Browser: "edge", ExtensionID: "x", Scope: "one_user"},
			wantErr: true,
		},
		{
			name:    "all_profiles drops context",
			req:     extensionRemovalCreateReq{Browser: "firefox", ExtensionID: "x", Scope: "all_profiles", UserAccount: strPtr("alice"), Profile: strPtr("Default")},
			wantErr: false, wantUserNil: true, wantProfNil: true,
		},
		{
			name:    "all_devices drops context",
			req:     extensionRemovalCreateReq{Browser: "chrome", ExtensionID: "x", Scope: "all_devices", UserAccount: strPtr("alice")},
			wantErr: false, wantUserNil: true, wantProfNil: true,
		},
		{
			name:    "missing extension_id",
			req:     extensionRemovalCreateReq{Browser: "chrome", Scope: "all_devices"},
			wantErr: true,
		},
		{
			// PAT-2071: 'safari' became a valid browser for the extension
			// POLICY vocabulary (tenant_extension_policies), but removal
			// requests must keep rejecting it — Patched does not actuate,
			// and a Safari app extension ships with its host app.
			name:    "invalid browser (safari is a policy value, not a removal target)",
			req:     extensionRemovalCreateReq{Browser: "safari", ExtensionID: "x", Scope: "all_devices"},
			wantErr: true,
		},
		{
			name:    "browser any is rejected for removal",
			req:     extensionRemovalCreateReq{Browser: "any", ExtensionID: "x", Scope: "all_devices"},
			wantErr: true,
		},
		{
			name:    "invalid scope",
			req:     extensionRemovalCreateReq{Browser: "chrome", ExtensionID: "x", Scope: "everywhere"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, user, prof, errMsg := validateExtensionRemoval(tc.req)
			if (errMsg != "") != tc.wantErr {
				t.Fatalf("errMsg=%q, wantErr=%v", errMsg, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if tc.wantUserNil && user != nil {
				t.Errorf("user_account: want nil, got %q", *user)
			}
			if tc.wantProfNil && prof != nil {
				t.Errorf("profile: want nil, got %q", *prof)
			}
		})
	}
}

func TestExtensionRemovalState(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name       string
		job        extensionRemovalJSON
		enabled    bool
		wantState  string
		wantReason string
	}{
		{name: "disabled control is blocked", job: extensionRemovalJSON{TargetsTotal: 2}, enabled: false, wantState: "blocked", wantReason: "extension_control_disabled"},
		{name: "no captured targets is blocked", job: extensionRemovalJSON{}, enabled: true, wantState: "blocked", wantReason: "no_matching_targets"},
		{name: "eligible request is queued", job: extensionRemovalJSON{TargetsTotal: 2, TargetsCompleted: 1}, enabled: true, wantState: "queued"},
		{name: "fulfilled wins over disabled", job: extensionRemovalJSON{Fulfilled: true, FulfilledAt: &now}, enabled: false, wantState: "completed"},
		{name: "cancelled wins over every other state", job: extensionRemovalJSON{Fulfilled: true, CancelledAt: &now}, enabled: true, wantState: "cancelled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extensionRemovalState(tc.job, tc.enabled)
			if got.State != tc.wantState {
				t.Fatalf("state=%q, want %q", got.State, tc.wantState)
			}
			if tc.wantReason == "" {
				if got.BlockedReason != nil {
					t.Fatalf("unexpected blocked reason %q", *got.BlockedReason)
				}
			} else if got.BlockedReason == nil || *got.BlockedReason != tc.wantReason {
				t.Fatalf("blocked reason=%v, want %q", got.BlockedReason, tc.wantReason)
			}
		})
	}
}

// TestExtensionRemovalCreate_BadTenantUUID asserts the UUID guard returns 400
// before any DB access (nil pool).
func TestExtensionRemovalCreate_BadTenantUUID(t *testing.T) {
	h := TenantExtensionRemovalCreateHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/not-a-uuid/extension-removals", strings.NewReader(`{}`))
	req = erWithTenantID(req, "not-a-uuid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// TestExtensionRemovalCreate_InvalidScope asserts scope validation returns 400
// before any DB access (nil pool) — a malformed request never reaches Postgres.
func TestExtensionRemovalCreate_InvalidScope(t *testing.T) {
	h := TenantExtensionRemovalCreateHandler((*pgxpool.Pool)(nil))
	body := `{"browser":"chrome","extension_id":"x","scope":"one_profile","user_account":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+erTestTenantID+"/extension-removals", strings.NewReader(body))
	req = erWithTenantID(req, erTestTenantID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for one_profile missing profile, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "profile is required") {
		t.Errorf("want profile-required message, got %q", w.Body.String())
	}
}

// TestExtensionRemovalCreate_InvalidJSON asserts a malformed body returns 400.
func TestExtensionRemovalCreate_InvalidJSON(t *testing.T) {
	h := TenantExtensionRemovalCreateHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+erTestTenantID+"/extension-removals", strings.NewReader(`{not json`))
	req = erWithTenantID(req, erTestTenantID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// TestExtensionRemovalCancel_BadRequestID asserts a non-integer requestID is 400.
func TestExtensionRemovalCancel_BadRequestID(t *testing.T) {
	h := TenantExtensionRemovalCancelHandler((*pgxpool.Pool)(nil))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", erTestTenantID)
	rctx.URLParams.Add("requestID", "not-an-int")
	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+erTestTenantID+"/extension-removals/not-an-int", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}
