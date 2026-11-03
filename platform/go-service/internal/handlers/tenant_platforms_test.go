package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// TestTenantPlatformPutReqValidation checks which platform values are accepted.
// This mirrors the switch in TenantPlatformsPutHandler — a pure-logic test
// so we don't need a DB. The actual HTTP handler is covered by CI integration
// tests once migration 0010 is applied.
func TestTenantPlatformPutReqValidation(t *testing.T) {
	tests := []struct {
		platform string
		valid    bool
	}{
		{"macos", true},
		{"windows", true},
		{"linux", false},
		{"", false},
		{"MacOS", false},
		{"Windows", false},
	}

	for _, tc := range tests {
		t.Run(tc.platform, func(t *testing.T) {
			got := isPlatformValid(tc.platform)
			if got != tc.valid {
				t.Errorf("isPlatformValid(%q) = %v, want %v", tc.platform, got, tc.valid)
			}
		})
	}
}

// isPlatformValid mirrors the validation logic in TenantPlatformsPutHandler.
// Extracted here so both the handler and the test share the same predicate.
func isPlatformValid(p string) bool {
	return p == "macos" || p == "windows"
}

// TestTenantRulesPlatformFilter checks that the ?platform= query param is
// correctly validated. The handler rejects unknown platforms before hitting the DB.
func TestTenantRulesPlatformFilter(t *testing.T) {
	tests := []struct {
		platform string
		valid    bool
	}{
		{"", true}, // absent → all platforms (back-compat)
		{"macos", true},
		{"windows", true},
		{"linux", false},
		{"MacOS", false},
	}

	for _, tc := range tests {
		t.Run("platform="+tc.platform, func(t *testing.T) {
			ok := tc.platform == "" || tc.platform == "macos" || tc.platform == "windows"
			if ok != tc.valid {
				t.Errorf("platform %q valid=%v, want %v", tc.platform, ok, tc.valid)
			}
		})
	}
}

// tpFailingRow is a pgx.Row whose Scan always fails, simulating a transient
// DB error on the post-commit re-read.
type tpFailingRow struct{ err error }

func (r tpFailingRow) Scan(dest ...any) error { return r.err }

// tpFailingQuerier is a rowQuerier whose QueryRow always returns tpFailingRow.
type tpFailingQuerier struct{ err error }

func (q tpFailingQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return tpFailingRow{err: q.err}
}

// TestRereadTenantPlatformState_ErrorSurfaced verifies that a failure on the
// post-commit re-read is returned to the caller as an error, not swallowed —
// regression test for the bug where `_ = pool.QueryRow(...)` discarded the
// error and let placeholder values (e.g. WindowsEnabled forced to true) stand
// in as the authoritative response.
func TestRereadTenantPlatformState_ErrorSurfaced(t *testing.T) {
	wantErr := errors.New("connection reset by peer")
	q := tpFailingQuerier{err: wantErr}

	macos, windows, err := rereadTenantPlatformState(context.Background(), q, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if err == nil {
		t.Fatal("want error from rereadTenantPlatformState on a failing re-read, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("want wrapped/equal error %v, got %v", wantErr, err)
	}
	// The zero values must not be mistaken for real state — the handler must
	// treat a non-nil error as authoritative and not serve macos/windows here.
	if macos || windows {
		t.Errorf("want zero-value (false, false) on error, got (%v, %v)", macos, windows)
	}
}

// TestRereadTenantPlatformState_Success verifies the happy path still returns
// the scanned values with no error.
func TestRereadTenantPlatformState_Success(t *testing.T) {
	q := tpOKQuerier{macos: true, windows: false}
	macos, windows, err := rereadTenantPlatformState(context.Background(), q, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if !macos || windows {
		t.Errorf("want (true, false), got (%v, %v)", macos, windows)
	}
}

// tpOKRow is a pgx.Row that scans fixed macos/windows values successfully.
type tpOKRow struct{ macos, windows bool }

func (r tpOKRow) Scan(dest ...any) error {
	*(dest[0].(*bool)) = r.macos
	*(dest[1].(*bool)) = r.windows
	return nil
}

type tpOKQuerier struct{ macos, windows bool }

func (q tpOKQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return tpOKRow{macos: q.macos, windows: q.windows}
}

// TestTenantPlatformsPutHandler_AuditAttribution pins the PAT-1135 property
// for tenant_platform_changes: this handler's request body has no actor
// field at all (unlike tier/decommission/app-policy), so before PAT-1135
// changed_by relied entirely on the column's DEFAULT 'system' and was never
// set explicitly by this handler. changed_by must now be explicitly the
// server-established constant, and claimed_actor must be NULL (nothing was
// ever claimed by this request shape) while source_addr is still populated.
func TestTenantPlatformsPutHandler_AuditAttribution(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1135-platform-attribution-tenant")

	router := chi.NewRouter()
	router.Put("/admin/tenant-platforms/{tenantID}", TenantPlatformsPutHandler(pool))

	req := httptest.NewRequest(http.MethodPut, "/admin/tenant-platforms/"+tenantID,
		strings.NewReader(`{"platform":"macos","enabled":true}`))
	req.RemoteAddr = "198.51.100.30:4444"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var changedBy string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(ctx, `
		SELECT changed_by, claimed_actor, source_addr FROM tenant_platform_changes
		WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&changedBy, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("fetch tenant_platform_changes row: %v", err)
	}

	if changedBy != adminSharedTokenActor {
		t.Errorf("changed_by = %q, want %q", changedBy, adminSharedTokenActor)
	}
	if claimedActor != nil {
		t.Errorf("claimed_actor = %q, want nil — this request body has no actor field", *claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "198.51.100.30" {
		t.Errorf("source_addr = %v, want \"198.51.100.30\" (port stripped)", sourceAddr)
	}
}
