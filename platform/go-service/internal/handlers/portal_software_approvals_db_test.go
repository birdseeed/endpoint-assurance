package handlers

// PAT-2007 review P2: races between a portal approval write and an operator
// extension-policy write. DB-backed; skipped without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

func approvalRaceTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) (string, string) {
	t.Helper()
	tenantID := catSeedTenant(t, ctx, pool, name)
	if _, err := pool.Exec(ctx, `UPDATE tenants SET app_control_enabled = TRUE WHERE id = $1::uuid`, tenantID); err != nil {
		t.Fatalf("enable app control: %v", err)
	}
	email := strings.ToLower(name) + "-" + tenantID[:8] + "-admin@race.example"
	if _, err := pool.Exec(ctx, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'admin')`, email, tenantID); err != nil {
		t.Fatalf("seed portal admin: %v", err)
	}
	return tenantID, email
}

// The block check passes (the operator's chrome row reads approved), then,
// before the portal takes the row FOR UPDATE, a writer blocks the extension
// and commits. The re-check on the locked row must refuse, and the block
// must survive. Remove that re-check and this test goes red.
func TestPortalApprovalLockedRowRecheckRefusesLateBlock(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close) // registered first so it runs after the tenant cleanup
	ctx := context.Background()
	tenantID, email := approvalRaceTenant(t, ctx, pool, "pat2007-race-recheck")
	const extID = "raceextensionabcdefghijklmnopqrs"
	var rowID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'chrome', $2, 'Race', 'approved') RETURNING id`, tenantID, extID).Scan(&rowID); err != nil {
		t.Fatalf("seed operator row: %v", err)
	}

	fired := false
	approvalBeforeExtensionRowLock = func(_ context.Context, tid, browser, ext string) {
		if tid != tenantID || browser != "chrome" || ext != extID {
			return
		}
		fired = true
		// A separate connection, committed immediately: the late block.
		if _, err := pool.Exec(context.Background(),
			`UPDATE tenant_extension_policies SET policy = 'unapproved' WHERE id = $1`, rowID); err != nil {
			t.Errorf("late block: %v", err)
		}
	}
	t.Cleanup(func() { approvalBeforeExtensionRowLock = nil })

	body := `{"state":"ignored","items":[{"type":"browser_extension","browser":"chrome","extension_id":"` + extID + `"}]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/portal/software-approvals", strings.NewReader(body))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	PortalSoftwareApprovalsPutHandler(pool).ServeHTTP(rec, req)

	if !fired {
		t.Fatal("the test seam never fired; the interleaving was not exercised")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	var out approvalErrorResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Items) != 1 || out.Items[0].Code != "app_control_managed" {
		t.Fatalf("body = %s (%v)", rec.Body.String(), err)
	}
	var policy string
	if err := pool.QueryRow(ctx, `SELECT policy FROM tenant_extension_policies WHERE id = $1`, rowID).Scan(&policy); err != nil || policy != "unapproved" {
		t.Fatalf("operator block = %q (%v), want unapproved kept", policy, err)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM software_approval_decisions WHERE tenant_id = $1::uuid`, tenantID).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("audit rows = %d (%v), want 0", audits, err)
	}
}

// The operator extension-policy insert, update and delete each wait for the
// tenant policy advisory lock, so they serialise with a portal write that
// holds it. The test holds the lock itself, checks the operator call is
// blocked, then releases it and checks the call completes.
func TestOperatorExtensionPolicyWritersTakeTenantPolicyLock(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close) // registered first so it runs after the tenant cleanup
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2007-race-operator")
	var rowID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'chrome', 'operatorlockextensionabcdefghijk', 'Lock', 'approved') RETURNING id`, tenantID).Scan(&rowID); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	withParams := func(r *http.Request, entryID string) *http.Request {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("tenantID", tenantID)
		if entryID != "" {
			rctx.URLParams.Add("entryID", entryID)
		}
		return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	}
	id := strconv.FormatInt(rowID, 10)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
		want    int
	}{
		{"insert", TenantExtensionPolicyAddHandler(pool),
			withParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"browser":"edge","extension_id":"operatorlockinsertabcdefghijklmn","policy":"unapproved"}`)), ""),
			http.StatusCreated},
		{"update", TenantExtensionPolicyUpdateHandler(pool),
			withParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"policy":"unapproved","notes":"block"}`)), id),
			http.StatusNoContent},
		{"delete", TenantExtensionPolicyDeleteHandler(pool),
			withParams(httptest.NewRequest(http.MethodDelete, "/", nil), id),
			http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holder, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin holder: %v", err)
			}
			defer holder.Rollback(ctx) //nolint:errcheck
			if err := lockMandatoryTenantPolicy(ctx, holder, tenantID); err != nil {
				t.Fatalf("hold lock: %v", err)
			}

			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				tc.handler.ServeHTTP(rec, tc.req)
				close(done)
			}()
			select {
			case <-done:
				t.Fatalf("operator %s finished (%d) while the tenant policy lock was held", tc.name, rec.Code)
			case <-time.After(400 * time.Millisecond):
			}
			if err := holder.Rollback(ctx); err != nil {
				t.Fatalf("release lock: %v", err)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("operator %s never finished after the lock was released", tc.name)
			}
			if rec.Code != tc.want {
				t.Fatalf("operator %s = %d, want %d: %s", tc.name, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
