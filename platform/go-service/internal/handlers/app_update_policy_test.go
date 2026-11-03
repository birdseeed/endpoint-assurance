package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestAppUpdatePolicyDefaultPutHandler_AuditAttribution pins the PAT-1135
// property for tenant_app_policy_changes on the default-flip path: a
// request body claiming changed_by="alice" must never land in the
// authoritative changed_by column. changed_by must always be the
// server-established constant "admin_shared_token"; the caller's claim
// goes only into claimed_actor, and source_addr must be populated from the
// observed request address.
func TestAppUpdatePolicyDefaultPutHandler_AuditAttribution(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1135-app-policy-attribution-tenant")

	router := chi.NewRouter()
	router.Put("/admin/tenant-app-policy/{tenantID}/default", AppUpdatePolicyDefaultPutHandler(pool))

	req := httptest.NewRequest(http.MethodPut, "/admin/tenant-app-policy/"+tenantID+"/default",
		strings.NewReader(`{"enabled":true,"changed_by":"alice"}`))
	req.RemoteAddr = "198.51.100.50:8888"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var changedBy string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(ctx, `
		SELECT changed_by, claimed_actor, source_addr FROM tenant_app_policy_changes
		WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&changedBy, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("fetch tenant_app_policy_changes row: %v", err)
	}

	if changedBy != adminSharedTokenActor {
		t.Errorf("changed_by = %q, want %q (must never be the caller's claimed name)", changedBy, adminSharedTokenActor)
	}
	if claimedActor == nil || *claimedActor != "alice" {
		t.Errorf("claimed_actor = %v, want \"alice\"", claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "198.51.100.50" {
		t.Errorf("source_addr = %v, want \"198.51.100.50\" (port stripped)", sourceAddr)
	}
}
