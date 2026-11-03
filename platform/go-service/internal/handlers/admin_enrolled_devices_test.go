package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestRevokeDeviceHandler_AuditAttribution pins the PAT-1135 property for
// device_revocations, the special case among the six PAT-1135 tables:
// RevokeDeviceHandler takes NO request body at all (unlike the other five
// handlers, there was never a caller-supplied "actor" JSON field here --
// admin_id was a hardcoded 'admin' literal before PAT-1135). So this test
// asserts the honest version of that: admin_id is the server-established
// constant, not the old 'admin' literal, claimed_actor is NULL (nothing was
// ever claimed), and source_addr is still populated from the observed
// request address. See TestTenantDecommissionPut_AuditAttribution
// (agent_decommission_test.go) and TestSetTenantTierDB_AuditAttribution
// (admin_tier_test.go) for the other two tables required by PAT-1135's
// brief.
func TestRevokeDeviceHandler_AuditAttribution(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1135-revoke-attribution-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "11111111-2222-3333-4444-555555555501", "pat1135-revoke-host")

	// RevokeDeviceHandler resolves tenant_id from the device row itself, so
	// it needs an active credential to revoke -- seed one directly, mirroring
	// the fixed-key style already used by adSeedTenant/adSeedDevice.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid,
		        '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea,
		        '\x2222222222222222222222222222222222222222222222222222222222222222'::bytea)
	`, tenantID, deviceID); err != nil {
		t.Fatalf("seed tenant_credentials: %v", err)
	}

	router := chi.NewRouter()
	router.Post("/admin/devices/{deviceID}/revoke", RevokeDeviceHandler(pool))

	req := httptest.NewRequest(http.MethodPost, "/admin/devices/"+deviceID+"/revoke", nil)
	req.RemoteAddr = "198.51.100.20:9999"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var adminID string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(ctx, `
		SELECT admin_id, claimed_actor, source_addr FROM device_revocations
		WHERE device_id = $1::uuid ORDER BY revoked_at DESC LIMIT 1
	`, deviceID).Scan(&adminID, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("fetch device_revocations row: %v", err)
	}

	if adminID != adminSharedTokenActor {
		t.Errorf("admin_id = %q, want %q (must never be the old hardcoded 'admin' literal)", adminID, adminSharedTokenActor)
	}
	if claimedActor != nil {
		t.Errorf("claimed_actor = %q, want nil -- this handler takes no request body, so nothing was ever claimed", *claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "198.51.100.20" {
		t.Errorf("source_addr = %v, want \"198.51.100.20\" (port stripped)", sourceAddr)
	}
}
