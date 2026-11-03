package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func shadowITRequest(req *http.Request, tenantID, label string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	if label != "" {
		rctx.URLParams.Add("label", label)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestShadowITFindingsAndExceptionLifecycle(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool,
		"pat1354-shadow-it", "pat1354-shadow-it-token", "pat1354-shadow-it-hmac-32bytes")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "22222222-3333-4444-5555-666666666654", 0, "macOS")
	if _, err := pool.Exec(ctx, `UPDATE devices SET hostname = 'pat1354-mac' WHERE id = $1::uuid`, deviceID); err != nil {
		t.Fatalf("set hostname: %v", err)
	}
	firstSeen := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	lastSeen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, first_seen, last_seen)
		VALUES ($1::uuid, 'Steam Client', 'com.valvesoftware.steam', '1.0', $2, $3)
	`, deviceID, firstSeen, lastSeen); err != nil {
		t.Fatalf("insert app: %v", err)
	}

	get := func() map[string]interface{} {
		req := shadowITRequest(httptest.NewRequest(http.MethodGet,
			"/admin/tenants/"+tenantID+"/shadow-it/findings", nil), tenantID, "")
		rr := httptest.NewRecorder()
		ShadowITFindingsHandler(pool).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("decode GET: %v", err)
		}
		return response
	}

	initial := get()
	findings := initial["findings"].([]interface{})
	if len(findings) != 1 {
		t.Fatalf("initial findings = %d, want 1: %#v", len(findings), initial)
	}
	finding := findings[0].(map[string]interface{})
	if finding["policy"] != "flag" || finding["hostname"] != "pat1354-mac" || finding["identifier"] != "com.valvesoftware.steam" {
		t.Fatalf("unexpected initial finding: %#v", finding)
	}
	if finding["first_seen"] == nil || finding["last_seen"] == nil {
		t.Fatalf("observation timestamps missing: %#v", finding)
	}

	missingReason := shadowITRequest(httptest.NewRequest(http.MethodPut,
		"/admin/tenants/"+tenantID+"/shadow-it/steam",
		bytes.NewBufferString(`{"policy":"allow","actor":"andy@patched.im"}`)), tenantID, "steam")
	missingReasonRR := httptest.NewRecorder()
	ShadowITPolicyPutHandler(pool).ServeHTTP(missingReasonRR, missingReason)
	if missingReasonRR.Code != http.StatusBadRequest {
		t.Fatalf("allow without reason = %d, want 400", missingReasonRR.Code)
	}

	allowReq := shadowITRequest(httptest.NewRequest(http.MethodPut,
		"/admin/tenants/"+tenantID+"/shadow-it/steam",
		bytes.NewBufferString(`{"policy":"allow","reason":"Approved for the design team","actor":"andy@patched.im"}`)), tenantID, "steam")
	allowReq.Header.Set("X-Forwarded-For", "100.64.0.10")
	allowRR := httptest.NewRecorder()
	ShadowITPolicyPutHandler(pool).ServeHTTP(allowRR, allowReq)
	if allowRR.Code != http.StatusOK {
		t.Fatalf("allow want 200, got %d: %s", allowRR.Code, allowRR.Body.String())
	}

	allowed := get()
	allowedFindings := allowed["findings"].([]interface{})
	if len(allowedFindings) != 1 || allowedFindings[0].(map[string]interface{})["policy"] != "allow" {
		t.Fatalf("allowed current match not returned: %#v", allowed)
	}
	exceptions := allowed["exceptions"].([]interface{})
	if len(exceptions) != 1 || exceptions[0].(map[string]interface{})["reason"] != "Approved for the design team" {
		t.Fatalf("exception metadata not returned: %#v", allowed)
	}

	var actor string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(ctx, `
		SELECT actor, claimed_actor, source_addr::text
		FROM tenant_shadow_it_policy_changes
		WHERE tenant_id = $1::uuid AND label = 'steam'
		ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&actor, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if actor != adminSharedTokenActor || claimedActor == nil || *claimedActor != "andy@patched.im" || sourceAddr == nil || *sourceAddr != "100.64.0.10/32" {
		t.Fatalf("bad attribution actor=%q claimed=%v source=%v", actor, claimedActor, sourceAddr)
	}

	revokeReq := shadowITRequest(httptest.NewRequest(http.MethodPut,
		"/admin/tenants/"+tenantID+"/shadow-it/steam",
		bytes.NewBufferString(`{"policy":"flag","reason":"Exception withdrawn","actor":"andy@patched.im"}`)), tenantID, "steam")
	revokeRR := httptest.NewRecorder()
	ShadowITPolicyPutHandler(pool).ServeHTTP(revokeRR, revokeReq)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("revoke want 200, got %d: %s", revokeRR.Code, revokeRR.Body.String())
	}
	if got := get()["exception_total"].(float64); got != 0 {
		t.Fatalf("exception_total after revoke = %v, want 0", got)
	}
}
