package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func softwareComparisonRequest(tenantID, deviceID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/devices/"+deviceID+"/software-observation-comparison", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	rctx.URLParams.Add("deviceID", deviceID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestSoftwareObservationComparisonRejectsBadIDsBeforeDatabase(t *testing.T) {
	recorder := httptest.NewRecorder()
	SoftwareObservationComparisonHandler(nil).ServeHTTP(recorder, softwareComparisonRequest("bad", "also-bad"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", recorder.Code, http.StatusBadRequest)
	}
}

func TestSoftwareObservationComparisonEnforcesTenantBoundary(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	seedTenant := func(name string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
			VALUES($1,'\x00','\x00') RETURNING id::text
		`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, id) })
		return id
	}

	tenantID := seedTenant("pat1461-comparison")
	otherTenantID := seedTenant("pat1461-comparison-other")
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,'macOS','PAT1461-COMPARE')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps(device_id,name,version,identifier)
		VALUES($1::uuid,'Comparison App','1','im.patched.comparison')
	`, deviceID); err != nil {
		t.Fatal(err)
	}
	var runID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO software_inventory_runs(
			tenant_id,device_id,platform,received_at,provenance,coverage
		) VALUES($1::uuid,$2::uuid,'macos',$3,'backfill_current_snapshot','{}')
		RETURNING id::text
	`, tenantID, deviceID, time.Now().UTC()).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	const fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var observationID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO software_observations(
			inventory_run_id,tenant_id,device_id,ordinal,platform,observed_name,
			observed_identifier,identity_kind,identity_value_normalized,
			identity_confidence,identity_fingerprint,observed_at
		) VALUES($1::uuid,$2::uuid,$3::uuid,0,'macos','Comparison App',
		         'im.patched.comparison','macos_bundle','im.patched.comparison',
		         'medium',$4,now()) RETURNING id
	`, runID, tenantID, deviceID, fingerprint).Scan(&observationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO software_observation_resolutions(observation_id,tenant_id,resolution_state,resolution_method)
		VALUES($1,$2::uuid,'unresolved','none')
	`, observationID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO software_installations(
			tenant_id,device_id,platform,identity_kind,identity_value_normalized,
			identity_fingerprint,current_name,first_seen_at,last_seen_at,
			latest_observation_id,provenance
		) VALUES($1::uuid,$2::uuid,'macos','macos_bundle','im.patched.comparison',
		         $3,'Comparison App',now(),now(),$4,'backfill_current_snapshot')
	`, tenantID, deviceID, fingerprint, observationID); err != nil {
		t.Fatal(err)
	}

	wrongTenant := httptest.NewRecorder()
	SoftwareObservationComparisonHandler(pool).ServeHTTP(wrongTenant, softwareComparisonRequest(otherTenantID, deviceID))
	if wrongTenant.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status=%d want=%d", wrongTenant.Code, http.StatusNotFound)
	}

	correctTenant := httptest.NewRecorder()
	SoftwareObservationComparisonHandler(pool).ServeHTTP(correctTenant, softwareComparisonRequest(tenantID, deviceID))
	if correctTenant.Code != http.StatusOK {
		t.Fatalf("correct-tenant status=%d body=%s", correctTenant.Code, correctTenant.Body.String())
	}
	var response softwareObservationComparisonResponse
	if err := json.Unmarshal(correctTenant.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.LegacyCurrent != 1 || response.ObservationCurrent != 1 || response.UnresolvedCurrent != 1 || response.LegacyOnly != 0 || response.ObservationOnly != 0 {
		t.Fatalf("unexpected comparison response: %#v", response)
	}
}
