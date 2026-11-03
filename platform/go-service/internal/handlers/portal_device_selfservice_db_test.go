package handlers

// PAT-2135: DB-backed checks for the device retirement write lock and the
// stale endpoints report's retired handling. The end-to-end API behaviour is
// in integration/portal_device_selfservice_test.go. Skipped without
// TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

func selfServiceAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) (string, string) {
	t.Helper()
	tenantID := catSeedTenant(t, ctx, pool, name)
	email := strings.ToLower(name) + "-" + tenantID[:8] + "-admin@selfservice.example"
	if _, err := pool.Exec(ctx, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'admin')`, email, tenantID); err != nil {
		t.Fatalf("seed portal admin: %v", err)
	}
	return tenantID, email
}

func selfServiceDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, hostname string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version, last_seen)
		VALUES ($1::uuid, $2, 'macOS', '15', $3) RETURNING id::text
	`, tenantID, hostname, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

// A second writer that commits a retirement while this request waits for
// the per-device lock must be seen by this request's read of the current
// state: the request then changes nothing, and exactly one row exists.
// Without the lock the request reads "not retired", inserts its own row and
// two rows result, so removing the lock turns this test red.
func TestPortalDeviceRetirementLockSerialisesConcurrentWriter(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, email := selfServiceAdmin(t, ctx, pool, "pat2135-lock")
	deviceID := selfServiceDevice(t, ctx, pool, tenantID, "lock-box", time.Now())

	fired := false
	done := make(chan error, 1)
	retirementBeforeDeviceLock = func(_ context.Context, tid, did string) {
		if tid != tenantID || did != deviceID {
			return
		}
		fired = true
		other, err := pool.Begin(context.Background())
		if err != nil {
			t.Errorf("begin other writer: %v", err)
			done <- err
			return
		}
		if _, err := other.Exec(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			tenantID+"|"+deviceID+"|device-retirement"); err != nil {
			t.Errorf("other writer lock: %v", err)
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			_, err := other.Exec(context.Background(), `
				INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
				VALUES ($1::uuid, $2::uuid, 'retire', 'other@selfservice.example')`, tenantID, deviceID)
			if err == nil {
				err = other.Commit(context.Background())
			}
			done <- err
		}()
	}
	t.Cleanup(func() { retirementBeforeDeviceLock = nil })

	req := httptest.NewRequest(http.MethodPut, "/v1/portal/devices/"+deviceID+"/retirement", strings.NewReader(`{"retired":true}`))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("deviceID", deviceID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	PortalDeviceRetirementPutHandler(pool).ServeHTTP(rec, req)

	if !fired {
		t.Fatal("the test seam never fired; the interleaving was not exercised")
	}
	if err := <-done; err != nil {
		t.Fatalf("other writer: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out retirementWriteResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Changed || out.Retirement == nil || out.Retirement.RetiredBy != "other@selfservice.example" {
		t.Fatalf("response = %s, want unchanged with the other writer's retirement", rec.Body.String())
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM device_retirement_decisions WHERE device_id = $1::uuid`, deviceID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("decision rows = %d (%v), want 1", rows, err)
	}
}

// The stale endpoints report (portal and admin PDF) lists a retired device
// apart, never among the stale ones, and renders.
func TestStaleEndpointsReportListsRetiredApart(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, _ := selfServiceAdmin(t, ctx, pool, "pat2135-stale")
	old := time.Now().Add(-30 * 24 * time.Hour)
	selfServiceDevice(t, ctx, pool, tenantID, "still-stale", old)
	retired := selfServiceDevice(t, ctx, pool, tenantID, "retired-stale", old)
	selfServiceDevice(t, ctx, pool, tenantID, "fresh", time.Now())
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
		VALUES ($1::uuid, $2::uuid, 'retire', 'admin@selfservice.example')`, tenantID, retired); err != nil {
		t.Fatalf("retire: %v", err)
	}

	rep, err := report.FetchStaleEndpointsReport(ctx, pool, tenantID, 14)
	if err != nil {
		t.Fatalf("FetchStaleEndpointsReport: %v", err)
	}
	if len(rep.Devices) != 1 || rep.Devices[0].Hostname != "still-stale" {
		t.Fatalf("stale devices = %+v, want only still-stale", rep.Devices)
	}
	if len(rep.Retired) != 1 || rep.Retired[0].Hostname != "retired-stale" || rep.Retired[0].RetiredBy != "admin@selfservice.example" {
		t.Fatalf("retired devices = %+v", rep.Retired)
	}
	pdf, err := report.RenderStaleEndpointsPDF(rep)
	if err != nil || len(pdf) == 0 {
		t.Fatalf("RenderStaleEndpointsPDF: %d bytes, %v", len(pdf), err)
	}
}
