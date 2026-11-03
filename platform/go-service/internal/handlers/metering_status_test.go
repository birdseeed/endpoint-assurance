package handlers

// Tests for collection-health surfacing on the software-metering endpoints
// (PAT-1320). devices.metering_status ('ok' | 'spotlight_disabled' |
// 'no_user_session' | NULL) is persisted by the extractor (PAT-116/0020) but
// was never returned by MeteringFleetHandler / MeteringBreakdownHandler — a
// consumer of the API could not tell "collector reported ok, this app
// genuinely has no usage" from "Spotlight was disabled, we never found out".
// These tests pin: the per-device passthrough on the breakdown route, the
// per-app aggregation rule on the fleet route (all-agree / never-reported /
// disagree), and that metering_status_at tracks devices.last_seen only when
// a status is actually known.
//
// DB-backed: require TEST_DATABASE_URL and are skipped otherwise, same convention
// as allowlist_agent_known_path_test.go / ring_rollout_db_test.go in this
// package — reuses their parConnectOrSkip/parSeedTenant helpers.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mchWithTenantID injects a chi tenantID URL param (fleet route).
func mchWithTenantID(r *http.Request, tenantID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// mchWithTenantAndApp injects tenantID + appName chi URL params (breakdown route).
func mchWithTenantAndApp(r *http.Request, tenantID, appName string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	rctx.URLParams.Add("appName", appName)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// mchInsertDevice inserts a devices row with an explicit metering_status
// (nil for "never reported") and last_seen, matching the extractor's real
// columns (upsert.go) closely enough to exercise the metering queries.
func mchInsertDevice(t *testing.T, pool *pgxpool.Pool, tenantID, hwUUID, hostname, osName string, meteringStatus *string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, hw_uuid, hostname, os, metering_status, last_seen)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		RETURNING id::text
	`, tenantID, hwUUID, hostname, osName, meteringStatus, lastSeen).Scan(&id); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, id) })
	return id
}

// mchInsertDeviceApp inserts one device_apps row. lastUsedAt/launchCount nil
// means "no usage evidence recorded" — the honest NULL semantics from
// migration 0020.
func mchInsertDeviceApp(t *testing.T, pool *pgxpool.Pool, deviceID, name string, lastUsedAt *time.Time, launchCount *int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO device_apps (device_id, name, identifier, last_used_at, launch_count)
		VALUES ($1::uuid, $2, $3, $4, $5)
	`, deviceID, name, "com.test."+name, lastUsedAt, launchCount); err != nil {
		t.Fatalf("insert device_apps: %v", err)
	}
}

// strPtr / intPtr reused from agent_config_test.go (same package).

// ---------------------------------------------------------------------------
// Fleet aggregate — collection health
// ---------------------------------------------------------------------------

// TestMeteringFleetHandler_OkStatusWithUsage: a single device that reported
// metering_status='ok' and genuine usage. Expect the app row's
// metering_status to pass straight through as "ok" and metering_status_at to
// be populated (not the "unknown" fallback).
func TestMeteringFleetHandler_OkStatusWithUsage(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1320-ok-tenant", "pat1320-ok-token", "pat1320-ok-hmac-secret-32byte!!")

	lastSeen := time.Now().UTC().Truncate(time.Second)
	deviceID := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000001", "ok-host", "macOS", strPtr("ok"), lastSeen)

	lastUsed := lastSeen.Add(-2 * time.Hour)
	mchInsertDeviceApp(t, pool, deviceID, "OkApp", &lastUsed, intPtr(42))

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/metering", nil)
	req = mchWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	MeteringFleetHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp meteringFleetResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	row := requireSingleAppRow(t, resp, "OkApp")

	if row.MeteringStatus != "ok" {
		t.Errorf("metering_status = %q, want %q", row.MeteringStatus, "ok")
	}
	if row.MeteringStatusAt == nil || !row.MeteringStatusAt.Equal(lastSeen) {
		t.Errorf("metering_status_at = %v, want %v", row.MeteringStatusAt, lastSeen)
	}
	if row.TotalLaunchCount == nil || *row.TotalLaunchCount != 42 {
		t.Errorf("total_launch_count = %v, want 42", row.TotalLaunchCount)
	}
	if row.LastUsedAt == nil {
		t.Errorf("last_used_at = nil, want %v", lastUsed)
	}
}

// TestMeteringFleetHandler_SpotlightDisabledWithNullUsage: a single device
// that reported metering_status='spotlight_disabled' and, correctly, no
// usage evidence at all (NULL last_used_at/launch_count — the collector
// could not read Spotlight, so it has no opinion on usage). Expect
// metering_status to pass through as "spotlight_disabled" — never
// misreported as "ok" or silently dropped — while last_used_at/
// days_since_last_use stay NULL (unaffected by this change).
func TestMeteringFleetHandler_SpotlightDisabledWithNullUsage(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1320-spotlight-tenant", "pat1320-spotlight-token", "pat1320-spot-hmac-secret-32byte!")

	lastSeen := time.Now().UTC().Truncate(time.Second)
	deviceID := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000002", "spotlight-host", "macOS", strPtr("spotlight_disabled"), lastSeen)
	mchInsertDeviceApp(t, pool, deviceID, "DisabledApp", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/metering", nil)
	req = mchWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	MeteringFleetHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp meteringFleetResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	row := requireSingleAppRow(t, resp, "DisabledApp")

	if row.MeteringStatus != "spotlight_disabled" {
		t.Errorf("metering_status = %q, want %q", row.MeteringStatus, "spotlight_disabled")
	}
	if row.MeteringStatusAt == nil || !row.MeteringStatusAt.Equal(lastSeen) {
		t.Errorf("metering_status_at = %v, want %v", row.MeteringStatusAt, lastSeen)
	}
	if row.LastUsedAt != nil {
		t.Errorf("last_used_at = %v, want nil", row.LastUsedAt)
	}
	if row.DaysSinceLastUse != nil {
		t.Errorf("days_since_last_use = %v, want nil", row.DaysSinceLastUse)
	}
}

// TestMeteringFleetHandler_NoMeteringStatusReported: a device that has never
// reported a metering_status at all (old agent / Windows — NULL, not one of
// the enum strings). Expect metering_status to read "unknown" (genuinely
// no evidence either way) rather than "ok", and metering_status_at nil since
// there is no collection event to date.
func TestMeteringFleetHandler_NoMeteringStatusReported(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1320-nostatus-tenant", "pat1320-nostatus-token", "pat1320-none-hmac-secret-32byt!")

	lastSeen := time.Now().UTC().Truncate(time.Second)
	deviceID := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000003", "nostatus-host", "Windows", nil, lastSeen)
	mchInsertDeviceApp(t, pool, deviceID, "UnknownApp", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/metering", nil)
	req = mchWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	MeteringFleetHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp meteringFleetResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	row := requireSingleAppRow(t, resp, "UnknownApp")

	if row.MeteringStatus != "unknown" {
		t.Errorf("metering_status = %q, want %q", row.MeteringStatus, "unknown")
	}
	if row.MeteringStatusAt != nil {
		t.Errorf("metering_status_at = %v, want nil", row.MeteringStatusAt)
	}
}

// TestMeteringFleetHandler_DisagreeingDevicesAggregateAsMixed pins the
// aggregation rule: two devices in the same tenant both carry the same app,
// one reported metering_status='ok' (older last_seen), the other
// 'spotlight_disabled' (newer last_seen). The row must not silently pick
// either device's status — it must say "mixed" — and metering_status_at
// must be the freshest last_seen among devices that DID report a status
// (the newer, spotlight_disabled device), not just MAX(last_seen) overall
// and not the older ok device's timestamp.
func TestMeteringFleetHandler_DisagreeingDevicesAggregateAsMixed(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1320-mixed-tenant", "pat1320-mixed-token", "pat1320-mixed-hmac-secret-32by!")

	base := time.Now().UTC().Truncate(time.Second)
	olderSeen := base.Add(-2 * time.Hour)
	newerSeen := base.Add(-1 * time.Minute)

	deviceOK := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000004", "mixed-ok-host", "macOS", strPtr("ok"), olderSeen)
	deviceBad := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000005", "mixed-bad-host", "macOS", strPtr("spotlight_disabled"), newerSeen)

	usedAt := olderSeen.Add(-1 * time.Hour)
	mchInsertDeviceApp(t, pool, deviceOK, "SharedApp", &usedAt, intPtr(10))
	mchInsertDeviceApp(t, pool, deviceBad, "SharedApp", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/metering", nil)
	req = mchWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	MeteringFleetHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp meteringFleetResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	row := requireSingleAppRow(t, resp, "SharedApp")

	if row.MeteringStatus != "mixed" {
		t.Errorf("metering_status = %q, want %q (devices disagree — must not silently pick one)", row.MeteringStatus, "mixed")
	}
	if row.DeviceCount != 2 {
		t.Errorf("device_count = %d, want 2", row.DeviceCount)
	}
	if row.MeteringStatusAt == nil || !row.MeteringStatusAt.Equal(newerSeen) {
		t.Errorf("metering_status_at = %v, want freshest reporting device's last_seen %v", row.MeteringStatusAt, newerSeen)
	}
}

// TestMeteringFleetHandler_ReportedVsNeverReportedAggregatesAsMixed pins the
// other half of the "mixed" branch: one device reported metering_status='ok'
// with usage, the other has NEVER reported a status at all (NULL — old
// agent / Windows), not a competing enum value. This is the case that most
// plausibly regresses into silently reading as "ok" for a fleet where one
// device's usage was never actually readable — exactly the dishonesty
// PAT-1320 exists to remove.
//
// The never-reported device is deliberately given the NEWER last_seen, so
// that if the aggregation wrongly used MAX(last_seen) across all devices
// (rather than MAX(last_seen) among devices that actually reported a
// status), metering_status_at would come back wrong and this test would
// catch it.
func TestMeteringFleetHandler_ReportedVsNeverReportedAggregatesAsMixed(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1320-unreported-tenant", "pat1320-unreported-token", "pat1320-unrep-hmac-secret-32by!")

	base := time.Now().UTC().Truncate(time.Second)
	olderSeen := base.Add(-2 * time.Hour)   // device A: reported 'ok' — OLDER
	newerSeen := base.Add(-1 * time.Minute) // device B: never reported — NEWER

	deviceOK := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000008", "unrep-ok-host", "macOS", strPtr("ok"), olderSeen)
	deviceNever := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000009", "unrep-never-host", "macOS", nil, newerSeen)

	usedAt := olderSeen.Add(-1 * time.Hour)
	mchInsertDeviceApp(t, pool, deviceOK, "PartlyUnreportedApp", &usedAt, intPtr(7))
	mchInsertDeviceApp(t, pool, deviceNever, "PartlyUnreportedApp", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/metering", nil)
	req = mchWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	MeteringFleetHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp meteringFleetResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	row := requireSingleAppRow(t, resp, "PartlyUnreportedApp")

	if row.MeteringStatus != "mixed" {
		t.Errorf("metering_status = %q, want %q (one device never reported — must not silently read as \"ok\")", row.MeteringStatus, "mixed")
	}
	if row.DeviceCount != 2 {
		t.Errorf("device_count = %d, want 2", row.DeviceCount)
	}
	if row.MeteringStatusAt == nil || !row.MeteringStatusAt.Equal(olderSeen) {
		t.Errorf("metering_status_at = %v, want reporting device A's last_seen %v (not the never-reported device B's newer last_seen %v)", row.MeteringStatusAt, olderSeen, newerSeen)
	}
}

// requireSingleAppRow finds the app row named appName in resp.Apps, failing
// the test if it is missing or if more than one row was returned (these
// tests seed exactly one app name per isolated tenant).
func requireSingleAppRow(t *testing.T, resp meteringFleetResp, appName string) meteringAppRow {
	t.Helper()
	for _, row := range resp.Apps {
		if row.Name == appName {
			return row
		}
	}
	t.Fatalf("no app row named %q in response apps=%+v", appName, resp.Apps)
	return meteringAppRow{}
}

// ---------------------------------------------------------------------------
// Per-device breakdown — raw passthrough
// ---------------------------------------------------------------------------

// TestMeteringBreakdownHandler_PerDeviceStatusPassthrough: the breakdown
// route is one row per device, so there is nothing to aggregate — it must
// pass each device's raw metering_status straight through, including nil for
// a device that never reported one, with metering_status_at nil exactly
// when metering_status is nil.
func TestMeteringBreakdownHandler_PerDeviceStatusPassthrough(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1320-breakdown-tenant", "pat1320-breakdown-token", "pat1320-brkdwn-hmac-secret-32b!")

	seenA := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Hour)
	seenB := time.Now().UTC().Truncate(time.Second).Add(-30 * time.Minute)

	deviceA := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000006", "breakdown-a", "macOS", strPtr("ok"), seenA)
	deviceB := mchInsertDevice(t, pool, tenantID, "AAAAAAAA-0000-0000-0000-000000000007", "breakdown-b", "macOS", nil, seenB)

	usedAt := seenA.Add(-1 * time.Hour)
	mchInsertDeviceApp(t, pool, deviceA, "BreakdownApp", &usedAt, intPtr(5))
	mchInsertDeviceApp(t, pool, deviceB, "BreakdownApp", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/metering/BreakdownApp", nil)
	req = mchWithTenantAndApp(req, tenantID, "BreakdownApp")
	rr := httptest.NewRecorder()
	MeteringBreakdownHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp meteringBreakdownResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("devices count = %d, want 2: %+v", len(resp.Devices), resp.Devices)
	}

	var gotA, gotB *meteringDeviceRow
	for i := range resp.Devices {
		switch resp.Devices[i].DeviceID {
		case deviceA:
			gotA = &resp.Devices[i]
		case deviceB:
			gotB = &resp.Devices[i]
		}
	}
	if gotA == nil || gotB == nil {
		t.Fatalf("missing expected device rows: %+v", resp.Devices)
	}

	if gotA.MeteringStatus == nil || *gotA.MeteringStatus != "ok" {
		t.Errorf("device A metering_status = %v, want \"ok\"", gotA.MeteringStatus)
	}
	if gotA.MeteringStatusAt == nil || !gotA.MeteringStatusAt.Equal(seenA) {
		t.Errorf("device A metering_status_at = %v, want %v", gotA.MeteringStatusAt, seenA)
	}

	if gotB.MeteringStatus != nil {
		t.Errorf("device B metering_status = %v, want nil (never reported)", gotB.MeteringStatus)
	}
	if gotB.MeteringStatusAt != nil {
		t.Errorf("device B metering_status_at = %v, want nil", gotB.MeteringStatusAt)
	}
}
