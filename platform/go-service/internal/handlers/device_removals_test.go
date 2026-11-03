package handlers

// Tests for the per-device app-removal task queue (PAT-781 / PAT-462).
//
// Pure-logic (nil-pool) tests run in every environment and cover the
// validation branches that return before any DB access. DB-backed tests
// require TEST_DATABASE_URL and are skipped otherwise; they drive the real admin
// lifecycle (queue → idempotent re-queue → list → cancel) against Postgres.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func drWithDeviceID(r *http.Request, deviceID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("deviceID", deviceID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func drWithDeviceTask(r *http.Request, deviceID, taskID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("deviceID", deviceID)
	rctx.URLParams.Add("taskID", taskID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func drConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping device-removal DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

func drSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		            '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`, name).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}

func drSeedDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	var deviceID string
	err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os) VALUES ($1::uuid, 'macOS') RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return deviceID
}

// ---------------------------------------------------------------------------
// Pure-logic (nil-pool) tests — no database required
// ---------------------------------------------------------------------------

func TestDeviceRemovalsListBadUUID(t *testing.T) {
	h := DeviceRemovalsListHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodGet, "/admin/devices/not-a-uuid/removals", nil)
	req = drWithDeviceID(req, "not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad deviceID, got %d", w.Code)
	}
}

func TestDeviceRemovalsCreateBadUUID(t *testing.T) {
	h := DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPost, "/admin/devices/not-a-uuid/removals", strings.NewReader(`{"app_name":"Zoom"}`))
	req = drWithDeviceID(req, "not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad deviceID, got %d", w.Code)
	}
}

func TestDeviceRemovalsCreateInvalidJSON(t *testing.T) {
	h := DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPost, "/admin/devices/11111111-1111-1111-1111-111111111111/removals", strings.NewReader(`{not json`))
	req = drWithDeviceID(req, "11111111-1111-1111-1111-111111111111")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid JSON, got %d", w.Code)
	}
}

func TestDeviceRemovalsCreateEmptyAppName(t *testing.T) {
	h := DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPost, "/admin/devices/11111111-1111-1111-1111-111111111111/removals", strings.NewReader(`{"app_name":"   "}`))
	req = drWithDeviceID(req, "11111111-1111-1111-1111-111111111111")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty app_name, got %d", w.Code)
	}
}

func TestDeviceRemovalsCancelBadTaskUUID(t *testing.T) {
	h := DeviceRemovalsCancelHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodDelete, "/admin/devices/11111111-1111-1111-1111-111111111111/removals/nope", nil)
	req = drWithDeviceTask(req, "11111111-1111-1111-1111-111111111111", "nope")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad taskID, got %d", w.Code)
	}
}

func TestDeviceRemovalTasksPendingUnauthorized(t *testing.T) {
	h := DeviceRemovalTasksPendingHandlerForLegacyExecutionCompatibility((*pgxpool.Pool)(nil), nil, 0)
	req := httptest.NewRequest(http.MethodGet, "/v1/devices/11111111-1111-1111-1111-111111111111/removal-tasks/pending", nil)
	req = drWithDeviceID(req, "11111111-1111-1111-1111-111111111111")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 with no bearer, got %d", w.Code)
	}
}

func TestDeviceRemovalTasksReportUnauthorized(t *testing.T) {
	h := DeviceRemovalTasksReportHandler((*pgxpool.Pool)(nil), nil, 0)
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/11111111-1111-1111-1111-111111111111/removal-tasks/report", strings.NewReader(`{"reports":[]}`))
	req = drWithDeviceID(req, "11111111-1111-1111-1111-111111111111")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 with no bearer, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DB-backed admin lifecycle test
// ---------------------------------------------------------------------------

func TestDeviceRemovalsAdminLifecycle(t *testing.T) {
	pool := drConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := drSeedTenant(t, ctx, pool, "pat781-lifecycle")
	deviceID := drSeedDevice(t, ctx, pool, tenantID)

	// 1. Queue a removal → 201 with a task in state 'queued'.
	createH := DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility(pool)
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"app_name":"Zoom"}`))
	req = drWithDeviceID(req, deviceID)
	w := httptest.NewRecorder()
	createH(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("queue: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var first removalTaskJSON
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}
	if first.State != "queued" || first.AppName != "Zoom" || first.TaskID == "" {
		t.Fatalf("unexpected task: %+v", first)
	}
	if !first.ExpiresAt.After(first.QueuedAt) {
		t.Fatalf("expires_at %v must be after queued_at %v", first.ExpiresAt, first.QueuedAt)
	}

	// 2. Re-queue the same app → idempotent, returns the SAME task, 200 not 201.
	req = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"app_name":"Zoom"}`))
	req = drWithDeviceID(req, deviceID)
	w = httptest.NewRecorder()
	createH(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("re-queue: want 200 (idempotent), got %d (%s)", w.Code, w.Body.String())
	}
	var second removalTaskJSON
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode re-queue resp: %v", err)
	}
	if second.TaskID != first.TaskID {
		t.Fatalf("idempotent re-queue should return same task: %s != %s", second.TaskID, first.TaskID)
	}

	// 3. List → exactly one task.
	listH := DeviceRemovalsListHandler(pool)
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req = drWithDeviceID(req, deviceID)
	w = httptest.NewRecorder()
	listH(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	var listResp removalTasksResp
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Tasks) != 1 {
		t.Fatalf("want 1 task after idempotent re-queue, got %d", len(listResp.Tasks))
	}

	// 4. Cancel the queued task → 204.
	cancelH := DeviceRemovalsCancelHandler(pool)
	req = httptest.NewRequest(http.MethodDelete, "/x", nil)
	req = drWithDeviceTask(req, deviceID, first.TaskID)
	w = httptest.NewRecorder()
	cancelH(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("cancel: want 204, got %d (%s)", w.Code, w.Body.String())
	}

	// 5. List again → cancelled task is excluded.
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req = drWithDeviceID(req, deviceID)
	w = httptest.NewRecorder()
	listH(w, req)
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list-2: %v", err)
	}
	if len(listResp.Tasks) != 0 {
		t.Fatalf("want 0 tasks after cancel, got %d", len(listResp.Tasks))
	}

	// 6. Cancelling again → 404 (no longer cancellable).
	req = httptest.NewRequest(http.MethodDelete, "/x", nil)
	req = drWithDeviceTask(req, deviceID, first.TaskID)
	w = httptest.NewRecorder()
	cancelH(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("double-cancel: want 404, got %d", w.Code)
	}

	// 7. After cancel, the same app can be queued afresh (partial unique index
	//    excludes cancelled rows) → 201 with a NEW task id.
	req = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"app_name":"Zoom"}`))
	req = drWithDeviceID(req, deviceID)
	w = httptest.NewRecorder()
	createH(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("re-queue after cancel: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var third removalTaskJSON
	if err := json.Unmarshal(w.Body.Bytes(), &third); err != nil {
		t.Fatalf("decode third: %v", err)
	}
	if third.TaskID == first.TaskID {
		t.Fatalf("re-queue after cancel should mint a new task id")
	}
}

// TestDeviceRemovalsCreateDeviceNotFound verifies a well-formed request for a
// non-existent device returns 404, not a 500.
func TestDeviceRemovalsCreateDeviceNotFound(t *testing.T) {
	pool := drConnectOrSkip(t)
	defer pool.Close()

	h := DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility(pool)
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"app_name":"Zoom"}`))
	req = drWithDeviceID(req, "22222222-2222-2222-2222-222222222222")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown device, got %d (%s)", w.Code, w.Body.String())
	}
}
