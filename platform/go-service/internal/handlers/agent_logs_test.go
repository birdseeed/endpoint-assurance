package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// -- helpers ------------------------------------------------------------------

func alWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func alWithTenantDeviceAndRequest(r *http.Request, tenantID, deviceID, requestID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	rctx.URLParams.Add("deviceID", deviceID)
	rctx.URLParams.Add("requestID", requestID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

const (
	alTestTenantID  = "b3a1e2c4-d5f6-7a8b-9c0d-e1f2a3b4c5d6"
	alTestDeviceID  = "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6"
	alTestRequestID = "f1e2d3c4-b5a6-7f8e-9d0c-b1a2c3d4e5f6"
)

func alOKAuthFn(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
	return alTestTenantID, alTestDeviceID, nil
}

func alOKExistsFn(ctx context.Context, tenantID string) (bool, error) {
	return true, nil
}

// -- POST /v1/agent-logs tests ------------------------------------------------

func TestAgentLogsIngestStored(t *testing.T) {
	bundle := []byte("fake-gzip-bundle")
	var storedBundle []byte
	var storedTenant, storedDevice, storedRequest string

	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, b []byte) (int64, bool, error) {
		storedTenant = tenantID
		storedDevice = deviceID
		storedRequest = requestID
		storedBundle = b
		return 42, true, nil
	}

	h := newAgentLogsHandler(alOKAuthFn, ingestFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", bytes.NewReader(bundle))
	req.Header.Set("X-Patched-Log-Request-ID", alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if storedTenant != alTestTenantID {
		t.Errorf("want tenant %q, got %q", alTestTenantID, storedTenant)
	}
	if storedDevice != alTestDeviceID {
		t.Errorf("want device %q, got %q", alTestDeviceID, storedDevice)
	}
	if storedRequest != alTestRequestID {
		t.Errorf("want request_id %q, got %q", alTestRequestID, storedRequest)
	}
	if !bytes.Equal(storedBundle, bundle) {
		t.Error("stored bundle does not match uploaded body")
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["stored"] != true {
		t.Errorf("want stored=true in response, got %v", resp["stored"])
	}
}

func TestAgentLogsIngestIdempotent(t *testing.T) {
	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, b []byte) (int64, bool, error) {
		return 7, false, nil // already exists
	}

	h := newAgentLogsHandler(alOKAuthFn, ingestFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader("bundle"))
	req.Header.Set("X-Patched-Log-Request-ID", alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["stored"] != false {
		t.Errorf("want stored=false for idempotent re-upload, got %v", resp["stored"])
	}
}

func TestAgentLogsAuthFailure(t *testing.T) {
	badAuthFn := func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
		return "", "", errors.New("bad token")
	}
	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, b []byte) (int64, bool, error) {
		t.Fatal("ingestFn must not be called after auth failure")
		return 0, false, nil
	}

	h := newAgentLogsHandler(badAuthFn, ingestFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader("bundle"))
	req.Header.Set("X-Patched-Log-Request-ID", alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestAgentLogsMissingRequestID(t *testing.T) {
	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, b []byte) (int64, bool, error) {
		t.Fatal("ingestFn must not be called with missing request_id")
		return 0, false, nil
	}

	h := newAgentLogsHandler(alOKAuthFn, ingestFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader("bundle"))
	// no X-Patched-Log-Request-ID header
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing request_id, got %d", w.Code)
	}
}

func TestAgentLogsInvalidRequestID(t *testing.T) {
	h := newAgentLogsHandler(alOKAuthFn,
		func(ctx context.Context, a, b, c string, d []byte) (int64, bool, error) { return 0, false, nil },
		nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader("bundle"))
	req.Header.Set("X-Patched-Log-Request-ID", "not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid request_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAgentLogsEmptyBody(t *testing.T) {
	h := newAgentLogsHandler(alOKAuthFn,
		func(ctx context.Context, a, b, c string, d []byte) (int64, bool, error) { return 0, false, nil },
		nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader(""))
	req.Header.Set("X-Patched-Log-Request-ID", alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty body, got %d", w.Code)
	}
}

func TestAgentLogsCeilingExceeded(t *testing.T) {
	// Simulate ingestFn returning ErrLogCeilingExceeded (ceiling is now checked atomically inside dbIngestAgentLog).
	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, b []byte) (int64, bool, error) {
		return 0, false, ErrLogCeilingExceeded
	}

	h := newAgentLogsHandler(alOKAuthFn, ingestFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader("bundle"))
	req.Header.Set("X-Patched-Log-Request-ID", alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 when ceiling exceeded, got %d", w.Code)
	}
}

func TestAgentLogsIngestError(t *testing.T) {
	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, b []byte) (int64, bool, error) {
		return 0, false, errors.New("db down")
	}

	h := newAgentLogsHandler(alOKAuthFn, ingestFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-logs", strings.NewReader("bundle"))
	req.Header.Set("X-Patched-Log-Request-ID", alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on ingest error, got %d", w.Code)
	}
}

// -- GET /admin/tenants/{tenantID}/agent-logs tests ---------------------------

func TestAdminAgentLogsListOK(t *testing.T) {
	items := []agentLogMeta{
		{ID: 1, DeviceID: alTestDeviceID, RequestID: alTestRequestID,
			ReceivedAt: time.Now().UTC(), BundleSizeBytes: 1024},
	}
	listFn := func(ctx context.Context, tenantID string) ([]agentLogMeta, error) {
		return items, nil
	}

	h := newAdminAgentLogsListHandler(alOKExistsFn, listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+alTestTenantID+"/agent-logs", nil)
	req = alWithTenantID(req, alTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	logs, ok := resp["logs"].([]any)
	if !ok || len(logs) != 1 {
		t.Errorf("want 1 item in logs, got %v", resp["logs"])
	}
}

func TestAdminAgentLogsListEmpty(t *testing.T) {
	listFn := func(ctx context.Context, tenantID string) ([]agentLogMeta, error) {
		return nil, nil
	}

	h := newAdminAgentLogsListHandler(alOKExistsFn, listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+alTestTenantID+"/agent-logs", nil)
	req = alWithTenantID(req, alTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	logs, ok := resp["logs"].([]any)
	if !ok {
		t.Fatalf("logs field should be an array, got %T", resp["logs"])
	}
	if len(logs) != 0 {
		t.Errorf("want empty array, got %v", logs)
	}
}

func TestAdminAgentLogsListUnknownTenant(t *testing.T) {
	notFoundFn := func(ctx context.Context, tenantID string) (bool, error) {
		return false, nil
	}
	listFn := func(ctx context.Context, tenantID string) ([]agentLogMeta, error) {
		t.Fatal("listFn must not be called for unknown tenant")
		return nil, nil
	}

	h := newAdminAgentLogsListHandler(notFoundFn, listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+alTestTenantID+"/agent-logs", nil)
	req = alWithTenantID(req, alTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestAdminAgentLogsListInvalidTenantID(t *testing.T) {
	h := newAdminAgentLogsListHandler(alOKExistsFn,
		func(ctx context.Context, tenantID string) ([]agentLogMeta, error) { return nil, nil })
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/bad/agent-logs", nil)
	req = alWithTenantID(req, "bad-not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// -- GET /admin/tenants/{tenantID}/agent-logs/{deviceID}/{requestID} tests ----

func TestAdminAgentLogFetchOK(t *testing.T) {
	bundle := []byte("gzip-bundle-bytes")
	fetchFn := func(ctx context.Context, tenantID, deviceID, requestID string) ([]byte, error) {
		return bundle, nil
	}

	h := newAdminAgentLogFetchHandler(alOKExistsFn, fetchFn)
	req := httptest.NewRequest(http.MethodGet,
		"/admin/tenants/"+alTestTenantID+"/agent-logs/"+alTestDeviceID+"/"+alTestRequestID, nil)
	req = alWithTenantDeviceAndRequest(req, alTestTenantID, alTestDeviceID, alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), bundle) {
		t.Error("response body does not match stored bundle")
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/octet-stream" {
		t.Errorf("want Content-Type application/octet-stream, got %q", ct)
	}
}

func TestAdminAgentLogFetchNotFound(t *testing.T) {
	fetchFn := func(ctx context.Context, tenantID, deviceID, requestID string) ([]byte, error) {
		return nil, nil // bundle doesn't exist
	}

	h := newAdminAgentLogFetchHandler(alOKExistsFn, fetchFn)
	req := httptest.NewRequest(http.MethodGet,
		"/admin/tenants/"+alTestTenantID+"/agent-logs/"+alTestDeviceID+"/"+alTestRequestID, nil)
	req = alWithTenantDeviceAndRequest(req, alTestTenantID, alTestDeviceID, alTestRequestID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestAdminAgentLogFetchInvalidRequestID(t *testing.T) {
	h := newAdminAgentLogFetchHandler(alOKExistsFn,
		func(ctx context.Context, a, b, c string) ([]byte, error) {
			t.Fatal("fetchFn must not be called for invalid requestID")
			return nil, nil
		})
	req := httptest.NewRequest(http.MethodGet,
		"/admin/tenants/"+alTestTenantID+"/agent-logs/"+alTestDeviceID+"/bad", nil)
	req = alWithTenantDeviceAndRequest(req, alTestTenantID, alTestDeviceID, "bad-not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// -- POST /admin/agent-logs/purge tests ---------------------------------------

func TestAdminAgentLogsPurge(t *testing.T) {
	var calledDays int
	purgeFn := func(_ context.Context, days int) (int64, error) {
		calledDays = days
		return 5, nil
	}
	h := newAdminAgentLogsPurgeHandler(purgeFn)
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-logs/purge?days=30", nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if calledDays != 30 {
		t.Errorf("want days=30, got %d", calledDays)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp["deleted"].(float64) != 5 {
		t.Errorf("want deleted=5, got %v", resp["deleted"])
	}
}

func TestAdminAgentLogsPurgeDefaultDays(t *testing.T) {
	var calledDays int
	purgeFn := func(_ context.Context, days int) (int64, error) {
		calledDays = days
		return 0, nil
	}
	h := newAdminAgentLogsPurgeHandler(purgeFn)
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-logs/purge", nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if calledDays != 90 {
		t.Errorf("want default days=90, got %d", calledDays)
	}
}

func TestAdminAgentLogsPurgeInvalidDays(t *testing.T) {
	purgeFn := func(_ context.Context, days int) (int64, error) {
		t.Fatal("purgeFn must not be called for invalid days")
		return 0, nil
	}
	h := newAdminAgentLogsPurgeHandler(purgeFn)
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-logs/purge?days=bad", nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}
