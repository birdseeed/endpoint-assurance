package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOpsMaintenanceHandler_MissingFile covers the "unconfigured" contract
// when patched-maintenance-facts.sh has never run on this box (or the timer
// hasn't fired yet since a fresh deploy): HTTP 200, a top-level "error" key,
// generated_at null.
func TestOpsMaintenanceHandler_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")

	rr := httptest.NewRecorder()
	OpsMaintenanceHandler(path)(rr, httptest.NewRequest(http.MethodGet, "/admin/ops/maintenance", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp opsMaintenanceErrorResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("want a non-empty error, got %+v", resp)
	}
	if resp.GeneratedAt != nil {
		t.Fatalf("want generated_at null for a missing file, got %q", *resp.GeneratedAt)
	}
}

// TestOpsMaintenanceHandler_PresentAndFresh covers the healthy path: the
// file exists with a recent generated_at, and the handler must pass its
// bytes through verbatim (not re-marshal, not drop unknown fields).
func TestOpsMaintenanceHandler_PresentAndFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	body := `{"generated_at":"` + time.Now().UTC().Format(time.RFC3339) + `","hostname":"patched-api-01","pending_updates":17,"security_updates":0,"esm_updates":null,"pro_attached":false,"reboot_required":true,"running_kernel":"6.8.0-124-generic","newest_kernel":"6.8.0-136-generic","automatic_reboot_configured":false,"third_party_pending":[{"package":"tailscale","installed":"1.98.4","candidate":"1.102.2","origin":"pkgs.tailscale.com"}],"timers":[{"unit":"patched-backup.timer","enabled":"enabled","last_trigger":"2026-08-06T03:10:34Z","last_result":"success"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	rr := httptest.NewRecorder()
	OpsMaintenanceHandler(path)(rr, httptest.NewRequest(http.MethodGet, "/admin/ops/maintenance", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if rr.Body.String() != body {
		t.Fatalf("want verbatim passthrough:\n got:  %s\n want: %s", rr.Body.String(), body)
	}
	// Sanity: the passthrough body must NOT parse as the error shape (no
	// "error" key), so a consumer's `"error" in response` check works.
	var probe map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &probe); err != nil {
		t.Fatalf("decode passthrough body: %v", err)
	}
	if _, hasError := probe["error"]; hasError {
		t.Fatalf("healthy passthrough must not contain an 'error' key: %+v", probe)
	}
}

// TestOpsMaintenanceHandler_Stale covers a snapshot whose generated_at is
// older than opsMaintenanceStaleAfter — e.g. the timer stopped firing.
// Unlike the missing/unparseable cases, generated_at in the response carries
// the original (stale) value rather than null, per the documented contract.
func TestOpsMaintenanceHandler_Stale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	staleAt := time.Now().UTC().Add(-6 * time.Hour).Format(time.RFC3339)
	body := `{"generated_at":"` + staleAt + `","hostname":"patched-api-01","pending_updates":3,"security_updates":0,"esm_updates":null,"pro_attached":false,"reboot_required":false,"running_kernel":"6.8.0-124-generic","newest_kernel":"6.8.0-124-generic","automatic_reboot_configured":false,"third_party_pending":[],"timers":[]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	rr := httptest.NewRecorder()
	OpsMaintenanceHandler(path)(rr, httptest.NewRequest(http.MethodGet, "/admin/ops/maintenance", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp opsMaintenanceErrorResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("want a non-empty error for a stale snapshot, got %+v", resp)
	}
	if resp.GeneratedAt == nil || *resp.GeneratedAt != staleAt {
		t.Fatalf("want generated_at to carry the original stale value %q, got %+v", staleAt, resp.GeneratedAt)
	}
}

// TestOpsMaintenanceHandler_Unparseable covers a corrupt/truncated file
// (e.g. the emitter was killed mid-write outside its atomic tmp+mv path, or
// disk filled up) — must degrade the same way as a missing file rather than
// 500ing or serving garbage.
func TestOpsMaintenanceHandler_Unparseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	if err := os.WriteFile(path, []byte(`{"generated_at": "2026-08-06T13:00:`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	rr := httptest.NewRecorder()
	OpsMaintenanceHandler(path)(rr, httptest.NewRequest(http.MethodGet, "/admin/ops/maintenance", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp opsMaintenanceErrorResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("want a non-empty error for unparseable JSON, got %+v", resp)
	}
	if resp.GeneratedAt != nil {
		t.Fatalf("want generated_at null for unparseable JSON, got %q", *resp.GeneratedAt)
	}
}
