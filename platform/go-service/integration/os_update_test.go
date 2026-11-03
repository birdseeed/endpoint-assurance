//go:build integration

package integration

// PAT-2123: the Windows agent is moving to omitting (or null-ing)
// os_update.target_os when Windows Update reports a pending OS update before
// WUA has resolved which build it is updating to, rather than inventing a
// placeholder version. This test proves the real ingest -> extractor ->
// storage -> rollup path accepts that shape end to end:
//
//  1. POST /v1/inventory with os_update.state=update_required and no
//     target_os key at all returns 200, not 400.
//  2. The extracted device_os_update row stores target_os = NULL and
//     state = "update_required".
//  3. report.FetchOSUpdateStatus buckets the device as behind (and, since
//     this report also carries security_relevant=true, behind-security),
//     never current and never not-reported.
//
// Before this ticket's validate.go change, os_update.target_os was a
// required, non-nullable string (internal/extractor/validate.go), so this
// exact payload was rejected with 400 by ValidatePayload — see the
// red-proof note on windowsOSUpdatePendingPayload below.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
	"patched.im/api/internal/report"
)

// windowsOSUpdatePendingPayload builds a minimal valid schema_version=2
// Windows-flavoured payload carrying an os_update block with
// state=update_required, security_relevant=true, and target_os OMITTED
// entirely — the exact shape the updated Windows agent sends when WUA
// reports a pending update before it has resolved the target build.
//
// Against origin/main (before this ticket), ValidatePayload rejects this
// payload with a 400 because os_update.target_os was in the required list
// and type-checked as a plain string: the omitted key fails
// schemaCheckRequired before target_os's own type check is ever reached.
func windowsOSUpdatePendingPayload(hwUUID, serial, hostname string, collectedAt time.Time) []byte {
	payload := map[string]any{
		"schema_version": 2,
		"agent":          "patched-collect-win",
		"agent_version":  "0.20.0",
		"tenant_id":      "00000000-0000-0000-0000-000000000000", // informational only; real tenant comes from bearer auth
		"collected_at":   collectedAt.Format(time.RFC3339),
		"device": map[string]any{
			"serial":    serial,
			"hw_uuid":   hwUUID,
			"hostname":  hostname,
			"hw_model":  "Dell OptiPlex 7090",
			"arch":      "x86_64",
			"last_boot": collectedAt.Format(time.RFC3339),
		},
		"hardware": map[string]any{
			"cpu_model":     "Intel Core i7-11700",
			"cpu_cores":     8,
			"ram_gb":        16,
			"disk_total_gb": 512.0,
			"disk_free_gb":  200.0,
		},
		"os": map[string]any{
			"name":    "Windows",
			"version": "10.0.19045",
			"build":   "19045.4529",
		},
		"compliance":        map[string]any{},
		"security_tools":    []any{},
		"system_extensions": []any{},
		"background_items":  []any{},
		"icloud":            map[string]any{"signed_in": "Unknown"},
		"apps": []any{
			map[string]any{"name": "Notepad++", "version": "8.6", "bundle_id": "notepadplusplus"},
		},
		// target_os deliberately absent — the whole point of this fixture.
		"os_update": map[string]any{
			"installed_os":        "10.0.19045",
			"state":               "update_required",
			"severity":            "high",
			"security_relevant":   true,
			"actively_exploited":  false,
			"deferrals_remaining": 0,
			"checked_at":          collectedAt.Format(time.RFC3339),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic("marshal windows os_update pending payload: " + err.Error())
	}
	return body
}

// TestInventory_OSUpdate_TargetOSAbsent_PendingUpdate_AcceptedAndBucketedBehind
// is the PAT-2123 acceptance test described in the file header.
func TestInventory_OSUpdate_TargetOSAbsent_PendingUpdate_AcceptedAndBucketedBehind(t *testing.T) {
	ctx := context.Background()

	tenantID, bearerToken, hmacSecret, err := createTestTenant(env.internalSrv.URL, "pat2123-os-update-pending")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	now := time.Now().UTC().Truncate(time.Second)
	const hwUUID = "CCCCCCCC-1111-2222-3333-444444444444"
	body := windowsOSUpdatePendingPayload(hwUUID, "PAT2123SERIAL", "pat2123-win-host", now)

	req := signedInventoryRequestWithAuth(t, bearerToken, hmacSecret, body)
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory with os_update.target_os absent: want 200, got %d: %s", resp.StatusCode, raw)
	}

	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	// device_os_update: target_os must be NULL, state must be
	// "update_required" — never a crash, never an invented placeholder.
	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		SELECT d.id::text FROM devices d
		WHERE d.tenant_id = $1::uuid AND d.hw_uuid = $2
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("find extracted device: %v", err)
	}

	var gotState string
	var gotTargetOS *string
	var gotSecurityRelevant bool
	if err := env.pool.QueryRow(ctx, `
		SELECT state, target_os, security_relevant
		FROM device_os_update WHERE device_id = $1::uuid
	`, deviceID).Scan(&gotState, &gotTargetOS, &gotSecurityRelevant); err != nil {
		t.Fatalf("select device_os_update: %v", err)
	}
	if gotState != "update_required" {
		t.Errorf("state = %q, want \"update_required\"", gotState)
	}
	if gotTargetOS != nil {
		t.Errorf("target_os = %q, want NULL", *gotTargetOS)
	}
	if !gotSecurityRelevant {
		t.Error("security_relevant = false, want true")
	}

	// Rollup: a state of "update_required" (anything other than
	// "up_to_date") must bucket as behind, and — since the report also
	// carries security_relevant=true — as behind-security too. It must never
	// land in current or not-reported: FetchOSUpdateStatus keys entirely off
	// state, never target_os, so target_os being NULL must not perturb this.
	status, err := report.FetchOSUpdateStatus(ctx, env.pool, tenantID)
	if err != nil {
		t.Fatalf("FetchOSUpdateStatus: %v", err)
	}
	if status.DevicesCurrent != 0 {
		t.Errorf("DevicesCurrent = %d, want 0", status.DevicesCurrent)
	}
	if status.DevicesBehind != 1 {
		t.Errorf("DevicesBehind = %d, want 1", status.DevicesBehind)
	}
	if status.DevicesBehindSecurityRelevant != 1 {
		t.Errorf("DevicesBehindSecurityRelevant = %d, want 1", status.DevicesBehindSecurityRelevant)
	}
	if status.DevicesNotReported != 0 {
		t.Errorf("DevicesNotReported = %d, want 0", status.DevicesNotReported)
	}
}
