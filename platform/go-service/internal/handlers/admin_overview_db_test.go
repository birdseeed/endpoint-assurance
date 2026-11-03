package handlers

// PAT-1007 handler-level test for GET /admin/devices/{deviceID}: proves
// outcome/failure_reason actually survive into the real HTTP JSON response,
// not just into report.Fetch/report.MergePatchHistory in isolation. Those
// two are already covered directly in internal/report/report_db_test.go and
// internal/report/report_test.go; this closes the gap a second-round review
// flagged — nothing previously exercised DeviceDetailHandler itself, so a
// future refactor that dropped these two fields on the way out to JSON
// (e.g. reverting to rep.PatchHistory instead of
// report.MergePatchHistory(rep.PatchHistory, rep.ProvenancePatchHistory))
// would have stayed fully green.
//
// DB-backed: requires TEST_DATABASE_URL against a fully-migrated schema, same
// convention as device_removals_test.go / ring_rollout_db_test.go /
// allowlist_agent_known_path_test.go in this package — reuses their
// parConnectOrSkip/parSeedTenant/rrInsertDeviceOS/rrInsertProvenance/
// drWithDeviceID helpers rather than inventing new ones.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDeviceDetailHandler_PatchHistoryCarriesOutcomeAndFailureReason drives
// the real handler over HTTP: one OS-patch row (patches table) and one
// failed third-party provenance row for the same device, then asserts the
// decoded JSON response's patch_history array carries outcome/failure_reason
// on the provenance-sourced entry, that it sorts before the OS-patch entry
// (newest first), and that the OS-patch entry's outcome/failure_reason keys
// are genuinely ABSENT from the JSON (omitempty), not merely empty strings —
// exactly today's unaffected OS-patch behavior.
func TestDeviceDetailHandler_PatchHistoryCarriesOutcomeAndFailureReason(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat1007-devicedetail-tenant", "pat1007-devicedetail-token", "pat1007-devicedetail-hmac-secret-32b!")

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	deviceID := rrInsertDeviceOS(t, pool, tenantID, hwUUID, 0, "macOS")

	now := time.Now().UTC()

	// OS-patch row: older, must stay outcome-less.
	if _, err := pool.Exec(ctx, `
		INSERT INTO patches (device_id, title, identifier, installed_at)
		VALUES ($1::uuid, 'macOS 15.5', 'macOS 15.5|15.5', $2)
	`, deviceID, now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("insert patch row: %v", err)
	}

	// Provenance row: newer, a FAILED third-party install with a real outcome.
	rrInsertProvenance(t, pool, tenantID, now, map[string]any{
		"record_type":    "third_party_update",
		"device":         map[string]any{"hw_uuid": hwUUID},
		"outcome":        "verification_failed",
		"failure_reason": "checksum mismatch",
		"app": map[string]any{
			"label":             "1password",
			"available_version": "8.10.0",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/devices/"+deviceID, nil)
	req = drWithDeviceID(req, deviceID)
	rr := httptest.NewRecorder()
	DeviceDetailHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		PatchHistory []map[string]any `json:"patch_history"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	if len(resp.PatchHistory) != 2 {
		t.Fatalf("len(patch_history) = %d, want 2: %+v", len(resp.PatchHistory), resp.PatchHistory)
	}

	// Newest first: the provenance row (now) before the OS-patch row (now-3h).
	prov := resp.PatchHistory[0]
	osRow := resp.PatchHistory[1]

	if got, want := prov["identifier"], "1password|8.10.0"; got != want {
		t.Errorf("patch_history[0].identifier = %v, want %v (full response: %+v)", got, want, resp.PatchHistory)
	}
	if got, want := prov["outcome"], "verification_failed"; got != want {
		t.Errorf("patch_history[0].outcome = %v, want %v — outcome must survive into the actual JSON response", got, want)
	}
	if got, want := prov["failure_reason"], "checksum mismatch"; got != want {
		t.Errorf("patch_history[0].failure_reason = %v, want %v — failure_reason must survive into the actual JSON response", got, want)
	}

	if got, want := osRow["identifier"], "macOS 15.5|15.5"; got != want {
		t.Errorf("patch_history[1].identifier = %v, want %v (full response: %+v)", got, want, resp.PatchHistory)
	}
	// omitempty: these keys must be genuinely ABSENT for an OS-patch row, not
	// present-and-empty — a stricter check than a decoded Go struct field
	// being "" would give, since an absent key and an empty string both
	// decode to the zero value there.
	if _, present := osRow["outcome"]; present {
		t.Errorf("patch_history[1] (OS-patch row) has an \"outcome\" key at all, want it absent (omitempty): %+v", osRow)
	}
	if _, present := osRow["failure_reason"]; present {
		t.Errorf("patch_history[1] (OS-patch row) has a \"failure_reason\" key at all, want it absent (omitempty): %+v", osRow)
	}
}
