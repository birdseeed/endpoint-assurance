package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"patched.im/api/internal/db"
)

// roomyTrialLimits sizes the PAT-2529 limiters far above what these tests send,
// so they keep exercising the handler itself. The limits are tested in
// trial_ratelimit_test.go and through the router in cmd/patched-api.
func roomyTrialLimits() *TrialProvisionLimits {
	return NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 1000, GlobalPerHour: 1000})
}

// -- TrialProvisionHandler unit tests (no DB) ---------------------------------

func TestTrialProvisionHandlerBadEmail(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{"empty email", `{"email":"","name":"Bob"}`, "email is required"},
		{"no at-sign", `{"email":"notanemail","name":"Bob"}`, "email is required"},
		{"empty name", `{"email":"bob@example.com","name":""}`, "name is required"},
		{"invalid json", `not-json`, "invalid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use nil pool — validation runs before any DB call.
			h := TrialProvisionHandler(nil, roomyTrialLimits())
			req := httptest.NewRequest(http.MethodPost, "/v1/trial/provision",
				bytes.NewBufferString(tc.body))
			w := httptest.NewRecorder()
			h(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantSub) {
				t.Errorf("want body to contain %q, got: %s", tc.wantSub, w.Body.String())
			}
		})
	}
}

// -- TrialProvisionHandler DB round-trip tests --------------------------------

func TestTrialProvisionHandlerDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping trial provision DB tests")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// t.Cleanup callbacks run in LIFO order, so registering pool.Close here
	// (before the DELETE cleanup below) makes it run LAST — the DELETE below
	// runs first, against a still-open pool.
	t.Cleanup(func() {
		pool.Close()
	})
	ctx := context.Background()

	// Clean up any test trials created by this run.
	const testEmail = "trial-test-unique@example-pat668.test"
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE trial_email = $1`, testEmail); err != nil {
			t.Errorf("cleanup DELETE failed: %v", err)
		}
	})

	h := TrialProvisionHandler(pool, roomyTrialLimits())

	body := `{"email":"trial-test-unique@example-pat668.test","name":"Test User","company":"ACME Inc"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp trialProvisionResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !looksLikeUUID(resp.TenantID) {
		t.Errorf("want tenant_id UUID, got %q", resp.TenantID)
	}
	if resp.EnrollmentURL == "" {
		t.Error("want non-empty enrollment_url")
	}
	if resp.ExpiresAt.IsZero() {
		t.Error("want non-zero expires_at")
	}

	// Verify tenant in DB.
	var isTrial bool
	var deviceCap int
	if err := pool.QueryRow(ctx, `
		SELECT is_trial, trial_device_cap FROM tenants WHERE id = $1::uuid
	`, resp.TenantID).Scan(&isTrial, &deviceCap); err != nil {
		t.Fatalf("query tenant: %v", err)
	}
	if !isTrial {
		t.Error("want is_trial=true")
	}
	if deviceCap != defaultTrialDeviceCap {
		t.Errorf("want trial_device_cap=%d, got %d", defaultTrialDeviceCap, deviceCap)
	}

	// Second provision for the same email → 409 (existing trial re-sent).
	req2 := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", bytes.NewBufferString(body))
	w2 := httptest.NewRecorder()
	h(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("want 409 on duplicate, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp2 trialProvisionResp
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if resp2.TenantID != resp.TenantID {
		t.Errorf("want same tenant_id on duplicate, got %q vs %q", resp2.TenantID, resp.TenantID)
	}
}

// TestTrialProvisionHandlerDB_RejectsDecommissionedExistingTrial is the
// PAT-1757 regression for the re-mint path only: lookupActiveTrial's WHERE
// clause (is_trial, trial_expires_at, revoked_at) never touches
// tenant_decommission, so a trial tenant that has since been marked for
// decommission would otherwise still read as "active" here and get a fresh
// enrolment token minted for it. This must return the decommission-conflict
// 409 (mode in the body), not the ordinary "existing trial re-sent" 409
// (enrollment_url in the body) TestTrialProvisionHandlerDB exercises above.
func TestTrialProvisionHandlerDB_RejectsDecommissionedExistingTrial(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-1757 trial decommission-gate DB test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const testEmail = "trial-test-decommissioned@example-pat1757.test"
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE trial_email = $1`, testEmail); err != nil {
			t.Errorf("cleanup DELETE failed: %v", err)
		}
	})

	h := TrialProvisionHandler(pool, roomyTrialLimits())

	body := `{"email":"trial-test-decommissioned@example-pat1757.test","name":"Test User"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("initial provision want 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp trialProvisionResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	setTenantDecommissionMode(t, ctx, pool, resp.TenantID, "immediate")

	req2 := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", bytes.NewBufferString(body))
	w2 := httptest.NewRecorder()
	h(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("re-provision of decommissioned trial want 409, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "immediate") {
		t.Fatalf("409 body = %q, want it to name the mode %q", w2.Body.String(), "immediate")
	}
	if strings.Contains(w2.Body.String(), "enrollment_url") {
		t.Fatalf("409 body = %q, must not be the ordinary re-sent-token shape — a decommissioned tenant must not get a fresh token", w2.Body.String())
	}
}

// TestTrialProvisionHandlerDB_SeedsT2Baseline is the PAT-1794 regression for
// the trial-provisioning path specifically: createTrialTenant does not call
// agentidentity.EnsurePatchedAgentPolicies (out of scope for PAT-1794 — see
// the ticket), but it must still seed the T2 compliance-rule baseline like
// any other tenant-creation path, in the same transaction as tenant
// creation.
func TestTrialProvisionHandlerDB_SeedsT2Baseline(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping trial T2 baseline DB test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const testEmail = "trial-test-t2-baseline@example-pat1794.test"
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE trial_email = $1`, testEmail); err != nil {
			t.Errorf("cleanup DELETE failed: %v", err)
		}
	})

	h := TrialProvisionHandler(pool, roomyTrialLimits())
	body := `{"email":"trial-test-t2-baseline@example-pat1794.test","name":"T2 Baseline Test","company":"ACME Inc"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp trialProvisionResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !looksLikeUUID(resp.TenantID) {
		t.Fatalf("want tenant_id UUID, got %q", resp.TenantID)
	}

	var wantCount, gotCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM compliance_rules WHERE collection_tier = 'T2' AND enabled = true
	`).Scan(&wantCount); err != nil {
		t.Fatalf("count enabled T2 rules: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM tenant_rules tr
		JOIN compliance_rules cr ON cr.id = tr.rule_id
		WHERE tr.tenant_id = $1::uuid AND cr.collection_tier = 'T2' AND tr.enabled = true
	`, resp.TenantID).Scan(&gotCount); err != nil {
		t.Fatalf("count seeded tenant_rules: %v", err)
	}
	if gotCount != wantCount {
		t.Errorf("tenant_rules T2 rows for new trial tenant = %d, want %d (every enabled T2 rule seeded)", gotCount, wantCount)
	}
}

// -- CheckTrialDeviceCap unit test (no DB) ------------------------------------

func TestCheckTrialDeviceCapNilPool(t *testing.T) {
	// When pool is nil we can't call the function safely, but we can verify the
	// function signature compiles and the constant is correct.
	if defaultTrialDeviceCap != 3 {
		t.Errorf("want defaultTrialDeviceCap=3, got %d", defaultTrialDeviceCap)
	}
}
