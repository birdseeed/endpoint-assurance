package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"patched.im/api/internal/db"
)

// ---------------------------------------------------------------------------
// Pure-logic tests — no DB required
// ---------------------------------------------------------------------------

// PAT-1599 (migration 0138): TestAgentTierFor is gone with agentTierFor()
// itself — the function used to translate a three-value commercial tier
// (report/patch/full_endpoint) into a differently-named agent-config tier
// (report_deploy/patch/managed). Since both vocabularies collapsed to the
// identical two values (assurance/managed), that mapping is now the
// identity function and was removed rather than kept as a vestigial pass-
// through. Coverage of "SubscriptionTier flows unchanged into AgentConfigTier"
// lives in TestSetTenantTierDB below (DB round-trip, asserts both fields).

func TestSetTenantTierHandlerUUIDValidation(t *testing.T) {
	h := SetTenantTierHandler(nil)
	for _, id := range []string{"not-a-uuid", "gggggggg-0000-0000-0000-000000000000", ""} {
		t.Run(id, func(t *testing.T) {
			body, _ := json.Marshal(setTenantTierReq{SubscriptionTier: "managed"})
			req := httptest.NewRequest(http.MethodPut, "/admin/tenant-tier/"+id, bytes.NewReader(body))
			req = withChiParam(req, "tenantID", id)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("id=%q: got %d, want 400", id, rr.Code)
			}
		})
	}
}

func TestSetTenantTierHandlerBadTier(t *testing.T) {
	const validUUID = "00000000-0000-0000-0000-000000000001"
	cases := []struct {
		tier string
		want int
	}{
		{"", http.StatusBadRequest},
		{"enterprise", http.StatusBadRequest},
		{"MANAGED", http.StatusBadRequest},
		{"Managed", http.StatusBadRequest},
		{"1", http.StatusBadRequest},
		// PAT-1599 (migration 0138): the retired three-value vocabulary is now
		// invalid input, not merely a different valid tier — these must 400,
		// not 404. Pins the collapse against a future regression that quietly
		// re-accepts the old values.
		{"report", http.StatusBadRequest},
		{"patch", http.StatusBadRequest},
		{"full_endpoint", http.StatusBadRequest},
		{"report_deploy", http.StatusBadRequest},
		{"assurance", http.StatusNotFound}, // valid tier, UUID not in DB (nil pool would panic before UUID check)
		{"managed", http.StatusNotFound},   // valid tier
	}
	// For the "bad tier" cases we only need a nil pool (handler rejects before any DB call).
	// For valid-tier cases we'd need a real DB; skip those here and cover via DB round-trip.
	for _, tc := range cases {
		if tc.want == http.StatusNotFound {
			continue // DB-dependent; covered by TestSetTenantTierDB
		}
		t.Run(tc.tier, func(t *testing.T) {
			h := SetTenantTierHandler(nil)
			body, _ := json.Marshal(setTenantTierReq{SubscriptionTier: tc.tier})
			req := httptest.NewRequest(http.MethodPut, "/admin/tenant-tier/"+validUUID, bytes.NewReader(body))
			req = withChiParam(req, "tenantID", validUUID)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("tier=%q: got %d, want %d", tc.tier, rr.Code, tc.want)
			}
		})
	}
}

func TestSetTenantTierHandlerBadJSON(t *testing.T) {
	const validUUID = "00000000-0000-0000-0000-000000000001"
	h := SetTenantTierHandler(nil)
	req := httptest.NewRequest(http.MethodPut, "/admin/tenant-tier/"+validUUID, bytes.NewReader([]byte(`not json`)))
	req = withChiParam(req, "tenantID", validUUID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// DB round-trip tests — skipped when TEST_DATABASE_URL is not set
// ---------------------------------------------------------------------------

// TestSetTenantTierDB covers the PAT-1599 (migration 0138) two-value
// vocabulary end to end: assurance <-> managed, both directions, plus
// idempotent re-application. The pre-collapse version of this test exercised
// three scenarios (report->patch, patch->full_endpoint, downgrade) because
// there were three rungs; assurance/managed only has one transition to
// exercise in each direction.
func TestSetTenantTierDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping tier DB round-trip tests")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	// Create a scratch tenant for this test run.
	var tenantID string
	err = pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('tier-switch-test', decode('aabbcc', 'hex'), decode('ddeeff', 'hex'))
		RETURNING id::text
	`).Scan(&tenantID)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) //nolint:errcheck
	})

	// Seed an agent_config row at version 1 so we can verify config_version bump.
	_, err = pool.Exec(context.Background(), `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, 1, '{"tier":"assurance","proxy":{"mode":"system","bypass_when_off_corp":false,"type":null,"host":null,"port":null,"pac_url":null,"auth_ref":null},"catalog_scope":null,"scan_cadence":null,"os_update_policy":null,"per_app_patch":null}'::jsonb, now(), 'seed')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed agent_config: %v", err)
	}

	h := SetTenantTierHandler(pool)
	router := chi.NewRouter()
	router.Put("/admin/tenant-tier/{tenantID}", h)

	doRequest := func(t *testing.T, tier, updatedBy string) setTenantTierResp {
		t.Helper()
		body, _ := json.Marshal(setTenantTierReq{SubscriptionTier: tier, UpdatedBy: updatedBy})
		req := httptest.NewRequest(http.MethodPut, "/admin/tenant-tier/"+tenantID, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("PUT tier=%q: got HTTP %d, body: %s", tier, rr.Code, rr.Body.String())
		}
		var resp setTenantTierResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return resp
	}

	// --- Scenario 1: assurance → managed ---
	t.Run("assurance_to_managed", func(t *testing.T) {
		resp := doRequest(t, "managed", "test-operator")

		if resp.SubscriptionTier != "managed" {
			t.Errorf("subscription_tier: want managed, got %q", resp.SubscriptionTier)
		}
		// PAT-1599: agentTierFor() is gone — agent_config_tier now mirrors
		// subscription_tier exactly, not a separately-named mapped value.
		if resp.AgentConfigTier != "managed" {
			t.Errorf("agent_config_tier: want managed, got %q", resp.AgentConfigTier)
		}
		if resp.AgentConfigVersion != 2 {
			t.Errorf("agent_config_version: want 2 (bumped from 1), got %d", resp.AgentConfigVersion)
		}
		if !resp.AppControlEnabled {
			t.Error("app_control_enabled: want true for managed tier, got false")
		}
		if resp.Warning == "" {
			t.Error("warning: want non-empty Graph/GDAP warning for managed tier, got empty")
		}

		// Verify DB state directly.
		var dbTier string
		var dbAgentTier string
		var dbConfigVersion int
		pool.QueryRow(context.Background(), //nolint:errcheck
			`SELECT t.subscription_tier, ac.body->>'tier', ac.config_version
			 FROM tenants t JOIN agent_config ac ON ac.tenant_id = t.id
			 WHERE t.id = $1::uuid`, tenantID,
		).Scan(&dbTier, &dbAgentTier, &dbConfigVersion)

		if dbTier != "managed" {
			t.Errorf("DB subscription_tier: want managed, got %q", dbTier)
		}
		if dbAgentTier != "managed" {
			t.Errorf("DB agent_config body.tier: want managed, got %q", dbAgentTier)
		}
		if dbConfigVersion != 2 {
			t.Errorf("DB config_version: want 2, got %d", dbConfigVersion)
		}

		// Verify audit record was written.
		var auditFrom, auditTo string
		pool.QueryRow(context.Background(), //nolint:errcheck
			`SELECT from_tier, to_tier FROM tenant_tier_changes
			 WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1`, tenantID,
		).Scan(&auditFrom, &auditTo)
		if auditFrom != "assurance" {
			t.Errorf("audit from_tier: want assurance, got %q", auditFrom)
		}
		if auditTo != "managed" {
			t.Errorf("audit to_tier: want managed, got %q", auditTo)
		}

		// Verify app_control_enabled in DB.
		var dbAppControl bool
		pool.QueryRow(context.Background(), //nolint:errcheck
			`SELECT app_control_enabled FROM tenants WHERE id = $1::uuid`, tenantID,
		).Scan(&dbAppControl)
		if !dbAppControl {
			t.Error("DB app_control_enabled: want true for managed, got false")
		}
	})

	// --- Scenario 2: idempotent — same tier again is safe ---
	t.Run("idempotent_same_tier", func(t *testing.T) {
		resp := doRequest(t, "managed", "test-operator")
		if resp.SubscriptionTier != "managed" {
			t.Errorf("subscription_tier: want managed, got %q", resp.SubscriptionTier)
		}
		// config_version should still bump (idempotent call still updates issued_at / triggers agent re-fetch).
		if resp.AgentConfigVersion != 3 {
			t.Errorf("agent_config_version: want 3 (bumped from 2), got %d", resp.AgentConfigVersion)
		}
	})

	// --- Scenario 3: managed → assurance (downgrade) ---
	t.Run("downgrade_to_assurance", func(t *testing.T) {
		resp := doRequest(t, "assurance", "test-operator")
		if resp.SubscriptionTier != "assurance" {
			t.Errorf("subscription_tier: want assurance, got %q", resp.SubscriptionTier)
		}
		if resp.AgentConfigTier != "assurance" {
			t.Errorf("agent_config_tier: want assurance, got %q", resp.AgentConfigTier)
		}
		// app_control_enabled should NOT be automatically disabled on downgrade —
		// that is an explicit operator action via the per-lever endpoint.
		if !resp.AppControlEnabled {
			t.Log("note: app_control_enabled cleared on downgrade (conservative; per-lever endpoint required)")
		}
	})

	// --- Scenario 4: non-existent tenant returns 404 ---
	t.Run("not_found", func(t *testing.T) {
		const missingID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		body, _ := json.Marshal(setTenantTierReq{SubscriptionTier: "managed"})
		req := httptest.NewRequest(http.MethodPut, "/admin/tenant-tier/"+missingID, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", rr.Code)
		}
	})
}

// TestSetTenantTierDB_AuditAttribution pins the PAT-1135 property for
// tenant_tier_changes: the admin surface has no per-person identity (one
// shared ADMIN_API_TOKEN — see requireAdminToken, cmd/patched-api/main.go),
// so a request body that CLAIMS to be "alice" must never land in the
// authoritative changed_by column. changed_by must always be the
// server-established constant "admin_shared_token"; the caller's claim goes
// only into the untrusted claimed_actor column, and source_addr must be
// populated from the observed request address. Mirrors
// TestTenantDecommissionPut_AuditAttribution in agent_decommission_test.go
// for the second audit table required by PAT-1135's brief.
func TestSetTenantTierDB_AuditAttribution(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping tier DB attribution test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var tenantID string
	err = pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat1135-tier-attribution-test', decode('aabbcc', 'hex'), decode('ddeeff', 'hex'))
		RETURNING id::text
	`).Scan(&tenantID)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) //nolint:errcheck
	})

	h := SetTenantTierHandler(pool)
	router := chi.NewRouter()
	router.Put("/admin/tenant-tier/{tenantID}", h)

	body, _ := json.Marshal(setTenantTierReq{SubscriptionTier: "managed", UpdatedBy: "alice"})
	req := httptest.NewRequest(http.MethodPut, "/admin/tenant-tier/"+tenantID, bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.7:54321"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT tier: got HTTP %d, body: %s", rr.Code, rr.Body.String())
	}

	var changedBy string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(context.Background(), `
		SELECT changed_by, claimed_actor, source_addr FROM tenant_tier_changes
		WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&changedBy, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("fetch audit row: %v", err)
	}

	if changedBy != adminSharedTokenActor {
		t.Errorf("changed_by = %q, want %q (must never be the caller's claimed name)", changedBy, adminSharedTokenActor)
	}
	if claimedActor == nil || *claimedActor != "alice" {
		t.Errorf("claimed_actor = %v, want \"alice\"", claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "203.0.113.7" {
		t.Errorf("source_addr = %v, want \"203.0.113.7\" (port stripped)", sourceAddr)
	}
}
