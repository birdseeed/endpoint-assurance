package handlers

// admin_agentidentity_db_test.go — PAT-1318 DB-backed regression test:
// CreateTenantHandler seeds an 'approved' tenant_app_policies row for every
// Patched Agent identity (internal/agentidentity) on a brand-new tenant, and
// re-running the seeder for the same tenant creates no duplicate rows.
//
// DB-backed: requires TEST_DATABASE_URL and is skipped otherwise, reusing
// parConnectOrSkip (allowlist_agent_known_path_test.go) rather than
// inventing a new connect-or-skip helper.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentidentity"
)

func TestCreateTenantHandler_SeedsPatchedAgentPolicies(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	body := `{"name":"pat1318-create-tenant-test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", strings.NewReader(body))
	rr := httptest.NewRecorder()
	CreateTenantHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("CreateTenantHandler: got status %d, body %s", rr.Code, rr.Body.String())
	}
	var resp createTenantResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	tenantID := resp.TenantID
	if tenantID == "" {
		t.Fatal("createTenantResp.TenantID is empty")
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

	assertPatchedAgentPoliciesSeeded(t, ctx, pool, tenantID)

	// Re-running the seeder — simulating the extraction sweep converging the
	// same tenant on its next batch, or a retried/duplicate call for any
	// other reason — must not create duplicate rows: ON CONFLICT DO NOTHING
	// against the tenant_app_policies identity unique index
	// (0032_tenant_app_policies.sql:56-62).
	if err := agentidentity.EnsurePatchedAgentPolicies(ctx, pool, tenantID); err != nil {
		t.Fatalf("second EnsurePatchedAgentPolicies call: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND policy = 'approved'
	`, tenantID).Scan(&count); err != nil {
		t.Fatalf("count approved policies: %v", err)
	}
	if count != len(agentidentity.Identities) {
		t.Errorf("tenant_app_policies has %d approved rows after a duplicate seed call, want exactly %d (no duplicates created)", count, len(agentidentity.Identities))
	}
}

func TestEnsurePatchedAgentPoliciesHonoursLegacyArbiterWithWingetRow(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat1399-seed-legacy-arbiter','\x00','\x00') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenantID) })
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_app_policies(tenant_id,winget_id,name,platform,policy,enforcement_tier,notes)
		VALUES($1::uuid,'patched.agent','Patched Agent','windows','unmanaged','report_deploy','operator row')
	`, tenantID); err != nil {
		t.Fatal(err)
	}

	if err := agentidentity.EnsurePatchedAgentPolicies(ctx, pool, tenantID); err != nil {
		t.Fatalf("seed under retained legacy arbiter: %v", err)
	}
	var count int
	var policy string
	if err := pool.QueryRow(ctx, `
		SELECT count(*),min(policy) FROM tenant_app_policies
		WHERE tenant_id=$1::uuid AND platform='windows' AND lower(name)='patched agent'
	`, tenantID).Scan(&count, &policy); err != nil {
		t.Fatal(err)
	}
	if count != 1 || policy != "unmanaged" {
		t.Fatalf("seeder displaced operator Winget policy: count=%d policy=%q", count, policy)
	}
}

// assertPatchedAgentPoliciesSeeded checks that every entry in
// agentidentity.Identities has a matching approved tenant_app_policies row
// for tenantID — covering every identity in the canonical list (both
// platforms), not just one.
func assertPatchedAgentPoliciesSeeded(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	for _, id := range agentidentity.Identities {
		var policy, tier, notes, platform string
		err := pool.QueryRow(ctx, `
			SELECT policy, enforcement_tier, notes, platform
			FROM tenant_app_policies
			WHERE tenant_id = $1::uuid
			  AND COALESCE(team_id, '')   = $2
			  AND COALESCE(bundle_id, '') = $3
			  AND COALESCE(name, '')      = $4
			  AND platform = $5
		`, tenantID, id.TeamID, id.BundleID, id.Name, id.Platform).Scan(&policy, &tier, &notes, &platform)
		if err != nil {
			t.Fatalf("no tenant_app_policies row for identity %+v: %v", id, err)
		}
		if policy != "approved" {
			t.Errorf("identity %+v: policy = %q, want \"approved\"", id, policy)
		}
		if tier == "managed" {
			t.Errorf("identity %+v: enforcement_tier = \"managed\" — must never auto-seed the destructive-enforcement tier", id)
		}
		if notes == "" {
			t.Errorf("identity %+v: notes is empty, want the PAT-1318 seed marker", id)
		}
	}
}

// TestCreateTenantHandler_SeedsT2Baseline is the PAT-1794 regression:
// CreateTenantHandler must seed an enabled tenant_rules row for every
// enabled T2 compliance rule on a brand-new tenant, in the same transaction
// as tenant creation — mirroring the PAT-1318 Patched Agent policy seed
// tested above.
func TestCreateTenantHandler_SeedsT2Baseline(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	body := `{"name":"pat1794-create-tenant-t2-test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", strings.NewReader(body))
	rr := httptest.NewRecorder()
	CreateTenantHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("CreateTenantHandler: got status %d, body %s", rr.Code, rr.Body.String())
	}
	var resp createTenantResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	tenantID := resp.TenantID
	if tenantID == "" {
		t.Fatal("createTenantResp.TenantID is empty")
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

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
	`, tenantID).Scan(&gotCount); err != nil {
		t.Fatalf("count seeded tenant_rules: %v", err)
	}
	if gotCount != wantCount {
		t.Errorf("tenant_rules T2 rows for new tenant = %d, want %d (every enabled T2 rule seeded)", gotCount, wantCount)
	}
}
