//go:build integration

// Integration tests for GET /v1/allowlist/pending-installs.
//
// PAT-659 / PAT-660's per-tenant Self-Service App Catalogue (tenant_catalogue)
// and its admin CRUD routes were retired by PAT-1561 (migrations/
// 0121_retire_tenant_catalogue.sql) — live-data survey showed only Patched.im's
// own internal tenant had ever used it. The agent-facing endpoint below is
// kept as a permanent no-op (see internal/handlers/catalogue_agent.go) rather
// than removed, so these tests now only cover its auth/tier behaviour.
//
// Run locally:
//
//	TEST_DATABASE_URL="postgres://user:pass@localhost/patched_test?sslmode=disable" \
//	  go test -tags=integration -v -timeout=120s ./integration/
package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/ratelimit"
)

type pendingInstallsResp struct {
	Installs []struct {
		PackageID     string `json:"package_id"`
		PackageSource string `json:"package_source"`
		DisplayName   string `json:"display_name"`
	} `json:"installs"`
}

// signedPendingInstallsRequest builds a signed GET for the agent catalogue-pull
// endpoint. The body is empty, so the HMAC is computed over zero bytes — the
// same scheme the agent-config and pending-removals endpoints use. A fresh
// nonce per call avoids replay collisions across sub-tests.
func signedPendingInstallsRequest(t *testing.T) *http.Request {
	return signedPendingInstallsRequestTo(t, env.publicSrv.URL)
}

func signedPendingInstallsRequestTo(t *testing.T, baseURL string) *http.Request {
	t.Helper()

	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, env.hmacSecretRaw)
	mac.Write(nil) // empty body
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/allowlist/pending-installs", nil)
	if err != nil {
		t.Fatalf("build pending-installs request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.bearerToken)
	req.Header.Set("X-Patched-Signature", sig)
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	return req
}

// signedLegacyQueueRequest builds a current v3-signed empty GET for one
// quarantined queue endpoint. It deliberately receives the endpoint ID rather
// than sharing the pending-installs helper, so these tests also prove the
// endpoint-binding part of the queue auth contract.
func signedLegacyQueueRequest(t *testing.T, baseURL, path, endpointID, token string, secret []byte) *http.Request {
	t.Helper()
	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v3\nGET\n" + endpointID + "\n" + ts + "\n" + nonce + "\n"))

	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatalf("build %s request: %v", endpointID, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	return req
}

// TestCatalogueAgentPendingInstalls verifies the retired agent endpoint's
// permanent no-op: authenticated polling at Managed tier always gets the
// established empty response shape and never touches tenant_allowlists.
// There is no tenant_catalogue left to seed against (PAT-1561) — this is
// exactly the point: the response no longer depends on any stored data.
func TestCatalogueAgentPendingInstalls(t *testing.T) {
	const probePkg = "Integration.AgentNoOp"
	ctx := context.Background()
	var previousTier string
	if err := env.pool.QueryRow(ctx, `SELECT subscription_tier FROM tenants WHERE id = $1::uuid`, env.tenantID).Scan(&previousTier); err != nil {
		t.Fatalf("read tenant subscription tier: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET subscription_tier = 'managed' WHERE id = $1::uuid`, env.tenantID); err != nil {
		t.Fatalf("set tenant managed tier: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `UPDATE tenants SET subscription_tier = $1 WHERE id = $2::uuid`, previousTier, env.tenantID)
	})

	req := signedPendingInstallsRequest(t)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET pending-installs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("pending-installs: want 200, got %d: %s", resp.StatusCode, b)
	}

	var out pendingInstallsResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode pending-installs: %v", err)
	}
	if len(out.Installs) != 0 {
		t.Fatalf("retired pending-installs = %+v, want permanently empty response", out.Installs)
	}

	// The retired endpoint must not have written any allowlist pre-approval row.
	var allowCount int
	if err := env.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tenant_allowlists WHERE tenant_id = $1::uuid AND name = $2`,
		env.tenantID, probePkg,
	).Scan(&allowCount); err != nil {
		t.Fatalf("count allowlist: %v", err)
	}
	if allowCount != 0 {
		t.Errorf("retired pending-installs must not write allowlist rows, got %d", allowCount)
	}
}

// TestCatalogueAgentPendingInstalls_AssuranceTierDeniedBeforeDisabledCompatibility
// verifies that the public route authenticates and enforces Managed tier before
// its disabled-compatibility helper can return an empty successful response.
func TestCatalogueAgentPendingInstalls_AssuranceTierDeniedBeforeDisabledCompatibility(t *testing.T) {
	ctx := context.Background()
	var previousTier string
	if err := env.pool.QueryRow(ctx, `SELECT subscription_tier FROM tenants WHERE id = $1::uuid`, env.tenantID).Scan(&previousTier); err != nil {
		t.Fatalf("read tenant subscription tier: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET subscription_tier = 'assurance' WHERE id = $1::uuid`, env.tenantID); err != nil {
		t.Fatalf("set tenant assurance tier: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `UPDATE tenants SET subscription_tier = $1 WHERE id = $2::uuid`, previousTier, env.tenantID)
	})

	rl := ratelimit.New(ratelimit.Config{RPM: 100, Burst: 100})
	srv := httptest.NewServer(handlers.PendingInstallsHandler(env.pool, rl, 5*time.Minute))
	defer srv.Close()

	resp, err := http.DefaultClient.Do(signedPendingInstallsRequestTo(t, srv.URL))
	if err != nil {
		t.Fatalf("GET pending-installs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("assurance-tier pending-installs: want 403 before compatibility handling, got %d: %s", resp.StatusCode, body)
	}
}

// TestLegacyQueueReads_AssuranceTierDeniedBeforeDisabledCompatibility keeps every
// retired queue read on the same security contract: authenticating as a
// assurance-tier tenant is not equivalent to a successful disabled empty poll.
func TestLegacyQueueReads_AssuranceTierDeniedBeforeDisabledCompatibility(t *testing.T) {
	ctx := context.Background()
	var previousTier string
	if err := env.pool.QueryRow(ctx, `SELECT subscription_tier FROM tenants WHERE id = $1::uuid`, env.tenantID).Scan(&previousTier); err != nil {
		t.Fatalf("read tenant subscription tier: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET subscription_tier = 'assurance' WHERE id = $1::uuid`, env.tenantID); err != nil {
		t.Fatalf("set tenant assurance tier: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `UPDATE tenants SET subscription_tier = $1 WHERE id = $2::uuid`, previousTier, env.tenantID)
	})

	deviceID, deviceToken, deviceSecret := seedExtensionRemovalDevice(t, "94")
	for _, tc := range []struct {
		name, path, endpointID, token string
		secret                        []byte
	}{
		{"pending installs", "/v1/allowlist/pending-installs", "pending_installs", env.bearerToken, env.hmacSecretRaw},
		{"pending removals", "/v1/allowlist/pending-removals", "pending_removals", env.bearerToken, env.hmacSecretRaw},
		{"device removal tasks", "/v1/devices/" + deviceID + "/removal-tasks/pending", "device_removal_tasks_pending", deviceToken, deviceSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(signedLegacyQueueRequest(t, env.publicSrv.URL, tc.path, tc.endpointID, tc.token, tc.secret))
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("assurance-tier %s: want 403 before disabled compatibility, got %d: %s", tc.name, resp.StatusCode, body)
			}
		})
	}
}

// TestLegacyQueueReads_ProductionRouterReturnsDisabledEmptyPayloads exercises
// the production-like public router, whose retained queue routes are wired
// permanently false. Queue-loader unit tests separately prove this path never
// reads or mutates legacy queue state.
func TestLegacyQueueReads_ProductionRouterReturnsDisabledEmptyPayloads(t *testing.T) {
	ctx := context.Background()
	var previousTier string
	if err := env.pool.QueryRow(ctx, `SELECT subscription_tier FROM tenants WHERE id = $1::uuid`, env.tenantID).Scan(&previousTier); err != nil {
		t.Fatalf("read tenant subscription tier: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET subscription_tier = 'managed' WHERE id = $1::uuid`, env.tenantID); err != nil {
		t.Fatalf("set tenant managed tier: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `UPDATE tenants SET subscription_tier = $1 WHERE id = $2::uuid`, previousTier, env.tenantID)
	})

	deviceID, deviceToken, deviceSecret := seedExtensionRemovalDevice(t, "95")
	for _, tc := range []struct {
		name, path, endpointID, token, emptyField string
		secret                                    []byte
	}{
		{"pending installs", "/v1/allowlist/pending-installs", "pending_installs", env.bearerToken, `"installs":[]`, env.hmacSecretRaw},
		{"pending removals", "/v1/allowlist/pending-removals", "pending_removals", env.bearerToken, `"items":[]`, env.hmacSecretRaw},
		{"device removal tasks", "/v1/devices/" + deviceID + "/removal-tasks/pending", "device_removal_tasks_pending", deviceToken, `"tasks":[]`, deviceSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(signedLegacyQueueRequest(t, env.publicSrv.URL, tc.path, tc.endpointID, tc.token, tc.secret))
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), tc.emptyField) {
				t.Fatalf("production %s: want 200 with %s, got %d: %s", tc.name, tc.emptyField, resp.StatusCode, body)
			}
		})
	}
}
