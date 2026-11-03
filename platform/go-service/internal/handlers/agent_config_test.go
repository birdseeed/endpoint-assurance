package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/agentconfig"
)

const (
	acTestTenantID  = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	acOtherTenantID = "b1ffcd00-ad1c-5f09-cc7e-7cc0ce491b22"
)

// newTestSigningKey builds a deterministic Ed25519 key from a fixed seed.
// Not cryptographically safe — for tests only.
func newTestSigningKey() *agentconfig.SigningKey {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return &agentconfig.SigningKey{
		Private:   priv,
		Public:    pub,
		KeyID:     hex.EncodeToString(h[:8]),
		PubKeyB64: base64.StdEncoding.EncodeToString(pub),
	}
}

// acAuthAlways returns a stub authFn that always resolves to tenantID (no device).
func acAuthAlways(tenantID string) agentConfigAuthFn {
	return func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return tenantID, "", nil
	}
}

// acAuthNever returns a stub authFn that always fails.
func acAuthNever() agentConfigAuthFn {
	return func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return "", "", errors.New("unauthorized")
	}
}

// acAuthDevice returns a stub authFn that resolves to a device-scoped credential,
// mirroring what auth.LookupDeviceByBearer returns for a real device credential
// (PAT-1026 device_id injection).
func acAuthDevice(tenantID, deviceID string) agentConfigAuthFn {
	return func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return tenantID, deviceID, nil
	}
}

// acGetEmpty returns a stub agentConfigGetFn that returns no existing row.
func acGetEmpty() agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{}, false, nil
	}
}

// acGetRow returns a stub getFn that returns a row with the given configVersion.
func acGetRow(tenantID string, configVersion int) agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: configVersion,
			Body:          agentconfig.DefaultConfigBody(),
			IssuedAt:      time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
		}, true, nil
	}
}

// acGetNotFound returns a stub getFn that always returns found=false.
func acGetNotFound() agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{}, false, nil
	}
}

// acWithTenantID injects a chi tenantID URL param into the request context.
func acWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// decodeSignedPayload base64-decodes resp.SignedPayload and verifies the
// Ed25519 signature. Returns the raw canonical bytes on success; calls
// t.Fatal on any error. The caller json-parses the result as needed.
func decodeSignedPayload(t *testing.T, resp agentConfigResp, key *agentconfig.SigningKey) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(resp.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if err := agentconfig.Verify(key.Public, raw, resp.Signature); err != nil {
		t.Fatalf("signature verification: %v", err)
	}
	return raw
}

// ---- GET handler tests ----

// TestAgentConfigGet_SignedResponse asserts that an authed GET returns HTTP 200
// with a signed_payload whose Ed25519 signature verifies against the published
// public key, and whose decoded contents contain the expected tenant + version.
func TestAgentConfigGet_SignedResponse(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 3), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Signature == "" {
		t.Fatal("signature must not be empty")
	}
	if resp.KeyID != key.KeyID {
		t.Errorf("key_id: want %q, got %q", key.KeyID, resp.KeyID)
	}

	// Decode and verify signed_payload; parse config fields from verified bytes.
	raw := decodeSignedPayload(t, resp, key)

	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if cfg["tenant_id"] != acTestTenantID {
		t.Errorf("tenant_id: want %q, got %v", acTestTenantID, cfg["tenant_id"])
	}
	if v, _ := cfg["config_version"].(float64); int(v) != 3 {
		t.Errorf("config_version: want 3, got %v", cfg["config_version"])
	}
}

// TestAgentConfigGet_TamperedPayloadFails asserts that mutating the signed_payload
// bytes causes signature verification to fail — a tampered config is rejected.
func TestAgentConfigGet_TamperedPayloadFails(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 3), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	// Tamper: flip a byte in the decoded payload, then re-encode.
	raw, err := base64.StdEncoding.DecodeString(resp.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	raw[0] ^= 0xFF
	resp.SignedPayload = base64.StdEncoding.EncodeToString(raw)

	if err := agentconfig.Verify(key.Public, raw, resp.Signature); err == nil {
		t.Error("expected verification failure on tampered payload, got nil error")
	}
}

// TestAgentConfigGet_ETagMatch304 asserts that an If-None-Match matching the
// ETag just served for an unchanged config returns HTTP 304 — auth runs before
// the ETag check. The ETag is now a hash of the full canonical signed payload
// (PAT-868), not a fixed literal, so this first does a GET to learn the real
// value before replaying it.
func TestAgentConfigGet_ETagMatch304(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 5), nil, 0, nil)

	first := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	firstRR := httptest.NewRecorder()
	handler.ServeHTTP(firstRR, first)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("want 200 on initial GET, got %d: %s", firstRR.Code, firstRR.Body.String())
	}
	etag := firstRR.Header().Get("ETag")
	if etag == "" {
		t.Fatal("initial GET returned no ETag")
	}
	if !strings.HasPrefix(etag, `"v5-r3-`) {
		t.Errorf("ETag should keep the v<version>-r<ring> prefix for readability, got %q", etag)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	req.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotModified {
		t.Fatalf("want 304, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("ETag"); got != etag {
		t.Errorf("ETag on 304: want %q, got %q", etag, got)
	}
}

// TestAgentConfigGet_ETagMismatch200 asserts that a stale ETag returns 200 with
// the fresh config, and that an unchanged config keeps serving the exact same
// ETag on repeated requests (304 must still work for real cache hits).
func TestAgentConfigGet_ETagMismatch200(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 5), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	req.Header.Set("If-None-Match", `"stale"`) // stale
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for stale ETag, got %d", rr.Code)
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on 200 response")
	}

	// Same unchanged row served again must produce the identical ETag.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if got := rr2.Header().Get("ETag"); got != etag {
		t.Errorf("ETag must be stable for an unchanged config: first %q, second %q", etag, got)
	}
}

// TestAgentConfigGet_ETagChangesOnPolicyOnlyChange asserts the PAT-868 fix:
// changing a signed security-policy field (app_control enabled/allowlist/
// approved_admins or the extension blocklist/removals)
// changes the ETag even when config_version does not move, and a conditional
// GET carrying the pre-change ETag gets a fresh 200 rather than a stale 304.
// Before the fix the ETag was `v{ConfigVersion}-r{ring}` only, so none of these
// mutations affected it and the device would have been served 304 forever.
func TestAgentConfigGet_ETagChangesOnPolicyOnlyChange(t *testing.T) {
	const fixedConfigVersion = 7

	baseRow := agentConfigRow{
		TenantID:      acTestTenantID,
		ConfigVersion: fixedConfigVersion,
		Body:          agentconfig.DefaultConfigBody(),
		IssuedAt:      time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
	}

	cases := []struct {
		name   string
		mutate func(agentConfigRow) agentConfigRow
	}{
		{
			name: "app_control enabled flips",
			mutate: func(r agentConfigRow) agentConfigRow {
				r.AppControlEnabled = true
				return r
			},
		},
		{
			name: "app allowlist gains an entry",
			mutate: func(r agentConfigRow) agentConfigRow {
				r.AppControlEnabled = true
				r.AppControlAppAllowlist = []string{"com.example.app"}
				return r
			},
		},
		{
			name: "approved admins changes",
			mutate: func(r agentConfigRow) agentConfigRow {
				r.AppControlEnabled = true
				r.AppControlAdmins = []string{"admin@example.com"}
				return r
			},
		},
		{
			name: "extension blocklist gains an entry",
			mutate: func(r agentConfigRow) agentConfigRow {
				r.ExtensionBlocklist = []agentconfig.ExtensionBlocklistEntry{
					{Browser: "chrome", ExtensionID: "aaaabbbbccccdddd"},
				}
				return r
			},
		},
		{
			name: "extension removals gains an entry",
			mutate: func(r agentConfigRow) agentConfigRow {
				r.ExtensionRemovals = []agentconfig.ExtensionRemovalEntry{
					{Browser: "chrome", ExtensionID: "aaaabbbbccccdddd", Scope: "all_devices"},
				}
				return r
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := newTestSigningKey()

			before := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
				func(_ context.Context, _ string) (agentConfigRow, bool, error) { return baseRow, true, nil },
				nil, 0, nil)
			beforeReq := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
			beforeRR := httptest.NewRecorder()
			before.ServeHTTP(beforeRR, beforeReq)
			if beforeRR.Code != http.StatusOK {
				t.Fatalf("want 200 pre-change, got %d: %s", beforeRR.Code, beforeRR.Body.String())
			}
			etagBefore := beforeRR.Header().Get("ETag")
			if etagBefore == "" {
				t.Fatal("missing pre-change ETag")
			}

			changed := tc.mutate(baseRow)
			if changed.ConfigVersion != fixedConfigVersion {
				t.Fatalf("test setup bug: mutate must not touch config_version")
			}
			after := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
				func(_ context.Context, _ string) (agentConfigRow, bool, error) { return changed, true, nil },
				nil, 0, nil)

			// Conditional GET carrying the stale (pre-change) ETag — the device
			// must NOT get 304 even though config_version is unchanged.
			afterReq := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
			afterReq.Header.Set("If-None-Match", etagBefore)
			afterRR := httptest.NewRecorder()
			after.ServeHTTP(afterRR, afterReq)

			if afterRR.Code != http.StatusOK {
				t.Fatalf("policy-only change with unchanged config_version must return 200, got %d (stale 304 would hide the policy change): %s",
					afterRR.Code, afterRR.Body.String())
			}
			etagAfter := afterRR.Header().Get("ETag")
			if etagAfter == etagBefore {
				t.Errorf("ETag did not change after %s despite config_version staying at %d: %q",
					tc.name, fixedConfigVersion, etagAfter)
			}
		})
	}
}

// TestAgentConfigGet_Unauthenticated asserts that auth failure returns 401
// and no config body is served.
func TestAgentConfigGet_Unauthenticated(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthNever(), acGetRow(acTestTenantID, 1), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

// TestAgentConfigGet_CrossTenantIsolation asserts that the signed config contains
// exactly the authenticated tenant's ID and not any other tenant's.
func TestAgentConfigGet_CrossTenantIsolation(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 1), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if cfg["tenant_id"] == acOtherTenantID {
		t.Errorf("cross-tenant leak detected: got other tenant's ID")
	}
	if cfg["tenant_id"] != acTestTenantID {
		t.Errorf("want tenant_id=%q, got %v", acTestTenantID, cfg["tenant_id"])
	}
}

// TestAgentConfigGet_SyntheticDefaultWhenNoRow asserts that a tenant with no
// agent_config row in the DB gets a valid signed default response (version 1).
func TestAgentConfigGet_SyntheticDefaultWhenNoRow(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetNotFound(), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	// Synthetic default must be validly signed.
	raw := decodeSignedPayload(t, resp, key)

	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if v, _ := cfg["config_version"].(float64); int(v) != 1 {
		t.Errorf("want config_version=1 for synthetic default, got %v", cfg["config_version"])
	}
	if cfg["tier"] != "report_deploy" {
		t.Errorf("want tier=report_deploy, got %v", cfg["tier"])
	}
	// PAT-1108: a brand-new tenant (no agent_config row at all) must also get
	// the inert decommission default — "no directive" can never mean anything
	// other than mode="none", including for a tenant that doesn't exist yet.
	if dec, ok := cfg["decommission"].(map[string]interface{}); !ok || dec["mode"] != "none" {
		t.Errorf("want decommission.mode=none for synthetic default, got %v", cfg["decommission"])
	}
}

// TestAgentConfigGet_SyntheticDefaultConsultsDecommissionWhenNoAgentConfigRow
// is the PAT-1108 finding 2 regression: a tenant with an ACTIVE
// tenant_decommission directive but NO agent_config row (e.g. legacy data
// from before the directive-write path started creating one as part of the
// finding 1 fix, or a directive set directly against a brand-new tenant)
// must still have that directive served — dbGetAgentConfig's LEFT JOIN never
// runs when the agent_config row itself is absent, so before this fix the
// directive was silently dropped into the synthetic mode="none" default.
// Uses the real DB (adConnectOrSkip / adSeedTenant, agent_decommission_test.go)
// because the bug lives inside dbGetAgentConfig's real SQL, not in any
// stubbable interface.
func TestAgentConfigGet_SyntheticDefaultConsultsDecommissionWhenNoAgentConfigRow(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-f2-tenant")

	// Seed the directive directly, bypassing PUT /admin/tenants/{id}/decommission
	// -- that handler now also creates an agent_config row as part of the
	// finding 1 fix, which would make this exact shape unreachable through it.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_decommission (tenant_id, mode, purge, reason, set_by, directive_version)
		VALUES ($1::uuid, 'immediate', true, 'pre-fix legacy directive', 'test', 1)
	`, tenantID); err != nil {
		t.Fatalf("seed tenant_decommission: %v", err)
	}

	// Precondition: no agent_config row exists for this tenant.
	var agentConfigCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&agentConfigCount); err != nil {
		t.Fatalf("count agent_config rows: %v", err)
	}
	if agentConfigCount != 0 {
		t.Fatalf("precondition failed: expected no agent_config row, found %d", agentConfigCount)
	}

	// dbGetAgentConfig directly: found must be false (no agent_config row),
	// but Decommission must already carry the directive.
	row, found, err := dbGetAgentConfig(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("dbGetAgentConfig: %v", err)
	}
	if found {
		t.Fatalf("found = true, want false — no agent_config row exists for this tenant")
	}
	if row.Decommission.Mode != "immediate" {
		t.Errorf("row.Decommission.Mode = %q, want immediate — must consult tenant_decommission even when agent_config is absent", row.Decommission.Mode)
	}

	// End to end: the served signed payload must carry the directive too.
	key := newTestSigningKey()
	getFn := func(ctx context.Context, tid string) (agentConfigRow, bool, error) {
		return dbGetAgentConfig(ctx, pool, tid)
	}
	handler := newAgentConfigHandler(key, acAuthAlways(tenantID), getFn, nil, 0, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	dec, ok := cfg["decommission"].(map[string]interface{})
	if !ok {
		t.Fatal("decommission must be present in the signed payload")
	}
	if dec["mode"] != "immediate" {
		t.Errorf("signed payload decommission.mode = %v, want immediate — the directive must not be dropped just because agent_config is absent", dec["mode"])
	}
}

// TestDbGetAgentConfig_NotFoundFallbackObservesConcurrentDecommissionPut is
// the PAT-1108 fifth-round finding P1-D regression. It drives a deterministic
// interleaving, mirroring TestLockTenantAndReadDecommissionState_SerializesConcurrentWrites
// and TestAgentDecommissionStatusHandler_ConcurrentCancellationNeverYieldsProceed
// (agent_decommission_test.go): tx1 takes the SAME tenants-row FOR UPDATE
// lock dbGetAgentConfigNotFoundFallback now takes, and — while still holding
// it uncommitted — performs exactly what a real decommission PUT does for a
// tenant's FIRST-EVER directive (bumpAgentConfigVersionForDecommission's
// INSERT into agent_config, plus the matching tenant_decommission INSERT).
// dbGetAgentConfig is then called concurrently against a tenant that has NO
// agent_config row yet, so its lock-free first read reliably finds nothing
// (tx1's writes are uncommitted and therefore invisible to it under MVCC,
// regardless of goroutine scheduling), forcing it into the not-found
// fallback, which must then block on tx1's lock.
//
// Before the fix, the fallback ran a second, independent, unlocked query
// against tenant_decommission alone and would have observed tx1's directive
// (mode="immediate") the moment it committed, while still reporting
// found=false — so the caller would sign that directive against the
// synthetic default config_version (1), not the REAL value tx1 just
// persisted. This test proves the fix: once tx1 commits, dbGetAgentConfig
// must report found=true with the REAL config_version and the REAL
// directive together, never the synthetic default paired with real data.
func TestDbGetAgentConfig_NotFoundFallbackObservesConcurrentDecommissionPut(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p1d-race-tenant")

	var agentConfigCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&agentConfigCount); err != nil {
		t.Fatalf("count agent_config rows: %v", err)
	}
	if agentConfigCount != 0 {
		t.Fatalf("precondition failed: expected no agent_config row, found %d", agentConfigCount)
	}

	// tx1 simulates a decommission PUT that has decided to write but not yet
	// committed — the exact race window P1-D closes. It takes the SAME
	// tenants-row lock dbGetAgentConfigNotFoundFallback takes, via the SAME
	// helper.
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()

	exists1, oldMode1, _, _, _, _, err := lockTenantAndReadDecommissionState(ctx, tx1, tenantID)
	if err != nil {
		t.Fatalf("tx1 lock and read: %v", err)
	}
	if !exists1 || oldMode1 != nil {
		t.Fatalf("tx1 precondition failed: exists=%v oldMode=%v, want exists with no prior directive", exists1, oldMode1)
	}

	// Mirrors bumpAgentConfigVersionForDecommission's INSERT: the tenant's
	// first-ever agent_config row, at config_version
	// syntheticDefaultConfigVersion+1 (never AT the synthetic default —
	// see that function's own doc comment).
	newConfigVersion := syntheticDefaultConfigVersion + 1
	defaultBody, err := json.Marshal(agentconfig.DefaultConfigBody())
	if err != nil {
		t.Fatalf("marshal default config body: %v", err)
	}
	if _, err := tx1.Exec(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, $2, $3::jsonb, now(), 'system')
	`, tenantID, newConfigVersion, defaultBody); err != nil {
		t.Fatalf("tx1 insert agent_config: %v", err)
	}
	if _, err := tx1.Exec(ctx, `
		INSERT INTO tenant_decommission (tenant_id, mode, purge, set_by, directive_version)
		VALUES ($1::uuid, 'immediate', false, 'race-test', $2)
	`, tenantID, newConfigVersion); err != nil {
		t.Fatalf("tx1 insert tenant_decommission: %v", err)
	}

	type result struct {
		row   agentConfigRow
		found bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		row, found, err := dbGetAgentConfig(ctx, pool, tenantID)
		done <- result{row, found, err}
	}()

	select {
	case res := <-done:
		t.Fatalf("dbGetAgentConfig returned (found=%v, config_version=%d, mode=%q, err=%v) while tx1 held the tenants lock with an uncommitted first-ever directive — "+
			"the not-found fallback is not serialising against a concurrent decommission PUT, exactly the P1-D race",
			res.found, res.row.ConfigVersion, res.row.Decommission.Mode, res.err)
	case <-time.After(2 * time.Second):
		// Expected: dbGetAgentConfig's not-found fallback is blocked on
		// tx1's tenants-row lock.
	}

	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1 (the racing decommission PUT): %v", err)
	}
	res := <-done

	if res.err != nil {
		t.Fatalf("dbGetAgentConfig after tx1 commit: %v", res.err)
	}
	if !res.found {
		t.Fatalf("found = false, want true — the racing PUT's agent_config row must be observed once committed, not missed by a stale not-found determination")
	}
	if res.row.ConfigVersion != newConfigVersion {
		t.Errorf("ConfigVersion = %d, want %d — the REAL persisted value, never the synthetic default (%d) paired with real directive data",
			res.row.ConfigVersion, newConfigVersion, syntheticDefaultConfigVersion)
	}
	if res.row.Decommission.Mode != "immediate" {
		t.Errorf("Decommission.Mode = %q, want immediate", res.row.Decommission.Mode)
	}
}

// TestAgentConfigGet_DecommissionTamperedPayloadFailsVerification proves the
// server-side half of "fail closed means DO NOT REMOVE" for decommission
// specifically: a signed payload carrying an active mode="immediate"
// directive, once tampered in transit, fails Ed25519 verification exactly
// like any other field. Per the contract (agent-config-schema.md), the agent
// verifies the raw transmitted bytes BEFORE parsing JSON — so a tampered
// payload is rejected wholesale and the agent never observes any mode at
// all, let alone acts on one. This is what makes "invalid signature never
// triggers removal" true: decommission has no separate signing or delivery
// path that could bypass this.
func TestAgentConfigGet_DecommissionTamperedPayloadFailsVerification(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
		acGetRowWithDecommission(acTestTenantID, 1, agentconfig.DecommissionPolicy{Mode: "immediate", Purge: true}),
		nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(resp.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	// Sanity: the untampered payload really does carry the dangerous directive,
	// so the test would fail loudly if verification were somehow skipped.
	if !bytes.Contains(raw, []byte(`"mode":"immediate"`)) {
		t.Fatalf("precondition failed: expected mode:immediate in canonical bytes: %s", raw)
	}

	raw[0] ^= 0xFF // flip one byte anywhere in the signed canonical payload
	if err := agentconfig.Verify(key.Public, raw, resp.Signature); err == nil {
		t.Fatal("expected verification failure on tampered payload carrying an active decommission directive, got nil error")
	}
}

// TestAgentConfigGet_DecommissionDoesNotLeakAcrossTenants asserts that two
// tenants with different decommission directives never see each other's
// state — the "mismatched tenant" acceptance criterion's server-side half.
// Each response's tenant_id is signed inside the SAME canonical payload as
// decommission, so an agent comparing tenant_id against its local
// configuration (per agent-config-schema.md's verification guide) can always
// detect a substituted payload; this test proves the server itself never
// conflates the two tenants' directives in the first place.
func TestAgentConfigGet_DecommissionDoesNotLeakAcrossTenants(t *testing.T) {
	key := newTestSigningKey()
	reasonA := "tenant A offboarded"
	reasonB := "tenant B offboarded"

	getFn := func(_ context.Context, tenantID string) (agentConfigRow, bool, error) {
		switch tenantID {
		case acTestTenantID:
			return agentConfigRow{
				TenantID: acTestTenantID, ConfigVersion: 1, Body: agentconfig.DefaultConfigBody(),
				IssuedAt:     time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
				Decommission: agentconfig.DecommissionPolicy{Mode: "immediate", Reason: &reasonA},
			}, true, nil
		case acOtherTenantID:
			return agentConfigRow{
				TenantID: acOtherTenantID, ConfigVersion: 1, Body: agentconfig.DefaultConfigBody(),
				IssuedAt:     time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
				Decommission: agentconfig.DecommissionPolicy{Mode: "none", Reason: &reasonB},
			}, true, nil
		default:
			return agentConfigRow{}, false, nil
		}
	}

	fetch := func(tenantID string) map[string]interface{} {
		handler := newAgentConfigHandler(key, acAuthAlways(tenantID), getFn, nil, 0, nil)
		req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tenant %s: want 200, got %d: %s", tenantID, rr.Code, rr.Body.String())
		}
		var resp agentConfigResp
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		raw := decodeSignedPayload(t, resp, key)
		var cfg map[string]interface{}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return cfg
	}

	cfgA := fetch(acTestTenantID)
	cfgB := fetch(acOtherTenantID)

	if cfgA["tenant_id"] != acTestTenantID {
		t.Errorf("tenant A response tenant_id = %v, want %v", cfgA["tenant_id"], acTestTenantID)
	}
	if cfgB["tenant_id"] != acOtherTenantID {
		t.Errorf("tenant B response tenant_id = %v, want %v", cfgB["tenant_id"], acOtherTenantID)
	}
	decA, _ := cfgA["decommission"].(map[string]interface{})
	decB, _ := cfgB["decommission"].(map[string]interface{})
	if decA["mode"] != "immediate" {
		t.Errorf("tenant A decommission.mode = %v, want immediate", decA["mode"])
	}
	if decB["mode"] != "none" {
		t.Errorf("tenant B decommission.mode = %v, want none — must not inherit tenant A's directive", decB["mode"])
	}
}

// TestAgentConfigGet_DecommissionSharesConfigVersionAntiRollback asserts that
// decommission carries no version or freshness field of its own — it lives
// entirely inside the single config_version-gated, signed envelope every
// other directive uses. This is what makes "regressed config_version never
// triggers removal" true: there is no side channel through which a stale
// decommission directive could be replayed independently of the anti-rollback
// counter the agent already tracks (agent-config-schema.md's Anti-rollback
// section — enforced client-side, but only possible because the server never
// gives decommission its own versioning to bypass it with).
func TestAgentConfigGet_DecommissionSharesConfigVersionAntiRollback(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
		acGetRowWithDecommission(acTestTenantID, 7, agentconfig.DecommissionPolicy{Mode: "expiry", ExpiresAt: strPtr("2026-09-01T00:00:00Z")}),
		nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if v, _ := cfg["config_version"].(float64); int(v) != 7 {
		t.Errorf("config_version = %v, want 7", cfg["config_version"])
	}
	dec, ok := cfg["decommission"].(map[string]interface{})
	if !ok {
		t.Fatal("decommission must be present")
	}
	for _, forbidden := range []string{"config_version", "version", "issued_at"} {
		if _, present := dec[forbidden]; present {
			t.Errorf("decommission object must not carry its own %q field — it must rely on the envelope's config_version for anti-rollback", forbidden)
		}
	}
}

// TestAgentConfigGet_DeviceIDInjectedForDeviceScopedCredential asserts that a
// device-scoped credential's own platform device_id is injected as a top-level
// field in the signed payload (PAT-1026), following the same per-request
// injection pattern as the PAT-117 per-device ring.
func TestAgentConfigGet_DeviceIDInjectedForDeviceScopedCredential(t *testing.T) {
	key := newTestSigningKey()
	deviceID := "c2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
	handler := newAgentConfigHandler(key, acAuthDevice(acTestTenantID, deviceID), acGetRow(acTestTenantID, 1), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if cfg["device_id"] != deviceID {
		t.Errorf("device_id: want %q, got %v", deviceID, cfg["device_id"])
	}
}

// TestAgentConfigGet_DeviceIDEmptyForTenantWideCredential asserts that a
// tenant-wide credential (no resolved device) never receives a device_id —
// it must not be possible for one device's response to carry another's id, and
// a tenant-wide credential has no single correct device to attribute it to.
func TestAgentConfigGet_DeviceIDEmptyForTenantWideCredential(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 1), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if cfg["device_id"] != "" {
		t.Errorf("device_id: want empty string for tenant-wide credential, got %v", cfg["device_id"])
	}
}

// TestAgentConfigGet_DeviceIDDoesNotLeakAcrossDevices asserts that two
// different device-scoped credentials for the same tenant each receive only
// their own device_id — the value tracks the resolved credential, not any
// client-supplied input, so one device can never see another's identity.
func TestAgentConfigGet_DeviceIDDoesNotLeakAcrossDevices(t *testing.T) {
	key := newTestSigningKey()
	deviceA := "aaaaaaaa-0000-4000-8000-000000000001"
	deviceB := "bbbbbbbb-0000-4000-8000-000000000002"

	for _, tc := range []struct {
		name     string
		deviceID string
	}{
		{"device A", deviceA},
		{"device B", deviceB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := newAgentConfigHandler(key, acAuthDevice(acTestTenantID, tc.deviceID), acGetRow(acTestTenantID, 1), nil, 0, nil)
			req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			var resp agentConfigResp
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			raw := decodeSignedPayload(t, resp, key)
			var cfg map[string]interface{}
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("unmarshal signed_payload: %v", err)
			}
			if cfg["device_id"] != tc.deviceID {
				t.Errorf("device_id: want %q, got %v", tc.deviceID, cfg["device_id"])
			}
		})
	}
}

// ---- Admin write handler tests ----

// TestAdminAgentConfigPut_BumpsVersion asserts that a write increments
// config_version and returns the new version in the response.
func TestAdminAgentConfigPut_BumpsVersion(t *testing.T) {
	key := newTestSigningKey()
	currentVersion := 3
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		currentVersion++
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: currentVersion,
			Body:          body,
			IssuedAt:      time.Now().UTC(),
		}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	body := `{"tier":"managed","proxy":{"mode":"system","bypass_when_off_corp":false}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var putResp adminAgentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if putResp.ConfigVersion != 4 {
		t.Errorf("want config_version=4 after bump from 3, got %d", putResp.ConfigVersion)
	}
	if putResp.ConfigVersion == 3 {
		t.Error("config_version was not bumped — old ETag would still match")
	}
}

func TestAdminAgentConfigPut_RejectsReservedMandatoryInstallIntents(t *testing.T) {
	key := newTestSigningKey()
	upsertCalled := false
	upsertFn := func(_ context.Context, _, _ string, _ agentconfig.ConfigBody) (agentConfigRow, error) {
		upsertCalled = true
		return agentConfigRow{}, nil
	}
	putHandler := newAdminAgentConfigPutHandler(key, func(context.Context, string) (bool, error) { return true, nil }, acGetEmpty(), upsertFn)
	body := `{"tier":"managed","proxy":{"mode":"system","bypass_when_off_corp":false},"mandatory_install_intents":[{"intent_id":"operator-injected"}]}`
	req := acWithTenantID(httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(body)), acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "reserved response-only") {
		t.Fatalf("reserved authority injection status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upsertCalled {
		t.Fatal("reserved mandatory authority reached persistence")
	}

	var stored agentconfig.ConfigBody
	if err := json.Unmarshal([]byte(`{"tier":"managed","mandatory_install_intents":[{"intent_id":"stored-injection"}]}`), &stored); err != nil {
		t.Fatal(err)
	}
	if reencoded, err := json.Marshal(stored); err != nil || strings.Contains(string(reencoded), "mandatory_install") {
		t.Fatalf("stored reserved authority survived deserialization: %s (err %v)", reencoded, err)
	}
}

// TestAdminAgentConfigPut_UnknownTenant asserts that a non-existent tenantID
// returns 404 and the upsert function is never invoked.
func TestAdminAgentConfigPut_UnknownTenant(t *testing.T) {
	key := newTestSigningKey()
	upsertCalled := false
	upsertFn := func(_ context.Context, _ string, _ string, _ agentconfig.ConfigBody) (agentConfigRow, error) {
		upsertCalled = true
		return agentConfigRow{}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return false, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	body := `{"tier":"assurance","proxy":{"mode":"system","bypass_when_off_corp":false}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown tenant, got %d", rr.Code)
	}
	if upsertCalled {
		t.Error("upsert must not be called for an unknown tenant")
	}
}

// TestValidateAgentConfigReq covers validation rules for the admin write body.
func TestValidateAgentConfigReq(t *testing.T) {
	host := "proxy.corp.example"
	deadline := "2026-12-31"
	tests := []struct {
		name    string
		req     adminAgentConfigReq
		wantErr bool
	}{
		{
			name: "valid assurance + system proxy",
			req:  adminAgentConfigReq{Tier: "assurance", Proxy: agentconfig.ProxyConfig{Mode: "system"}},
		},
		{
			name: "valid managed + off proxy",
			req:  adminAgentConfigReq{Tier: "managed", Proxy: agentconfig.ProxyConfig{Mode: "off"}},
		},
		{
			name: "valid managed (PAT-1048 Tier 3) + system proxy",
			req:  adminAgentConfigReq{Tier: "managed", Proxy: agentconfig.ProxyConfig{Mode: "system"}},
		},
		{
			name: "valid manual proxy with host",
			req:  adminAgentConfigReq{Tier: "assurance", Proxy: agentconfig.ProxyConfig{Mode: "manual", Host: &host}},
		},
		{
			name:    "invalid tier",
			req:     adminAgentConfigReq{Tier: "unknown", Proxy: agentconfig.ProxyConfig{Mode: "system"}},
			wantErr: true,
		},
		{
			name:    "invalid proxy mode",
			req:     adminAgentConfigReq{Tier: "managed", Proxy: agentconfig.ProxyConfig{Mode: "auto"}},
			wantErr: true,
		},
		{
			name:    "manual proxy missing host",
			req:     adminAgentConfigReq{Tier: "managed", Proxy: agentconfig.ProxyConfig{Mode: "manual"}},
			wantErr: true,
		},
		{
			name: "valid os_update_policy enabled",
			req: adminAgentConfigReq{
				Tier:  "assurance",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:               true,
					GraceDays:             14,
					DeferralBudget:        5,
					DeferIntervalHours:    24,
					BlockingWindowDays:    3,
					MinimumAgeDays:        7,
					ExploitedOverridesAge: true,
				},
			},
		},
		{
			name: "valid os_update_policy with ISO deadline",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          14,
					DeferralBudget:     3,
					DeferIntervalHours: 48,
					BlockingWindowDays: 5,
					MinimumAgeDays:     0,
					Deadline:           &deadline,
				},
			},
		},
		{
			name: "disabled os_update_policy — no validation applied",
			req: adminAgentConfigReq{
				Tier:  "assurance",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:   false,
					GraceDays: 999, // out of range but irrelevant when disabled
				},
			},
		},
		{
			name: "nil os_update_policy — valid",
			req:  adminAgentConfigReq{Tier: "assurance", Proxy: agentconfig.ProxyConfig{Mode: "system"}},
		},
		{
			name: "grace_days out of range",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          0, // must be >= 1
					DeferralBudget:     3,
					DeferIntervalHours: 24,
					BlockingWindowDays: 3,
					MinimumAgeDays:     7,
				},
			},
			wantErr: true,
		},
		{
			name: "deferral_budget out of range",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          14,
					DeferralBudget:     11, // must be <= 10
					DeferIntervalHours: 24,
					BlockingWindowDays: 3,
					MinimumAgeDays:     7,
				},
			},
			wantErr: true,
		},
		{
			name: "defer_interval_hours out of range",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          14,
					DeferralBudget:     5,
					DeferIntervalHours: 0, // must be >= 1
					BlockingWindowDays: 3,
					MinimumAgeDays:     7,
				},
			},
			wantErr: true,
		},
		{
			name: "blocking_window_days out of range",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          14,
					DeferralBudget:     5,
					DeferIntervalHours: 24,
					BlockingWindowDays: 31, // must be <= 30
					MinimumAgeDays:     7,
				},
			},
			wantErr: true,
		},
		{
			name: "minimum_age_days out of range",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          14,
					DeferralBudget:     5,
					DeferIntervalHours: 24,
					BlockingWindowDays: 3,
					MinimumAgeDays:     31, // must be <= 30
				},
			},
			wantErr: true,
		},
		{
			name: "invalid deadline format",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				OsUpdatePolicy: &OsUpdatePolicyReq{
					Enabled:            true,
					GraceDays:          14,
					DeferralBudget:     5,
					DeferIntervalHours: 24,
					BlockingWindowDays: 3,
					MinimumAgeDays:     7,
					Deadline:           strPtr("not-a-date"),
				},
			},
			wantErr: true,
		},
		{
			name: "valid blocking_process_policy — all fields",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{
					ActionOnTimeout:    strPtr("prompt_then_quit"),
					TimeoutSeconds:     intPtr(600),
					MaxDeferrals:       intPtr(0),
					DeferWindowSeconds: intPtr(1800),
					Message:            strPtr("Close the app to update."),
				},
			},
		},
		{
			name: "valid blocking_process_policy — action omitted (defaults later)",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{TimeoutSeconds: intPtr(120)},
			},
		},
		{
			name: "blocking_process_policy — unknown action rejected",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{ActionOnTimeout: strPtr("force_quit")},
			},
			wantErr: true,
		},
		{
			name: "blocking_process_policy — timeout too low",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{TimeoutSeconds: intPtr(10)},
			},
			wantErr: true,
		},
		{
			name: "blocking_process_policy — timeout too high",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{TimeoutSeconds: intPtr(90000)},
			},
			wantErr: true,
		},
		{
			name: "blocking_process_policy — negative max_deferrals",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{MaxDeferrals: intPtr(-1)},
			},
			wantErr: true,
		},
		{
			name: "blocking_process_policy — defer_window too low",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{DeferWindowSeconds: intPtr(30)},
			},
			wantErr: true,
		},
		{
			name: "blocking_process_policy — message too long",
			req: adminAgentConfigReq{
				Tier:                  "managed",
				Proxy:                 agentconfig.ProxyConfig{Mode: "system"},
				BlockingProcessPolicy: &BlockingProcessPolicyReq{Message: strPtr(strings.Repeat("x", 501))},
			},
			wantErr: true,
		},
		{
			name: "valid blocked_versions",
			req: adminAgentConfigReq{
				Tier:  "managed",
				Proxy: agentconfig.ProxyConfig{Mode: "system"},
				BlockedVersions: map[string][]string{
					"google-chrome": {"139.0.7258.67", "139.0.7258.68"},
					"1password":     {"8.10.40"},
				},
			},
		},
		{
			name: "nil blocked_versions — valid",
			req:  adminAgentConfigReq{Tier: "managed", Proxy: agentconfig.ProxyConfig{Mode: "system"}},
		},
		{
			name: "blocked_versions — empty label rejected",
			req: adminAgentConfigReq{
				Tier:            "managed",
				Proxy:           agentconfig.ProxyConfig{Mode: "system"},
				BlockedVersions: map[string][]string{"": {"1.2.3"}},
			},
			wantErr: true,
		},
		{
			name: "blocked_versions — label with path separator rejected",
			req: adminAgentConfigReq{
				Tier:            "managed",
				Proxy:           agentconfig.ProxyConfig{Mode: "system"},
				BlockedVersions: map[string][]string{"../../etc/passwd": {"1.2.3"}},
			},
			wantErr: true,
		},
		{
			name: "blocked_versions — empty version list rejected",
			req: adminAgentConfigReq{
				Tier:            "managed",
				Proxy:           agentconfig.ProxyConfig{Mode: "system"},
				BlockedVersions: map[string][]string{"google-chrome": {}},
			},
			wantErr: true,
		},
		{
			name: "blocked_versions — empty version string rejected",
			req: adminAgentConfigReq{
				Tier:            "managed",
				Proxy:           agentconfig.ProxyConfig{Mode: "system"},
				BlockedVersions: map[string][]string{"google-chrome": {"1.2.3", ""}},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAgentConfigReq(tc.req)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateAgentConfigReq() error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// acGetRowWithAC returns a stub getFn that returns a row with AppControlEnabled set.
func acGetRowWithAC(tenantID string, configVersion int, acEnabled bool) agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{
			TenantID:          tenantID,
			ConfigVersion:     configVersion,
			Body:              agentconfig.DefaultConfigBody(),
			IssuedAt:          time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
			AppControlEnabled: acEnabled,
		}, true, nil
	}
}

// acGetRowWithACLists returns a stub getFn with full AC policy fields set.
func acGetRowWithACLists(tenantID string, admins, allowlist []string) agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{
			TenantID:               tenantID,
			ConfigVersion:          1,
			Body:                   agentconfig.DefaultConfigBody(),
			IssuedAt:               time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
			AppControlEnabled:      true,
			AppControlAdmins:       admins,
			AppControlAppAllowlist: allowlist,
		}, true, nil
	}
}

// acGetRowWithExtensions returns a stub getFn whose row carries the given
// extension blocklist and removal projections (PAT-832).
func acGetRowWithExtensions(tenantID string, blocklist []agentconfig.ExtensionBlocklistEntry, removals []agentconfig.ExtensionRemovalEntry) agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{
			TenantID:           tenantID,
			ConfigVersion:      1,
			Body:               agentconfig.DefaultConfigBody(),
			IssuedAt:           time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
			AppControlEnabled:  true,
			ExtensionBlocklist: blocklist,
			ExtensionRemovals:  removals,
		}, true, nil
	}
}

// strPtr is a convenience helper for pointer-to-string literals in tests.
func strPtr(s string) *string { return &s }

// intPtr is a convenience helper for pointer-to-int literals in tests.
func intPtr(i int) *int { return &i }

// acGetRowWithBody returns a stub getFn that returns a row carrying the given body.
func acGetRowWithBody(tenantID string, configVersion int, body agentconfig.ConfigBody) agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: configVersion,
			Body:          body,
			IssuedAt:      time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
		}, true, nil
	}
}

// TestBlockingProcessPolicy_PutPersistGetRoundTrip is the PAT-296 end-to-end proof:
// a PUT with a blocking_process_policy is materialised into the stored ConfigBody,
// and feeding that exact stored body back through the GET handler surfaces the
// policy inside the signed, verifiable canonical payload with the same values.
func TestBlockingProcessPolicy_PutPersistGetRoundTrip(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{TenantID: tenantID, ConfigVersion: 2, Body: body, IssuedAt: time.Now().UTC()}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	putBody := `{
		"tier": "managed",
		"proxy": {"mode": "system", "bypass_when_off_corp": false},
		"blocking_process_policy": {
			"action_on_timeout": "prompt_then_quit",
			"timeout_seconds": 600,
			"max_deferrals": 0,
			"defer_window_seconds": 1800,
			"message": "Close the app to update."
		}
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The stored body must carry the materialised policy.
	if capturedBody.BlockingProcessPolicy == nil {
		t.Fatal("stored body must contain blocking_process_policy after PUT")
	}
	if got := capturedBody.BlockingProcessPolicy.ActionOnTimeout; got != "prompt_then_quit" {
		t.Errorf("stored action_on_timeout: want prompt_then_quit, got %q", got)
	}

	// Now GET, using the stored body, and assert the signed payload carries it.
	getHandler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRowWithBody(acTestTenantID, 2, capturedBody), nil, 0, nil)
	getReq := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	getRR := httptest.NewRecorder()
	getHandler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET want 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	var resp agentConfigResp
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key) // also verifies the signature
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed payload: %v", err)
	}
	bpp, ok := cfg["blocking_process_policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("signed payload must contain blocking_process_policy object, got %v", cfg["blocking_process_policy"])
	}
	if bpp["action_on_timeout"] != "prompt_then_quit" {
		t.Errorf("action_on_timeout: want prompt_then_quit, got %v", bpp["action_on_timeout"])
	}
	if v, _ := bpp["timeout_seconds"].(float64); int(v) != 600 {
		t.Errorf("timeout_seconds: want 600, got %v", bpp["timeout_seconds"])
	}
	if v, _ := bpp["defer_window_seconds"].(float64); int(v) != 1800 {
		t.Errorf("defer_window_seconds: want 1800, got %v", bpp["defer_window_seconds"])
	}
	if v, ok := bpp["max_deferrals"].(float64); !ok || int(v) != 0 {
		t.Errorf("max_deferrals: want 0, got %v", bpp["max_deferrals"])
	}
	if bpp["message"] != "Close the app to update." {
		t.Errorf("message: want the custom copy, got %v", bpp["message"])
	}
}

// TestBlockingProcessPolicy_DefaultActionWhenUnset asserts that a PUT which sets a
// policy but omits action_on_timeout stores the safe "notify_only" default, and
// fills the numeric fields with their schema defaults — the agent must never be
// told to force-quit by an incompletely-specified policy.
func TestBlockingProcessPolicy_DefaultActionWhenUnset(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{TenantID: tenantID, ConfigVersion: 1, Body: body, IssuedAt: time.Now().UTC()}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	// Policy object present but action_on_timeout (and numerics) omitted.
	putBody := `{"tier":"managed","proxy":{"mode":"system"},"blocking_process_policy":{"message":"Please close."}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	p := capturedBody.BlockingProcessPolicy
	if p == nil {
		t.Fatal("policy must be materialised")
	}
	if p.ActionOnTimeout != "notify_only" {
		t.Errorf("action_on_timeout default: want notify_only, got %q", p.ActionOnTimeout)
	}
	if p.TimeoutSeconds != 300 || p.MaxDeferrals != 2 || p.DeferWindowSeconds != 3600 {
		t.Errorf("numeric defaults wrong: %+v", p)
	}
}

// TestBlockingProcessPolicy_ClearedOnOmit asserts that a PUT omitting the policy
// stores nil (clears it) — same clear-on-omit semantics as os_update_policy.
func TestBlockingProcessPolicy_ClearedOnOmit(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{TenantID: tenantID, ConfigVersion: 1, Body: body, IssuedAt: time.Now().UTC()}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	putBody := `{"tier":"managed","proxy":{"mode":"system"}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if capturedBody.BlockingProcessPolicy != nil {
		t.Errorf("policy must be nil when omitted, got %+v", capturedBody.BlockingProcessPolicy)
	}
}

// TestBlockingProcessPolicy_AbsentFromSignedPayload asserts that a tenant with no
// policy gets a signed payload with NO blocking_process_policy key — the
// backward-compat guarantee at the handler level (existing agents unaffected).
func TestBlockingProcessPolicy_AbsentFromSignedPayload(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 1), nil, 0, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)
	if strings.Contains(string(raw), "blocking_process_policy") {
		t.Errorf("signed payload must not contain blocking_process_policy when unset: %s", raw)
	}
}

// TestBlockedVersions_PutPersistGetRoundTrip is the PAT-1238 end-to-end proof:
// a PUT with blocked_versions is stored verbatim in ConfigBody, and feeding that
// exact stored body back through the GET handler surfaces it inside the signed,
// verifiable canonical payload with the same label/version data.
func TestBlockedVersions_PutPersistGetRoundTrip(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{TenantID: tenantID, ConfigVersion: 2, Body: body, IssuedAt: time.Now().UTC()}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	putBody := `{
		"tier": "managed",
		"proxy": {"mode": "system"},
		"blocked_versions": {
			"google-chrome": ["139.0.7258.67", "139.0.7258.68"],
			"1password": ["8.10.40"]
		}
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The stored body must carry the map verbatim.
	if got := capturedBody.BlockedVersions["google-chrome"]; len(got) != 2 || got[0] != "139.0.7258.67" || got[1] != "139.0.7258.68" {
		t.Errorf("stored blocked_versions[google-chrome]: got %v", got)
	}
	if got := capturedBody.BlockedVersions["1password"]; len(got) != 1 || got[0] != "8.10.40" {
		t.Errorf("stored blocked_versions[1password]: got %v", got)
	}

	// Now GET, using the stored body, and assert the signed payload carries it.
	getHandler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRowWithBody(acTestTenantID, 2, capturedBody), nil, 0, nil)
	getReq := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	getRR := httptest.NewRecorder()
	getHandler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET want 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	var resp agentConfigResp
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key) // also verifies the signature
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed payload: %v", err)
	}
	bv, ok := cfg["blocked_versions"].(map[string]interface{})
	if !ok {
		t.Fatalf("signed payload must contain blocked_versions object, got %v", cfg["blocked_versions"])
	}
	chromeVersions, ok := bv["google-chrome"].([]interface{})
	if !ok || len(chromeVersions) != 2 {
		t.Fatalf("signed payload blocked_versions[google-chrome]: got %v", bv["google-chrome"])
	}
	if chromeVersions[0] != "139.0.7258.67" || chromeVersions[1] != "139.0.7258.68" {
		t.Errorf("signed payload blocked_versions[google-chrome] values: got %v", chromeVersions)
	}
}

// TestBlockedVersions_ClearedOnOmit asserts full-replace semantics (PAT-1238):
// a PUT that omits blocked_versions clears any previously-set value, matching
// every other general field on this endpoint that has no special
// preserve-on-omit precedent (unlike ring_promotions/update_channel).
func TestBlockedVersions_ClearedOnOmit(t *testing.T) {
	key := newTestSigningKey()

	// Existing stored body already has a blocked_versions map set.
	existingBody := agentconfig.DefaultConfigBody()
	existingBody.BlockedVersions = map[string][]string{"google-chrome": {"139.0.7258.67"}}
	getExistingFn := acGetRowWithBody(acTestTenantID, 1, existingBody)

	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{TenantID: tenantID, ConfigVersion: 2, Body: body, IssuedAt: time.Now().UTC()}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, getExistingFn, upsertFn)

	// PUT omits blocked_versions entirely.
	putBody := `{"tier":"managed","proxy":{"mode":"system"}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(capturedBody.BlockedVersions) != 0 {
		t.Errorf("blocked_versions must be cleared when omitted (full-replace), got %+v", capturedBody.BlockedVersions)
	}
}

// TestAdminAgentConfigPut_RejectsMalformedBlockedVersions asserts the write path
// returns 400 for malformed blocked_versions entries (PAT-1238) — an empty
// label and an empty version string, exercised through the actual HTTP handler
// (not just validateAgentConfigReq directly) so the wiring is proven too.
func TestAdminAgentConfigPut_RejectsMalformedBlockedVersions(t *testing.T) {
	key := newTestSigningKey()
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		t.Fatal("upsertFn must not be called when validation fails")
		return agentConfigRow{}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "empty label",
			body: `{"tier":"managed","proxy":{"mode":"system"},"blocked_versions":{"":["1.2.3"]}}`,
		},
		{
			name: "empty version string",
			body: `{"tier":"managed","proxy":{"mode":"system"},"blocked_versions":{"google-chrome":["1.2.3",""]}}`,
		},
		{
			name: "empty version list",
			body: `{"tier":"managed","proxy":{"mode":"system"},"blocked_versions":{"google-chrome":[]}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = acWithTenantID(req, acTestTenantID)
			rr := httptest.NewRecorder()
			putHandler.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("want 400, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestAgentConfigGet_AppControlInPayload asserts that the signed payload always
// contains an app_control block with the expected structure, and that
// AppControlEnabled=true flows through to enabled=true in the payload.
func TestAgentConfigGet_AppControlInPayload(t *testing.T) {
	key := newTestSigningKey()

	tests := []struct {
		name        string
		acEnabled   bool
		wantEnabled bool
	}{
		{"ac disabled (default)", false, false},
		{"ac enabled", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRowWithAC(acTestTenantID, 1, tc.acEnabled), nil, 0, nil)

			req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
			}

			var resp agentConfigResp
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode body: %v", err)
			}

			raw := decodeSignedPayload(t, resp, key)

			var cfg map[string]interface{}
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("unmarshal signed_payload: %v", err)
			}

			acRaw, ok := cfg["app_control"]
			if !ok {
				t.Fatal("app_control must be present in the signed payload")
			}
			ac, ok := acRaw.(map[string]interface{})
			if !ok {
				t.Fatalf("app_control must be an object, got %T", acRaw)
			}
			if enabled, _ := ac["enabled"].(bool); enabled != tc.wantEnabled {
				t.Errorf("app_control.enabled: want %v, got %v", tc.wantEnabled, enabled)
			}
			if al, ok := ac["app_allowlist"].([]interface{}); !ok || len(al) != 0 {
				t.Errorf("app_control.app_allowlist must be an empty array, got %v", ac["app_allowlist"])
			}
			if aa, ok := ac["approved_admins"].([]interface{}); !ok || len(aa) != 0 {
				t.Errorf("app_control.approved_admins must be an empty array, got %v", ac["approved_admins"])
			}
		})
	}
}

// TestAgentConfigGet_AppControlListsInPayload asserts that non-empty AC lists
// flow from agentConfigRow through Sign() into the signed canonical payload (PAT-602).
func TestAgentConfigGet_AppControlListsInPayload(t *testing.T) {
	key := newTestSigningKey()
	admins := []string{"alice", `DOMAIN\bob`}
	allowlist := []string{"com.apple.Safari", "chrome.exe"}
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
		acGetRowWithACLists(acTestTenantID, admins, allowlist), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)

	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	ac, ok := cfg["app_control"].(map[string]interface{})
	if !ok {
		t.Fatal("app_control must be present in signed payload")
	}
	if enabled, _ := ac["enabled"].(bool); !enabled {
		t.Error("app_control.enabled: want true")
	}
	gotAdmins, _ := ac["approved_admins"].([]interface{})
	if len(gotAdmins) != 2 {
		t.Errorf("approved_admins: want 2, got %d (%v)", len(gotAdmins), gotAdmins)
	}
	gotAllowlist, _ := ac["app_allowlist"].([]interface{})
	if len(gotAllowlist) != 2 {
		t.Errorf("app_allowlist: want 2, got %d (%v)", len(gotAllowlist), gotAllowlist)
	}
}

// TestAgentConfigGet_ExtensionFieldsDefaultEmpty asserts that a tenant with no
// extension policies/removals still gets app_control.extension_blocklist and
// extension_removals present as empty arrays (PAT-832) — the agent's fail-safe
// "enforce/remove nothing" default, matching the app_allowlist convention.
func TestAgentConfigGet_ExtensionFieldsDefaultEmpty(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
		acGetRowWithAC(acTestTenantID, 1, true), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	ac, ok := cfg["app_control"].(map[string]interface{})
	if !ok {
		t.Fatal("app_control must be present")
	}
	if bl, ok := ac["extension_blocklist"].([]interface{}); !ok || len(bl) != 0 {
		t.Errorf("extension_blocklist must be an empty array, got %v", ac["extension_blocklist"])
	}
	if rm, ok := ac["extension_removals"].([]interface{}); !ok || len(rm) != 0 {
		t.Errorf("extension_removals must be an empty array, got %v", ac["extension_removals"])
	}
}

// acGetRowWithDecommission returns a stub getFn with an explicit Decommission
// policy set on the row, mirroring acGetRowWithAC's shape for app_control.
func acGetRowWithDecommission(tenantID string, configVersion int, d agentconfig.DecommissionPolicy) agentConfigGetFn {
	return func(_ context.Context, _ string) (agentConfigRow, bool, error) {
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: configVersion,
			Body:          agentconfig.DefaultConfigBody(),
			IssuedAt:      time.Date(2026, 12, 10, 12, 0, 0, 0, time.UTC),
			Decommission:  d,
		}, true, nil
	}
}

// TestAgentConfigGet_DecommissionAbsent_DefaultsToNone is the acceptance-
// criterion proof that "an agent-config with no decommission object behaves
// exactly as today": a row with the zero-value Decommission field (exactly
// what dbGetAgentConfig produces for a tenant with no tenant_decommission
// row, PAT-1108) must serve mode="none" in the signed payload, with the key
// always present (never omitted, unlike blocking_process_policy) — "no
// directive" and "mode=none" are the same signed bytes by construction.
func TestAgentConfigGet_DecommissionAbsent_DefaultsToNone(t *testing.T) {
	key := newTestSigningKey()
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 1), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)

	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	decRaw, ok := cfg["decommission"]
	if !ok {
		t.Fatal("decommission must be present in the signed payload even when absent from the row")
	}
	dec, ok := decRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("decommission must be an object, got %T", decRaw)
	}
	if mode, _ := dec["mode"].(string); mode != "none" {
		t.Errorf("decommission.mode = %q, want \"none\"", mode)
	}
	if dec["expires_at"] != nil {
		t.Errorf("decommission.expires_at = %v, want nil", dec["expires_at"])
	}
	if purge, _ := dec["purge"].(bool); purge {
		t.Error("decommission.purge = true, want false")
	}
	if dec["reason"] != nil {
		t.Errorf("decommission.reason = %v, want nil", dec["reason"])
	}
}

// TestAgentConfigGet_DecommissionEnumValues covers every enum value
// (none/expiry/immediate) flowing from agentConfigRow through Sign() into the
// signed payload, per the contract-test acceptance criterion.
func TestAgentConfigGet_DecommissionEnumValues(t *testing.T) {
	key := newTestSigningKey()
	expiresAt := "2026-09-01T00:00:00Z"
	reason := "tenant offboarded"

	tests := []struct {
		name string
		in   agentconfig.DecommissionPolicy
	}{
		{"none", agentconfig.DecommissionPolicy{Mode: "none"}},
		{"expiry", agentconfig.DecommissionPolicy{Mode: "expiry", ExpiresAt: &expiresAt, Reason: &reason}},
		{"immediate", agentconfig.DecommissionPolicy{Mode: "immediate", Purge: true, Reason: &reason}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
				acGetRowWithDecommission(acTestTenantID, 1, tc.in), nil, 0, nil)

			req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
			}

			var resp agentConfigResp
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			raw := decodeSignedPayload(t, resp, key)
			var cfg map[string]interface{}
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			dec, ok := cfg["decommission"].(map[string]interface{})
			if !ok {
				t.Fatal("decommission must be present")
			}
			if mode, _ := dec["mode"].(string); mode != tc.in.Mode {
				t.Errorf("decommission.mode = %q, want %q", mode, tc.in.Mode)
			}
		})
	}
}

// TestAgentConfigGet_ExtensionFieldsPopulated asserts that projected blocklist and
// removal entries flow from agentConfigRow through Sign() into the signed payload
// with the exact agent contract shape (PAT-828/PAT-829), including null
// user_account/profile for device-wide scopes and set values for narrow scopes.
func TestAgentConfigGet_ExtensionFieldsPopulated(t *testing.T) {
	key := newTestSigningKey()
	blocklist := []agentconfig.ExtensionBlocklistEntry{
		{Browser: "chrome", ExtensionID: "aaaabbbbccccdddd"},
		{Browser: "firefox", ExtensionID: "evil@example.com"},
	}
	removals := []agentconfig.ExtensionRemovalEntry{
		{Browser: "chrome", ExtensionID: "aaaabbbbccccdddd", Scope: "one_profile",
			UserAccount: strPtr(`MACHINE\alice`), Profile: strPtr("Default")},
		{Browser: "edge", ExtensionID: "eeeeffffgggghhhh", Scope: "all_devices"},
	}
	handler := newAgentConfigHandler(key, acAuthAlways(acTestTenantID),
		acGetRowWithExtensions(acTestTenantID, blocklist, removals), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	raw := decodeSignedPayload(t, resp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	ac := cfg["app_control"].(map[string]interface{})

	bl, _ := ac["extension_blocklist"].([]interface{})
	if len(bl) != 2 {
		t.Fatalf("extension_blocklist: want 2, got %d (%v)", len(bl), bl)
	}
	first := bl[0].(map[string]interface{})
	if first["browser"] != "chrome" || first["extension_id"] != "aaaabbbbccccdddd" {
		t.Errorf("blocklist[0]: want chrome/aaaabbbbccccdddd, got %v", first)
	}

	rm, _ := ac["extension_removals"].([]interface{})
	if len(rm) != 2 {
		t.Fatalf("extension_removals: want 2, got %d (%v)", len(rm), rm)
	}
	narrow := rm[0].(map[string]interface{})
	if narrow["scope"] != "one_profile" || narrow["user_account"] != `MACHINE\alice` || narrow["profile"] != "Default" {
		t.Errorf("removals[0] narrow scope context wrong: %v", narrow)
	}
	wide := rm[1].(map[string]interface{})
	if wide["scope"] != "all_devices" {
		t.Errorf("removals[1]: want scope all_devices, got %v", wide["scope"])
	}
	// Device-wide scopes carry no target context — must serialise as null, not omitted.
	if v, ok := wide["user_account"]; !ok || v != nil {
		t.Errorf("removals[1].user_account must be present and null, got %v (present=%v)", v, ok)
	}
	if v, ok := wide["profile"]; !ok || v != nil {
		t.Errorf("removals[1].profile must be present and null, got %v (present=%v)", v, ok)
	}
}

// TestAdminAgentConfigPut_WithOsUpdatePolicy asserts that a PUT with
// os_update_policy enabled writes the policy fields into the config body
// and that they appear in the signed canonical payload.
func TestAdminAgentConfigPut_WithOsUpdatePolicy(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: 1,
			Body:          body,
			IssuedAt:      time.Now().UTC(),
		}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	body := `{
		"tier": "managed",
		"proxy": {"mode": "system", "bypass_when_off_corp": false},
		"os_update_policy": {
			"enabled": true,
			"grace_days": 14,
			"deferral_budget": 5,
			"defer_interval_hours": 24,
			"blocking_window_days": 3,
			"minimum_age_days": 7,
			"exploited_overrides_age": true
		}
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify that OsUpdatePolicy in the captured body is non-null and contains
	// the expected fields.
	if string(capturedBody.OsUpdatePolicy) == "null" {
		t.Fatal("expected OsUpdatePolicy to be non-null in captured config body")
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(capturedBody.OsUpdatePolicy, &policy); err != nil {
		t.Fatalf("unmarshal captured OsUpdatePolicy: %v", err)
	}
	if v, _ := policy["grace_days"].(float64); int(v) != 14 {
		t.Errorf("grace_days: want 14, got %v", policy["grace_days"])
	}
	if v, _ := policy["deferral_budget"].(float64); int(v) != 5 {
		t.Errorf("deferral_budget: want 5, got %v", policy["deferral_budget"])
	}
	if v, _ := policy["defer_interval_hours"].(float64); int(v) != 24 {
		t.Errorf("defer_interval_hours: want 24, got %v", policy["defer_interval_hours"])
	}
	if v, _ := policy["blocking_window_days"].(float64); int(v) != 3 {
		t.Errorf("blocking_window_days: want 3, got %v", policy["blocking_window_days"])
	}
	if v, _ := policy["minimum_age_days"].(float64); int(v) != 7 {
		t.Errorf("minimum_age_days: want 7, got %v", policy["minimum_age_days"])
	}
	if v, _ := policy["exploited_overrides_age"].(bool); !v {
		t.Errorf("exploited_overrides_age: want true, got %v", policy["exploited_overrides_age"])
	}
	// target_os must be present as null (contract requirement).
	if _, ok := policy["target_os"]; !ok {
		t.Error("target_os key must be present in os_update_policy wire shape")
	}
}

// TestAdminAgentConfigPut_OsUpdatePolicyOmitted asserts that a PUT without
// os_update_policy (or with enabled=false) stores null in the config body.
func TestAdminAgentConfigPut_OsUpdatePolicyOmitted(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: 1,
			Body:          body,
			IssuedAt:      time.Now().UTC(),
		}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	body := `{"tier":"managed","proxy":{"mode":"system","bypass_when_off_corp":false}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if string(capturedBody.OsUpdatePolicy) != "null" {
		t.Errorf("want OsUpdatePolicy=null when omitted, got %s", capturedBody.OsUpdatePolicy)
	}
}

// TestAdminAgentConfigPut_OsUpdatePolicyDisabled asserts that a PUT with
// os_update_policy.enabled=false stores null (clears any active policy).
func TestAdminAgentConfigPut_OsUpdatePolicyDisabled(t *testing.T) {
	key := newTestSigningKey()
	var capturedBody agentconfig.ConfigBody
	upsertFn := func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
		capturedBody = body
		return agentConfigRow{
			TenantID:      tenantID,
			ConfigVersion: 2,
			Body:          body,
			IssuedAt:      time.Now().UTC(),
		}, nil
	}
	existsFn := func(_ context.Context, _ string) (bool, error) { return true, nil }
	putHandler := newAdminAgentConfigPutHandler(key, existsFn, acGetEmpty(), upsertFn)

	body := `{
		"tier": "assurance",
		"proxy": {"mode": "system", "bypass_when_off_corp": false},
		"os_update_policy": {"enabled": false}
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	putHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if string(capturedBody.OsUpdatePolicy) != "null" {
		t.Errorf("want OsUpdatePolicy=null when disabled, got %s", capturedBody.OsUpdatePolicy)
	}
}
