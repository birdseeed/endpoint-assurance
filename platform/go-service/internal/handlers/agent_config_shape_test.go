package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/auth"
)

// agentConfigShapeGolden is the normalised signed payload the production
// GET /v1/agent-config handler served to a tenant-zero-like device before
// PAT-2246 retired the signed catalogue and the mandatory-install delivery
// path that read it. It was captured from the pre-change handler and must not
// move: retiring server-side authority must leave the signed bytes agents
// verify exactly as they were. Only per-run identifiers (tenant_id,
// device_id, issued_at) are replaced with placeholders; everything else,
// including key order, is compared byte for byte.
//
// mandatory_install_intents is absent here and must stay absent: the field is
// omitempty and production already served no intents (legacy execution is
// quarantined), so agents have never received it from this handler.
const agentConfigShapeGolden = `{"app_control":{"app_allowlist":[],"approved_admins":[],"enabled":false,"extension_blocklist":[],"extension_removals":[]},"app_control_authority":"enforce","blocked_versions":{"googlechrome":["129.0.1"]},"catalog_scope":null,"config_version":8,"decommission":{"expires_at":null,"mode":"none","purge":false,"reason":null},"device_id":"<device_id>","issued_at":"<issued_at>","legacy_app_execution_enabled":false,"log_request":null,"os_update_policy":{"deadline":null,"target_os":null,"grace_days":14,"deferral_budget":3,"minimum_age_days":7,"blocking_window_days":2,"defer_interval_hours":24,"exploited_overrides_age":true},"per_app_patch":null,"pinned_version":null,"proxy":{"auth_ref":null,"bypass_when_off_corp":false,"host":null,"mode":"system","pac_url":null,"port":null,"type":null},"report_user_attribution":"off","ring":1,"ring_promotions":null,"ring_promotions_scoped":{"macos":null,"windows":null},"scan_cadence":null,"tenant_id":"<tenant_id>","tier":"report_deploy","update_channel":"stable","update_channel_source":"tenant"}`

// agentConfigShapeTenantWideGolden is the same capture for the tenant-wide
// credential path (device_id empty, ring defaulted to GA).
const agentConfigShapeTenantWideGolden = `{"app_control":{"app_allowlist":[],"approved_admins":[],"enabled":false,"extension_blocklist":[],"extension_removals":[]},"app_control_authority":"enforce","blocked_versions":{"googlechrome":["129.0.1"]},"catalog_scope":null,"config_version":8,"decommission":{"expires_at":null,"mode":"none","purge":false,"reason":null},"device_id":"","issued_at":"<issued_at>","legacy_app_execution_enabled":false,"log_request":null,"os_update_policy":{"deadline":null,"target_os":null,"grace_days":14,"deferral_budget":3,"minimum_age_days":7,"blocking_window_days":2,"defer_interval_hours":24,"exploited_overrides_age":true},"per_app_patch":null,"pinned_version":null,"proxy":{"auth_ref":null,"bypass_when_off_corp":false,"host":null,"mode":"system","pac_url":null,"port":null,"type":null},"report_user_attribution":"off","ring":3,"ring_promotions":null,"ring_promotions_scoped":{"macos":null,"windows":null},"scan_cadence":null,"tenant_id":"<tenant_id>","tier":"report_deploy","update_channel":"stable"}`

func normaliseAgentConfigShape(t *testing.T, canonical []byte, tenantID, deviceID string) string {
	t.Helper()
	var issued struct {
		IssuedAt string `json:"issued_at"`
	}
	if err := json.Unmarshal(canonical, &issued); err != nil {
		t.Fatalf("decode canonical payload: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, issued.IssuedAt); err != nil {
		t.Fatalf("issued_at %q is not RFC3339: %v", issued.IssuedAt, err)
	}
	out := string(canonical)
	out = strings.ReplaceAll(out, `"issued_at":"`+issued.IssuedAt+`"`, `"issued_at":"<issued_at>"`)
	out = strings.ReplaceAll(out, tenantID, "<tenant_id>")
	if deviceID != "" {
		out = strings.ReplaceAll(out, deviceID, "<device_id>")
	}
	// windows_installation_evidence is a global, time-bounded projection of
	// the migration-seeded evidence catalogue (it lapses at its expires_at),
	// not tenant config, and is covered by agent_config_evidence_test.go. It
	// is the canonical payload's last key; drop it so this pin cannot rot on
	// a calendar date or an unrelated evidence migration.
	if i := strings.Index(out, `,"windows_installation_evidence":`); i >= 0 {
		out = out[:i] + "}"
	}
	return out
}

func getAgentConfigShape(t *testing.T, h http.Handler, bearer, secret, ifNoneMatch string) (*httptest.ResponseRecorder, agentConfigResp, []byte) {
	t.Helper()
	req := aadV3Request(t, http.MethodGet, "/v1/agent-config", auth.EndpointAgentConfig, bearer, secret)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		return rr, agentConfigResp{}, nil
	}
	var env agentConfigResp
	dec := json.NewDecoder(bytes.NewReader(rr.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v (%s)", err, rr.Body.String())
	}
	canonical, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	return rr, env, canonical
}

// TestAgentConfigSignedShapeStableAcrossCatalogueRetirement drives the
// production AgentConfigHandler against a real database for a tenant-zero-like
// tenant (managed tier, an existing stored config at a non-trivial version, a
// device with a ring override) and pins the complete signed response: envelope
// keys, signature validity, key id, headers, the normalised canonical payload,
// and the anti-rollback behaviour of config_version across the quarantine
// activation and a repeat poll (PAT-2246).
func TestAgentConfigSignedShapeStableAcrossCatalogueRetirement(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		tenantBearer = "pat2246-shape-tenant-token"
		tenantSecret = "pat2246-shape-tenant-hmac"
		deviceBearer = "pat2246-shape-device-token"
		deviceSecret = "pat2246-shape-device-hmac"
		storedVer    = 7
	)
	tenantID := parSeedTenant(t, ctx, pool, "pat2246-shape-tenant-zero", tenantBearer, tenantSecret)
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "2246aaaa-0000-4000-8000-000000002246", "tenant-zero-mac")
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, deviceBearer, deviceSecret)
	if _, err := pool.Exec(ctx, `UPDATE devices SET ring_override = 1 WHERE id = $1::uuid`, deviceID); err != nil {
		t.Fatalf("set ring override: %v", err)
	}

	body := agentconfig.DefaultConfigBody()
	body.Tier = "managed"
	body.UpdateChannel = "stable"
	body.OsUpdatePolicy = json.RawMessage(`{"target_os":null,"minimum_age_days":7,"grace_days":14,"deadline":null,"deferral_budget":3,"defer_interval_hours":24,"blocking_window_days":2,"exploited_overrides_age":true}`)
	body.BlockedVersions = map[string][]string{"googlechrome": {"129.0.1"}}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, $2, $3::jsonb, now() - interval '1 day', 'pat2246-shape-test')
	`, tenantID, storedVer, bodyJSON); err != nil {
		t.Fatalf("insert agent_config: %v", err)
	}

	key := newTestSigningKey()
	h := AgentConfigHandler(pool, key, nil, time.Minute)

	rr, env, canonical := getAgentConfigShape(t, h, deviceBearer, deviceSecret, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("device GET status = %d: %s", rr.Code, rr.Body.String())
	}
	if err := agentconfig.Verify(key.Public, canonical, env.Signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if env.KeyID != key.KeyID {
		t.Fatalf("key_id = %q, want %q", env.KeyID, key.KeyID)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	etag := rr.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"v8-r1-`) {
		t.Fatalf("ETag = %q, want config_version 8 (stored 7 + one quarantine activation) and ring 1", etag)
	}
	if strings.Contains(string(canonical), "mandatory_install") {
		t.Fatalf("signed payload carries a mandatory-install field: %s", canonical)
	}
	if got := normaliseAgentConfigShape(t, canonical, tenantID, deviceID); got != agentConfigShapeGolden {
		t.Fatalf("device-scoped signed payload changed shape.\n got: %s\nwant: %s", got, agentConfigShapeGolden)
	}

	// Anti-rollback: a repeat poll from the same process must neither advance
	// nor regress config_version, and must sign identical bytes.
	rr2, env2, canonical2 := getAgentConfigShape(t, h, deviceBearer, deviceSecret, "")
	if rr2.Code != http.StatusOK {
		t.Fatalf("repeat device GET status = %d: %s", rr2.Code, rr2.Body.String())
	}
	if !bytes.Equal(canonical, canonical2) || rr2.Header().Get("ETag") != etag || env2.Signature != env.Signature {
		t.Fatalf("repeat poll changed the signed response:\nfirst:  %s\nrepeat: %s", canonical, canonical2)
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&stored); err != nil || stored != 8 {
		t.Fatalf("durable config_version = %d (err %v), want 8", stored, err)
	}

	// Conditional GET with the served ETag is a bodyless 304.
	rr304, _, _ := getAgentConfigShape(t, h, deviceBearer, deviceSecret, etag)
	if rr304.Code != http.StatusNotModified || rr304.Body.Len() != 0 {
		t.Fatalf("If-None-Match status = %d body=%q, want bodyless 304", rr304.Code, rr304.Body.String())
	}

	rrT, envT, canonicalT := getAgentConfigShape(t, h, tenantBearer, tenantSecret, "")
	if rrT.Code != http.StatusOK {
		t.Fatalf("tenant-wide GET status = %d: %s", rrT.Code, rrT.Body.String())
	}
	if err := agentconfig.Verify(key.Public, canonicalT, envT.Signature); err != nil {
		t.Fatalf("tenant-wide signature does not verify: %v", err)
	}
	if !strings.HasPrefix(rrT.Header().Get("ETag"), `"v8-r3-`) {
		t.Fatalf("tenant-wide ETag = %q, want v8-r3", rrT.Header().Get("ETag"))
	}
	if got := normaliseAgentConfigShape(t, canonicalT, tenantID, ""); got != agentConfigShapeTenantWideGolden {
		t.Fatalf("tenant-wide signed payload changed shape.\n got: %s\nwant: %s", got, agentConfigShapeTenantWideGolden)
	}
}
