package handlers

// Tests for PAT-1252: GET /v1/agent/artifact and POST /admin/agent-versions
// grow the additive artifact_metadata_signature envelope (the server half of
// PAT-1248, Patched-LTD/updater commit daf68734). Reuses the
// parConnectOrSkip/parSeedTenant/aavtCleanupVersion/aavtSignedGET scaffolding
// already established for this handler by the PAT-1233 tests
// (agent_artifact_test.go) rather than inventing new helpers.
//
// Covers the ticket's five acceptance criteria:
//  1. A release registered with a well-formed envelope round-trips
//     byte-identical on GET.
//  2. A release registered without one still registers, and GET
//     omits the field rather than erroring or fabricating one.
//  3. A malformed envelope is rejected 400 on registration and never stored.
//  4. Every existing response field is unchanged and still populated.
//  5. A pre-existing row with no envelope (seeded directly, bypassing the
//     handler — standing in for a row that existed before this migration)
//     continues to serve correctly.
//
// The server never holds ARTIFACT_SIGNING_KEY and so never verifies the
// Ed25519 signature itself (see agent_artifact.go's package-level design
// note) — these tests build syntactically well-formed (or deliberately
// malformed) envelopes with arbitrary base64/hex content, not real
// signatures, exactly matching what patched-api can and cannot check.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/ratelimit"
)

// aaetEnvelope builds a well-formed {signed_payload, signature, key_id}
// envelope as compact JSON — the same shape validateArtifactMetadataSignature
// checks and json.Compact would produce from any equivalent input, so tests
// asserting byte-identical round trips can compare directly against these
// bytes without a separate compaction step.
func aaetEnvelope(t *testing.T, payload, sig, keyID string) json.RawMessage {
	t.Helper()
	env := struct {
		SignedPayload string `json:"signed_payload"`
		Signature     string `json:"signature"`
		KeyID         string `json:"key_id"`
	}{
		SignedPayload: base64.StdEncoding.EncodeToString([]byte(payload)),
		Signature:     base64.StdEncoding.EncodeToString([]byte(sig)),
		KeyID:         keyID,
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal test envelope: %v", err)
	}
	return json.RawMessage(b)
}

// TestAdminRegisterAgentVersionHandler_ArtifactMetadataSignatureRoundTrips
// covers acceptance criteria 1 and 4: a release registered with a
// well-formed envelope round-trips byte-identical on GET, and every
// pre-existing field (version, artifact_url, artifact_sha256, artifact_hmac,
// published_at) is still populated exactly as before.
func TestAdminRegisterAgentVersionHandler_ArtifactMetadataSignatureRoundTrips(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const platform = "windows"
	const channel = "beta"
	const version = "1252.0.0-roundtrip"
	aavtCleanupVersion(t, ctx, pool, platform, channel, version)

	envelope := aaetEnvelope(t,
		`{"version":"1252.0.0-roundtrip","platform":"windows","channel":"beta","artifact_url":"https://cdn.patched.im/windows/1252.0.0/PatchedAgent.zip","artifact_sha256":"`+strings.Repeat("a", 64)+`"}`,
		"deadbeef-signature-bytes",
		"ecd47f2c5b3d5705",
	)

	req := adminRegisterVersionReq{
		Platform:                  platform,
		Channel:                   channel,
		Version:                   version,
		ArtifactURL:               "https://cdn.patched.im/windows/1252.0.0/PatchedAgent.zip",
		ArtifactSHA256:            strings.Repeat("a", 64),
		ArtifactHMAC:              strings.Repeat("b", 64),
		ArtifactMetadataSignature: envelope,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/admin/agent-versions", strings.NewReader(string(body)))
	postRR := httptest.NewRecorder()
	AdminRegisterAgentVersionHandler(pool).ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201: %s", postRR.Code, postRR.Body.String())
	}

	bearerToken := "pat1252-roundtrip-token"
	hmacSecret := "pat1252-roundtrip-hmac-secret-32b!"
	parSeedTenant(t, ctx, pool, "pat1252-roundtrip-tenant", bearerToken, hmacSecret)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactHandler(pool, rl, 5*time.Minute)

	getReq := aavtSignedGET(t, "/v1/agent/artifact?platform="+platform+"&channel="+channel+"&version="+version, bearerToken, hmacSecret)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", getRR.Code, getRR.Body.String())
	}

	var resp agentArtifactResp
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, getRR.Body.String())
	}

	// Criterion 4: every pre-existing field is unchanged and populated.
	if resp.Version != version {
		t.Errorf("version = %q, want %q", resp.Version, version)
	}
	if resp.ArtifactURL != req.ArtifactURL {
		t.Errorf("artifact_url = %q, want %q", resp.ArtifactURL, req.ArtifactURL)
	}
	if resp.ArtifactSHA256 != req.ArtifactSHA256 {
		t.Errorf("artifact_sha256 = %q, want %q", resp.ArtifactSHA256, req.ArtifactSHA256)
	}
	if resp.ArtifactHMAC != req.ArtifactHMAC {
		t.Errorf("artifact_hmac = %q, want %q", resp.ArtifactHMAC, req.ArtifactHMAC)
	}
	if resp.PublishedAt == "" {
		t.Error("published_at is empty, want a populated RFC3339 timestamp")
	}

	// Criterion 1: byte-identical round trip. envelope was already compact
	// (json.Marshal of a struct emits no insignificant whitespace), so the
	// server's own json.Compact at write time is a no-op and what comes
	// back out must equal exactly what was sent in.
	if string(resp.ArtifactMetadataSignature) != string(envelope) {
		t.Errorf("artifact_metadata_signature = %s, want byte-identical to %s", resp.ArtifactMetadataSignature, envelope)
	}
}

// TestAdminRegisterAgentVersionHandler_NoEnvelope_StillRegistersAndOmitted
// covers acceptance criterion 2: a release registered without
// artifact_metadata_signature still registers (201), and GET omits the
// field from the response rather than erroring, nulling-with-a-fabricated-
// value, or otherwise inventing content the server has no key to produce.
func TestAdminRegisterAgentVersionHandler_NoEnvelope_StillRegistersAndOmitted(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const platform = "windows"
	const channel = "beta"
	const version = "1252.0.0-no-envelope"
	aavtCleanupVersion(t, ctx, pool, platform, channel, version)

	body := `{
		"platform": "windows",
		"channel": "beta",
		"version": "1252.0.0-no-envelope",
		"artifact_url": "https://cdn.patched.im/windows/1252.0.0-no-envelope/PatchedAgent.zip",
		"artifact_sha256": "` + strings.Repeat("c", 64) + `",
		"artifact_hmac": "` + strings.Repeat("d", 64) + `"
	}`

	postReq := httptest.NewRequest(http.MethodPost, "/admin/agent-versions", strings.NewReader(body))
	postRR := httptest.NewRecorder()
	AdminRegisterAgentVersionHandler(pool).ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201: %s", postRR.Code, postRR.Body.String())
	}

	bearerToken := "pat1252-no-envelope-token"
	hmacSecret := "pat1252-no-envelope-hmac-secret-32b"
	parSeedTenant(t, ctx, pool, "pat1252-no-envelope-tenant", bearerToken, hmacSecret)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactHandler(pool, rl, 5*time.Minute)

	getReq := aavtSignedGET(t, "/v1/agent/artifact?platform="+platform+"&channel="+channel+"&version="+version, bearerToken, hmacSecret)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", getRR.Code, getRR.Body.String())
	}

	// Assert the raw JSON has no artifact_metadata_signature key at all
	// (omitempty), not merely a null value — the strongest form of "do not
	// fabricate": the field is simply absent.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(getRR.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v (body: %s)", err, getRR.Body.String())
	}
	if _, present := raw["artifact_metadata_signature"]; present {
		t.Errorf("artifact_metadata_signature present in response (%s), want omitted entirely", getRR.Body.String())
	}

	var resp agentArtifactResp
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ArtifactMetadataSignature != nil {
		t.Errorf("ArtifactMetadataSignature = %s, want nil", resp.ArtifactMetadataSignature)
	}
	if resp.Version != version || resp.ArtifactURL == "" || resp.ArtifactSHA256 == "" || resp.ArtifactHMAC == "" {
		t.Errorf("legacy fields not fully populated: %+v", resp)
	}
}

// TestAdminRegisterAgentVersionHandler_MalformedArtifactMetadataSignatureRejected
// covers acceptance criterion 3: a malformed envelope is rejected 400 and
// never stored — a subsequent GET (or direct row count) must find nothing,
// not a partially-registered release.
func TestAdminRegisterAgentVersionHandler_MalformedArtifactMetadataSignatureRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	cases := []struct {
		name     string
		envelope string
	}{
		{"not_an_object", `"just a string"`},
		{"missing_key_id", `{"signed_payload":"YQ==","signature":"Yg=="}`},
		{"missing_signature", `{"signed_payload":"YQ==","key_id":"aabbccdd"}`},
		{"missing_signed_payload", `{"signature":"Yg==","key_id":"aabbccdd"}`},
		{"unknown_field", `{"signed_payload":"YQ==","signature":"Yg==","key_id":"aabbccdd","extra":"nope"}`},
		{"duplicate_key", `{"signed_payload":"YQ==","signed_payload":"YQ==","signature":"Yg==","key_id":"aabbccdd"}`},
		{"empty_signed_payload", `{"signed_payload":"","signature":"Yg==","key_id":"aabbccdd"}`},
		{"non_string_key_id", `{"signed_payload":"YQ==","signature":"Yg==","key_id":123}`},
		{"signed_payload_not_base64", `{"signed_payload":"not-valid-base64!!","signature":"Yg==","key_id":"aabbccdd"}`},
		{"signature_not_base64", `{"signed_payload":"YQ==","signature":"not-valid-base64!!","key_id":"aabbccdd"}`},
		{"key_id_not_hex", `{"signed_payload":"YQ==","signature":"Yg==","key_id":"not-hex-zzzz"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := "1252.0.0-malformed-" + tc.name
			aavtCleanupVersion(t, ctx, pool, "windows", "stable", version)

			body := `{
				"platform": "windows",
				"channel": "stable",
				"version": "` + version + `",
				"artifact_url": "https://cdn.patched.im/windows/malformed/PatchedAgent.zip",
				"artifact_sha256": "` + strings.Repeat("e", 64) + `",
				"artifact_hmac": "` + strings.Repeat("f", 64) + `",
				"artifact_metadata_signature": ` + tc.envelope + `
			}`

			postReq := httptest.NewRequest(http.MethodPost, "/admin/agent-versions", strings.NewReader(body))
			postRR := httptest.NewRecorder()
			AdminRegisterAgentVersionHandler(pool).ServeHTTP(postRR, postReq)

			if postRR.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", postRR.Code, postRR.Body.String())
			}

			var count int
			if err := pool.QueryRow(ctx, `
				SELECT count(*) FROM agent_versions WHERE platform = 'windows' AND channel = 'stable' AND version = $1
			`, version).Scan(&count); err != nil {
				t.Fatalf("verify no row persisted: %v", err)
			}
			if count != 0 {
				t.Errorf("agent_versions row count = %d, want 0 (a rejected envelope must not be stored)", count)
			}
		})
	}
}

// TestAgentArtifactHandler_PreExistingRowWithNoEnvelope_ServesCorrectly
// covers acceptance criterion 5: a row seeded directly (standing in for a
// row that existed before this migration, with no envelope at all) must
// continue to serve correctly — 200, legacy fields populated, envelope
// field omitted.
func TestAgentArtifactHandler_PreExistingRowWithNoEnvelope_ServesCorrectly(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1252-preexisting-token"
	hmacSecret := "pat1252-preexisting-hmac-secret-32b"
	parSeedTenant(t, ctx, pool, "pat1252-preexisting-tenant", bearerToken, hmacSecret)

	const platform = "macos"
	const channel = "stable"
	const version = "1252.0.0-preexisting"
	aavtCleanupVersion(t, ctx, pool, platform, channel, version)

	// Seeded directly, bypassing the handler, exactly like every row that
	// existed in the table before 0102 applied — artifact_metadata_signature
	// is left at its column default (NULL), never touched.
	if _, err := pool.Exec(ctx, `
		INSERT INTO agent_versions (platform, channel, version, artifact_url, artifact_sha256, artifact_hmac, released_by)
		VALUES ($1, $2, $3, 'https://cdn.patched.im/macos/1252.0.0/patched-collect.tar.gz', $4, $5, 'ci')
	`, platform, channel, version, strings.Repeat("1", 64), strings.Repeat("2", 64)); err != nil {
		t.Fatalf("seed agent_versions row: %v", err)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactHandler(pool, rl, 5*time.Minute)

	req := aavtSignedGET(t, "/v1/agent/artifact?platform="+platform+"&channel="+channel, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v (body: %s)", err, rr.Body.String())
	}
	if _, present := raw["artifact_metadata_signature"]; present {
		t.Errorf("artifact_metadata_signature present for a no-envelope row (%s), want omitted", rr.Body.String())
	}

	var resp agentArtifactResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Version != version {
		t.Errorf("version = %q, want %q", resp.Version, version)
	}
	if resp.ArtifactURL == "" || resp.ArtifactSHA256 == "" || resp.ArtifactHMAC == "" || resp.PublishedAt == "" {
		t.Errorf("legacy fields not fully populated: %+v", resp)
	}
}
