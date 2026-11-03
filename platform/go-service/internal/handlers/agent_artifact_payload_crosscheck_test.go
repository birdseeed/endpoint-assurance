package handlers

// Tests for PAT-1256: validateArtifactMetadataSignature grows a
// content-agreement cross-check on top of PAT-1252's shape-only check —
// once the {signed_payload, signature, key_id} envelope shape is valid, the
// base64-decoded signed_payload is parsed as JSON and its version, platform,
// and channel fields must agree with the registration request's own fields
// of the same name. Before this ticket, a legitimately-signed envelope for
// one (version, platform, channel) could be registered against an
// agent_versions row declaring entirely different values, because the
// signature covers signed_payload's bytes, not the row it gets attached to.
//
// Two layers of coverage, matching the pattern already established by
// agent_artifact_envelope_test.go (PAT-1252):
//
//  1. TestValidateArtifactMetadataSignature_PayloadCrossCheck exercises the
//     pure function directly — no DB required, runs unconditionally — with
//     one case per acceptance criterion: match, one mismatch per field,
//     invalid JSON, and one missing-field case per field.
//  2. TestAdminRegisterAgentVersionHandler_ArtifactMetadataSignaturePayloadMismatchRejected
//     drives the mismatch cases through the real HTTP handler (DB-backed,
//     skipped without TEST_DATABASE_URL, same aavtCleanupVersion/parConnectOrSkip
//     scaffolding as the rest of this package) to prove the end-to-end
//     acceptance criteria: 400, and nothing persisted. The match and absent
//     cases at the handler level are already covered by
//     TestAdminRegisterAgentVersionHandler_ArtifactMetadataSignatureRoundTrips
//     and TestAdminRegisterAgentVersionHandler_NoEnvelope_StillRegistersAndOmitted
//     respectively (agent_artifact_envelope_test.go) and are not duplicated
//     here.
//
// The server never holds ARTIFACT_SIGNING_KEY and so never verifies the
// Ed25519 signature (see agent_artifact.go's package-level design note) —
// every envelope built here uses arbitrary base64/hex content for signature
// and key_id, exactly matching what patched-api can and cannot check. Only
// signed_payload's decoded JSON content is exercised.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// aapcPayload builds a signed_payload JSON object with the given
// version/platform/channel (plus arbitrary artifact_url/artifact_sha256
// filler, mirroring the real shape documented in
// 0102_agent_versions_artifact_envelope.sql, though the cross-check itself
// ignores those two fields).
func aapcPayload(version, platform, channel string) string {
	return `{"version":"` + version + `","platform":"` + platform + `","channel":"` + channel + `",` +
		`"artifact_url":"https://cdn.patched.im/x/artifact","artifact_sha256":"` + strings.Repeat("a", 64) + `"}`
}

// TestValidateArtifactMetadataSignature_PayloadCrossCheck covers the
// function-level acceptance criteria directly: a matching envelope passes;
// a mismatch on any one of version/platform/channel is rejected naming that
// field; a signed_payload that is valid base64 but not valid JSON is
// rejected; and a signed_payload whose JSON omits any one of the three
// required fields is rejected, rather than silently skipping the
// cross-check.
func TestValidateArtifactMetadataSignature_PayloadCrossCheck(t *testing.T) {
	const (
		expectedVersion  = "0.13.16"
		expectedPlatform = "windows"
		expectedChannel  = "stable"
	)

	cases := []struct {
		name        string
		envelope    json.RawMessage
		wantErr     bool
		errContains string
	}{
		{
			name:     "matches",
			envelope: aaetEnvelope(t, aapcPayload(expectedVersion, expectedPlatform, expectedChannel), "sig-bytes", "aabbccdd"),
			wantErr:  false,
		},
		{
			name:        "version_mismatch",
			envelope:    aaetEnvelope(t, aapcPayload("0.13.17", expectedPlatform, expectedChannel), "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "version",
		},
		{
			name:        "platform_mismatch",
			envelope:    aaetEnvelope(t, aapcPayload(expectedVersion, "macos", expectedChannel), "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "platform",
		},
		{
			name:        "channel_mismatch",
			envelope:    aaetEnvelope(t, aapcPayload(expectedVersion, expectedPlatform, "beta"), "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "channel",
		},
		{
			name:        "signed_payload_not_json",
			envelope:    aaetEnvelope(t, "this is not json at all", "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "JSON",
		},
		{
			name:        "missing_version_field",
			envelope:    aaetEnvelope(t, `{"platform":"windows","channel":"stable"}`, "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "version",
		},
		{
			name:        "missing_platform_field",
			envelope:    aaetEnvelope(t, `{"version":"0.13.16","channel":"stable"}`, "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "platform",
		},
		{
			name:        "missing_channel_field",
			envelope:    aaetEnvelope(t, `{"version":"0.13.16","platform":"windows"}`, "sig-bytes", "aabbccdd"),
			wantErr:     true,
			errContains: "channel",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateArtifactMetadataSignature(tc.envelope, expectedVersion, expectedPlatform, expectedChannel)
			if tc.wantErr && err == nil {
				t.Fatalf("validateArtifactMetadataSignature() = nil error, want error containing %q", tc.errContains)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateArtifactMetadataSignature() = %v, want nil error", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("validateArtifactMetadataSignature() error = %q, want it to contain %q", err.Error(), tc.errContains)
			}
		})
	}
}

// TestAdminRegisterAgentVersionHandler_ArtifactMetadataSignaturePayloadMismatchRejected
// drives the three mismatch cases through the real POST /admin/agent-versions
// handler: a well-formed, well-shaped envelope whose decoded signed_payload
// disagrees with the request on version, platform, or channel must be
// rejected 400, and — critically — nothing must be stored. Mirrors
// TestAdminRegisterAgentVersionHandler_MalformedArtifactMetadataSignatureRejected's
// structure (agent_artifact_envelope_test.go) for the shape-check case.
func TestAdminRegisterAgentVersionHandler_ArtifactMetadataSignaturePayloadMismatchRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	cases := []struct {
		name            string
		reqPlatform     string
		reqChannel      string
		reqVersion      string
		payloadVersion  string
		payloadPlatform string
		payloadChannel  string
	}{
		{
			name:            "version_disagrees",
			reqPlatform:     "windows",
			reqChannel:      "stable",
			reqVersion:      "1256.0.0-version-mismatch",
			payloadVersion:  "1256.0.0-different-version",
			payloadPlatform: "windows",
			payloadChannel:  "stable",
		},
		{
			name:            "platform_disagrees",
			reqPlatform:     "windows",
			reqChannel:      "stable",
			reqVersion:      "1256.0.0-platform-mismatch",
			payloadVersion:  "1256.0.0-platform-mismatch",
			payloadPlatform: "macos",
			payloadChannel:  "stable",
		},
		{
			name:            "channel_disagrees",
			reqPlatform:     "windows",
			reqChannel:      "stable",
			reqVersion:      "1256.0.0-channel-mismatch",
			payloadVersion:  "1256.0.0-channel-mismatch",
			payloadPlatform: "windows",
			payloadChannel:  "beta",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aavtCleanupVersion(t, ctx, pool, tc.reqPlatform, tc.reqChannel, tc.reqVersion)

			envelope := aaetEnvelope(t,
				aapcPayload(tc.payloadVersion, tc.payloadPlatform, tc.payloadChannel),
				"deadbeef-signature-bytes",
				"ecd47f2c5b3d5705",
			)

			req := adminRegisterVersionReq{
				Platform:                  tc.reqPlatform,
				Channel:                   tc.reqChannel,
				Version:                   tc.reqVersion,
				ArtifactURL:               "https://cdn.patched.im/windows/1256.0.0/PatchedAgent.zip",
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

			if postRR.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", postRR.Code, postRR.Body.String())
			}

			var count int
			if err := pool.QueryRow(ctx, `
				SELECT count(*) FROM agent_versions WHERE platform = $1 AND channel = $2 AND version = $3
			`, tc.reqPlatform, tc.reqChannel, tc.reqVersion).Scan(&count); err != nil {
				t.Fatalf("verify no row persisted: %v", err)
			}
			if count != 0 {
				t.Errorf("agent_versions row count = %d, want 0 (a disagreeing envelope must not be stored)", count)
			}
		})
	}
}
