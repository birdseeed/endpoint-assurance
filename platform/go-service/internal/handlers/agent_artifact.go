package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

// validAgentVersionPlatforms lists every platform value agent_versions
// accepts (migration 0097 — PAT-1233). "macos-menubar" is a distinct
// artifact channel from "macos": the menu-bar apps (PatchedUpdater.app /
// PatchedSelfService.app) are different binaries from the endpoint
// collector/updater daemon and must never share a platform value with it.
var validAgentVersionPlatforms = []string{"macos", "windows", "macos-menubar"}

// isValidAgentVersionPlatform reports whether platform is one of
// validAgentVersionPlatforms.
func isValidAgentVersionPlatform(platform string) bool {
	for _, p := range validAgentVersionPlatforms {
		if platform == p {
			return true
		}
	}
	return false
}

// agentArtifactResp is returned by GET /v1/agent/artifact.
//
// ArtifactMetadataSignature (PAT-1252) is the additive Ed25519 signed
// envelope PAT-1248's client verifies against. Every field above it is
// unchanged from before PAT-1252 and stays populated exactly as it was —
// this is an addition, not a cutover (see agent_artifact.go's package-level
// design note and 0102_agent_versions_artifact_envelope.sql). It carries
// the shared {signed_payload, signature, key_id} shape (same as
// agent-config) as raw, previously-validated JSON
// (json.RawMessage), so it is served back byte-identical to what was
// registered — never re-derived. omitempty: a row with no envelope (every
// row today, until PAT-1255 provisions ARTIFACT_SIGNING_KEY) omits the
// field entirely rather than serving a fabricated or empty value — the
// server has no signing key and must never appear to sign on its own
// behalf.
type agentArtifactResp struct {
	Version                   string          `json:"version"`
	ArtifactURL               string          `json:"artifact_url"`
	ArtifactSHA256            string          `json:"artifact_sha256"`
	ArtifactHMAC              string          `json:"artifact_hmac"`
	PublishedAt               string          `json:"published_at"`
	ArtifactMetadataSignature json.RawMessage `json:"artifact_metadata_signature,omitempty"`
}

// adminRegisterVersionReq is the body for POST /admin/agent-versions.
//
// ArtifactMetadataSignature (PAT-1252) is optional: the updater release
// workflow forwards it once ARTIFACT_SIGNING_KEY exists (PAT-1255), but a
// release cut before then must still be able to register without one — see
// validateArtifactMetadataSignature for the shape check applied when it is
// present, plus the PAT-1256 cross-check that its decoded contents agree
// with this request's own Version/Platform/Channel.
type adminRegisterVersionReq struct {
	Platform                  string          `json:"platform"`
	Channel                   string          `json:"channel"`
	Version                   string          `json:"version"`
	ArtifactURL               string          `json:"artifact_url"`
	ArtifactSHA256            string          `json:"artifact_sha256"`
	ArtifactHMAC              string          `json:"artifact_hmac"`
	ReleasedBy                string          `json:"released_by"`
	ArtifactMetadataSignature json.RawMessage `json:"artifact_metadata_signature,omitempty"`
}

// hasJSONValue reports whether raw carries an actual JSON value, as opposed
// to being absent (the field was omitted from the request body entirely) or
// an explicit JSON null (the standard way to say "no value" for an optional
// field). Both of those mean "no envelope registered" and must be treated
// identically — a caller should not need to know Go's zero-value
// conventions for json.RawMessage to omit an optional field correctly.
func hasJSONValue(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null"
}

// artifactMetadataPayload is the subset of the decoded signed_payload JSON
// that validateArtifactMetadataSignature cross-checks against the
// registration request (PAT-1256). The real payload also carries
// artifact_url and artifact_sha256 (see migration
// 0102_agent_versions_artifact_envelope.sql), but those aren't compared
// here — this struct only needs the fields the cross-check reads. Pointer
// fields so a field that is absent, or explicitly JSON null, is
// distinguishable from a field that is present but the empty string; either
// way it must be treated as missing, not as an empty value that happens to
// disagree with the request.
type artifactMetadataPayload struct {
	Version  *string `json:"version"`
	Platform *string `json:"platform"`
	Channel  *string `json:"channel"`
}

// validateArtifactMetadataSignature checks a signed artifact envelope
// submitted to POST /admin/agent-versions in two stages: the SHAPE of the
// envelope itself, and — PAT-1256 — that the decoded signed_payload's own
// version/platform/channel agree with the values the registration request
// declares for the row.
//
// Shape: the same {signed_payload, signature, key_id} wire format as the
// signed agent-config (internal/agentconfig). It reuses decodeStrictEnvelope for the same
// exact-key, no-duplicate, string-typed parsing already hardened for that
// identical shape (see that function's doc comment for the Go-vs-other-parser
// differential it closes), then additionally checks that signed_payload and
// signature are each valid base64 and key_id is valid hex: three
// present-but-empty or present-but-undecodable fields would still pass a
// presence-only check, only to fail at every endpoint instead of being
// rejected at the door here.
//
// Content agreement (PAT-1256): a signature that is valid base64/hex still
// says nothing about which row it was ever meant for — the signature covers
// signed_payload's bytes, not the agent_versions row it gets attached to at
// registration time. So once the shape checks pass, this decodes
// signed_payload and compares its version, platform, and channel against
// expectedVersion/expectedPlatform/expectedChannel (the request's own
// fields). Any disagreement, or a signed_payload that isn't valid JSON, or
// JSON missing any of those three fields, is rejected — fail closed rather
// than silently skip the cross-check on an unparseable payload.
//
// What this function still does NOT do, and must never do: verify the
// Ed25519 signature. patched-api does not hold ARTIFACT_SIGNING_KEY (the
// Ed25519 private key) — deliberately, per PAT-1248, so that compromising
// this server can never let an attacker forge a valid artifact signature —
// so it has no key to verify the signature against and must not try.
// Whether signed_payload's signature actually verifies is entirely the
// endpoint's job, against its own pinned public key, at self-update time.
// The content-agreement check above closes a real integrity gap (a
// legitimately-signed envelope registered against a row with different
// declared values), but it is not, and cannot be, a substitute for that
// signature verification.
func validateArtifactMetadataSignature(raw json.RawMessage, expectedVersion, expectedPlatform, expectedChannel string) error {
	env, err := decodeStrictEnvelope(raw)
	if err != nil {
		return err
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		return fmt.Errorf("signed_payload is not valid base64: %w", err)
	}
	if _, err := base64.StdEncoding.DecodeString(env.Signature); err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if _, err := hex.DecodeString(env.KeyID); err != nil {
		return fmt.Errorf("key_id is not valid hex: %w", err)
	}

	var payload artifactMetadataPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("signed_payload does not decode to JSON: %w", err)
	}
	if payload.Version == nil {
		return errors.New(`signed_payload is missing required field "version"`)
	}
	if payload.Platform == nil {
		return errors.New(`signed_payload is missing required field "platform"`)
	}
	if payload.Channel == nil {
		return errors.New(`signed_payload is missing required field "channel"`)
	}
	if *payload.Version != expectedVersion {
		return fmt.Errorf("signed_payload version %q disagrees with request version %q", *payload.Version, expectedVersion)
	}
	if *payload.Platform != expectedPlatform {
		return fmt.Errorf("signed_payload platform %q disagrees with request platform %q", *payload.Platform, expectedPlatform)
	}
	if *payload.Channel != expectedChannel {
		return fmt.Errorf("signed_payload channel %q disagrees with request channel %q", *payload.Channel, expectedChannel)
	}
	return nil
}

// AgentArtifactHandler builds GET /v1/agent/artifact.
// Auth: bearer + HMAC (same as /v1/agent-config). Rate-limited by tenant.
// Query params: platform (required), channel (default "stable"), version (optional — for pinned tenants).
func AgentArtifactHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "agent_artifact")

		// Auth — empty body (GET).
		body := []byte{}
		tenantID, _, err := func() (string, string, error) {
			if tid, did, secret, e := auth.LookupDeviceByBearer(r.Context(), pool, r.Header.Get("Authorization")); e == nil {
				if e2 := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointAgentArtifact, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); e2 != nil {
					return "", "", e2
				}
				return tid, did, nil
			}
			tid, secret, e := auth.LookupTenantByBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if e != nil {
				return "", "", e
			}
			if e2 := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointAgentArtifact, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); e2 != nil {
				return "", "", e2
			}
			return tid, "", nil
		}()
		if err != nil {
			logger.Warn("auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		if pool != nil {
			if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
				logger.Warn("timestamp validation failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
				logger.Warn("nonce check failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		channel := strings.TrimSpace(r.URL.Query().Get("channel"))
		version := strings.TrimSpace(r.URL.Query().Get("version"))

		if !isValidAgentVersionPlatform(platform) {
			http.Error(w, "platform must be \"macos\", \"windows\", or \"macos-menubar\"", http.StatusBadRequest)
			return
		}
		if channel == "" {
			channel = "stable"
		}
		if channel != "stable" && channel != "beta" {
			http.Error(w, "channel must be \"stable\" or \"beta\"", http.StatusBadRequest)
			return
		}

		var row agentArtifactResp
		var publishedAt time.Time
		// artifactMetadataSignature is scanned as a nullable TEXT (PAT-1252)
		// — NULL for every row until a release is registered with an
		// envelope (PAT-1255). A nil pointer here becomes an omitted field
		// on row.ArtifactMetadataSignature below, never a fabricated one.
		var artifactMetadataSignature *string
		var queryErr error
		if version != "" {
			// Pinned version lookup.
			queryErr = pool.QueryRow(r.Context(), `
				SELECT version, artifact_url, artifact_sha256, artifact_hmac, published_at, artifact_metadata_signature
				FROM agent_versions
				WHERE platform = $1 AND channel = $2 AND version = $3
			`, platform, channel, version).Scan(
				&row.Version, &row.ArtifactURL, &row.ArtifactSHA256, &row.ArtifactHMAC, &publishedAt, &artifactMetadataSignature,
			)
		} else {
			// Latest for channel.
			queryErr = pool.QueryRow(r.Context(), `
				SELECT version, artifact_url, artifact_sha256, artifact_hmac, published_at, artifact_metadata_signature
				FROM agent_versions
				WHERE platform = $1 AND channel = $2
				ORDER BY published_at DESC
				LIMIT 1
			`, platform, channel).Scan(
				&row.Version, &row.ArtifactURL, &row.ArtifactSHA256, &row.ArtifactHMAC, &publishedAt, &artifactMetadataSignature,
			)
		}
		if isNoRowsErr(queryErr) {
			http.Error(w, "no artifact found for platform/channel", http.StatusNotFound)
			return
		}
		if queryErr != nil {
			logger.Error("agent_versions query failed", "err", queryErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		row.PublishedAt = publishedAt.UTC().Format(time.RFC3339)
		if artifactMetadataSignature != nil {
			row.ArtifactMetadataSignature = json.RawMessage(*artifactMetadataSignature)
		}

		logger.Info("agent artifact resolved",
			"tenant_id", tenantID, "platform", platform, "channel", channel, "version", row.Version)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(row)
	}
}

// AdminRegisterAgentVersionHandler builds POST /admin/agent-versions.
// Admin-only: registered by the CI release pipeline after signing + publishing each tarball.
func AdminRegisterAgentVersionHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_register_agent_version")

		var req adminRegisterVersionReq
		body, ok := readLimitedBody(w, r, 64<<10)
		if !ok {
			return
		}
		if err := decodeStrictJSON(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if !isValidAgentVersionPlatform(req.Platform) {
			http.Error(w, "platform must be \"macos\", \"windows\", or \"macos-menubar\"", http.StatusBadRequest)
			return
		}
		if req.Channel != "stable" && req.Channel != "beta" {
			http.Error(w, "channel must be \"stable\" or \"beta\"", http.StatusBadRequest)
			return
		}
		if req.Version == "" || req.ArtifactURL == "" || req.ArtifactSHA256 == "" || req.ArtifactHMAC == "" {
			http.Error(w, "version, artifact_url, artifact_sha256, and artifact_hmac are required", http.StatusBadRequest)
			return
		}
		if req.ReleasedBy == "" {
			req.ReleasedBy = "ci"
		}

		// artifact_metadata_signature (PAT-1252) is optional on input — a
		// release cut before ARTIFACT_SIGNING_KEY exists (PAT-1255) must
		// still be able to register. When present, its SHAPE is checked
		// and — PAT-1256 — its decoded contents are cross-checked against
		// req.Version/req.Platform/req.Channel (see
		// validateArtifactMetadataSignature); a malformed value or a
		// disagreeing one is rejected here, before it is ever stored or
		// served to an endpoint. The validated bytes are json.Compact'd
		// before storage so GET always serves back the identical compacted
		// form it was stored as, regardless of whatever incidental
		// whitespace the submitted request body happened to contain.
		var artifactMetadataSignature *string
		if hasJSONValue(req.ArtifactMetadataSignature) {
			if err := validateArtifactMetadataSignature(req.ArtifactMetadataSignature, req.Version, req.Platform, req.Channel); err != nil {
				logger.Warn("malformed artifact_metadata_signature", "err", err)
				http.Error(w, "invalid artifact_metadata_signature: "+err.Error(), http.StatusBadRequest)
				return
			}
			var compacted bytes.Buffer
			if err := json.Compact(&compacted, req.ArtifactMetadataSignature); err != nil {
				// decodeStrictEnvelope (inside validateArtifactMetadataSignature)
				// already proved this is well-formed JSON, so this should be
				// unreachable. Fail closed rather than store anything if it
				// somehow isn't.
				logger.Error("compact artifact_metadata_signature failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			s := compacted.String()
			artifactMetadataSignature = &s
		}

		err := registerAgentRelease(r.Context(), pool, req, artifactMetadataSignature)
		if err != nil {
			if strings.HasPrefix(err.Error(), "release_conflict:") || strings.HasPrefix(err.Error(), "promotion_required:") {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			logger.Error("insert agent_version failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("agent version registered",
			"platform", req.Platform, "channel", req.Channel, "version", req.Version)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"platform": req.Platform,
			"channel":  req.Channel,
			"version":  req.Version,
		})
	}
}
