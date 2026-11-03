package handlers

// POST /admin/devices/{deviceID}/credentials — issue a per-device bearer token
// so the agent can authenticate GET /v1/posture with device_id derived from
// the credential (not a client-supplied parameter).
//
// Auth: network-only (Tailscale-bound internal listener), same posture as all
// other /admin/* endpoints.
//
// Credentials are returned once in plaintext; neither the bearer token nor the
// HMAC secret is recoverable after this response.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
)

type issueDeviceCredResp struct {
	DeviceID      string `json:"device_id"`
	CredentialID  int64  `json:"credential_id"`
	BearerToken   string `json:"bearer_token"`
	HMACSecretB64 string `json:"hmac_secret_b64"`
	Warning       string `json:"warning"`
}

// IssueDeviceCredentialHandler mints a new bearer token + HMAC secret keyed to
// the given device. Multiple active credentials per device are allowed (rotation
// support); revoke old ones via the existing /admin/tenants/{tenantID}/rotate-credentials
// flow or direct DB update.
func IssueDeviceCredentialHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		logger := slog.With("req_id", reqID, "handler", "issue_device_credential", "device_id", deviceID)

		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify the device exists and resolve its tenant_id.
		var tenantID string
		err := pool.QueryRow(r.Context(), `
			SELECT tenant_id::text FROM devices WHERE id = $1::uuid
		`, deviceID).Scan(&tenantID)
		if err != nil {
			if isNoRowsErr(err) {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			logger.Error("device lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Generate bearer token: 32 random bytes, base64url-no-padding.
		bearerBytes := make([]byte, 32)
		if _, err := rand.Read(bearerBytes); err != nil {
			logger.Error("rand bearer failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		bearerToken := base64.RawURLEncoding.EncodeToString(bearerBytes)
		bearerHash := sha256.Sum256([]byte(bearerToken))

		// Generate HMAC secret: 32 random bytes.
		hmacSecret := make([]byte, 32)
		if _, err := rand.Read(hmacSecret); err != nil {
			logger.Error("rand hmac failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-687: encrypt the ACTIVE auth secret at rest; auth/bearer.go decrypts
		// with a plaintext fallback. No-op passthrough when PATCHED_KEK is unset.
		encHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
		if err != nil {
			logger.Error("hmac_secret encryption failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var credID int64
		err = pool.QueryRow(r.Context(), `
			INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
			VALUES ($1::uuid, $2::uuid, $3, $4)
			RETURNING id
		`, tenantID, deviceID, bearerHash[:], encHMAC).Scan(&credID)
		if err != nil {
			logger.Error("insert device credential failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device credential issued", "tenant_id", tenantID, "credential_id", credID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(issueDeviceCredResp{
			DeviceID:      deviceID,
			CredentialID:  credID,
			BearerToken:   bearerToken,
			HMACSecretB64: base64.StdEncoding.EncodeToString(hmacSecret),
			Warning:       "store bearer_token and hmac_secret_b64 immediately — neither is recoverable after this response.",
		})
	}
}
