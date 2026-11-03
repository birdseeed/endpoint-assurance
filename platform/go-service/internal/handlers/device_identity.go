package handlers

// GET /v1/device/identity — tells an agent which device its own credential
// belongs to (PAT-2424).
//
// Why it exists: an agent proves its signed config is addressed to it by
// comparing the config's device_id with a canonical device id it stored at
// enrolment. A device that enrolled on an agent build which discarded that
// field has nothing to compare with, and the config must never be allowed to
// supply the value it is being checked against. This endpoint is the
// authenticated source instead: the platform looks the device up from the
// credential row POST /v1/enrol wrote for it.
//
// Security invariants:
//   - The device is tenant_credentials.device_id for the presented bearer. No
//     header, query parameter or body field is read to choose it.
//   - Strict v3 HMAC only (method, endpoint id, timestamp, nonce, body). The
//     targetless and body-only transition forms other endpoints still accept
//     are refused here: this is a new route with no installed callers to keep
//     working, and those forms do not bind the timestamp or nonce.
//   - Unknown, revoked or expired credentials, a revoked tenant, a bad
//     signature, a stale timestamp and a replayed nonce all get the same
//     generic 401 the other agent endpoints give.
//   - A tenant-level credential (device_id NULL: POST /admin/tenants, rotation,
//     trial provisioning) cannot name a device, so it never gets an identity.
//     It gets 409 device_credential_required, but only after the same request
//     has authenticated at tenant level (bearer, strict HMAC, timestamp and
//     nonce). A caller who cannot do that sees the generic 401, so the answer
//     tells nobody anything about a credential they do not already hold in
//     full. The agent needs the distinction: a 401 here would otherwise look
//     like a revocation.
//   - Read-only apart from the replay nonce every signed endpoint stores in
//     seen_nonces. It creates no device and does not move last_seen. One log
//     line per served request records tenant, device and request id.
//   - The response is exactly {tenant_id, device_id}: the two values POST
//     /v1/enrol already returned to this same credential holder.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
)

// deviceIdentityAuthFn authenticates the request. A non-empty deviceID is a
// device-scoped credential. An empty deviceID with a nil error is a
// tenant-level credential that passed the same bearer and HMAC checks. Any
// error is an authentication failure.
type deviceIdentityAuthFn func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (tenantID, deviceID string, err error)

// deviceIdentityExistsFn reports whether deviceID is a device of tenantID.
type deviceIdentityExistsFn func(ctx context.Context, tenantID, deviceID string) (bool, error)

type deviceIdentityResp struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
}

// DeviceIdentityHandler builds the production GET /v1/device/identity handler.
func DeviceIdentityHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	authFn := func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
		tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(ctx, pool, authHeader)
		if errors.Is(err, auth.ErrDeviceCredentialRequired) {
			// Live tenant-level credential. Authenticate it as one so the
			// caller can be told why it has no identity; a failure here stays
			// the generic 401.
			tenantID, secret, err = auth.LookupTenantByBearer(ctx, pool, authHeader)
			deviceID = ""
		}
		if err != nil {
			return "", "", err
		}
		if err := auth.VerifyHMACSignedStrict(secret, http.MethodGet, auth.EndpointDeviceIdentity, ts, nonce, body, sigHeader); err != nil {
			return "", "", err
		}
		return tenantID, deviceID, nil
	}
	existsFn := func(ctx context.Context, tenantID, deviceID string) (bool, error) {
		var ok bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1::uuid AND tenant_id = $2::uuid)`,
			deviceID, tenantID).Scan(&ok)
		return ok, err
	}
	return newDeviceIdentityHandler(authFn, existsFn, rl, replaySkew, pool)
}

// newDeviceIdentityHandler is the injectable form. rl and pool may be nil in
// unit tests that stub authFn; replay validation is skipped when pool is nil.
func newDeviceIdentityHandler(
	authFn deviceIdentityAuthFn,
	existsFn deviceIdentityExistsFn,
	rl *ratelimit.TenantLimiter,
	replaySkew time.Duration,
	pool *pgxpool.Pool,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_identity")

		// GET: the body is empty and the HMAC is computed over zero bytes.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, err := authFn(r.Context(), r.Header.Get("Authorization"), r.Header.Get("X-Patched-Signature"), r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body)
		if err != nil {
			logger.Warn("auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		logger = logger.With("tenant_id", tenantID)

		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				logger.Warn("rate limit exceeded")
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

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")

		if deviceID == "" {
			metrics.DeviceCredentialRequiredTotal.WithLabelValues("device_identity").Inc()
			logger.Warn("refused: tenant-level credential has no device identity")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "device_credential_required"})
			return
		}
		logger = logger.With("device_id", deviceID)

		ok, err := existsFn(r.Context(), tenantID, deviceID)
		if err != nil {
			logger.Error("device lookup failed", "err", err)
			w.Header().Del("Content-Type")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			// The credential names a device that is not a device of its own
			// tenant. The schema should make this impossible; never vouch for it.
			logger.Error("credential device is not a device of the credential tenant")
			w.Header().Del("Content-Type")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		logger.Info("device identity served")
		_ = json.NewEncoder(w).Encode(deviceIdentityResp{TenantID: tenantID, DeviceID: deviceID})
	}
}
