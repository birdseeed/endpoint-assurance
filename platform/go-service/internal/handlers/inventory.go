// Package handlers contains the HTTP handlers for the patched.im API service.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/extractor"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
)

// maxBodyBytes mirrors Caddy's request_body cap. Caddy enforces this at the
// edge; we double-check on the application side as defence-in-depth.
const maxBodyBytes = 6 << 20 // 6 MB

// InventoryHandler is the public POST /v1/inventory endpoint.
//
// Flow: read body -> bearer-lookup tenant -> rate check -> HMAC verify ->
// replay validation (timestamp+nonce) -> insert raw payload.
// Auth failures return a uniform 401; rate limit returns 429.
func InventoryHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "inventory")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		// Bearer lookup -> tenant + raw HMAC secret
		tenantID, secret, err := auth.LookupTenantByBearer(r.Context(), pool, r.Header.Get("Authorization"))
		if err != nil {
			logger.Warn("bearer lookup failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Per-tenant rate limit — after bearer (needs tenant ID), before HMAC.
		if allowed, retryAfter := rl.Allow(tenantID); !allowed {
			logger.Warn("rate limit exceeded", "tenant_id", tenantID)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// HMAC verify of the raw body. The returned form is observation only:
		// VerifyHMACSignedWithForm has the same acceptance branches and ordering
		// as VerifyHMACSigned, and telemetry is written only after the payload has
		// otherwise been accepted and stored.
		signingForm, err := auth.VerifyHMACSignedWithForm(secret, r.Method, auth.EndpointInventory, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature"))
		if err != nil {
			logger.Warn("hmac verify failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Timestamp freshness check
		if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
			logger.Warn("timestamp validation failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Nonce uniqueness check
		if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
			logger.Warn("nonce check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// PAT-867: reject ingestion from an expired trial tenant. This runs only
		// AFTER the full two-layer auth + replay gate above (bearer, HMAC,
		// timestamp, nonce) — deliberately, so it never fires for a request that
		// would otherwise be rejected 401. Placing it before HMAC would both
		// break the "bearer plus HMAC both gate processing" contract and hand a
		// bearer-only holder a trial-status oracle without the second factor.
		//
		// Fails CLOSED: a lookup error returns 500 rather than accepting the
		// payload. This is a paid-tier gate, so a failure path must never let an
		// expired trial ingest. The availability cost is negligible — the
		// raw_payload insert immediately below hits the same DB, so a genuine DB
		// fault fails the request regardless.
		if expired, err := CheckTrialExpired(r.Context(), pool, tenantID); err != nil {
			logger.Error("trial expiry check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		} else if expired {
			logger.Warn("inventory rejected: trial expired", "tenant_id", tenantID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "trial_expired"})
			return
		}

		// Payload schema validation — rejects malformed and schema-invalid bodies
		// before any DB write.  ValidatePayload covers JSON syntax + all constraints
		// from docs/payload.schema.json; it returns a descriptive error on failure.
		if err := extractor.ValidatePayload(body); err != nil {
			// PAT-2021: an MCP privacy guard hit is an alertable event of its
			// own. The error carries only fixed class names and counts,
			// never a field name the agent sent or any value.
			var guard *extractor.MCPPrivacyGuardError
			if errors.As(err, &guard) {
				metrics.MCPPrivacyGuardRejectionsTotal.Inc()
				logger.Error("mcp privacy guard rejected inventory payload",
					"event", "mcp_privacy_guard_rejected", "tenant_id", tenantID,
					"entries", guard.Entries, "classes", guard.ClassNames())
			}
			logger.Warn("payload schema validation failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Best-effort source IP — chi's RealIP middleware already overwrote
		// r.RemoteAddr with X-Forwarded-For when Caddy set it. Strip the port
		// if one is present; pass nil to get a NULL in Postgres if we can't.
		var sourceIPArg any
		if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil && host != "" {
			sourceIPArg = host
		} else if r.RemoteAddr != "" {
			sourceIPArg = r.RemoteAddr
		}

		var rowID int64
		err = pool.QueryRow(r.Context(), `
			INSERT INTO raw_payloads (tenant_id, source_ip, user_agent, body)
			VALUES ($1, $2, $3, $4)
			RETURNING id
		`, tenantID, sourceIPArg, r.Header.Get("User-Agent"), body).Scan(&rowID)
		if err != nil {
			logger.Error("insert raw_payload failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("inventory accepted",
			"tenant_id", tenantID,
			"raw_payload_id", rowID,
			"size_bytes", len(body),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"request_id":     reqID,
			"raw_payload_id": rowID,
		})

		// PAT-1872: best-effort, estate-wide compatibility evidence. This runs
		// only after the unchanged success response has been written, so a slow
		// or unavailable telemetry table cannot alter request acceptance. It is
		// detached from client cancellation so a disconnect after acceptance does
		// not erase evidence, but its two-second deadline bounds the handler and DB
		// transaction lifetime. The recorder receives only a closed signing-form
		// value and a sanitised top-level agent version; no tenant/device/request
		// material is passed.
		if hmacCompatibilityTelemetryEnabled() {
			agentVersion := hmacCompatibilityAgentVersion(body)
			telemetryCtx, cancelTelemetry := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
			defer cancelTelemetry()
			if err := recordHMACCompatibility(telemetryCtx, pool, signingForm, agentVersion); err != nil {
				logger.Error("record HMAC compatibility telemetry failed", "err", err)
			}
		}
	}
}
