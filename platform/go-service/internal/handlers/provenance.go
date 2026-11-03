package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

// ProvenanceHandler is the public POST /v1/provenance endpoint. It records one
// third-party-update provenance record per request, written by the Patched
// Updater endpoint daemon. Same auth chain as /v1/inventory: bearer lookup,
// rate check, HMAC verify, replay validation, then archive body verbatim.
func ProvenanceHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "provenance")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, secret, err := auth.LookupTenantByBearer(r.Context(), pool, r.Header.Get("Authorization"))
		if err != nil {
			logger.Warn("bearer lookup failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if allowed, retryAfter := rl.Allow(tenantID); !allowed {
			logger.Warn("rate limit exceeded", "tenant_id", tenantID)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		if err := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointProvenance, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
			logger.Warn("hmac verify failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
			logger.Warn("timestamp validation failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
			logger.Warn("nonce check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !json.Valid(body) {
			logger.Warn("body not valid json", "tenant_id", tenantID)
			http.Error(w, "body not valid JSON", http.StatusBadRequest)
			return
		}

		var sourceIPArg any
		if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil && host != "" {
			sourceIPArg = host
		} else if r.RemoteAddr != "" {
			sourceIPArg = r.RemoteAddr
		}

		var rowID int64
		err = pool.QueryRow(r.Context(), `
			INSERT INTO provenance_records (tenant_id, source_ip, user_agent, body)
			VALUES ($1, $2, $3, $4)
			RETURNING id
		`, tenantID, sourceIPArg, r.Header.Get("User-Agent"), body).Scan(&rowID)
		if err != nil {
			logger.Error("insert provenance_record failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("provenance accepted",
			"tenant_id", tenantID, "provenance_id", rowID, "size_bytes", len(body))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "ok",
			"request_id":    reqID,
			"provenance_id": rowID,
		})
	}
}
