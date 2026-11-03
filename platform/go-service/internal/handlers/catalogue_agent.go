package handlers

// Agent-facing catalogue endpoint — GET /v1/allowlist/pending-installs
// (PAT-659, retired PAT-1561).
//
// Auth: bearer + HMAC-SHA256 over the (empty) request body + replay headers —
// identical to GET /v1/allowlist/pending-removals. Network access is public (:8080).
//
// PAT-1561: the per-tenant Self-Service App Catalogue (tenant_catalogue) this
// endpoint used to read has been dropped (migration
// 0121_retire_tenant_catalogue.sql) — live-data survey showed only Patched.im's
// own internal tenant had ever used it, and this endpoint was already a
// permanent no-op in production before the table went away: legacyExecutionEnabled
// was compiled false, so it always returned {"installs":[]} without querying
// tenant_catalogue or writing the tenant_allowlists pre-approval side-effect
// (see integration/catalogue_test.go's TestCatalogueAgentPendingInstalls,
// which already asserted this fail-closed behaviour with live rows present).
//
// The route is kept — not removed or turned into a 404/503 — so any endpoint
// agent still polling it keeps getting the exact response it has always
// received in production: 200 with an empty install list, after the same
// auth/rate-limit/tier checks as before. This is a deliberate, permanent
// no-op, not a placeholder for a future re-implementation.
import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

type catalogueInstallJSON struct {
	PackageID     string `json:"package_id"`
	PackageSource string `json:"package_source"`
	DisplayName   string `json:"display_name"`
}

type pendingInstallsResp struct {
	Installs []catalogueInstallJSON `json:"installs"`
}

// PendingInstallsHandler authenticates the request exactly as before and
// always returns an empty install list. See the file-level comment: this is
// a permanent no-op following the removal of tenant_catalogue (PAT-1561).
func PendingInstallsHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "pending_installs")

		// GET — body is empty; HMAC is computed over zero bytes.
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

		if err := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointPendingInstalls, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
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

		// Like pending removals, the legacy install queue was a Patch-tier
		// feature; that rung collapsed into "managed" (PAT-1599, migration
		// 0138) since it gates endpoint actuation. This check deliberately
		// still runs before the empty response so tier enforcement behaviour
		// is unchanged from before the retirement. Kept for auth-surface
		// parity only, not because the response depends on tier - do not
		// remove this gate without first confirming no currently-deployed
		// agent's behaviour depends on getting a 403 here instead of a 200
		// (review finding, 2026-09-11).
		if !requireTenantTier(w, r, poolTierLoader(pool), tenantID, subTierManaged) {
			return
		}

		logger.Info("pending installs fetched", "tenant_id", tenantID, "count", 0, "mode", "retired-noop")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pendingInstallsResp{Installs: []catalogueInstallJSON{}})
	}
}
