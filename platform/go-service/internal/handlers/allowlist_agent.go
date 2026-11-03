package handlers

// Agent-facing allowlist endpoint — GET /v1/allowlist/pending-removals (PAT-376).
//
// Auth: bearer + HMAC-SHA256 over the (empty) request body + replay headers —
// identical to GET /v1/agent-config. Network access is public (:8080).
//
// Returns the list of tenant_allowlists entries with enforcement =
// 'marked_for_uninstall' whose queue timestamp is older than 24 h.  The agent
// uses this to drive its uninstall-execution engine; the platform only queues
// *intent* — execution and verification are entirely agent-side.
//
// ⚠️  The non-author-review gate applies before any enforcement action reaches a customer
// endpoint.  The 24 h server-side hold is a safety window; it cannot be
// shortened by the agent.

import (
	"context"
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

type pendingRemovalJSON struct {
	EntryID   int64     `json:"entry_id"`
	Name      string    `json:"name"`
	Publisher *string   `json:"publisher"`
	Platform  string    `json:"platform"`
	MatchMode string    `json:"match_mode"`
	QueuedAt  time.Time `json:"queued_at"`
	// KnownPath is the app's on-disk bundle path from known_app_bundles
	// (PAT-806), keyed by (name, platform) -- null when this tenant-agnostic,
	// auto-populated table has never seen a device report this app on this
	// platform. Distinct from the curated EULA/mirror Catalogue: this is
	// auto-populated inventory data, not a manually-reviewed record. The
	// join is scoped to this entry's OWN platform column (never 'any' --
	// known_app_bundles only stores 'macos'/'windows'), so a macOS bundle
	// path can never leak onto a Windows-platform queue entry or vice versa.
	KnownPath *string `json:"known_path"`
}

type pendingRemovalsResp struct {
	TenantID string               `json:"tenant_id"`
	WindowH  int                  `json:"window_hours"`
	Items    []pendingRemovalJSON `json:"items"`
}

// PendingRemovalsHandler returns the list of apps queued for uninstall by this
// tenant that have been pending for at least 24 h.
// PendingRemovalsHandler is the production route. Legacy execution is
// permanently disabled; the compatibility constructor below is test-only.
func PendingRemovalsHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return pendingRemovalsHandler(pool, rl, replaySkew, false)
}

// PendingRemovalsHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. Production router wiring must use
// PendingRemovalsHandler, which cannot enable legacy execution.
func PendingRemovalsHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return pendingRemovalsHandler(pool, rl, replaySkew, true)
}

func pendingRemovalsHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "pending_removals")

		// GET — body is empty; HMAC is computed over zero bytes (same as agent-config).
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

		if err := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointPendingRemovals, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
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

		// PAT-650: the uninstall queue is a Patch-tier feature, which collapsed
		// into "managed" (PAT-1599, migration 0138) since it gates endpoint
		// actuation. Assurance-tier tenants get 403 here even with valid
		// credentials.
		if !requireTenantTier(w, r, poolTierLoader(pool), tenantID, subTierManaged) {
			return
		}

		items, err := pendingRemovalsAfterAuth(r.Context(), tenantID, legacyExecutionEnabled,
			func(ctx context.Context, tenantID string) ([]pendingRemovalJSON, error) {
				return loadPendingRemovals(ctx, pool, tenantID)
			})
		if err != nil {
			logger.Error("pending removals query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("pending removals fetched", "tenant_id", tenantID, "count", len(items))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pendingRemovalsResp{
			TenantID: tenantID,
			WindowH:  24,
			Items:    items,
		})
	}
}

type pendingRemovalsLoader func(context.Context, string) ([]pendingRemovalJSON, error)

// pendingRemovalsAfterAuth is called only after the endpoint's bearer, rate,
// HMAC, timestamp, nonce, and subscription-tier checks have passed. Keeping
// the compatibility decision here prevents disabled callers from reaching the
// legacy queue, while preserving those protections.
func pendingRemovalsAfterAuth(ctx context.Context, tenantID string, legacyExecutionEnabled bool, load pendingRemovalsLoader) ([]pendingRemovalJSON, error) {
	if !legacyExecutionEnabled {
		return []pendingRemovalJSON{}, nil
	}
	return load(ctx, tenantID)
}

// loadPendingRemovals queries tenant_allowlists entries with enforcement =
// 'marked_for_uninstall'. queued_at is derived from tenant_allowlist_changes:
// the most recent enforcement transition or seed event. The 24 h hold is
// enforced server-side.
func loadPendingRemovals(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]pendingRemovalJSON, error) {
	rows, err := pool.Query(ctx, `
			WITH queued AS (
			    SELECT
			        tal.id          AS entry_id,
			        tal.name,
			        tal.publisher,
			        tal.platform,
			        tal.match_mode,
			        COALESCE(
			            (SELECT MAX(tac.changed_at)
			             FROM tenant_allowlist_changes tac
			             WHERE tac.entry_id = tal.id
			               AND (
			                   (tac.action = 'enforcement_changed' AND tac.detail->>'to'          = 'marked_for_uninstall')
			                OR (tac.action = 'added'               AND tac.detail->>'enforcement' = 'marked_for_uninstall')
			               )
			            ),
			            tal.created_at
			        ) AS queued_at
			    FROM tenant_allowlists tal
			    WHERE tal.tenant_id = $1::uuid
			      AND tal.enforcement = 'marked_for_uninstall'
			)
			SELECT q.entry_id, q.name, q.publisher, q.platform, q.match_mode, q.queued_at,
			       kb.app_path
			FROM queued q
			LEFT JOIN known_app_bundles kb
			    ON kb.platform = q.platform AND LOWER(kb.name) = LOWER(q.name)
			WHERE q.queued_at < NOW() - INTERVAL '24 hours'
			ORDER BY q.queued_at
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []pendingRemovalJSON{}
	for rows.Next() {
		var item pendingRemovalJSON
		if err := rows.Scan(&item.EntryID, &item.Name, &item.Publisher,
			&item.Platform, &item.MatchMode, &item.QueuedAt, &item.KnownPath); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
