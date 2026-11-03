package handlers

// readiness.go — GET /ready on the public :8080 listener (PAT-1215).
//
// /health (cmd/patched-api/main.go's healthHandler) proves only that the
// process is listening — it is a hardcoded string that never touches the
// database, so patched_api_health_up (patched-alert-metrics.sh) and the
// prod-01 shell alerter (patched-prod-alerts.sh) both stay green through a
// total database outage. Both of those consume /health's exact existing
// 200-always contract, so this is a SEPARATE endpoint, not a change to
// /health.
//
// /ready performs one bounded, trivial database round trip and reports
// success/failure in the HTTP status code — an external uptime prober's only
// signal is the status code, so a 200 with an "error" body would still read
// as "up" to anything that isn't parsing JSON.
//
// Unauthenticated and internet-reachable (same public listener as
// /v1/inventory, Cloudflare-proxied), so:
//   - the query is a constant-cost "SELECT 1", never a table scan — hammering
//     this endpoint costs the DB one trivial round trip per call and nothing
//     more, so there's no meaningful load or attacker leverage in doing so;
//   - the response body never includes the underlying driver error, a
//     connection string, a hostname, or any other internal detail — just the
//     fixed strings "database" (what was checked) and, on failure,
//     "unreachable" (why) — so an unauthenticated caller learns nothing that
//     would help map the estate from a failing probe.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// readinessTimeout bounds the DB round trip so a hung database fails the
// check quickly instead of hanging the prober or tying up a server
// goroutine. Well inside the public listener's 30s request Timeout
// middleware (newPublicRouter, cmd/patched-api/main.go).
const readinessTimeout = 2 * time.Second

type readinessResp struct {
	Status  string `json:"status"`
	Checked string `json:"checked"`
	Reason  string `json:"reason,omitempty"`
}

// ReadinessHandler returns GET /ready: a real, bounded database round trip
// distinct from /health (see file doc comment above). Non-2xx on failure,
// 2xx on success — the status code is the signal an external prober reads;
// the JSON body is diagnostic only, and is deliberately detail-free (see
// above).
func ReadinessHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "readiness")

		w.Header().Set("Content-Type", "application/json")

		if pool == nil {
			// Should not happen in production (main.go always constructs a
			// pool before wiring routes) but fail closed rather than panic
			// on a nil-pool misconfiguration.
			logger.Warn("readiness check: db pool not configured")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(readinessResp{Status: "error", Checked: "database", Reason: "unreachable"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		var one int
		if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			logger.Warn("readiness db round trip failed", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(readinessResp{Status: "error", Checked: "database", Reason: "unreachable"})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(readinessResp{Status: "ok", Checked: "database"})
	}
}
