package handlers

// POST /v1/agent-logs — on-demand agent log ingest (PAT-286).
//
// The agent uploads a gzipped JSON-lines bundle in response to a log_request
// directive embedded in its signed agent config. Auth is the device-level bearer
// + HMAC scheme (same as GET /v1/posture): the bearer token must belong to a
// per-device credential (tenant_credentials row with device_id IS NOT NULL).
//
// Security invariants (GitHub-Non-Author-Review evidence):
//   - Tenant resolved from DB credential; no client-supplied tenant parameter.
//   - Device resolved from DB credential; cross-device upload is impossible.
//   - HMAC-SHA256 over the request body — tampering → 401.
//   - Replay protection via X-Patched-Timestamp and X-Patched-Nonce.
//   - request_id header required; idempotent: re-upload with same request_id
//     for the same device is a no-op (returns 200 silently).
//   - Body size cap: hard server cap (maxAgentLogBytes). 413 when exceeded.
//   - Per-tenant ceiling (agentLogsCeilingBytes total across all bundles) enforced
//     atomically inside dbIngestAgentLog via a transaction advisory lock. 413 when exceeded.
//
// Admin read:
//   GET  /admin/tenants/{tenantID}/agent-logs                       — list bundle metadata
//   GET  /admin/tenants/{tenantID}/agent-logs/{deviceID}/{requestID} — download a bundle
//
// Retention:
//   POST /admin/agent-logs/purge?days=N — deletes rows older than N days (default 90).
//   Intended for cron invocation via curl from a Tailscale node.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
)

const (
	// maxAgentLogBytes is the global hard per-request body cap for POST /v1/agent-logs.
	// Larger than the standard maxBodyBytes because log bundles can be up to
	// several MB when compressed. Per-request max_bytes from the agent's signed
	// log_request directive is enforced by the agent, not this handler.
	maxAgentLogBytes = 10 << 20 // 10 MiB

	// agentLogsCeilingBytes is the default maximum total stored bytes per tenant
	// across all agent_logs rows. When adding a new bundle would exceed this, the
	// server returns 413 to the agent. A per-tenant override column can be added
	// later without changing the handler interface.
	agentLogsCeilingBytes = 512 << 20 // 512 MiB
)

// ErrLogCeilingExceeded is returned by dbIngestAgentLog when the tenant's
// total stored log bytes would exceed agentLogsCeilingBytes after this upload.
var ErrLogCeilingExceeded = errors.New("tenant log storage ceiling exceeded")

// -- Injectable function types -----------------------------------------------

// agentLogsAuthFn resolves tenantID + deviceID + HMAC secret from request headers.
type agentLogsAuthFn func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (tenantID, deviceID string, err error)

// agentLogsIngestFn stores a log bundle idempotently.
// Returns (id, true, nil) when stored; (id, false, nil) when already exists;
// (0, false, ErrLogCeilingExceeded) when the per-tenant ceiling would be exceeded.
type agentLogsIngestFn func(ctx context.Context, tenantID, deviceID, requestID string, bundle []byte) (id int64, stored bool, err error)

// agentLogsListFn returns bundle metadata (no bytes) for a tenant.
type agentLogsListFn func(ctx context.Context, tenantID string) ([]agentLogMeta, error)

// agentLogsFetchFn returns a single bundle's bytes (for download).
type agentLogsFetchFn func(ctx context.Context, tenantID, deviceID, requestID string) ([]byte, error)

// agentLogsExistsFn reports whether a tenant row exists.
type agentLogsExistsFn func(ctx context.Context, tenantID string) (bool, error)

// -- Response/data types -----------------------------------------------------

type agentLogMeta struct {
	ID              int64     `json:"id"`
	DeviceID        string    `json:"device_id"`
	RequestID       string    `json:"request_id"`
	ReceivedAt      time.Time `json:"received_at"`
	BundleSizeBytes int64     `json:"bundle_size_bytes"`
}

// -- Public constructors ------------------------------------------------------

// AgentLogsHandler serves POST /v1/agent-logs on the public listener.
func AgentLogsHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	authFn := func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
		tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(ctx, pool, authHeader)
		if err != nil {
			return "", "", err
		}
		if err := auth.VerifyHMACSigned(secret, http.MethodPost, auth.EndpointAgentLogs, ts, nonce, body, sigHeader); err != nil {
			return "", "", err
		}
		return tenantID, deviceID, nil
	}
	ingestFn := func(ctx context.Context, tenantID, deviceID, requestID string, bundle []byte) (int64, bool, error) {
		return dbIngestAgentLog(ctx, pool, tenantID, deviceID, requestID, bundle)
	}
	return newAgentLogsHandler(authFn, ingestFn, rl, replaySkew, pool)
}

// AdminAgentLogsListHandler serves GET /admin/tenants/{tenantID}/agent-logs.
func AdminAgentLogsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	existsFn := func(ctx context.Context, tenantID string) (bool, error) {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
		).Scan(&exists)
		return exists, err
	}
	listFn := func(ctx context.Context, tenantID string) ([]agentLogMeta, error) {
		return dbListAgentLogs(ctx, pool, tenantID)
	}
	return newAdminAgentLogsListHandler(existsFn, listFn)
}

// AdminAgentLogFetchHandler serves GET /admin/tenants/{tenantID}/agent-logs/{deviceID}/{requestID}.
func AdminAgentLogFetchHandler(pool *pgxpool.Pool) http.HandlerFunc {
	existsFn := func(ctx context.Context, tenantID string) (bool, error) {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
		).Scan(&exists)
		return exists, err
	}
	fetchFn := func(ctx context.Context, tenantID, deviceID, requestID string) ([]byte, error) {
		return dbFetchAgentLogBundle(ctx, pool, tenantID, deviceID, requestID)
	}
	return newAdminAgentLogFetchHandler(existsFn, fetchFn)
}

// AdminAgentLogsPurgeHandler serves POST /admin/agent-logs/purge?days=N.
// Deletes all agent_logs rows older than N days (default 90). Returns a JSON
// body with the number of rows deleted. Intended for cron invocation via
// curl from a Tailscale node — no additional auth beyond network-only.
func AdminAgentLogsPurgeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	purgeFn := func(ctx context.Context, days int) (int64, error) {
		return PurgeOldAgentLogs(ctx, pool, days)
	}
	return newAdminAgentLogsPurgeHandler(purgeFn)
}

func newAdminAgentLogsPurgeHandler(purgeFn func(context.Context, int) (int64, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_agent_logs_purge")

		days := 90
		if s := r.URL.Query().Get("days"); s != "" {
			if n, err := strconv.Atoi(s); err != nil || n <= 0 {
				http.Error(w, "days must be a positive integer", http.StatusBadRequest)
				return
			} else {
				days = n
			}
		}

		deleted, err := purgeFn(r.Context(), days)
		if err != nil {
			logger.Error("purge agent logs failed", "err", err, "days", days)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("agent logs purged", "days", days, "deleted", deleted)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deleted": deleted,
			"days":    days,
		})
	}
}

// PurgeOldAgentLogs deletes all agent_logs rows older than retentionDays.
// Designed to be called from a cron job or admin endpoint. Returns the number
// of rows deleted.
func PurgeOldAgentLogs(ctx context.Context, pool *pgxpool.Pool, retentionDays int) (int64, error) {
	tag, err := pool.Exec(ctx, `
		DELETE FROM agent_logs
		WHERE received_at < now() - make_interval(days => $1)
	`, retentionDays)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// -- Handler constructors (injectable for tests) -----------------------------

func newAgentLogsHandler(
	authFn agentLogsAuthFn,
	ingestFn agentLogsIngestFn,
	rl *ratelimit.TenantLimiter,
	replaySkew time.Duration,
	pool *pgxpool.Pool,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "agent_logs_ingest")

		// Read body before auth so HMAC is computed over the actual bytes.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentLogBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxAgentLogBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}

		tenantID, deviceID, err := authFn(r.Context(), r.Header.Get("Authorization"), r.Header.Get("X-Patched-Signature"), r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body)
		if err != nil {
			if errors.Is(err, auth.ErrDeviceCredentialRequired) {
				logger.Warn("auth failed: credential is tenant-level, this endpoint requires a device-scoped credential", "err", err)
				metrics.DeviceCredentialRequiredTotal.WithLabelValues("agent_logs_ingest").Inc()
			} else {
				logger.Warn("auth failed", "err", err)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		logger = logger.With("tenant_id", tenantID, "device_id", deviceID)

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

		requestID := strings.TrimSpace(r.Header.Get("X-Patched-Log-Request-ID"))
		if !looksLikeUUID(requestID) {
			http.Error(w, "X-Patched-Log-Request-ID must be a UUID", http.StatusBadRequest)
			return
		}

		if len(body) == 0 {
			http.Error(w, "bundle body is empty", http.StatusBadRequest)
			return
		}

		id, stored, err := ingestFn(r.Context(), tenantID, deviceID, requestID, body)
		if errors.Is(err, ErrLogCeilingExceeded) {
			logger.Warn("per-tenant log ceiling exceeded", "bundle_bytes", len(body))
			http.Error(w, "tenant log storage ceiling exceeded", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			logger.Error("ingest failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if stored {
			logger.Info("agent log bundle stored",
				"request_id", requestID, "bundle_bytes", len(body), "log_id", id)
		} else {
			logger.Info("agent log bundle already exists (idempotent)",
				"request_id", requestID)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"log_id":     id,
			"request_id": requestID,
			"stored":     stored,
		})
	}
}

func newAdminAgentLogsListHandler(existsFn agentLogsExistsFn, listFn agentLogsListFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_agent_logs_list")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		exists, err := existsFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("tenant existence check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		items, err := listFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("list agent logs failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if items == nil {
			items = []agentLogMeta{}
		}

		logger.Info("agent logs listed", "tenant_id", tenantID, "count", len(items))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"logs":  items,
			"total": len(items),
		})
	}
}

func newAdminAgentLogFetchHandler(existsFn agentLogsExistsFn, fetchFn agentLogsFetchFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_agent_log_fetch")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}
		requestID := strings.TrimSpace(chi.URLParam(r, "requestID"))
		if !looksLikeUUID(requestID) {
			http.Error(w, "requestID must be a UUID", http.StatusBadRequest)
			return
		}

		exists, err := existsFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("tenant existence check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		bundle, err := fetchFn(r.Context(), tenantID, deviceID, requestID)
		if err != nil {
			logger.Error("fetch agent log failed", "err", err, "tenant_id", tenantID, "device_id", deviceID, "request_id", requestID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if bundle == nil {
			http.Error(w, "log bundle not found", http.StatusNotFound)
			return
		}

		logger.Info("agent log bundle served",
			"tenant_id", tenantID, "device_id", deviceID, "request_id", requestID, "bundle_bytes", len(bundle))

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="agent-log-%s.jsonl.gz"`, requestID))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}
}

// -- DB helpers ---------------------------------------------------------------

func dbIngestAgentLog(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, requestID string, bundle []byte) (int64, bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Advisory lock serializes concurrent uploads for this tenant so the
	// size check + insert are atomic. The lock is released on tx commit/rollback.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(('x' || left(md5($1), 16))::bit(64)::bigint)`,
		tenantID,
	); err != nil {
		return 0, false, err
	}

	var currentSize int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(bundle_size_bytes), 0) FROM agent_logs WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&currentSize); err != nil {
		return 0, false, err
	}
	if currentSize+int64(len(bundle)) > agentLogsCeilingBytes {
		return 0, false, ErrLogCeilingExceeded
	}

	var id int64
	err = tx.QueryRow(ctx, `
		INSERT INTO agent_logs (tenant_id, device_id, request_id, bundle_bytes, bundle_size_bytes)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)
		ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING
		RETURNING id
	`, tenantID, deviceID, requestID, bundle, int64(len(bundle))).Scan(&id)
	if isNoRowsErr(err) {
		// Idempotent re-upload — fetch existing id without re-committing the ceiling check.
		var existingID int64
		if lookupErr := tx.QueryRow(ctx,
			`SELECT id FROM agent_logs WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND request_id = $3::uuid`,
			tenantID, deviceID, requestID,
		).Scan(&existingID); lookupErr != nil {
			return 0, false, lookupErr
		}
		_ = tx.Commit(ctx)
		return existingID, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func dbListAgentLogs(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]agentLogMeta, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, device_id::text, request_id::text, received_at, bundle_size_bytes
		FROM agent_logs
		WHERE tenant_id = $1::uuid
		ORDER BY received_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []agentLogMeta
	for rows.Next() {
		var m agentLogMeta
		if err := rows.Scan(&m.ID, &m.DeviceID, &m.RequestID, &m.ReceivedAt, &m.BundleSizeBytes); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

func dbFetchAgentLogBundle(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, requestID string) ([]byte, error) {
	var bundle []byte
	err := pool.QueryRow(ctx, `
		SELECT bundle_bytes
		FROM agent_logs
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND request_id = $3::uuid
	`, tenantID, deviceID, requestID).Scan(&bundle)
	if isNoRowsErr(err) {
		return nil, nil
	}
	return bundle, err
}
