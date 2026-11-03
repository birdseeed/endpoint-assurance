package handlers

// Per-device app-removal task queue — agent surface (PAT-781 / PAT-462).
//
// The updater agent consumes and drives per-device removal tasks queued by an
// operator (device_removals.go). Two public routes on :8080:
//
//	GET  /v1/devices/{deviceID}/removal-tasks/pending  – tasks the agent should act on
//	POST /v1/devices/{deviceID}/removal-tasks/report   – agent reports execution state
//
// Auth is the device-level bearer + HMAC-SHA256 + replay (timestamp + nonce)
// scheme (auth.LookupDeviceByBearer), identical to POST
// /v1/inventory/enforcement-audit. The {deviceID} path segment is required to
// match the authenticated device — a credential can only ever read or mutate
// its own tasks. Like the tenant-wide uninstall queue, this is a Patch-tier
// feature: report-only tenants get 403 even with valid device credentials.
//
// Terminal reports (removed / residual / manual / failed) are mirrored into the
// enforcement_audit trail (PAT-603) using the existing admin_removed /
// admin_removal_skipped event types, so every executed removal is auditable via
// GET /admin/tenants/{tenantID}/enforcement-audit. Non-terminal ('in-progress')
// and operator-side lifecycle (queued/cancelled) are recorded on the task row
// itself (queued_at / updated_at / cancelled_at).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
)

// agentReportableStates is the closed set of states the agent may report. The
// server owns 'queued' (set on create) and cancellation; the agent drives
// everything from pickup onwards.
var agentReportableStates = map[string]bool{
	"in-progress": true,
	"removed":     true,
	"residual":    true,
	"manual":      true,
	"failed":      true,
}

// terminalRemovalStates are the states after which no further transition is
// possible; reaching one is what gets mirrored into enforcement_audit.
var terminalRemovalStates = map[string]bool{
	"removed":  true,
	"residual": true,
	"manual":   true,
	"failed":   true,
}

type removalReport struct {
	TaskID string `json:"task_id"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type removalReportReq struct {
	Reports []removalReport `json:"reports"`
}

// authenticateRemovalAgent runs the shared bearer+HMAC+replay+tier gate for the
// agent-facing removal endpoints and confirms the URL deviceID is the caller's
// own device. On success it returns (tenantID, deviceID, true); otherwise it has
// already written the response and returns ok=false.
//
// metricsHandler is the "handler" label to increment DeviceCredentialRequiredTotal
// with; it must match the caller's own logger "handler" attribute (removal_tasks_pending
// or removal_tasks_report) so logs and the metric stay in sync.
func authenticateRemovalAgent(
	w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool,
	rl *ratelimit.TenantLimiter, replaySkew time.Duration, endpointID auth.EndpointID, body []byte, logger *slog.Logger, metricsHandler string,
) (string, string, bool) {
	tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(r.Context(), pool, r.Header.Get("Authorization"))
	if err != nil {
		if errors.Is(err, auth.ErrDeviceCredentialRequired) {
			logger.Warn("device bearer lookup failed: credential is tenant-level, this endpoint requires a device-scoped credential", "err", err)
			metrics.DeviceCredentialRequiredTotal.WithLabelValues(metricsHandler).Inc()
		} else {
			logger.Warn("device bearer lookup failed", "err", err)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}

	if rl != nil {
		if allowed, retryAfter := rl.Allow(tenantID); !allowed {
			logger.Warn("rate limit exceeded", "tenant_id", tenantID)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return "", "", false
		}
	}

	if err := auth.VerifyHMACSigned(secret, r.Method, endpointID, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); err != nil {
		logger.Warn("hmac verify failed", "err", err, "tenant_id", tenantID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}
	if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
		logger.Warn("timestamp validation failed", "err", err, "tenant_id", tenantID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}
	if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
		logger.Warn("nonce check failed", "err", err, "tenant_id", tenantID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}

	// Patch-tier gate — mirrors the tenant-wide uninstall queue (PAT-650).
	// Collapsed to "managed" (PAT-1599, migration 0138): this gates endpoint
	// actuation, which only the managed tier retains.
	if !requireTenantTier(w, r, poolTierLoader(pool), tenantID, subTierManaged) {
		return "", "", false
	}

	// The credential resolves the device; the path segment must not point
	// anywhere else. A device can only ever touch its own tasks.
	urlDeviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
	if urlDeviceID != deviceID {
		logger.Warn("device path mismatch", "tenant_id", tenantID, "auth_device", deviceID, "url_device", urlDeviceID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return "", "", false
	}

	return tenantID, deviceID, true
}

// DeviceRemovalTasksPendingHandler serves GET /v1/devices/{deviceID}/removal-tasks/pending.
// Returns tasks the agent still needs to act on: queued or already-in-progress
// (so an interrupted run is retried), uncancelled, and not past expiry.
// DeviceRemovalTasksPendingHandler is the production route. It cannot enable
// legacy execution; retained compatibility coverage uses the explicit test seam.
func DeviceRemovalTasksPendingHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return deviceRemovalTasksPendingHandler(pool, rl, replaySkew, false)
}

// DeviceRemovalTasksPendingHandlerForLegacyExecutionCompatibility exists only
// for retained compatibility tests. It must never be used in production wiring.
func DeviceRemovalTasksPendingHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return deviceRemovalTasksPendingHandler(pool, rl, replaySkew, true)
}

func deviceRemovalTasksPendingHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "removal_tasks_pending")

		// GET — body is empty; HMAC is computed over zero bytes.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, ok := authenticateRemovalAgent(w, r, pool, rl, replaySkew, auth.EndpointDeviceRemovalTasksPending, body, logger, "removal_tasks_pending")
		if !ok {
			return
		}

		tasks, err := deviceRemovalTasksAfterAuth(r.Context(), deviceID, legacyExecutionEnabled,
			func(ctx context.Context, deviceID string) ([]removalTaskJSON, error) {
				return loadPendingDeviceRemovalTasks(ctx, pool, deviceID)
			})
		if err != nil {
			logger.Error("pending removal tasks query failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("pending removal tasks fetched", "tenant_id", tenantID, "device_id", deviceID, "count", len(tasks))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(removalTasksResp{DeviceID: deviceID, Tasks: tasks})
	}
}

type deviceRemovalTasksLoader func(context.Context, string) ([]removalTaskJSON, error)

// deviceRemovalTasksAfterAuth runs only after the device-scoped bearer, HMAC,
// replay, rate, tier, and path checks. The disabled path preserves the success
// response while never reading or changing the legacy removal queue.
func deviceRemovalTasksAfterAuth(ctx context.Context, deviceID string, legacyExecutionEnabled bool, load deviceRemovalTasksLoader) ([]removalTaskJSON, error) {
	if !legacyExecutionEnabled {
		return []removalTaskJSON{}, nil
	}
	return load(ctx, deviceID)
}

func loadPendingDeviceRemovalTasks(ctx context.Context, pool *pgxpool.Pool, deviceID string) ([]removalTaskJSON, error) {
	rows, err := pool.Query(ctx, `
			SELECT task_id::text, app_name, state, queued_at, expires_at
			FROM device_removal_tasks
			WHERE device_id = $1::uuid
			  AND cancelled_at IS NULL
			  AND state IN ('queued','in-progress')
			  AND expires_at > now()
			ORDER BY queued_at
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := []removalTaskJSON{}
	for rows.Next() {
		var task removalTaskJSON
		if err := rows.Scan(&task.TaskID, &task.AppName, &task.State, &task.QueuedAt, &task.ExpiresAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tasks, nil
}

// DeviceRemovalTasksReportHandler serves POST /v1/devices/{deviceID}/removal-tasks/report.
// Body: {"reports": [{"task_id": "...", "state": "removed", "detail": "..."}]}.
func DeviceRemovalTasksReportHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "removal_tasks_report")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, ok := authenticateRemovalAgent(w, r, pool, rl, replaySkew, auth.EndpointDeviceRemovalTasksReport, body, logger, "removal_tasks_report")
		if !ok {
			return
		}

		var req removalReportReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.Reports == nil {
			http.Error(w, "reports array is required", http.StatusBadRequest)
			return
		}
		// Validate every report before mutating anything.
		for i, rep := range req.Reports {
			if !looksLikeUUID(strings.TrimSpace(rep.TaskID)) {
				http.Error(w, fmt.Sprintf("reports[%d]: task_id must be a UUID", i), http.StatusBadRequest)
				return
			}
			if !agentReportableStates[rep.State] {
				http.Error(w, fmt.Sprintf("reports[%d]: state must be one of in-progress, removed, residual, manual, failed", i), http.StatusBadRequest)
				return
			}
		}

		var auditEvents []enforcementAuditEvent
		updated := 0
		for _, rep := range req.Reports {
			// Only a live (uncancelled, non-terminal) task belonging to THIS
			// device may transition. RowsAffected 0 means the task is unknown,
			// belongs to another device, was cancelled, or is already terminal —
			// all safely ignored.
			var appName string
			err := pool.QueryRow(r.Context(), `
				UPDATE device_removal_tasks
				SET state = $1, updated_at = now()
				WHERE task_id = $2::uuid AND device_id = $3::uuid
				  AND cancelled_at IS NULL AND state IN ('queued','in-progress')
				RETURNING app_name
			`, rep.State, strings.TrimSpace(rep.TaskID), deviceID).Scan(&appName)
			if err != nil {
				if isNoRows(err) {
					logger.Info("removal report skipped (not actionable)", "task_id", rep.TaskID, "state", rep.State)
					continue
				}
				logger.Error("removal task update failed", "err", err, "task_id", rep.TaskID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			updated++

			if terminalRemovalStates[rep.State] {
				eventType := "admin_removal_skipped"
				if rep.State == "removed" {
					eventType = "admin_removed"
				}
				detail, _ := json.Marshal(map[string]string{
					"task_id": strings.TrimSpace(rep.TaskID),
					"result":  rep.State,
					"detail":  strings.TrimSpace(rep.Detail),
				})
				auditEvents = append(auditEvents, enforcementAuditEvent{
					EventType:  eventType,
					Subject:    appName,
					Details:    json.RawMessage(detail),
					OccurredAt: time.Now().UTC().Format(time.RFC3339),
				})
			}
		}

		// Mirror terminal outcomes into the enforcement_audit trail. Best-effort:
		// the task row is the source of truth for state; a failed audit write is
		// logged but does not fail the agent's report.
		if len(auditEvents) > 0 {
			if _, err := dbIngestEnforcementAudit(r.Context(), pool, tenantID, deviceID, auditEvents); err != nil {
				logger.Error("removal audit mirror failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
			}
		}

		logger.Info("removal tasks reported", "tenant_id", tenantID, "device_id", deviceID, "updated", updated, "reports", len(req.Reports))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"updated": updated})
	}
}
