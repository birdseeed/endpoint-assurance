package handlers

// Per-device app-removal task queue — admin surface (PAT-781 / PAT-462).
//
// Routes (all on :8081 Tailscale-only admin listener):
//
//	GET    /admin/devices/{deviceID}/removals           – list this device's removal tasks
//	POST   /admin/devices/{deviceID}/removals           – queue a removal ({app_name})
//	DELETE /admin/devices/{deviceID}/removals/{taskID}   – cancel a queued task (soft-delete)
//
// This is DEVICE-scoped (one app on one device) and deliberately distinct from
// the TENANT-scoped allowlist uninstall mechanism (allowlist.go,
// enforcement = 'marked_for_uninstall'), which flags an app across the whole
// estate. The updater agent consumes queued tasks and reports execution state
// via the agent-facing endpoints in device_removals_agent.go.
//
// ⚠️  Queue is intent only. Actual uninstall execution and every state
// transition after 'queued' happen agent-side, gated by the Patch subscription
// tier at the agent-poll endpoint.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// removalTaskExpiry is how long a queued task remains actionable before it is
// considered stale. The agent-poll endpoint stops returning tasks past this
// window; the dashboard surfaces it as the task's expiry.
const removalTaskExpiry = 7 * 24 * time.Hour

// removalTaskJSON is the wire shape shared by the admin list/create responses
// and (for the queued subset) the agent-poll response. Field names match the
// dashboard's _draRenderTasks / _asRemovalCell contract exactly.
type removalTaskJSON struct {
	TaskID    string    `json:"task_id"`
	AppName   string    `json:"app_name"`
	State     string    `json:"state"`
	QueuedAt  time.Time `json:"queued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type removalTasksResp struct {
	DeviceID string            `json:"device_id"`
	Tasks    []removalTaskJSON `json:"tasks"`
}

type removalCreateReq struct {
	AppName string `json:"app_name"`
}

// DeviceRemovalsListHandler serves GET /admin/devices/{deviceID}/removals.
// Cancelled tasks are excluded; terminal states are retained so the operator
// sees the outcome of past removals.
func DeviceRemovalsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_removals_list")

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT task_id::text, app_name, state, queued_at, expires_at
			FROM device_removal_tasks
			WHERE device_id = $1::uuid AND cancelled_at IS NULL
			ORDER BY queued_at DESC
		`, deviceID)
		if err != nil {
			logger.Error("device removals query failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		tasks := []removalTaskJSON{}
		for rows.Next() {
			var t removalTaskJSON
			if err := rows.Scan(&t.TaskID, &t.AppName, &t.State, &t.QueuedAt, &t.ExpiresAt); err != nil {
				logger.Error("device removal row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			tasks = append(tasks, t)
		}
		if err := rows.Err(); err != nil {
			logger.Error("device removals rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(removalTasksResp{DeviceID: deviceID, Tasks: tasks})
	}
}

// DeviceRemovalsCreateHandler serves POST /admin/devices/{deviceID}/removals.
// Idempotent per (device, app): if a live task already exists it is returned
// (200) rather than stacking a duplicate.
// DeviceRemovalsCreateHandler is the production route and cannot enable
// legacy execution.
func DeviceRemovalsCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return deviceRemovalsCreateHandler(pool, false)
}

// DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func DeviceRemovalsCreateHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool) http.HandlerFunc {
	return deviceRemovalsCreateHandler(pool, true)
}

func deviceRemovalsCreateHandler(pool *pgxpool.Pool, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !legacyExecutionEnabled {
			legacyExecutionDisabledHandler(w, r)
			return
		}
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_removals_create")

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req removalCreateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.AppName = strings.TrimSpace(req.AppName)
		if req.AppName == "" {
			http.Error(w, "app_name is required", http.StatusBadRequest)
			return
		}

		// Resolve the owning tenant from the device (denormalised onto the task
		// row so the agent-report path can write enforcement_audit without a join).
		var tenantID string
		if err := pool.QueryRow(r.Context(),
			`SELECT tenant_id::text FROM devices WHERE id = $1::uuid`, deviceID,
		).Scan(&tenantID); err != nil {
			if isNoRows(err) {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			logger.Error("device lookup failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		now := time.Now().UTC()
		expiresAt := now.Add(removalTaskExpiry)

		task := removalTaskJSON{AppName: req.AppName, State: "queued", QueuedAt: now, ExpiresAt: expiresAt}
		err = pool.QueryRow(r.Context(), `
			INSERT INTO device_removal_tasks (tenant_id, device_id, app_name, state, queued_at, expires_at, updated_at)
			VALUES ($1::uuid, $2::uuid, $3, 'queued', $4, $5, $4)
			RETURNING task_id::text
		`, tenantID, deviceID, req.AppName, now, expiresAt).Scan(&task.TaskID)
		if err != nil {
			// A live task for this (device, app) already exists (partial unique
			// index) — return it rather than erroring, so a double-submit is a
			// no-op from the operator's perspective.
			if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
				existing, ferr := fetchActiveRemovalTask(r.Context(), pool, deviceID, req.AppName)
				if ferr == nil {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(existing)
					return
				}
				logger.Error("existing task fetch failed", "err", ferr)
			}
			logger.Error("device removal insert failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device removal queued", "device_id", deviceID, "task_id", task.TaskID, "app", req.AppName)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(task)
	}
}

// fetchActiveRemovalTask returns the live (uncancelled, non-terminal) task for
// a device+app, used to make POST idempotent on a unique-index conflict.
func fetchActiveRemovalTask(ctx context.Context, pool *pgxpool.Pool, deviceID, appName string) (removalTaskJSON, error) {
	var t removalTaskJSON
	err := pool.QueryRow(ctx, `
		SELECT task_id::text, app_name, state, queued_at, expires_at
		FROM device_removal_tasks
		WHERE device_id = $1::uuid AND app_name = $2
		  AND cancelled_at IS NULL AND state IN ('queued','in-progress')
		LIMIT 1
	`, deviceID, appName).Scan(&t.TaskID, &t.AppName, &t.State, &t.QueuedAt, &t.ExpiresAt)
	return t, err
}

// DeviceRemovalsCancelHandler serves DELETE /admin/devices/{deviceID}/removals/{taskID}.
// Only a still-queued task can be cancelled — once the agent has picked it up
// (in-progress) or it has reached a terminal state, cancellation is refused.
func DeviceRemovalsCancelHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_removals_cancel")

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		taskID := strings.TrimSpace(chi.URLParam(r, "taskID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(taskID) {
			http.Error(w, "taskID must be a UUID", http.StatusBadRequest)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE device_removal_tasks
			SET cancelled_at = now(), updated_at = now()
			WHERE task_id = $1::uuid AND device_id = $2::uuid
			  AND state = 'queued' AND cancelled_at IS NULL
		`, taskID, deviceID)
		if err != nil {
			logger.Error("device removal cancel failed", "err", err, "task_id", taskID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "task not found or no longer cancellable", http.StatusNotFound)
			return
		}

		logger.Info("device removal cancelled", "device_id", deviceID, "task_id", taskID)
		w.WriteHeader(http.StatusNoContent)
	}
}
