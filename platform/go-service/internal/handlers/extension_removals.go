package handlers

// Per-tenant browser-extension REMOVAL request queue — admin surface (PAT-832,
// part of PAT-773).
//
// Routes (all on :8081 Tailscale-only admin listener, Patch tier):
//
//	GET    /admin/tenants/{tenantID}/extension-removals              – list pending requests
//	POST   /admin/tenants/{tenantID}/extension-removals              – queue a removal ("Remove now")
//	DELETE /admin/tenants/{tenantID}/extension-removals/{requestID}  – cancel a pending request
//
// Deliberately distinct from tenant_extension_policies (PAT-826): that is the
// policy plane (approve/unapprove/ignore) driving the PAT-828 managed-policy
// blocklist. Destructive removal is an explicit escalation an operator triggers,
// never implied by policy state — mixing them would risk removing an extension
// just because it was toggled "unapproved" (PAT-773 blast-radius concern).
//
// Active requests are projected into the signed agent-config's
// app_control.extension_removals block (agent_config.go) and consumed by the
// PAT-829 agent removal primitive. PAT-1169 captures the exact device/profile
// targets at request time and completes them only from authenticated
// extension_removed audit evidence.

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var extensionRemovalValidBrowsers = map[string]bool{
	"chrome": true, "edge": true, "firefox": true,
}

var extensionRemovalValidScopes = map[string]bool{
	"one_profile": true, "one_user": true, "all_profiles": true, "all_devices": true,
}

type extensionRemovalJSON struct {
	ID               int64      `json:"id"`
	Browser          string     `json:"browser"`
	ExtensionID      string     `json:"extension_id"`
	Scope            string     `json:"scope"`
	UserAccount      *string    `json:"user_account"`
	Profile          *string    `json:"profile"`
	RequestedBy      string     `json:"requested_by"`
	RequestedAt      time.Time  `json:"requested_at"`
	Fulfilled        bool       `json:"fulfilled"`
	FulfilledAt      *time.Time `json:"fulfilled_at"`
	CancelledAt      *time.Time `json:"cancelled_at"`
	State            string     `json:"state"`
	BlockedReason    *string    `json:"blocked_reason"`
	TargetsTotal     int        `json:"targets_total"`
	TargetsCompleted int        `json:"targets_completed"`
	LastCompletedAt  *time.Time `json:"last_completed_at"`
}

func extensionRemovalState(e extensionRemovalJSON, appControlEnabled bool) extensionRemovalJSON {
	switch {
	case e.CancelledAt != nil:
		e.State = "cancelled"
	case e.Fulfilled:
		e.State = "completed"
	case !appControlEnabled:
		e.State = "blocked"
		reason := "extension_control_disabled"
		e.BlockedReason = &reason
	case e.TargetsTotal == 0:
		e.State = "blocked"
		reason := "no_matching_targets"
		e.BlockedReason = &reason
	default:
		e.State = "queued"
	}
	return e
}

type extensionRemovalsGetResp struct {
	TenantID string                 `json:"tenant_id"`
	Requests []extensionRemovalJSON `json:"requests"`
}

type extensionRemovalCreateReq struct {
	Browser     string  `json:"browser"`
	ExtensionID string  `json:"extension_id"`
	Scope       string  `json:"scope"`
	UserAccount *string `json:"user_account"`
	Profile     *string `json:"profile"`
	RequestedBy string  `json:"requested_by"`
}

// validateExtensionRemoval normalises and validates a create request. It returns
// the browser/extension_id/scope (trimmed) and the user_account/profile narrowed
// to exactly what the scope uses — context a scope ignores is dropped to NULL so a
// stored request can never carry misleading targeting, and a narrow scope missing
// its required context is rejected outright (never silently widened).
func validateExtensionRemoval(req extensionRemovalCreateReq) (browser, extensionID, scope string, userAccount, profile *string, errMsg string) {
	browser = strings.ToLower(strings.TrimSpace(req.Browser))
	extensionID = strings.TrimSpace(req.ExtensionID)
	scope = strings.TrimSpace(req.Scope)
	userAccount = normalizeOptionalString(req.UserAccount)
	profile = normalizeOptionalString(req.Profile)

	if extensionID == "" {
		return "", "", "", nil, nil, "extension_id is required"
	}
	if !extensionRemovalValidBrowsers[browser] {
		return "", "", "", nil, nil, "browser must be one of: chrome, edge, firefox"
	}
	if !extensionRemovalValidScopes[scope] {
		return "", "", "", nil, nil, "scope must be one of: one_profile, one_user, all_profiles, all_devices"
	}

	switch scope {
	case "one_profile":
		if userAccount == nil {
			return "", "", "", nil, nil, "user_account is required for scope one_profile"
		}
		if profile == nil {
			return "", "", "", nil, nil, "profile is required for scope one_profile"
		}
	case "one_user":
		if userAccount == nil {
			return "", "", "", nil, nil, "user_account is required for scope one_user"
		}
		profile = nil // one_user targets every profile of the user; a profile is meaningless
	default: // all_profiles / all_devices — device-wide; any target context is dropped
		userAccount = nil
		profile = nil
	}
	return browser, extensionID, scope, userAccount, profile, ""
}

// TenantExtensionRemovalsGetHandler serves GET .../extension-removals.
// Lists active requests by default. include_history=true also returns completed
// and cancelled jobs for the redesigned dashboard without changing the legacy
// response shape seen by older clients.
func TenantExtensionRemovalsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_removals_list")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, logger, err)
			return
		}

		includeHistory := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("include_history")), "true")
		rows, err := pool.Query(r.Context(), `
			SELECT r.id, r.browser, r.extension_id, r.scope, r.user_account, r.profile,
			       r.requested_by, r.requested_at, r.fulfilled, r.fulfilled_at,
			       r.cancelled_at, t.app_control_enabled,
			       COUNT(rt.request_id)::int AS targets_total,
			       COUNT(rt.completed_at)::int AS targets_completed,
			       MAX(rt.completed_at) AS last_completed_at
			FROM tenant_extension_removal_requests r
			JOIN tenants t ON t.id = r.tenant_id
			LEFT JOIN tenant_extension_removal_targets rt ON rt.request_id = r.id
			WHERE r.tenant_id = $1::uuid
			  AND ($2::boolean OR (r.fulfilled = FALSE AND r.cancelled_at IS NULL))
			GROUP BY r.id, t.app_control_enabled
			ORDER BY r.requested_at DESC, r.id DESC
		`, tenantID, includeHistory)
		if err != nil {
			logger.Error("extension removals query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		requests := []extensionRemovalJSON{}
		for rows.Next() {
			var e extensionRemovalJSON
			var appControlEnabled bool
			if err := rows.Scan(&e.ID, &e.Browser, &e.ExtensionID, &e.Scope,
				&e.UserAccount, &e.Profile, &e.RequestedBy, &e.RequestedAt,
				&e.Fulfilled, &e.FulfilledAt, &e.CancelledAt, &appControlEnabled,
				&e.TargetsTotal, &e.TargetsCompleted, &e.LastCompletedAt); err != nil {
				logger.Error("extension removal row scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			requests = append(requests, extensionRemovalState(e, appControlEnabled))
		}
		if err := rows.Err(); err != nil {
			logger.Error("extension removal rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(extensionRemovalsGetResp{
			TenantID: tenantID,
			Requests: requests,
		})
	}
}

// TenantExtensionRemovalCreateHandler serves POST .../extension-removals — the
// dashboard "Remove now" action. Validates scope/context before any DB access.
func TenantExtensionRemovalCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_removal_create")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req extensionRemovalCreateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		browser, extensionID, scope, userAccount, profile, errMsg := validateExtensionRemoval(req)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, logger, err)
			return
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin extension removal transaction failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context())

		var appControlEnabled bool
		if err := tx.QueryRow(r.Context(), `
			SELECT app_control_enabled FROM tenants WHERE id = $1::uuid
		`, tenantID).Scan(&appControlEnabled); err != nil {
			logger.Error("extension control lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !appControlEnabled {
			http.Error(w, "extension control is disabled for this tenant", http.StatusConflict)
			return
		}

		now := time.Now().UTC()
		requestedBy := strings.TrimSpace(req.RequestedBy)
		var id int64
		err = tx.QueryRow(r.Context(), `
			INSERT INTO tenant_extension_removal_requests
			    (tenant_id, browser, extension_id, scope, user_account, profile,
			     requested_by, requested_at, fulfilled)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, FALSE)
			RETURNING id
		`, tenantID, browser, extensionID, scope, userAccount, profile,
			requestedBy, now).Scan(&id)
		if err != nil {
			if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
				http.Error(w, "an identical pending removal request already exists", http.StatusConflict)
				return
			}
			logger.Error("extension removal insert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		tag, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_extension_removal_targets
			    (request_id, device_id, user_account, profile)
			SELECT DISTINCT $1::bigint, dbe.device_id, dbe.user_account, dbe.profile
			FROM device_browser_extensions dbe
			JOIN devices d ON d.id = dbe.device_id
			WHERE d.tenant_id = $2::uuid
			  AND dbe.browser = $3
			  AND dbe.extension_id = $4
			  AND (
			       ($5 = 'one_profile' AND lower(dbe.user_account) = lower($6) AND dbe.profile = $7)
			    OR ($5 = 'one_user' AND lower(dbe.user_account) = lower($6))
			    OR $5 IN ('all_profiles', 'all_devices')
			  )
			ON CONFLICT DO NOTHING
		`, id, tenantID, browser, extensionID, scope, userAccount, profile)
		if err != nil {
			logger.Error("extension removal target capture failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		targetsTotal := int(tag.RowsAffected())
		if targetsTotal == 0 {
			http.Error(w, "no installed extension matches the selected scope", http.StatusConflict)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit extension removal failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("extension removal queued", "tenant_id", tenantID, "id", id,
			"extension_id", extensionID, "scope", scope)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(extensionRemovalJSON{
			ID: id, Browser: browser, ExtensionID: extensionID, Scope: scope,
			UserAccount: userAccount, Profile: profile, RequestedBy: requestedBy,
			RequestedAt: now, Fulfilled: false, State: "queued",
			TargetsTotal: targetsTotal, TargetsCompleted: 0,
		})
	}
}

// TenantExtensionRemovalCancelHandler serves DELETE .../extension-removals/{requestID}.
// Only an active request can be cancelled. Cancellation is retained as lifecycle
// history instead of deleting the only audit record of a destructive request.
func TenantExtensionRemovalCancelHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "extension_removal_cancel")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		requestIDStr := strings.TrimSpace(chi.URLParam(r, "requestID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		requestID, err := parseInt64Param(requestIDStr)
		if err != nil {
			http.Error(w, "requestID must be an integer", http.StatusBadRequest)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE tenant_extension_removal_requests
			SET cancelled_at = NOW()
			WHERE id = $1 AND tenant_id = $2::uuid
			  AND fulfilled = FALSE AND cancelled_at IS NULL
		`, requestID, tenantID)
		if err != nil {
			logger.Error("extension removal cancel failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "request not found or already fulfilled", http.StatusNotFound)
			return
		}

		logger.Info("extension removal cancelled", "tenant_id", tenantID, "id", requestID)
		w.WriteHeader(http.StatusNoContent)
	}
}
