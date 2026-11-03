package handlers

// Unapproved software alert lifecycle (PAT-2097).
//
//   GET  /v1/portal/software-alerts                      tenant's alerts, filtered and paged (any role)
//   GET  /v1/portal/software-alerts/{id}                 one alert with its history (any role)
//   POST /v1/portal/software-alerts/{id}/acknowledge     acknowledge, optional note (admin role only)
//
//   GET  /admin/software-alerts                          operator queue across tenants
//   POST /admin/tenants/{tenantID}/software-alerts/{id}/acknowledge
//
// Portal routes are tenant scoped by the CF Access identity (PAT-693); no
// tenant identifier is read from the client, and an id belonging to another
// tenant is 404, never 403, so an id's existence is not disclosed. The admin
// write is enforced the way PAT-2007 enforces approval writes: the role is
// read from portal_users inside the write transaction, FOR SHARE, before the
// body is read, and anything but admin is 403.
//
// Acknowledging records that someone has seen the alert. It changes nothing
// on a device and resolves nothing: an alert resolves only on evidence (the
// policy changed, or an authoritative report proved the product gone). See
// internal/softwaregov/lifecycle.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/softwaregov"
)

const (
	softwareAlertsDefaultLimit = 100
	softwareAlertsMaxLimit     = 500
	softwareAlertAckMaxBody    = 8 << 10
	softwareAlertMaxProductKey = 700
)

type softwareAlertErr struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeSoftwareAlertError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(softwareAlertErr{Error: code, Message: msg})
}

// parseAlertStatuses reads a comma-separated status filter.
func parseAlertStatuses(v string) ([]string, bool) {
	if v == "" {
		return nil, true
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		switch s {
		case softwaregov.AlertOpen, softwaregov.AlertAcknowledged, softwaregov.AlertResolved:
		default:
			return nil, false
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, true
}

func parseAlertPaging(w http.ResponseWriter, q map[string][]string) (limit, offset int, ok bool) {
	limit = softwareAlertsDefaultLimit
	if v := firstQuery(q, "limit"); v != "" {
		n, good := strictPositiveInt(v, 1, softwareAlertsMaxLimit)
		if !good {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be 1 to %d", softwareAlertsMaxLimit))
			return 0, 0, false
		}
		limit = n
	}
	if v := firstQuery(q, "offset"); v != "" {
		n, good := strictPositiveInt(v, 0, 1<<30)
		if !good {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "offset must be 0 or more")
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

func firstQuery(q map[string][]string, k string) string {
	if v, ok := q[k]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func rejectUnknownParams(w http.ResponseWriter, q map[string][]string, allowed ...string) bool {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range q {
		if !ok[k] {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "unknown query parameter "+strconv.Quote(k))
			return false
		}
	}
	return true
}

func alertIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeSoftwareAlertError(w, http.StatusNotFound, "not_found", "alert not found")
		return 0, false
	}
	return id, true
}

// PortalSoftwareAlertsHandler serves GET /v1/portal/software-alerts.
func PortalSoftwareAlertsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		if !rejectUnknownParams(w, q, "status", "product_key", "device_id", "limit", "offset") {
			return
		}
		statuses, good := parseAlertStatuses(q.Get("status"))
		if !good {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "status must be open, acknowledged or resolved, comma separated")
			return
		}
		productKey := strings.TrimSpace(q.Get("product_key"))
		if len(productKey) > softwareAlertMaxProductKey || hasControlChars(productKey) {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "product_key is not valid")
			return
		}
		deviceID := strings.TrimSpace(q.Get("device_id"))
		if deviceID != "" && !looksLikeUUID(deviceID) {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "device_id must be a UUID")
			return
		}
		limit, offset, ok := parseAlertPaging(w, q)
		if !ok {
			return
		}
		page, err := softwaregov.ListAlerts(r.Context(), pool, id.TenantID, softwaregov.AlertFilter{
			Statuses: statuses, ProductKey: productKey, DeviceID: deviceID, Limit: limit, Offset: offset,
		})
		if err != nil {
			slog.Error("software alerts list failed", "err", err, "tenant_id", id.TenantID,
				"req_id", middleware.GetReqID(r.Context()))
			writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": page.Total, "limit": limit, "offset": offset, "returned": len(page.Alerts),
			"counts": page.Counts, "alerts": page.Alerts,
		})
	}
}

type softwareAlertDetail struct {
	softwaregov.AlertView
	History []softwaregov.AlertTransition `json:"history"`
}

// PortalSoftwareAlertHandler serves GET /v1/portal/software-alerts/{id}.
func PortalSoftwareAlertHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		alertID, ok := alertIDParam(w, r)
		if !ok {
			return
		}
		v, history, err := softwaregov.GetAlert(r.Context(), pool, id.TenantID, alertID)
		if errors.Is(err, softwaregov.ErrAlertNotFound) {
			writeSoftwareAlertError(w, http.StatusNotFound, "not_found", "alert not found")
			return
		}
		if err != nil {
			slog.Error("software alert read failed", "err", err, "tenant_id", id.TenantID)
			writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(softwareAlertDetail{AlertView: v, History: history})
	}
}

type alertAckRequest struct {
	Note *string `json:"note"`
}

type alertAckResponse struct {
	Changed bool `json:"changed"`
	softwareAlertDetail
}

// readAlertAckNote reads the optional {"note": "..."} body. An empty body is
// no note. Newlines are allowed in a note; other control characters are not.
func readAlertAckNote(w http.ResponseWriter, r *http.Request) (string, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, softwareAlertAckMaxBody+1))
	if err != nil {
		writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "could not read the request body")
		return "", false
	}
	if len(body) > softwareAlertAckMaxBody {
		writeSoftwareAlertError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
		return "", false
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", true
	}
	var req alertAckRequest
	if err := decodeStrictJSON(body, &req); err != nil {
		writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return "", false
	}
	if req.Note == nil {
		return "", true
	}
	note := strings.TrimSpace(*req.Note)
	if len([]rune(note)) > softwaregov.MaxAlertNoteLen {
		writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("note must be at most %d characters", softwaregov.MaxAlertNoteLen))
		return "", false
	}
	for _, c := range note {
		if c != '\n' && unicode.IsControl(c) {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "note contains control characters")
			return "", false
		}
	}
	return note, true
}

// PortalSoftwareAlertAcknowledgeHandler serves
// POST /v1/portal/software-alerts/{id}/acknowledge. Admin role only.
func PortalSoftwareAlertAcknowledgeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_software_alert_ack", "tenant_id", id.TenantID)
		internal := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			internal("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

		// Role before the body is read or the id looked up, as PAT-2007's
		// approval writes do. FOR SHARE holds the row so a concurrent
		// demotion waits.
		role, err := portalauth.DBRole(ctx, tx, id.Email, id.TenantID, true)
		if err != nil {
			internal("role lookup failed", err)
			return
		}
		if !portalauth.CanWrite(role) {
			writeSoftwareAlertError(w, http.StatusForbidden, "admin_role_required",
				"only a portal admin can acknowledge alerts; your role is "+role)
			return
		}
		alertID, ok := alertIDParam(w, r)
		if !ok {
			return
		}
		note, ok := readAlertAckNote(w, r)
		if !ok {
			return
		}
		acknowledge(w, r, pool, tx, id.TenantID, alertID,
			softwaregov.Actor{Kind: softwaregov.ActorPortalUser, Email: id.Email}, note, logger)
	}
}

// AdminSoftwareAlertAcknowledgeHandler serves
// POST /admin/tenants/{tenantID}/software-alerts/{id}/acknowledge.
func AdminSoftwareAlertAcknowledgeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "admin_software_alert_ack")
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		alertID, ok := alertIDParam(w, r)
		if !ok {
			return
		}
		note, ok := readAlertAckNote(w, r)
		if !ok {
			return
		}
		// Only an active tenant's alerts, as in the operator queue: a
		// revoked tenant's id is 404.
		var active bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
			tenantID).Scan(&active); err != nil {
			logger.Error("tenant lookup failed", "err", err)
			writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		if !active {
			writeSoftwareAlertError(w, http.StatusNotFound, "not_found", "alert not found")
			return
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		acknowledge(w, r, pool, tx, tenantID, alertID, softwaregov.Actor{Kind: softwaregov.ActorOperator}, note,
			logger.With("tenant_id", tenantID))
	}
}

// acknowledge runs the acknowledgement in tx, commits, and writes the alert
// with its history.
func acknowledge(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, tx pgx.Tx,
	tenantID string, alertID int64, actor softwaregov.Actor, note string, logger *slog.Logger) {
	ctx := r.Context()
	changed, err := softwaregov.AcknowledgeAlertTx(ctx, tx, tenantID, alertID, actor, note)
	switch {
	case errors.Is(err, softwaregov.ErrAlertNotFound):
		writeSoftwareAlertError(w, http.StatusNotFound, "not_found", "alert not found")
		return
	case errors.Is(err, softwaregov.ErrAlertResolved):
		writeSoftwareAlertError(w, http.StatusConflict, "alert_resolved",
			"this alert is resolved; it re-opens by itself if the software is found again")
		return
	case err != nil:
		logger.Error("acknowledge alert failed", "err", err)
		writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.Error("commit failed", "err", err)
		writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if changed {
		logger.Info("software alert acknowledged", "alert_id", alertID, "actor_kind", actor.Kind)
	}
	v, history, err := softwaregov.GetAlert(ctx, pool, tenantID, alertID)
	if err != nil {
		logger.Error("software alert read after acknowledge failed", "err", err)
		writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(alertAckResponse{Changed: changed,
		softwareAlertDetail: softwareAlertDetail{AlertView: v, History: history}})
}

// AdminSoftwareAlertsHandler serves GET /admin/software-alerts: the
// operator's queue of open and acknowledged alerts across every active
// tenant, oldest first. status and tenant_id narrow it.
func AdminSoftwareAlertsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !rejectUnknownParams(w, q, "status", "tenant_id", "limit", "offset") {
			return
		}
		statuses, good := parseAlertStatuses(q.Get("status"))
		if !good {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "status must be open, acknowledged or resolved, comma separated")
			return
		}
		tenantID := strings.TrimSpace(q.Get("tenant_id"))
		if tenantID != "" && !looksLikeUUID(tenantID) {
			writeSoftwareAlertError(w, http.StatusBadRequest, "invalid_request", "tenant_id must be a UUID")
			return
		}
		limit, offset, ok := parseAlertPaging(w, q)
		if !ok {
			return
		}
		now := time.Now().UTC()
		alerts, total, err := softwaregov.OperatorAlerts(r.Context(), pool, statuses, tenantID, limit, offset, now)
		if err != nil {
			slog.Error("operator software alerts failed", "err", err, "req_id", middleware.GetReqID(r.Context()))
			writeSoftwareAlertError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generated_at": now, "total": total, "limit": limit, "offset": offset,
			"returned": len(alerts), "alerts": alerts,
		})
	}
}
