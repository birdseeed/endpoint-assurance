// Portal report schedule handlers (PAT-703, PAT-1847). Tenant identity comes
// only from the verified portal auth context. The singular /schedule route is
// retained as an executive-summary compatibility alias; typed schedules use
// /schedules/{reportType}, with /schedules returning the configured collection.
//
// Every role reads schedules. Only a tenant admin creates or changes one
// (PAT-2408, ruled 2026-10-05): both PUT routes answer any other caller
// 403 admin_role_required and write nothing.
package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
	"patched.im/api/internal/reportsched"
)

type portalScheduleResp struct {
	Configured  bool       `json:"configured"`
	ReportType  string     `json:"report_type,omitempty"`
	ReportLabel string     `json:"report_label,omitempty"`
	Cadence     string     `json:"cadence,omitempty"`
	Weekday     *int       `json:"weekday,omitempty"`
	MonthDay    *int       `json:"month_day,omitempty"`
	HourUTC     *int       `json:"hour_utc,omitempty"`
	Enabled     bool       `json:"enabled"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	NextRunAt   *time.Time `json:"next_run_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

type portalSchedulesResp struct {
	Schedules []portalScheduleResp `json:"schedules"`
}

func customerReportDefinition(reportType string) (report.ReportDefinition, bool) {
	def, found := report.LookupReportDefinition(reportType)
	return def, found && def.CustomerFacing && def.Subject == report.SubjectTenant
}

func PortalReportScheduleGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return portalReportScheduleGetHandler(pool, "executive-summary")
}

func PortalReportScheduleTypeGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		reportType := chi.URLParam(r, "reportType")
		if _, ok := customerReportDefinition(reportType); !ok {
			http.Error(w, "unknown or unavailable report type", http.StatusBadRequest)
			return
		}
		portalReportScheduleGetHandler(pool, reportType).ServeHTTP(w, r)
	}
}

func portalReportScheduleGetHandler(pool *pgxpool.Pool, reportType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_report_schedule_get", "tenant_id", id.TenantID,
			"report_type", reportType)

		def, _ := customerReportDefinition(reportType)
		resp := portalScheduleResp{ReportType: reportType, ReportLabel: def.Label}
		var updatedAt time.Time
		err := pool.QueryRow(r.Context(), `
			SELECT cadence, weekday, month_day, hour_utc, enabled,
			       last_run_at, next_run_at, updated_at
			FROM portal_report_schedules
			WHERE tenant_id = $1::uuid AND report_type = $2
		`, id.TenantID, reportType).Scan(&resp.Cadence, &resp.Weekday, &resp.MonthDay,
			&resp.HourUTC, &resp.Enabled, &resp.LastRunAt, &resp.NextRunAt, &updatedAt)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			logger.Error("fetch portal report schedule failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		default:
			resp.Configured = true
			resp.UpdatedAt = &updatedAt
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func PortalReportSchedulesListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		rows, err := pool.Query(r.Context(), `
			SELECT report_type, cadence, weekday, month_day, hour_utc, enabled,
			       last_run_at, next_run_at, updated_at
			FROM portal_report_schedules
			WHERE tenant_id = $1::uuid
			ORDER BY report_type
		`, id.TenantID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		resp := portalSchedulesResp{Schedules: []portalScheduleResp{}}
		for rows.Next() {
			var item portalScheduleResp
			var updatedAt time.Time
			if err := rows.Scan(&item.ReportType, &item.Cadence, &item.Weekday,
				&item.MonthDay, &item.HourUTC, &item.Enabled, &item.LastRunAt,
				&item.NextRunAt, &updatedAt); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			item.Configured = true
			item.UpdatedAt = &updatedAt
			if def, found := customerReportDefinition(item.ReportType); found {
				item.ReportLabel = def.Label
			}
			resp.Schedules = append(resp.Schedules, item)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

type portalSchedulePutReq struct {
	Cadence  string `json:"cadence"`
	Weekday  *int   `json:"weekday"`
	MonthDay *int   `json:"month_day"`
	HourUTC  *int   `json:"hour_utc"`
	Enabled  *bool  `json:"enabled"`
}

func (req *portalSchedulePutReq) validate() string {
	switch req.Cadence {
	case reportsched.CadenceDaily:
		if req.Weekday != nil || req.MonthDay != nil {
			return "daily cadence takes neither weekday nor month_day"
		}
	case reportsched.CadenceWeekly:
		if req.Weekday == nil || *req.Weekday < 0 || *req.Weekday > 6 {
			return "weekly cadence requires weekday in [0,6] (0=Sunday)"
		}
		if req.MonthDay != nil {
			return "weekly cadence does not take month_day"
		}
	case reportsched.CadenceMonthly:
		if req.MonthDay == nil || *req.MonthDay < 1 || *req.MonthDay > 31 {
			return "monthly cadence requires month_day in [1,31]"
		}
		if req.Weekday != nil {
			return "monthly cadence does not take weekday"
		}
	default:
		return "cadence must be one of: daily, weekly, monthly"
	}
	if req.HourUTC == nil || *req.HourUTC < 0 || *req.HourUTC > 23 {
		return "hour_utc is required, in [0,23]"
	}
	if req.Enabled == nil {
		return "enabled is required"
	}
	return ""
}

func PortalReportSchedulePutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return portalReportSchedulePutHandler(pool, "executive-summary")
}

func PortalReportScheduleTypePutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		reportType := chi.URLParam(r, "reportType")
		if _, ok := customerReportDefinition(reportType); !ok {
			http.Error(w, "unknown or unavailable report type", http.StatusBadRequest)
			return
		}
		portalReportSchedulePutHandler(pool, reportType).ServeHTTP(w, r)
	}
}

func portalReportSchedulePutHandler(pool *pgxpool.Pool, reportType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_report_schedule_put", "tenant_id", id.TenantID,
			"report_type", reportType)

		var req portalSchedulePutReq
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<12))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if reason := req.validate(); reason != "" {
			http.Error(w, reason, http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		now := time.Now().UTC()
		next, err := reportsched.NextRun(req.Cadence,
			intOrDefault(req.Weekday, 0), intOrDefault(req.MonthDay, 1),
			*req.HourUTC, now)
		if err != nil {
			http.Error(w, "invalid schedule", http.StatusBadRequest)
			return
		}

		// PAT-2408: admin only, enforced the way every other admin-only portal
		// write enforces it. The role is re-read inside the transaction that
		// writes the schedule, with the caller's portal_users row held FOR
		// SHARE, so a demotion cannot commit between this check and the write.
		// A viewer, a user admitted only through the tenant's email domain (no
		// portal_users row) and the service identity all get
		// 403 admin_role_required. Body validation above runs first and needs
		// no database.
		tx, err := pool.Begin(ctx)
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalAdmin(ctx, tx, w, id, "change a report schedule", logger) {
			return
		}

		def, _ := customerReportDefinition(reportType)
		resp := portalScheduleResp{ReportType: reportType, ReportLabel: def.Label}
		var updatedAt time.Time
		err = tx.QueryRow(ctx, `
			INSERT INTO portal_report_schedules
				(tenant_id, report_type, cadence, weekday, month_day, hour_utc, enabled, next_run_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (tenant_id, report_type) DO UPDATE SET
				cadence     = EXCLUDED.cadence,
				weekday     = EXCLUDED.weekday,
				month_day   = EXCLUDED.month_day,
				hour_utc    = EXCLUDED.hour_utc,
				enabled     = EXCLUDED.enabled,
				next_run_at = EXCLUDED.next_run_at,
				updated_at  = now()
			RETURNING cadence, weekday, month_day, hour_utc, enabled,
			          last_run_at, next_run_at, updated_at
		`, id.TenantID, reportType, req.Cadence, req.Weekday, req.MonthDay,
			*req.HourUTC, *req.Enabled, next).Scan(
			&resp.Cadence, &resp.Weekday, &resp.MonthDay, &resp.HourUTC,
			&resp.Enabled, &resp.LastRunAt, &resp.NextRunAt, &updatedAt)
		if err != nil {
			logger.Error("upsert portal report schedule failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			logger.Error("commit portal report schedule failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp.Configured = true
		resp.UpdatedAt = &updatedAt

		logger.Info("portal report schedule updated", "email", id.Email,
			"cadence", resp.Cadence, "enabled", resp.Enabled,
			"next_run_at", next.Format(time.RFC3339))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func intOrDefault(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}
