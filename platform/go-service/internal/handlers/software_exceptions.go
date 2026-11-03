package handlers

// PAT-1824: software exception register (pinned version / accepted risk).
//
// Blocks PAT-1785 operating: the portal's /exceptions page (merged and
// deployed) has been rendering the upstream-error page in production
// because GET /v1/portal/exceptions did not exist on the platform. See
// internal/report/portal_exceptions.go for the read-side data shape and
// caps.
//
// Deliberately orthogonal to the app policy model (tenant_app_policies,
// mandatory/approved/unapproved) per PAT-1785's own ruling — an exception
// records accepted risk for a pinned version with an acceptor, a review
// date and a dependency reason, none of which a policy row carries, and a
// product can be policy-unapproved while also carrying an accepted
// exception. Nothing here writes to tenant_app_policies.
//
// A pinned version never suppresses a CVE finding for that product/version
// (root AGENTS.md: absence requires authority) — this file never touches
// device_cve_findings / cve_feed_entries. Any "update available" noise
// suppression tied to a pinned version is separate, deferred scope.
//
// Routes:
//
//	POST /admin/tenants/{tenantID}/exceptions
//	    Record a new exception request. Written by a named Patched
//	    specialist per the 12 Sept portal decision ("a customer asks, a
//	    specialist records") — not a customer-facing write path, so this is
//	    admin-token-authed on the internal listener, same pattern as
//	    protected_software.go's admin routes.
//	POST /admin/tenants/{tenantID}/exceptions/{exceptionID}/accept
//	    Record acceptance: acceptor + reason, moving status from
//	    'unaccepted' to 'accepted'. There is no un-accept path — recording a
//	    reversal is a new exception, not a mutation of this one, so the
//	    decision log this action appends to always reads left-to-right as
//	    the true sequence of what happened.
//	POST /admin/tenants/{tenantID}/exceptions/{exceptionID}/review-date
//	    Renew the review date. Independent of acceptance status — an
//	    accepted exception can still be review-overdue, and renewing the
//	    date does not itself accept or re-accept anything.
//	GET /v1/portal/exceptions (public listener, portal-JWT auth — see
//	    portalauth.Middleware, mounted in cmd/patched-api/main.go)
//	    The caller's own exception register, tenant-scoped like every other
//	    /v1/portal/* endpoint. Read-only — the portal never records a
//	    disposition itself.

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// ---------------------------------------------------------------------------
// GET /v1/portal/exceptions
// ---------------------------------------------------------------------------

type portalExceptionDeviceJSON struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
}

type portalExceptionHistoryJSON struct {
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

type portalExceptionEntry struct {
	ID               string                       `json:"id"`
	Product          string                       `json:"product"`
	Version          string                       `json:"version"`
	Type             string                       `json:"type"`
	DeviceCount      int                          `json:"device_count"`
	Devices          []portalExceptionDeviceJSON  `json:"devices"`
	DevicesTruncated bool                         `json:"devices_truncated"`
	RequestedBy      string                       `json:"requested_by"`
	RequestedAt      time.Time                    `json:"requested_at"`
	DependsOn        string                       `json:"depends_on"`
	Acceptor         *string                      `json:"acceptor"`
	AcceptedAt       *time.Time                   `json:"accepted_at"`
	Status           string                       `json:"status"`
	ReviewDate       *string                      `json:"review_date"`
	ReviewOverdue    bool                         `json:"review_overdue"`
	History          []portalExceptionHistoryJSON `json:"history"`
}

type portalExceptionsResp struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Total       int                    `json:"total"`
	Truncated   bool                   `json:"truncated"`
	Exceptions  []portalExceptionEntry `json:"exceptions"`
}

// PortalExceptionsHandler serves GET /v1/portal/exceptions — the tenant's
// software exception register, capped per report.FetchPortalExceptions.
func PortalExceptionsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_exceptions", "tenant_id", id.TenantID)

		res, err := report.FetchPortalExceptions(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch portal exceptions failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		exceptions := make([]portalExceptionEntry, 0, len(res.Exceptions))
		for _, e := range res.Exceptions {
			devices := make([]portalExceptionDeviceJSON, 0, len(e.Devices))
			for _, d := range e.Devices {
				devices = append(devices, portalExceptionDeviceJSON{DeviceID: d.DeviceID, Hostname: d.Hostname})
			}
			history := make([]portalExceptionHistoryJSON, 0, len(e.History))
			for _, h := range e.History {
				history = append(history, portalExceptionHistoryJSON{Actor: h.Actor, Action: h.Action, Reason: h.Reason, At: h.At})
			}
			exceptions = append(exceptions, portalExceptionEntry{
				ID:               e.ID,
				Product:          e.Product,
				Version:          e.Version,
				Type:             e.Type,
				DeviceCount:      e.DeviceCount,
				Devices:          devices,
				DevicesTruncated: e.DevicesTrunc,
				RequestedBy:      e.RequestedBy,
				RequestedAt:      e.RequestedAt,
				DependsOn:        e.DependsOn,
				Acceptor:         e.Acceptor,
				AcceptedAt:       e.AcceptedAt,
				Status:           e.Status,
				ReviewDate:       e.ReviewDate,
				ReviewOverdue:    e.ReviewOverdue,
				History:          history,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalExceptionsResp{
			GeneratedAt: time.Now().UTC(),
			Total:       res.Total,
			Truncated:   res.Truncated,
			Exceptions:  exceptions,
		})
	}
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/exceptions — create
// ---------------------------------------------------------------------------

type exceptionCreateReq struct {
	Product     string   `json:"product"`
	Version     string   `json:"version"`
	Type        string   `json:"type"`
	DependsOn   string   `json:"depends_on"`
	RequestedBy string   `json:"requested_by"`
	RequestedAt string   `json:"requested_at"` // RFC3339, optional — defaults to now()
	ReviewDate  string   `json:"review_date"`  // "2006-01-02", optional
	DeviceIDs   []string `json:"device_ids"`
}

type exceptionRow struct {
	ID          string     `json:"id"`
	Product     string     `json:"product"`
	Version     string     `json:"version"`
	Type        string     `json:"type"`
	DependsOn   string     `json:"depends_on"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	Status      string     `json:"status"`
	Acceptor    *string    `json:"acceptor"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	ReviewDate  *string    `json:"review_date"`
}

// ExceptionCreateHandler serves POST /admin/tenants/{tenantID}/exceptions.
//
// 201 exceptionRow | 400 bad input | 404 unknown tenant or a device_id not
// owned by this tenant
func ExceptionCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "exception_create")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req exceptionCreateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		req.Product = strings.TrimSpace(req.Product)
		req.Version = strings.TrimSpace(req.Version)
		req.Type = strings.TrimSpace(req.Type)
		req.DependsOn = strings.TrimSpace(req.DependsOn)
		req.RequestedBy = strings.TrimSpace(req.RequestedBy)
		if req.Product == "" || req.Version == "" || req.RequestedBy == "" {
			http.Error(w, "product, version and requested_by are required", http.StatusBadRequest)
			return
		}
		if req.Type == "" {
			req.Type = "application"
		}

		requestedAt := time.Now().UTC()
		if req.RequestedAt != "" {
			t, err := time.Parse(time.RFC3339, req.RequestedAt)
			if err != nil {
				http.Error(w, "requested_at must be RFC3339", http.StatusBadRequest)
				return
			}
			requestedAt = t
		}
		var reviewDate *string
		if req.ReviewDate != "" {
			if _, err := time.Parse("2006-01-02", req.ReviewDate); err != nil {
				http.Error(w, "review_date must be YYYY-MM-DD", http.StatusBadRequest)
				return
			}
			reviewDate = &req.ReviewDate
		}
		req.DeviceIDs = uniqueStrings(req.DeviceIDs)
		for _, d := range req.DeviceIDs {
			if !looksLikeUUID(d) {
				http.Error(w, "device_ids must be UUIDs", http.StatusBadRequest)
				return
			}
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var row exceptionRow
		row.Status = "unaccepted"
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO tenant_software_exceptions
			    (tenant_id, product, version, type, depends_on, requested_by, requested_at, review_date)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::date)
			RETURNING id::text, product, version, type, depends_on, requested_by, requested_at,
			          status, review_date::text
		`, tenantID, req.Product, req.Version, req.Type, req.DependsOn, req.RequestedBy, requestedAt, reviewDate,
		).Scan(&row.ID, &row.Product, &row.Version, &row.Type, &row.DependsOn, &row.RequestedBy,
			&row.RequestedAt, &row.Status, &row.ReviewDate); err != nil {
			logger.Error("exception insert failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if len(req.DeviceIDs) > 0 {
			var deviceCount int
			if err := tx.QueryRow(r.Context(),
				`SELECT count(*) FROM devices WHERE tenant_id = $1::uuid AND id = ANY($2::uuid[])`,
				tenantID, req.DeviceIDs,
			).Scan(&deviceCount); err != nil {
				logger.Error("device ownership check failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if deviceCount != len(req.DeviceIDs) {
				http.Error(w, "one or more device_ids do not belong to this tenant", http.StatusNotFound)
				return
			}
			for _, d := range req.DeviceIDs {
				if _, err := tx.Exec(r.Context(), `
					INSERT INTO tenant_software_exception_devices (exception_id, device_id)
					VALUES ($1::uuid, $2::uuid) ON CONFLICT DO NOTHING
				`, row.ID, d); err != nil {
					logger.Error("exception device insert failed", "err", err, "tenant_id", tenantID, "exception_id", row.ID)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_software_exception_changes (tenant_id, exception_id, action, actor, reason)
			VALUES ($1::uuid, $2::uuid, 'requested', $3, '')
		`, tenantID, row.ID, req.RequestedBy); err != nil {
			logger.Error("exception history insert failed", "err", err, "tenant_id", tenantID, "exception_id", row.ID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("exception created", "tenant_id", tenantID, "exception_id", row.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(row)
	}
}

// uniqueStrings de-duplicates, so a caller sending the same device_id twice
// doesn't fail the ownership-count check below.
func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/exceptions/{exceptionID}/accept
// ---------------------------------------------------------------------------

type exceptionAcceptReq struct {
	Acceptor string `json:"acceptor"`
	Reason   string `json:"reason"`
}

// ExceptionAcceptHandler serves
// POST /admin/tenants/{tenantID}/exceptions/{exceptionID}/accept.
//
// There is no un-accept path: reversing an accepted exception is recorded
// as a new exception, not a mutation of this one, so the append-only
// decision log this handler writes to always reads as the true sequence.
//
// 200 exceptionRow | 400 bad input | 404 unknown tenant/exception | 409 already accepted
func ExceptionAcceptHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "exception_accept")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		exceptionID := strings.TrimSpace(chi.URLParam(r, "exceptionID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(exceptionID) {
			http.Error(w, "tenantID and exceptionID must be UUIDs", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req exceptionAcceptReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.Acceptor = strings.TrimSpace(req.Acceptor)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Acceptor == "" || req.Reason == "" {
			http.Error(w, "acceptor and reason are both required", http.StatusBadRequest)
			return
		}

		var currentStatus string
		if err := pool.QueryRow(r.Context(), `
			SELECT status FROM tenant_software_exceptions
			WHERE id = $1::uuid AND tenant_id = $2::uuid
		`, exceptionID, tenantID).Scan(&currentStatus); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "exception not found", http.StatusNotFound)
				return
			}
			logger.Error("exception lookup failed", "err", err, "tenant_id", tenantID, "exception_id", exceptionID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if currentStatus == "accepted" {
			http.Error(w, "exception is already accepted", http.StatusConflict)
			return
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var row exceptionRow
		if err := tx.QueryRow(r.Context(), `
			UPDATE tenant_software_exceptions
			SET status = 'accepted', acceptor = $3, accepted_at = now()
			WHERE id = $1::uuid AND tenant_id = $2::uuid
			RETURNING id::text, product, version, type, depends_on, requested_by, requested_at,
			          status, acceptor, accepted_at, review_date::text
		`, exceptionID, tenantID, req.Acceptor,
		).Scan(&row.ID, &row.Product, &row.Version, &row.Type, &row.DependsOn, &row.RequestedBy,
			&row.RequestedAt, &row.Status, &row.Acceptor, &row.AcceptedAt, &row.ReviewDate); err != nil {
			logger.Error("exception accept update failed", "err", err, "tenant_id", tenantID, "exception_id", exceptionID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_software_exception_changes (tenant_id, exception_id, action, actor, reason)
			VALUES ($1::uuid, $2::uuid, 'accepted', $3, $4)
		`, tenantID, exceptionID, req.Acceptor, req.Reason); err != nil {
			logger.Error("exception history insert failed", "err", err, "tenant_id", tenantID, "exception_id", exceptionID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("exception accepted", "tenant_id", tenantID, "exception_id", exceptionID, "acceptor", req.Acceptor)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(row)
	}
}

// ---------------------------------------------------------------------------
// POST /admin/tenants/{tenantID}/exceptions/{exceptionID}/review-date
// ---------------------------------------------------------------------------

type exceptionReviewDateReq struct {
	ReviewDate string `json:"review_date"`
	Actor      string `json:"actor"`
	Reason     string `json:"reason"`
}

type exceptionReviewDateResp struct {
	ID         string  `json:"id"`
	ReviewDate *string `json:"review_date"`
}

// ExceptionReviewDateHandler serves
// POST /admin/tenants/{tenantID}/exceptions/{exceptionID}/review-date —
// renews the review date, independent of acceptance status: an accepted
// exception can still be review-overdue, and renewing the date neither
// accepts nor re-accepts anything.
//
// 200 exceptionReviewDateResp | 400 bad input | 404 unknown tenant/exception
func ExceptionReviewDateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "exception_review_date")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		exceptionID := strings.TrimSpace(chi.URLParam(r, "exceptionID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(exceptionID) {
			http.Error(w, "tenantID and exceptionID must be UUIDs", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req exceptionReviewDateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.ReviewDate = strings.TrimSpace(req.ReviewDate)
		req.Actor = strings.TrimSpace(req.Actor)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.ReviewDate == "" || req.Actor == "" {
			http.Error(w, "review_date and actor are both required", http.StatusBadRequest)
			return
		}
		if _, err := time.Parse("2006-01-02", req.ReviewDate); err != nil {
			http.Error(w, "review_date must be YYYY-MM-DD", http.StatusBadRequest)
			return
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var resp exceptionReviewDateResp
		if err := tx.QueryRow(r.Context(), `
			UPDATE tenant_software_exceptions
			SET review_date = $3::date
			WHERE id = $1::uuid AND tenant_id = $2::uuid
			RETURNING id::text, review_date::text
		`, exceptionID, tenantID, req.ReviewDate).Scan(&resp.ID, &resp.ReviewDate); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "exception not found", http.StatusNotFound)
				return
			}
			logger.Error("exception review-date update failed", "err", err, "tenant_id", tenantID, "exception_id", exceptionID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_software_exception_changes (tenant_id, exception_id, action, actor, reason)
			VALUES ($1::uuid, $2::uuid, 'review_date_renewed', $3, $4)
		`, tenantID, exceptionID, req.Actor, req.Reason); err != nil {
			logger.Error("exception history insert failed", "err", err, "tenant_id", tenantID, "exception_id", exceptionID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("exception review date renewed", "tenant_id", tenantID, "exception_id", exceptionID, "review_date", req.ReviewDate)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
