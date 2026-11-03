package handlers

// PAT-370 — Report delivery infrastructure.
//
// Endpoints:
//   GET    /admin/tenants/{tid}/report-schedules
//   POST   /admin/tenants/{tid}/report-schedules
//   PUT    /admin/tenants/{tid}/report-schedules/{id}
//   DELETE /admin/tenants/{tid}/report-schedules/{id}
//   GET    /admin/tenants/{tid}/delivery-contacts
//   POST   /admin/tenants/{tid}/delivery-contacts
//   PUT    /admin/tenants/{tid}/delivery-contacts/{id}
//   DELETE /admin/tenants/{tid}/delivery-contacts/{id}
//   GET    /admin/tenants/{tid}/report-records              (paginated)
//   POST   /admin/tenants/{tid}/report-records/generate     (ad-hoc)
//   GET    /admin/tenants/{tid}/report-records/{id}/download?format=pdf|xlsx
//   POST   /admin/report-download-tokens/{token}/redeem    (public, no auth)

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// reportStorageRoot is the directory where generated PDF and XLSX files are stored.
// Override via REPORT_STORAGE_ROOT env var (defaults to /srv/reports).
func reportStorageRoot() string {
	if v := os.Getenv("REPORT_STORAGE_ROOT"); v != "" {
		return v
	}
	return "/srv/reports"
}

var emailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ─── Delivery contacts ─────────────────────────────────────────────────────────

type deliveryContact struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Label     string    `json:"label"`
	Email     string    `json:"email"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UsedBy    int       `json:"used_by_schedules,omitempty"`
}

// ListDeliveryContactsHandler returns all delivery contacts for a tenant.
// GET /admin/tenants/{tid}/delivery-contacts
func ListDeliveryContactsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "list_delivery_contacts", "tenant_id", tid)

		rows, err := pool.Query(r.Context(), `
			SELECT
				dc.id::text,
				dc.tenant_id::text,
				dc.label,
				dc.email,
				dc.note,
				dc.created_at,
				COUNT(DISTINCT rs.id) AS used_by
			FROM delivery_contacts dc
			LEFT JOIN report_schedules rs
				ON rs.tenant_id = dc.tenant_id
				AND rs.recipient_ids::text ILIKE '%' || dc.id::text || '%'
			WHERE dc.tenant_id = $1::uuid
			GROUP BY dc.id, dc.tenant_id, dc.label, dc.email, dc.note, dc.created_at
			ORDER BY dc.label
		`, tid)
		if err != nil {
			logger.Error("query contacts", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var contacts []deliveryContact
		for rows.Next() {
			var c deliveryContact
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Label, &c.Email, &c.Note, &c.CreatedAt, &c.UsedBy); err != nil {
				logger.Error("scan contact", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			contacts = append(contacts, c)
		}
		if contacts == nil {
			contacts = []deliveryContact{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contacts)
	}
}

// CreateDeliveryContactHandler adds a new delivery contact.
// POST /admin/tenants/{tid}/delivery-contacts
func CreateDeliveryContactHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "create_delivery_contact", "tenant_id", tid)

		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		var req struct {
			Label string `json:"label"`
			Email string `json:"email"`
			Note  string `json:"note"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.Label = strings.TrimSpace(req.Label)
		req.Email = strings.TrimSpace(req.Email)
		if req.Label == "" || req.Email == "" {
			http.Error(w, "label and email are required", http.StatusBadRequest)
			return
		}
		if !emailRE.MatchString(req.Email) {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}

		var c deliveryContact
		err := pool.QueryRow(r.Context(), `
			INSERT INTO delivery_contacts (tenant_id, label, email, note)
			VALUES ($1::uuid, $2, $3, $4)
			RETURNING id::text, tenant_id::text, label, email, note, created_at
		`, tid, req.Label, req.Email, req.Note).Scan(
			&c.ID, &c.TenantID, &c.Label, &c.Email, &c.Note, &c.CreatedAt)
		if err != nil {
			if strings.Contains(err.Error(), "unique") {
				http.Error(w, "a contact with this email already exists", http.StatusConflict)
				return
			}
			logger.Error("insert contact", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(c)
	}
}

// UpdateDeliveryContactHandler edits a delivery contact.
// PUT /admin/tenants/{tid}/delivery-contacts/{id}
func UpdateDeliveryContactHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		cid := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tid) || !looksLikeUUID(cid) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "update_delivery_contact", "contact_id", cid)

		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		var req struct {
			Label string `json:"label"`
			Email string `json:"email"`
			Note  string `json:"note"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.Label = strings.TrimSpace(req.Label)
		req.Email = strings.TrimSpace(req.Email)
		if req.Label == "" || req.Email == "" {
			http.Error(w, "label and email are required", http.StatusBadRequest)
			return
		}
		if !emailRE.MatchString(req.Email) {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}

		var c deliveryContact
		err := pool.QueryRow(r.Context(), `
			UPDATE delivery_contacts
			SET label = $3, email = $4, note = $5
			WHERE id = $1::uuid AND tenant_id = $2::uuid
			RETURNING id::text, tenant_id::text, label, email, note, created_at
		`, cid, tid, req.Label, req.Email, req.Note).Scan(
			&c.ID, &c.TenantID, &c.Label, &c.Email, &c.Note, &c.CreatedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("update contact", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	}
}

// DeleteDeliveryContactHandler removes a delivery contact.
// Returns 409 if the contact is referenced by any active schedule.
// DELETE /admin/tenants/{tid}/delivery-contacts/{id}
func DeleteDeliveryContactHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		cid := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tid) || !looksLikeUUID(cid) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "delete_delivery_contact", "contact_id", cid)

		// Check if this contact is referenced by any schedule.
		var usedBy int
		_ = pool.QueryRow(r.Context(), `
			SELECT COUNT(*) FROM report_schedules
			WHERE tenant_id = $1::uuid
			  AND recipient_ids::text ILIKE '%' || $2 || '%'
		`, tid, cid).Scan(&usedBy)

		if usedBy > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "contact is used by active schedules",
				"used_by": usedBy,
			})
			return
		}

		tag, err := pool.Exec(r.Context(), `
			DELETE FROM delivery_contacts WHERE id = $1::uuid AND tenant_id = $2::uuid
		`, cid, tid)
		if err != nil {
			logger.Error("delete contact", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── Report schedules ─────────────────────────────────────────────────────────

type reportSchedule struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	Name          string          `json:"name"`
	Cadence       string          `json:"cadence"`
	CadenceConfig json.RawMessage `json:"cadence_config"`
	ContentType   string          `json:"content_type"`
	RecipientIDs  json.RawMessage `json:"recipient_ids"`
	AdHocEmails   json.RawMessage `json:"ad_hoc_emails"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

var validCadences = map[string]bool{
	"daily": true, "weekly": true, "monthly": true,
	"quarterly": true, "ad_hoc": true,
}
var validContentTypes = map[string]bool{
	"full": true, "cve_only": true, "cis_only": true,
}

// ListReportSchedulesHandler returns all schedules for a tenant.
// GET /admin/tenants/{tid}/report-schedules
func ListReportSchedulesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "list_report_schedules", "tenant_id", tid)

		rows, err := pool.Query(r.Context(), `
			SELECT id::text, tenant_id::text, name, cadence, cadence_config,
				   content_type, recipient_ids, ad_hoc_emails, created_at, updated_at
			FROM report_schedules
			WHERE tenant_id = $1::uuid
			ORDER BY name
		`, tid)
		if err != nil {
			logger.Error("query schedules", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var schedules []reportSchedule
		for rows.Next() {
			var s reportSchedule
			if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.Cadence,
				&s.CadenceConfig, &s.ContentType, &s.RecipientIDs,
				&s.AdHocEmails, &s.CreatedAt, &s.UpdatedAt); err != nil {
				logger.Error("scan schedule", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			schedules = append(schedules, s)
		}
		if schedules == nil {
			schedules = []reportSchedule{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(schedules)
	}
}

// CreateReportScheduleHandler creates a new report schedule.
// POST /admin/tenants/{tid}/report-schedules
func CreateReportScheduleHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "create_report_schedule", "tenant_id", tid)

		s, errMsg := parseScheduleBody(r.Body)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		var out reportSchedule
		err := pool.QueryRow(r.Context(), `
			INSERT INTO report_schedules
				(tenant_id, name, cadence, cadence_config, content_type, recipient_ids, ad_hoc_emails)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
			RETURNING id::text, tenant_id::text, name, cadence, cadence_config,
					  content_type, recipient_ids, ad_hoc_emails, created_at, updated_at
		`, tid, s.Name, s.Cadence, s.CadenceConfig, s.ContentType,
			s.RecipientIDs, s.AdHocEmails).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Cadence,
			&out.CadenceConfig, &out.ContentType, &out.RecipientIDs,
			&out.AdHocEmails, &out.CreatedAt, &out.UpdatedAt)
		if err != nil {
			logger.Error("insert schedule", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// UpdateReportScheduleHandler edits a report schedule.
// PUT /admin/tenants/{tid}/report-schedules/{id}
func UpdateReportScheduleHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		sid := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tid) || !looksLikeUUID(sid) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "update_report_schedule", "schedule_id", sid)

		s, errMsg := parseScheduleBody(r.Body)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		var out reportSchedule
		err := pool.QueryRow(r.Context(), `
			UPDATE report_schedules
			SET name          = $3,
				cadence        = $4,
				cadence_config = $5,
				content_type   = $6,
				recipient_ids  = $7,
				ad_hoc_emails  = $8,
				updated_at     = NOW()
			WHERE id = $1::uuid AND tenant_id = $2::uuid
			RETURNING id::text, tenant_id::text, name, cadence, cadence_config,
					  content_type, recipient_ids, ad_hoc_emails, created_at, updated_at
		`, sid, tid, s.Name, s.Cadence, s.CadenceConfig, s.ContentType,
			s.RecipientIDs, s.AdHocEmails).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Cadence,
			&out.CadenceConfig, &out.ContentType, &out.RecipientIDs,
			&out.AdHocEmails, &out.CreatedAt, &out.UpdatedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("update schedule", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// DeleteReportScheduleHandler removes a schedule.
// DELETE /admin/tenants/{tid}/report-schedules/{id}
func DeleteReportScheduleHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		sid := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tid) || !looksLikeUUID(sid) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "delete_report_schedule", "schedule_id", sid)

		tag, err := pool.Exec(r.Context(), `
			DELETE FROM report_schedules WHERE id = $1::uuid AND tenant_id = $2::uuid
		`, sid, tid)
		if err != nil {
			logger.Error("delete schedule", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// parseScheduleBody decodes the request body into a reportSchedule.
// Returns an error string for 400 responses, empty string on success.
func parseScheduleBody(body io.ReadCloser) (reportSchedule, string) {
	raw, _ := io.ReadAll(io.LimitReader(body, 1<<16))
	var req struct {
		Name          string          `json:"name"`
		Cadence       string          `json:"cadence"`
		CadenceConfig json.RawMessage `json:"cadence_config"`
		ContentType   string          `json:"content_type"`
		RecipientIDs  json.RawMessage `json:"recipient_ids"`
		AdHocEmails   json.RawMessage `json:"ad_hoc_emails"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return reportSchedule{}, "invalid JSON"
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return reportSchedule{}, "name is required"
	}
	if req.Cadence == "" {
		req.Cadence = "monthly"
	}
	if !validCadences[req.Cadence] {
		return reportSchedule{}, fmt.Sprintf("invalid cadence %q", req.Cadence)
	}
	if req.ContentType == "" {
		req.ContentType = "full"
	}
	if !validContentTypes[req.ContentType] {
		return reportSchedule{}, fmt.Sprintf("invalid content_type %q", req.ContentType)
	}
	if len(req.CadenceConfig) == 0 {
		req.CadenceConfig = json.RawMessage(`{}`)
	}
	if len(req.RecipientIDs) == 0 {
		req.RecipientIDs = json.RawMessage(`[]`)
	}
	if len(req.AdHocEmails) == 0 {
		req.AdHocEmails = json.RawMessage(`[]`)
	}
	return reportSchedule{
		Name:          req.Name,
		Cadence:       req.Cadence,
		CadenceConfig: req.CadenceConfig,
		ContentType:   req.ContentType,
		RecipientIDs:  req.RecipientIDs,
		AdHocEmails:   req.AdHocEmails,
	}, ""
}

// ─── Report records ────────────────────────────────────────────────────────────

type reportRecord struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	ScheduleID       *string         `json:"schedule_id"`
	Name             string          `json:"name"`
	ReportType       string          `json:"report_type"`
	ReportLabel      string          `json:"report_label"`
	GeneratedAt      time.Time       `json:"generated_at"`
	PeriodStart      *string         `json:"period_start"`
	PeriodEnd        *string         `json:"period_end"`
	PDFPath          *string         `json:"pdf_path,omitempty"`
	XLSXPath         *string         `json:"xlsx_path,omitempty"`
	CSVPath          *string         `json:"csv_path,omitempty"`
	RecipientSummary json.RawMessage `json:"recipient_summary"`
	DeliveryStatus   string          `json:"delivery_status"`
	Archived         bool            `json:"archived"`
	CreatedAt        time.Time       `json:"created_at"`

	// PAT-1613 issuance evidence. IssuedAt non-nil means the row is frozen:
	// the stored files, their hashes and the coverage figures below are what
	// was issued, and the database rejects any further edit to them.
	PDFSHA256            *string         `json:"pdf_sha256,omitempty"`
	XLSXSHA256           *string         `json:"xlsx_sha256,omitempty"`
	IssuedAt             *time.Time      `json:"issued_at"`
	CoverageSnapshot     json.RawMessage `json:"coverage_snapshot,omitempty"`
	SupersedesReportID   *string         `json:"supersedes_report_id"`
	SupersededByReportID *string         `json:"superseded_by_report_id"`
}

// ListReportRecordsHandler returns paginated report records for a tenant.
// GET /admin/tenants/{tid}/report-records?page=1&per_page=20
func ListReportRecordsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("handler", "list_report_records", "tenant_id", tid)

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if perPage < 1 || perPage > 100 {
			perPage = 20
		}
		offset := (page - 1) * perPage

		rows, err := pool.Query(r.Context(), `
			SELECT id::text, tenant_id::text,
				   CASE WHEN schedule_id IS NULL THEN NULL ELSE schedule_id::text END,
				   name, report_type, generated_at,
				   CASE WHEN period_start IS NULL THEN NULL ELSE period_start::text END,
				   CASE WHEN period_end   IS NULL THEN NULL ELSE period_end::text   END,
				   pdf_path, xlsx_path, recipient_summary, delivery_status, archived, created_at,
				   pdf_sha256, xlsx_sha256, issued_at, coverage_snapshot,
				   CASE WHEN supersedes_report_id IS NULL THEN NULL ELSE supersedes_report_id::text END,
				   CASE WHEN superseded_by_report_id IS NULL THEN NULL ELSE superseded_by_report_id::text END
			FROM report_records
			WHERE tenant_id = $1::uuid
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3
		`, tid, perPage, offset)
		if err != nil {
			logger.Error("query records", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var records []reportRecord
		for rows.Next() {
			var rec reportRecord
			if err := rows.Scan(&rec.ID, &rec.TenantID, &rec.ScheduleID,
				&rec.Name, &rec.ReportType, &rec.GeneratedAt, &rec.PeriodStart, &rec.PeriodEnd,
				&rec.PDFPath, &rec.XLSXPath, &rec.RecipientSummary,
				&rec.DeliveryStatus, &rec.Archived, &rec.CreatedAt,
				&rec.PDFSHA256, &rec.XLSXSHA256, &rec.IssuedAt, &rec.CoverageSnapshot,
				&rec.SupersedesReportID, &rec.SupersededByReportID); err != nil {
				logger.Error("scan record", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// Omit file paths from listing response — available on download only.
			rec.PDFPath = nil
			rec.XLSXPath = nil
			if def, found := report.LookupReportDefinition(rec.ReportType); found {
				rec.ReportLabel = def.Label
			}
			records = append(records, rec)
		}
		if records == nil {
			records = []reportRecord{}
		}

		// Return total count for pagination.
		var total int
		_ = pool.QueryRow(r.Context(),
			`SELECT COUNT(*) FROM report_records WHERE tenant_id = $1::uuid`, tid,
		).Scan(&total)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"records":  records,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		})
	}
}

// GenerateReportHandler generates a report on demand and stores the files.
// POST /admin/tenants/{tid}/report-records/generate
// Body: {"name":"Q3 2026","content_type":"full","period_start":"2026-07-01","period_end":"2026-09-30"}
//
// PAT-1685: an optional "supersedes_report_id" issues a correction instead of
// an unlinked report. The parameter lives on this handler rather than a
// dedicated /report-records/{id}/correct endpoint because a correction is not
// a metadata-only relinking — it runs the exact same generation pipeline
// (XLSX render, PDF render, coverage/findings snapshot) as any other report,
// then the same finalise step also records the linkage. A separate endpoint
// would either duplicate that whole pipeline or forward into this one, for no
// behavioural difference; the body parameter is the whole change.
// Body: {..., "supersedes_report_id":"<uuid of the report this corrects>"}
//
// ─── Supersession validation ──────────────────────────────────────────────────
//
// supersessionError classifies a rejected correction so the handler can write
// the right HTTP status without string-matching a driver error. Used both for
// the up-front existence/ownership/not-already-superseded check below and for
// the DB-level defence-in-depth against a race lost between that check and the
// write (migration 0126's unique index, CHECK and immutability trigger).
type supersessionError struct {
	status int
	msg    string
}

func (e *supersessionError) Error() string { return e.msg }

// validateSupersessionTarget confirms tenantID may issue a correction of
// supersedesID. Empty supersedesID is a no-op (today's behaviour: an ordinary,
// unlinked report). Otherwise the target must exist, belong to this exact
// tenant, be issued (frozen) evidence, and not already have a correction
// linked to it.
//
// A cross-tenant id and an unknown id return the identical 404: the query
// filters on tenant_id in the same WHERE clause as id, so a report belonging
// to another tenant is indistinguishable from one that does not exist at all
// — this must never leak which is true.
func validateSupersessionTarget(ctx context.Context, pool *pgxpool.Pool, tenantID, supersedesID string) error {
	if supersedesID == "" {
		return nil
	}
	if !looksLikeUUID(supersedesID) {
		return &supersessionError{status: http.StatusBadRequest, msg: "supersedes_report_id must be a UUID"}
	}
	var issuedAt *time.Time
	var supersededBy *string
	err := pool.QueryRow(ctx, `
		SELECT issued_at, superseded_by_report_id::text
		FROM report_records
		WHERE id = $1::uuid AND tenant_id = $2::uuid
	`, supersedesID, tenantID).Scan(&issuedAt, &supersededBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &supersessionError{status: http.StatusNotFound, msg: "report record not found"}
		}
		return fmt.Errorf("lookup supersession target: %w", err)
	}
	if issuedAt == nil {
		// Not yet issued — a placeholder row mid-generation, or one that never
		// finished. There is no evidence yet for a correction to point at, so
		// this reads the same as not found rather than a distinct status.
		return &supersessionError{status: http.StatusNotFound, msg: "report record not found"}
	}
	if supersededBy != nil {
		return &supersessionError{status: http.StatusConflict, msg: "report record has already been superseded"}
	}
	return nil
}

// classifyReportRecordsPGError maps the constraint violations migration 0126
// can raise on a correction into the clean 4xx a caller should see instead of
// a raw 500: a race that slips past validateSupersessionTarget's up-front
// check (two concurrent corrections of the same report, or the trigger's own
// single-transition guard) still ends in a 409, and a malformed target id that
// somehow reaches the database ends in the same conflict rather than an
// unclassified error.
func classifyReportRecordsPGError(err error) (status int, msg string, ok bool) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return 0, "", false
	}
	switch pgErr.ConstraintName {
	case "report_records_supersedes_uq":
		return http.StatusConflict, "report record has already been superseded", true
	case "report_records_no_self_supersession":
		return http.StatusConflict, "a report cannot supersede itself", true
	}
	if pgErr.Code == "23001" { // restrict_violation raised by trg_report_records_reject_issued_update
		return http.StatusConflict, "report record has already been superseded", true
	}
	return 0, "", false
}

func GenerateReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		logger := slog.With("req_id", reqID, "handler", "generate_report", "tenant_id", tid)

		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		var req struct {
			Name               string `json:"name"`
			ContentType        string `json:"content_type"`
			PeriodStart        string `json:"period_start"`
			PeriodEnd          string `json:"period_end"`
			SupersedesReportID string `json:"supersedes_report_id"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			req.Name = "Ad-hoc report " + time.Now().UTC().Format("2006-01-02")
		}
		ct := report.ContentType(req.ContentType)
		if ct == "" {
			ct = report.ContentTypeFull
		}
		if ct != report.ContentTypeFull && ct != report.ContentTypeCVEOnly && ct != report.ContentTypeCISOnly {
			http.Error(w, fmt.Sprintf("invalid content_type %q", req.ContentType), http.StatusBadRequest)
			return
		}

		var pStart, pEnd time.Time
		if req.PeriodStart != "" {
			pStart, _ = time.Parse("2006-01-02", req.PeriodStart)
		}
		if req.PeriodEnd != "" {
			pEnd, _ = time.Parse("2006-01-02", req.PeriodEnd)
		}

		// Validate the correction target, if any, before doing any generation
		// work: existence, tenant ownership and not-already-superseded are all
		// cheap checks against a caller that would otherwise waste a PDF/XLSX
		// render on a request that can never be stored. storeReportFiles below
		// re-checks the same constraints at the point of insertion (defence in
		// depth for a race between this check and that write).
		supersedesID := strings.TrimSpace(req.SupersedesReportID)
		if err := validateSupersessionTarget(r.Context(), pool, tid, supersedesID); err != nil {
			var sErr *supersessionError
			if errors.As(err, &sErr) {
				http.Error(w, sErr.msg, sErr.status)
				return
			}
			logger.Error("validate supersession target", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var supersedesArg *string
		if supersedesID != "" {
			supersedesArg = &supersedesID
		}

		// Generate XLSX.
		xlsxData, err := report.FetchXLSXData(r.Context(), pool, tid, pStart, pEnd)
		if err != nil {
			logger.Error("fetch xlsx data", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		xlsxBytes, err := report.RenderXLSX(xlsxData, ct)
		if err != nil {
			logger.Error("render xlsx", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Generate PDF (executive summary — applies to all content_type values as the
		// summary document; content_type governs the XLSX sheets only at this stage).
		pdfBytes, coverage, err := generateSummaryPDF(r.Context(), pool, tid, logger)
		if err != nil {
			// Non-fatal — store the XLSX, mark PDF as missing.
			logger.Warn("pdf generation failed", "err", err)
			pdfBytes = nil
		}

		// Persist files to disk. coverage is nil only when the summary fetch
		// itself failed, in which case there is no figure to freeze and the
		// snapshot stays empty rather than claiming zeros.
		rec, err := storeReportFiles(r.Context(), pool, tid, req.Name, nil, ct,
			pStart, pEnd, pdfBytes, xlsxBytes, "admin", "executive-summary", logger, nil, coverage, supersedesArg)
		if err != nil {
			var sErr *supersessionError
			if errors.As(err, &sErr) {
				http.Error(w, sErr.msg, sErr.status)
				return
			}
			logger.Error("store report", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("report generated", "record_id", rec.ID,
			"pdf_bytes", len(pdfBytes), "xlsx_bytes", len(xlsxBytes))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rec)
	}
}

// DownloadReportHandler streams the PDF or XLSX for a report record.
// GET /admin/tenants/{tid}/report-records/{id}/download?format=pdf|xlsx
func DownloadReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		rid := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(tid) || !looksLikeUUID(rid) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}
		format := r.URL.Query().Get("format")
		if format != "pdf" && format != "xlsx" {
			format = "pdf"
		}
		logger := slog.With("handler", "download_report", "record_id", rid, "format", format)

		var pdfPath, xlsxPath *string
		var name string
		err := pool.QueryRow(r.Context(), `
			SELECT name, pdf_path, xlsx_path
			FROM report_records
			WHERE id = $1::uuid AND tenant_id = $2::uuid
		`, rid, tid).Scan(&name, &pdfPath, &xlsxPath)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch record", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var filePath *string
		var contentType, ext string
		if format == "xlsx" {
			filePath = xlsxPath
			contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
			ext = ".xlsx"
		} else {
			filePath = pdfPath
			contentType = "application/pdf"
			ext = ".pdf"
		}

		if filePath == nil || *filePath == "" {
			http.Error(w, fmt.Sprintf("%s not available for this report", format), http.StatusNotFound)
			return
		}
		if *filePath == "archived" {
			// TODO: implement R2 cold-pull — for now flag as unavailable.
			http.Error(w, "report has been archived to cold storage — R2 retrieval not yet implemented", http.StatusGone)
			return
		}

		absPath := filepath.Join(reportStorageRoot(), *filePath)
		data, err := os.ReadFile(absPath)
		if err != nil {
			logger.Error("read file", "path", absPath, "err", err)
			http.Error(w, "file not found on disk", http.StatusNotFound)
			return
		}

		stem := sanitiseFilename(name)
		filename := stem + ext

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		logger.Info("report downloaded", "bytes", len(data))
	}
}

// ─── Token redemption (public, no auth) ───────────────────────────────────────

// RedeemDownloadTokenHandler validates a single-use download token and
// returns a signed (time-limited) redirect URL to the PDF or XLSX.
// This endpoint lives on the PUBLIC router — no bearer auth required.
// POST /admin/report-download-tokens/{token}/redeem?format=pdf|xlsx
func RedeemDownloadTokenHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(chi.URLParam(r, "token"))
		if !looksLikeUUID(token) {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		format := r.URL.Query().Get("format")
		if format != "xlsx" {
			format = "pdf"
		}
		logger := slog.With("handler", "redeem_download_token", "token", token[:8]+"…")

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		var tokenID int64
		var reportRecordID, email string
		var expiresAt time.Time
		var usedAt *time.Time
		// FOR UPDATE locks the token row for the life of the tx, so concurrent
		// redemptions serialise: the second one blocks until we commit and then
		// sees used_at set (410). Combined with the read-before-burn ordering
		// below, this gives correct single-use without wasting the token on a
		// failed file read.
		//
		// PAT-687: primary lookup is by SHA-256(token) hash (token_hash). We keep
		// a DUAL-READ fallback that matches the plaintext `token` column for rows
		// issued before this change (token_hash IS NULL), so existing live links
		// keep working for one release. Once a backfill lands and the plaintext
		// column is dropped, the fallback branch becomes dead and can be removed.
		tokenHash := hashDownloadToken(token)
		err = tx.QueryRow(r.Context(), `
			SELECT id, report_record_id::text, email, expires_at, used_at
			FROM report_download_tokens
			WHERE token_hash = $1
			   OR (token_hash IS NULL AND token = $2::uuid)
			FOR UPDATE
		`, tokenHash, token).Scan(&tokenID, &reportRecordID, &email, &expiresAt, &usedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "token not found", http.StatusNotFound)
				return
			}
			logger.Error("lookup token", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if usedAt != nil {
			http.Error(w, "token already used", http.StatusGone)
			return
		}
		if time.Now().After(expiresAt) {
			http.Error(w, "token expired", http.StatusGone)
			return
		}

		// Fetch the file path.
		var pdfPath, xlsxPath *string
		var name string
		err = tx.QueryRow(r.Context(), `
			SELECT name, pdf_path, xlsx_path FROM report_records WHERE id = $1::uuid
		`, reportRecordID).Scan(&name, &pdfPath, &xlsxPath)
		if err != nil {
			logger.Error("fetch report record", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var filePath *string
		var contentType, ext string
		if format == "xlsx" {
			filePath = xlsxPath
			contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
			ext = ".xlsx"
		} else {
			filePath = pdfPath
			contentType = "application/pdf"
			ext = ".pdf"
		}

		if filePath == nil || *filePath == "" || *filePath == "archived" {
			http.Error(w, fmt.Sprintf("%s not available", format), http.StatusNotFound)
			return
		}

		// Read the file BEFORE burning the token, so a missing/unreadable file
		// doesn't consume the recipient's single-use link (they can retry).
		absPath := filepath.Join(reportStorageRoot(), *filePath)
		data, err := os.ReadFile(absPath)
		if err != nil {
			logger.Error("read file", "path", absPath, "err", err)
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		// Now that we have the bytes, mark the token used (single-use) and commit.
		if _, err = tx.Exec(r.Context(), `
			UPDATE report_download_tokens SET used_at = NOW() WHERE id = $1
		`, tokenID); err != nil {
			logger.Error("mark token used", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(name)
		filename := stem + ext

		logger.Info("token redeemed", "email", email, "format", format, "bytes", len(data))

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// hashDownloadToken returns SHA-256 of the canonical (trimmed, lower-cased)
// token string. This is the value stored in report_download_tokens.token_hash
// and used for constant-shape lookups on redeem (PAT-687). Callers that ISSUE a
// download token must persist hashDownloadToken(token) into token_hash so that
// the plaintext token never has to be stored. Redemption hashes the token from
// the URL and matches on token_hash (with a plaintext dual-read fallback for
// rows issued before the hash column existed).
func hashDownloadToken(token string) []byte {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(token))))
	return sum[:]
}

// generateSummaryPDF calls the existing executive summary report path. It also
// returns the coverage figures the PDF was rendered from so the caller can
// freeze them onto the report row (PAT-1613) — the numbers have to come from
// the same fetch that produced the document, or the frozen figure and the
// printed one could disagree. The coverage map is nil when the fetch failed:
// no figure at all, rather than a zeroed one that reads as an empty estate.
func generateSummaryPDF(ctx context.Context, pool *pgxpool.Pool,
	tenantID string, logger *slog.Logger) ([]byte, map[string]any, error) {

	summary, err := report.FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch executive summary: %w", err)
	}
	coverage := executiveCoverageSnapshot(summary)
	addFindingsSnapshot(ctx, pool, tenantID, coverage, logger)
	pdf, err := report.RenderExecutiveSummaryPDF(summary)
	if err != nil {
		return nil, coverage, fmt.Errorf("render executive summary pdf: %w", err)
	}
	return pdf, coverage, nil
}

// executiveCoverageSnapshot is the coverage the executive summary was rendered
// from, in the shape frozen onto report_records.coverage_snapshot. Only the
// figures that describe how much of the estate the report could actually see
// belong here; the report's findings live in the document itself.
func executiveCoverageSnapshot(s report.ExecutiveSummary) map[string]any {
	return map[string]any{
		"source":                 "executive_summary",
		"devices_total":          s.Estate.TotalDevices,
		"devices_macos":          s.Estate.MacOSDevices,
		"devices_windows":        s.Estate.WindowsDevices,
		"devices_active_24h":     s.Estate.ActiveLast24h,
		"devices_active_7d":      s.Estate.ActiveLast7d,
		"compliance_overall_pct": s.Compliance.OverallPct,
	}
}

// addFindingsSnapshot merges the tenant's current CVE findings count into an
// in-progress coverage snapshot, frozen at issuance exactly like the coverage
// figures (PAT-1685, gap 2). It reads tenantCVESeverityCounts — the identical
// query and predicate TenantCVEFindingsHandler's severity_counts bar uses
// (PAT-402) — rather than a second, potentially-diverging count of its own,
// per the root AGENTS.md "CVE and usage claims require evidence" constraint.
//
// On a fetch failure the keys are left out of the snapshot entirely rather
// than written as zero: a report_records row with no findings_total means
// "not captured" to a later reader, whereas a devices_total of 0 would read as
// a clean estate, a claim this function would have no evidence for.
//
// There is no basis/confidence breakdown here: the surface being reused
// groups only by CVE and severity, with no match_confidence dimension, so
// none is invented for the snapshot either.
//
// findings_total includes tenantCVESeverityCounts' unknown count (a CVE with
// NULL, empty or unrecognised severity), unlike TenantCVEFindingsHandler's own
// summary bar, which silently drops those. A live display gap there is
// tolerable; a frozen "findings_total" is a CVE claim this evidence record
// makes forever, so it must not undercount. findings_by_severity carries an
// "unknown" key alongside the four known ones, but only when there is at
// least one such finding — an always-present zero would misread as "checked,
// none found" for a bucket this snapshot cannot actually characterise.
func addFindingsSnapshot(ctx context.Context, pool *pgxpool.Pool, tenantID string, coverage map[string]any, logger *slog.Logger) {
	counts, unknown, err := tenantCVESeverityCounts(ctx, pool, tenantID)
	if err != nil {
		logger.Warn("findings snapshot unavailable, coverage_snapshot omits it", "err", err)
		return
	}
	total := unknown
	for _, c := range counts {
		total += c
	}
	if unknown > 0 {
		counts["unknown"] = unknown
	}
	coverage["findings_total"] = total
	coverage["findings_by_severity"] = counts
}

// readReportFile reads a report file by its report_records relative path.
// Shared by the admin download handler and the portal download handler.
func readReportFile(relPath string) ([]byte, error) {
	return os.ReadFile(filepath.Join(reportStorageRoot(), relPath))
}

// hashReportBytes returns the lower-case hex SHA-256 of a generated report
// artefact, or nil when there is no artefact. This is the value stored in
// report_records.pdf_sha256 / .xlsx_sha256 (PAT-1613) and is what lets an
// auditor prove a downloaded file is the one that was issued. Same primitive
// as the per-device digests in device_report_digests (PAT-473); the tenant-level
// hash lives on the report row itself because that row already is one report.
func hashReportBytes(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	sum := sha256.Sum256(b)
	digest := fmt.Sprintf("%x", sum)
	return &digest
}

// storeReportFiles writes PDF and XLSX to disk and inserts a report_records
// row. source is 'admin' (console / scheduler, PAT-370) or 'portal'
// (customer-generated via POST /v1/portal/reports, PAT-693).
//
// coverage (PAT-1613) is the estate coverage figures the report was rendered
// from, snapshotted onto the row so an issued report keeps reading as it did.
// Nil is allowed and stores '{}': a caller with no coverage to record says so
// by omission rather than by writing zeros, which would be a false claim that
// the estate was empty.
//
// supersedesReportID (PAT-1685) is nil for an ordinary report — unchanged
// behaviour. Non-nil issues a correction: the new row is finalised with
// supersedes_report_id set (an ordinary pre-issuance write, unrestricted by
// migration 0126's trigger), and once that succeeds the superseded row's
// superseded_by_report_id is linked forward in a second statement — the one
// post-issuance mutation the trigger permits. Callers are expected to have
// already run validateSupersessionTarget; this function re-validates the
// self-reference and not-already-superseded cases at the point of writing, as
// defence in depth against a race with another request.
func storeReportFiles(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
	recordName string,
	scheduleID *string,
	ct report.ContentType,
	periodStart, periodEnd time.Time,
	pdfBytes, xlsxBytes []byte,
	source string,
	reportType string,
	logger *slog.Logger,
	scheduleSlot *time.Time,
	coverage map[string]any,
	supersedesReportID *string,
) (*reportRecord, error) {
	return storeReportRecord(ctx, pool, tenantID, recordName, scheduleID, ct, periodStart, periodEnd,
		pdfBytes, xlsxBytes, nil, source, reportType, logger, scheduleSlot, coverage, supersedesReportID)
}

// storeReportRecord is storeReportFiles with an optional CSV rendering
// (PAT-2405). csvBytes is written as report.csv beside the PDF, in the same
// tenant/record directory and under a fixed name, and its path and SHA-256 are
// set by the same finalising UPDATE as the PDF's, so they are frozen with the
// row at issuance (migration 0126). Nil csvBytes stores NULL for both.
func storeReportRecord(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
	recordName string,
	scheduleID *string,
	ct report.ContentType,
	periodStart, periodEnd time.Time,
	pdfBytes, xlsxBytes, csvBytes []byte,
	source string,
	reportType string,
	logger *slog.Logger,
	scheduleSlot *time.Time,
	coverage map[string]any,
	supersedesReportID *string,
) (*reportRecord, error) {

	// scheduleSlot is set ONLY by the PAT-703 portal schedule sweeper
	// (reportsched.Sweeper via PortalReportGenerator), holding the exact
	// portal_report_schedules.next_run_at slot this row was generated for.
	// It is nil for every ad-hoc/customer-triggered/admin report. PAT-874's
	// crash-recovery guard (reportsched.reportAlreadyGeneratedForSlot) relies
	// on this being an unambiguous, scheduler-only marker; do not set it
	// from any other call site.
	var scheduleSlotArg interface{}
	if scheduleSlot != nil {
		scheduleSlotArg = *scheduleSlot
	}

	// Create a placeholder row to get the UUID.
	var recID string
	err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name, recipient_summary, source, report_type, schedule_slot)
		VALUES ($1::uuid, $2, '[]', $3, $4, $5)
		RETURNING id::text
	`, tenantID, recordName, source, reportType, scheduleSlotArg).Scan(&recID)
	if err != nil {
		return nil, fmt.Errorf("insert report record: %w", err)
	}

	// Defence in depth: the DB CHECK constraint (report_records_no_self_supersession)
	// already rejects this, but a fresh, randomly-generated UUID colliding with
	// a caller-supplied one is unreachable in practice, so this fails fast and
	// cheaply before any file I/O rather than relying solely on that round trip.
	if supersedesReportID != nil && *supersedesReportID == recID {
		return nil, &supersessionError{status: http.StatusConflict, msg: "a report cannot supersede itself"}
	}

	dir := filepath.Join(reportStorageRoot(), tenantID, recID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	var pdfRelPath, xlsxRelPath, csvRelPath string

	if len(pdfBytes) > 0 {
		pdfFile := filepath.Join(dir, "report.pdf")
		if err := os.WriteFile(pdfFile, pdfBytes, 0644); err != nil {
			return nil, fmt.Errorf("write pdf: %w", err)
		}
		pdfRelPath = filepath.Join(tenantID, recID, "report.pdf")
	}

	if len(xlsxBytes) > 0 {
		xlsxFile := filepath.Join(dir, "report.xlsx")
		if err := os.WriteFile(xlsxFile, xlsxBytes, 0644); err != nil {
			return nil, fmt.Errorf("write xlsx: %w", err)
		}
		xlsxRelPath = filepath.Join(tenantID, recID, "report.xlsx")
	}

	if len(csvBytes) > 0 {
		csvFile := filepath.Join(dir, "report.csv")
		if err := os.WriteFile(csvFile, csvBytes, 0644); err != nil {
			return nil, fmt.Errorf("write csv: %w", err)
		}
		csvRelPath = filepath.Join(tenantID, recID, "report.csv")
	}

	// Build period args.
	var periodStartArg, periodEndArg interface{}
	if !periodStart.IsZero() {
		periodStartArg = periodStart.Format("2006-01-02")
	}
	if !periodEnd.IsZero() {
		periodEndArg = periodEnd.Format("2006-01-02")
	}
	var scheduleIDArg interface{}
	if scheduleID != nil {
		scheduleIDArg = *scheduleID
	}

	var pdfPathArg, xlsxPathArg, csvPathArg interface{}
	if pdfRelPath != "" {
		pdfPathArg = pdfRelPath
	}
	if xlsxRelPath != "" {
		xlsxPathArg = xlsxRelPath
	}
	if csvRelPath != "" {
		csvPathArg = csvRelPath
	}

	coverageArg := []byte("{}")
	if len(coverage) > 0 {
		encoded, err := json.Marshal(coverage)
		if err != nil {
			// A coverage figure we cannot serialise is a figure we cannot
			// honestly freeze. Store '{}' and say so, rather than fail the
			// whole report or invent a number.
			logger.Warn("coverage snapshot not serialisable, storing empty", "err", err)
		} else {
			coverageArg = encoded
		}
	}

	var supersedesArg interface{}
	if supersedesReportID != nil {
		supersedesArg = *supersedesReportID
	}

	// PAT-1613: this is issuance. The bytes are on disk, so the row is now
	// evidence: it records its own hashes and the coverage it was rendered
	// from, and migration 0126's trigger freezes it from here. This is the
	// last UPDATE this row will ever accept, apart from a later
	// superseded_by_report_id link. Anything that must still be written about
	// this report has to be written before this statement runs.
	//
	// supersedes_report_id is included here (PAT-1685): the row is still
	// pre-issuance at the top of this statement (issued_at is about to become
	// non-NULL, not already), so setting it alongside everything else is an
	// ordinary unrestricted write, not the trigger's one permitted exception.
	//
	// PAT-1685 review fix: the finalising UPDATE and the forward-link UPDATE
	// on the superseded row now run inside one transaction, committed only
	// once both have succeeded. Without this, a link failure after a
	// successful finalise (lost race, trigger rejection, or a plain
	// connection error) left the new row issued and immutable — permanently
	// claiming to supersede a report that never linked back. Rolling back
	// instead leaves the placeholder row exactly where an ordinary failed
	// generation already leaves it: present, un-issued (issued_at NULL), no
	// new cleanup path invented. Files already written to disk before this
	// transaction are not rolled back, same as any other generation failure
	// after the write step — the placeholder row's absence of issued_at is
	// what tells a reader the report was never actually issued.
	//
	// No SELECT ... FOR UPDATE is taken on the superseded row: migration
	// 0126's partial unique index on supersedes_report_id (not deferrable —
	// checked immediately, same inside a transaction as outside) already
	// serialises two concurrent corrections of the same report at this same
	// finalising UPDATE. A second correction's attempt to set the identical
	// supersedes_report_id blocks on that index until this transaction
	// resolves, then either succeeds (this one rolled back) or fails with a
	// unique violation (this one committed) — classifyReportRecordsPGError
	// maps that to 409 either way. The link UPDATE below is a single
	// statement gated on "AND superseded_by_report_id IS NULL", which
	// Postgres's normal per-row UPDATE locking already makes atomic; no
	// additional lock adds any protection the index and that WHERE clause
	// don't already provide.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin issuance tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck — no-op once Commit has succeeded

	var rec reportRecord
	err = tx.QueryRow(ctx, `
		UPDATE report_records
		SET schedule_id          = $2,
			period_start         = $3,
			period_end           = $4,
			pdf_path             = $5,
			xlsx_path            = $6,
			pdf_sha256           = $7,
			xlsx_sha256          = $8,
			coverage_snapshot    = $9::jsonb,
			supersedes_report_id = $10::uuid,
			csv_path             = $11,
			csv_sha256           = $12,
			delivery_status      = 'pending',
			issued_at            = now()
		WHERE id = $1::uuid
		RETURNING id::text, tenant_id::text,
			CASE WHEN schedule_id IS NULL THEN NULL ELSE schedule_id::text END,
			name, report_type, generated_at,
			CASE WHEN period_start IS NULL THEN NULL ELSE period_start::text END,
			CASE WHEN period_end   IS NULL THEN NULL ELSE period_end::text   END,
			pdf_path, xlsx_path, csv_path, recipient_summary, delivery_status, archived, created_at,
			pdf_sha256, xlsx_sha256, issued_at, coverage_snapshot,
			CASE WHEN supersedes_report_id IS NULL THEN NULL ELSE supersedes_report_id::text END,
			CASE WHEN superseded_by_report_id IS NULL THEN NULL ELSE superseded_by_report_id::text END
	`, recID, scheduleIDArg, periodStartArg, periodEndArg, pdfPathArg, xlsxPathArg,
		hashReportBytes(pdfBytes), hashReportBytes(xlsxBytes), coverageArg, supersedesArg,
		csvPathArg, hashReportBytes(csvBytes)).Scan(
		&rec.ID, &rec.TenantID, &rec.ScheduleID,
		&rec.Name, &rec.ReportType, &rec.GeneratedAt, &rec.PeriodStart, &rec.PeriodEnd,
		&rec.PDFPath, &rec.XLSXPath, &rec.CSVPath, &rec.RecipientSummary,
		&rec.DeliveryStatus, &rec.Archived, &rec.CreatedAt,
		&rec.PDFSHA256, &rec.XLSXSHA256, &rec.IssuedAt, &rec.CoverageSnapshot,
		&rec.SupersedesReportID, &rec.SupersededByReportID)
	if err != nil {
		if status, msg, ok := classifyReportRecordsPGError(err); ok {
			return nil, &supersessionError{status: status, msg: msg}
		}
		return nil, fmt.Errorf("update report record: %w", err)
	}
	if def, found := report.LookupReportDefinition(rec.ReportType); found {
		rec.ReportLabel = def.Label
	}

	if supersedesReportID != nil {
		// The one post-issuance mutation trg_report_records_reject_issued_update
		// permits: link the superseded row forward to this correction, once,
		// from NULL. The extra "AND superseded_by_report_id IS NULL" makes a
		// lost race (another correction linked it between
		// validateSupersessionTarget's check and here) read as zero rows
		// affected rather than relying on the trigger to raise; the trigger is
		// still there underneath as the actual enforcement. Either failure
		// mode aborts this whole transaction via the deferred Rollback above,
		// so the finalising UPDATE above never survives without its link.
		tag, linkErr := tx.Exec(ctx, `
			UPDATE report_records
			SET superseded_by_report_id = $1::uuid
			WHERE id = $2::uuid AND tenant_id = $3::uuid AND superseded_by_report_id IS NULL
		`, rec.ID, *supersedesReportID, tenantID)
		if linkErr != nil {
			if status, msg, ok := classifyReportRecordsPGError(linkErr); ok {
				return nil, &supersessionError{status: status, msg: msg}
			}
			return nil, fmt.Errorf("link superseded report: %w", linkErr)
		}
		if tag.RowsAffected() == 0 {
			return nil, &supersessionError{
				status: http.StatusConflict,
				msg:    "report record has already been superseded",
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit issuance tx: %w", err)
	}

	return &rec, nil
}
