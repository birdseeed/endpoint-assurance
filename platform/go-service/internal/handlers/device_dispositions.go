package handlers

// PAT-1825: device disposition records — the append-only-with-supersede
// table deferred from PAT-1595 (see migrations/0143_device_dispositions.sql
// for the full shape reasoning and why it is not folded into
// compliance_evaluations).
//
// Routes (internal admin listener, ADMIN_API_TOKEN):
//
//	POST /admin/tenants/{tenantID}/device-dispositions
//	    Record a disposition for one device (device_id) or a cohort
//	    (device_ids, sharing one generated cohort_id). A device that
//	    already carries a live disposition is corrected, not duplicated:
//	    the existing row is superseded (superseded_reason "correction")
//	    and the new row's supersedes_id points at it — see
//	    this file's writeDisposition.
//	GET  /admin/tenants/{tenantID}/device-dispositions
//	    List dispositions for the tenant, most-recent-first. Unfiltered
//	    (default) is the audit-trail view: every row, including superseded
//	    ones and their supersede chain. ?active=true narrows to only the
//	    live row per device, for a queue view.
//
// The automatic reappearance path (a device with a live disposition
// reporting inventory again) lives in internal/extractor, not here — see
// that package's disposition_reappearance.go. It writes into the same
// table using the same supersede shape (superseded_reason "reappeared")
// plus a device_lifecycle_findings row.
//
// DeviceLifecycleHandler (device_lifecycle.go) reads
// loadActiveDispositionDeviceIDs from this file to wire activeDisposition
// into internal/devicelifecycle.ClassifyState.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxDeviceDispositionBytes = 65536

var validDispositionCategories = map[string]bool{
	"decommissioned": true,
	"on-leave":       true,
	"lost":           true,
	"unaccounted":    true,
}

type deviceDispositionCreateReq struct {
	DeviceID       string   `json:"device_id"`
	DeviceIDs      []string `json:"device_ids"`
	Category       string   `json:"category"`
	ReportedBy     string   `json:"reported_by"`
	ReportedByRole string   `json:"reported_by_role"`
	Channel        string   `json:"channel"`
	Note           string   `json:"note"`
}

type deviceDispositionRow struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id,omitempty"`
	DeviceID         string     `json:"device_id"`
	Category         string     `json:"category"`
	ReportedBy       string     `json:"reported_by"`
	ReportedByRole   string     `json:"reported_by_role,omitempty"`
	Channel          string     `json:"channel,omitempty"`
	Note             string     `json:"note,omitempty"`
	RecordedAt       time.Time  `json:"recorded_at"`
	CohortID         *string    `json:"cohort_id,omitempty"`
	SupersedesID     *string    `json:"supersedes_id,omitempty"`
	SupersededAt     *time.Time `json:"superseded_at,omitempty"`
	SupersededReason *string    `json:"superseded_reason,omitempty"`
}

type deviceDispositionCreateResp struct {
	TenantID     string                 `json:"tenant_id"`
	CohortID     *string                `json:"cohort_id"`
	Category     string                 `json:"category"`
	Dispositions []deviceDispositionRow `json:"dispositions"`
}

// DeviceDispositionCreateHandler serves
// POST /admin/tenants/{tenantID}/device-dispositions.
//
// 201 deviceDispositionCreateResp | 400 bad input | 404 unknown tenant or a
// device_id not owned by this tenant
func DeviceDispositionCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_disposition_create")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxDeviceDispositionBytes+1))
		if err != nil || len(body) > maxDeviceDispositionBytes {
			http.Error(w, "cannot read body or body too large", http.StatusBadRequest)
			return
		}
		var req deviceDispositionCreateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		req.Category = strings.TrimSpace(req.Category)
		req.ReportedBy = strings.TrimSpace(req.ReportedBy)
		req.ReportedByRole = strings.TrimSpace(req.ReportedByRole)
		req.Channel = strings.TrimSpace(req.Channel)
		req.Note = strings.TrimSpace(req.Note)
		if !validDispositionCategories[req.Category] {
			http.Error(w, "category must be one of decommissioned, on-leave, lost, unaccounted", http.StatusBadRequest)
			return
		}
		if req.ReportedBy == "" {
			http.Error(w, "reported_by is required", http.StatusBadRequest)
			return
		}
		if req.DeviceID != "" && len(req.DeviceIDs) > 0 {
			http.Error(w, "specify device_id or device_ids, not both", http.StatusBadRequest)
			return
		}
		deviceIDs := req.DeviceIDs
		if req.DeviceID != "" {
			deviceIDs = []string{req.DeviceID}
		}
		deviceIDs = uniqueStrings(deviceIDs)
		if len(deviceIDs) == 0 {
			http.Error(w, "device_id or device_ids is required", http.StatusBadRequest)
			return
		}
		for _, d := range deviceIDs {
			if !looksLikeUUID(d) {
				http.Error(w, "device_id(s) must be UUIDs", http.StatusBadRequest)
				return
			}
		}
		// A "cohort" is a write naming more than one device in the same
		// request — every row it produces shares one generated cohort_id.
		// A single-device write leaves cohort_id NULL: there is nothing to
		// group it with.
		isCohort := len(deviceIDs) > 1

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

		var deviceCount int
		if err := tx.QueryRow(r.Context(),
			`SELECT count(*) FROM devices WHERE tenant_id = $1::uuid AND id = ANY($2::uuid[])`,
			tenantID, deviceIDs,
		).Scan(&deviceCount); err != nil {
			logger.Error("device ownership check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if deviceCount != len(deviceIDs) {
			http.Error(w, "one or more device_ids do not belong to this tenant", http.StatusNotFound)
			return
		}

		var cohortID *string
		if isCohort {
			var c string
			if err := tx.QueryRow(r.Context(), `SELECT gen_random_uuid()::text`).Scan(&c); err != nil {
				logger.Error("cohort id generation failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			cohortID = &c
		}

		resp := deviceDispositionCreateResp{
			TenantID: tenantID,
			CohortID: cohortID,
			Category: req.Category,
		}
		for _, deviceID := range deviceIDs {
			row, err := writeDisposition(r.Context(), tx, tenantID, deviceID, req.Category,
				req.ReportedBy, req.ReportedByRole, req.Channel, req.Note, cohortID, "correction")
			if err != nil {
				logger.Error("disposition write failed", "err", err, "tenant_id", tenantID, "device_id", deviceID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			resp.Dispositions = append(resp.Dispositions, row)
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device disposition(s) recorded", "tenant_id", tenantID,
			"device_count", len(deviceIDs), "category", req.Category, "cohort", isCohort)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// DeviceDispositionListHandler serves
// GET /admin/tenants/{tenantID}/device-dispositions.
//
// Returns every disposition row for the tenant, most-recent-first
// (recorded_at DESC), including superseded rows and their supersede chain
// (supersedes_id / superseded_at / superseded_reason) so a caller can
// reconstruct a device's correction history — this is the audit-trail view.
// ?active=true narrows to only the live (non-superseded) rows, for a queue
// view that only wants the current disposition per device.
//
// 200 deviceDispositionListResp | 400 bad tenantID
func DeviceDispositionListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "device_disposition_list")
		ctx := r.Context()

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		activeOnly := strings.TrimSpace(r.URL.Query().Get("active")) == "true"

		rows, err := pool.Query(ctx, `
			SELECT id::text, tenant_id::text, device_id::text, category, reported_by,
			       reported_by_role, channel, note, recorded_at, cohort_id::text,
			       supersedes_id::text, superseded_at, superseded_reason
			FROM device_dispositions
			WHERE tenant_id = $1::uuid
			  AND ($2::boolean = false OR superseded_at IS NULL)
			ORDER BY recorded_at DESC
		`, tenantID, activeOnly)
		if err != nil {
			logger.Error("list query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		dispositions := []deviceDispositionRow{}
		for rows.Next() {
			var d deviceDispositionRow
			if err := rows.Scan(
				&d.ID, &d.TenantID, &d.DeviceID, &d.Category, &d.ReportedBy,
				&d.ReportedByRole, &d.Channel, &d.Note, &d.RecordedAt, &d.CohortID,
				&d.SupersedesID, &d.SupersededAt, &d.SupersededReason,
			); err != nil {
				logger.Error("scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			dispositions = append(dispositions, d)
		}
		if err := rows.Err(); err != nil {
			logger.Error("row iteration failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dispositions": dispositions,
			"total":        len(dispositions),
		})
	}
}

// writeDisposition records one device's disposition inside tx: it first
// supersedes any existing active (non-superseded) disposition for that
// device — using supersededReason for that transition — then inserts the
// new row with supersedes_id pointing at whatever it just superseded (nil
// if there was nothing live). Shared by the admin create/correct handler
// (supersededReason "correction") and internal/extractor's automatic
// reappearance rule, which calls the same shape directly against its own
// tx with supersededReason "reappeared" — see that package's
// disposition_reappearance.go.
func writeDisposition(ctx context.Context, tx pgx.Tx, tenantID, deviceID, category,
	reportedBy, reportedByRole, channel, note string, cohortID *string, supersededReason string,
) (deviceDispositionRow, error) {
	var supersedesID *string
	var existingID string
	err := tx.QueryRow(ctx,
		`SELECT id::text FROM device_dispositions WHERE device_id = $1::uuid AND superseded_at IS NULL FOR UPDATE`,
		deviceID,
	).Scan(&existingID)
	switch {
	case err == nil:
		if _, uerr := tx.Exec(ctx, `
			UPDATE device_dispositions SET superseded_at = now(), superseded_reason = $2
			WHERE id = $1::uuid
		`, existingID, supersededReason); uerr != nil {
			return deviceDispositionRow{}, uerr
		}
		supersedesID = &existingID
	case err == pgx.ErrNoRows:
		// No active disposition to supersede — a first-time write.
	default:
		return deviceDispositionRow{}, err
	}

	var row deviceDispositionRow
	row.TenantID = tenantID
	row.DeviceID = deviceID
	row.Category = category
	row.ReportedBy = reportedBy
	row.ReportedByRole = reportedByRole
	row.Channel = channel
	row.Note = note
	row.CohortID = cohortID
	row.SupersedesID = supersedesID
	if err := tx.QueryRow(ctx, `
		INSERT INTO device_dispositions
		    (tenant_id, device_id, category, reported_by, reported_by_role, channel, note, cohort_id, supersedes_id)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::uuid, $9::uuid)
		RETURNING id::text, recorded_at
	`, tenantID, deviceID, category, reportedBy, reportedByRole, channel, note, cohortID, supersedesID,
	).Scan(&row.ID, &row.RecordedAt); err != nil {
		return deviceDispositionRow{}, err
	}
	return row, nil
}

// loadActiveDispositionDeviceIDs returns the set of this tenant's device IDs
// that currently carry a live (non-superseded) disposition record — read by
// DeviceLifecycleHandler (device_lifecycle.go) to wire activeDisposition
// into internal/devicelifecycle.ClassifyState. Coverage-gap devices never
// appear here: device_dispositions.device_id is a FK to devices(id), and a
// coverage-gap entry by definition has no devices row to reference.
func loadActiveDispositionDeviceIDs(ctx context.Context, pool *pgxpool.Pool, tenantID string) (map[string]bool, error) {
	rows, err := pool.Query(ctx,
		`SELECT device_id::text FROM device_dispositions WHERE tenant_id = $1::uuid AND superseded_at IS NULL`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
