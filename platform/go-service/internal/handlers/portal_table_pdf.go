package handlers

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
	"unicode/utf8"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

// POST /v1/portal/exports/table-pdf (PAT-2405).
//
// The portal assembles its CSV list exports itself from platform JSON and
// has no PDF renderer. This endpoint renders the same rows as a branded PDF:
// the portal posts the column headers and cells it would have written to the
// CSV, and gets a PDF back. It reads nothing but the tenant's name and, for
// the one admin-only export, the caller's role; it stores nothing.
//
// What the body cannot do: name a tenant (the name printed is looked up from
// the portalauth identity), set the title (the platform owns one per
// allow-listed export key), or carry any field outside the contract.
// Contract: contracts/portal-api.md.

const (
	tablePDFMaxBodyBytes = 16 << 20
	tablePDFMaxColumns   = 40
	tablePDFMaxRows      = 10000
	tablePDFMaxFilters   = 20
	// tablePDFMaxColumnName bounds one column header. Headers repeat on
	// every page, so unlike a cell they cannot be allowed to run to pages;
	// at this length the header row always fits whatever the column count.
	tablePDFMaxColumnName = 120
)

type portalTableExport struct {
	title string
	// adminOnly mirrors the JSON route the rows come from: the local
	// administrators roster holds account names and is admin only
	// (PortalLocalAdminsHandler); everything else every portal role reads.
	adminOnly bool
}

// portalTableExports is the allow-list of export keys and the title each one
// prints with. It is one half of a contract with the portal, which sends
// these keys; TestPortalTableExports_AllowListIsExactlyTheContract pins it.
var portalTableExports = map[string]portalTableExport{
	"devices":                        {title: "Devices"},
	"devices-stale":                  {title: "Stale devices"},
	"jamf-coverage":                  {title: "Jamf coverage"},
	"findings":                       {title: "Findings"},
	"homebrew":                       {title: "Homebrew packages"},
	"local-admins":                   {title: "Local administrators", adminOnly: true},
	"ai-tooling":                     {title: "AI tooling"},
	"ai-tooling-device":              {title: "AI tooling on one device"},
	"software-unsupported":           {title: "Unsupported software"},
	"software-unsupported-devices":   {title: "Unsupported software: installations"},
	"software-remote-access":         {title: "Remote access software"},
	"software-remote-access-devices": {title: "Remote access software: installations"},
	"software-version-sprawl":        {title: "Software version sprawl"},
	"software-duplicate-tools":       {title: "Duplicate tools"},
	"software-publishers":            {title: "Software publishers"},
	"software-publishers-devices":    {title: "Software publishers: installations"},
}

type portalTablePDFReq struct {
	Export  string `json:"export"`
	Filters []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"filters"`
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	TotalRows int        `json:"total_rows"`
}

// portalTablePDFDeps are the handler's lookups, injected so the handler can
// be tested without a database.
type portalTablePDFDeps struct {
	role       func(ctx context.Context, id portalauth.Identity) (string, error)
	tenantName func(ctx context.Context, tenantID string) (string, error)
	now        func() time.Time
}

// PortalTablePDFHandler serves POST /v1/portal/exports/table-pdf.
func PortalTablePDFHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return portalTablePDFHandler(portalTablePDFDeps{
		role: func(ctx context.Context, id portalauth.Identity) (string, error) {
			return portalauth.DBRole(ctx, pool, id.Email, id.TenantID, false)
		},
		tenantName: func(ctx context.Context, tenantID string) (string, error) {
			return report.FetchTenantName(ctx, pool, tenantID)
		},
		now: time.Now,
	})
}

func portalTablePDFHandler(deps portalTablePDFDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx),
			"handler", "portal_table_pdf", "tenant_id", id.TenantID)

		req, ok := decodePortalTablePDF(w, r)
		if !ok {
			return
		}
		export, known := portalTableExports[req.Export]
		if !known {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "unknown export "+strconv.Quote(req.Export), nil)
			return
		}
		if export.adminOnly {
			role, err := deps.role(ctx, id)
			if err != nil {
				logger.Error("role lookup failed", "err", err)
				writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
				return
			}
			if !portalauth.CanWrite(role) {
				writeApprovalError(w, http.StatusForbidden, "admin_role_required",
					"only a portal admin can export the local administrators roster; your role is "+role, nil)
				return
			}
		}
		if msg := validatePortalTablePDF(req); msg != "" {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", msg, nil)
			return
		}

		tenant, err := deps.tenantName(ctx, id.TenantID)
		if err != nil {
			logger.Error("tenant name lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		d := report.TablePDF{
			Title:       export.title,
			Tenant:      tenant,
			GeneratedAt: deps.now().UTC(),
			Columns:     req.Columns,
			Rows:        req.Rows,
			TotalRows:   req.TotalRows,
		}
		for _, f := range req.Filters {
			d.Filters = append(d.Filters, report.TableFilter{Label: f.Label, Value: f.Value})
		}
		pdf, err := report.RenderTablePDFContext(ctx, d)
		if err != nil {
			if errors.Is(err, report.ErrTablePDFLimit) {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "table exceeds PDF rendering budget; reduce the selection", nil)
				return
			}
			if errors.Is(err, report.ErrTablePDFBusy) {
				writeApprovalError(w, http.StatusServiceUnavailable, "renderer_busy", "PDF renderer is busy; retry later", nil)
				return
			}
			if ctx.Err() != nil {
				return
			}
			logger.Error("render table pdf failed", "err", err, "export", req.Export)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		writeInsurancePDF(w, pdf, req.Export+".pdf", logger)
		logger.Info("table pdf served", "export", req.Export, "rows", len(req.Rows), "columns", len(req.Columns), "bytes", len(pdf))
	}
}

// decodePortalTablePDF reads the body, answering 413 or 400 itself. Unknown
// fields are refused at every level, so a tenant hint or a title in the body
// is an error rather than something quietly ignored.
func decodePortalTablePDF(w http.ResponseWriter, r *http.Request) (portalTablePDFReq, bool) {
	var req portalTablePDFReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, tablePDFMaxBodyBytes))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	if err == nil {
		// Exactly one JSON document: anything after it is a malformed body.
		if _, err = dec.Token(); err == io.EOF {
			return req, true
		} else if err == nil {
			err = errors.New("trailing data")
		}
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeApprovalError(w, http.StatusRequestEntityTooLarge, "body_too_large",
			fmt.Sprintf("request body is larger than %d MiB", tablePDFMaxBodyBytes>>20), nil)
		return req, false
	}
	writeApprovalError(w, http.StatusBadRequest, "invalid_request", "the request body is not valid JSON for this endpoint", nil)
	return req, false
}

// validatePortalTablePDF returns why the decoded table is unacceptable, or
// "" when it is fine.
func validatePortalTablePDF(req portalTablePDFReq) string {
	switch {
	case len(req.Columns) == 0:
		return "columns is required and must not be empty"
	case len(req.Columns) > tablePDFMaxColumns:
		return fmt.Sprintf("at most %d columns", tablePDFMaxColumns)
	case req.Rows == nil:
		return "rows is required (it may be an empty list)"
	case len(req.Rows) > tablePDFMaxRows:
		return fmt.Sprintf("at most %d rows", tablePDFMaxRows)
	case len(req.Filters) > tablePDFMaxFilters:
		return fmt.Sprintf("at most %d filters", tablePDFMaxFilters)
	case req.TotalRows < 0:
		return "total_rows must not be negative"
	}
	for i, c := range req.Columns {
		if strings.TrimSpace(c) == "" {
			return fmt.Sprintf("column %d has no name", i+1)
		}
		if utf8.RuneCountInString(c) > tablePDFMaxColumnName {
			return fmt.Sprintf("column %d has a name longer than %d characters", i+1, tablePDFMaxColumnName)
		}
	}
	for i, row := range req.Rows {
		if len(row) != len(req.Columns) {
			return fmt.Sprintf("row %d has %d cells, want %d", i+1, len(row), len(req.Columns))
		}
	}
	// Apply the shared cheap budgets before any tenant lookup or PDF allocation.
	d := report.TablePDF{Columns: req.Columns, Rows: req.Rows}
	for _, f := range req.Filters {
		d.Filters = append(d.Filters, report.TableFilter{Label: f.Label, Value: f.Value})
	}
	if err := report.ValidateTablePDF(d); err != nil {
		return "table exceeds PDF rendering budget; reduce the selection"
	}
	return ""
}
