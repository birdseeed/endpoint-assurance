package handlers

// PAT-2151: the SAM duplicate-tools-by-category report (PAT-2146),
// tenant-scoped and read-only. Every portal role can read it.
//
//	GET /v1/portal/reports/software/duplicate-tools   summary, basis, per-category product rows (paged)
//
// Takes ?format=json (default) or ?format=csv. The CSV is always the
// per-device (and per-user) rows behind every product, unpaged, so an export
// is the evidence behind every figure rather than one page of it. The
// tenant comes only from the verified portal identity. Unknown query
// parameters are refused so a typo cannot silently widen or narrow the
// answer.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/duplicatetools"
)

const (
	duplicateToolsDefaultLimit = 50
	duplicateToolsMaxLimit     = 200
)

type duplicateToolsFilter struct {
	category, productKey string
	limit, offset        int
}

func parseDuplicateToolsFilter(w http.ResponseWriter, r *http.Request) (string, duplicateToolsFilter, bool) {
	format, ok := governanceFormat(w, r, "category", "product_key", "limit", "offset")
	if !ok {
		return "", duplicateToolsFilter{}, false
	}
	q := r.URL.Query()
	f := duplicateToolsFilter{
		category:   strings.TrimSpace(q.Get("category")),
		productKey: strings.TrimSpace(q.Get("product_key")),
		limit:      duplicateToolsDefaultLimit,
	}
	bad := func(msg string) (string, duplicateToolsFilter, bool) {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", msg, nil)
		return "", duplicateToolsFilter{}, false
	}
	if f.category != "" {
		known := false
		for _, c := range duplicatetools.Categories {
			if f.category == c {
				known = true
				break
			}
		}
		if !known {
			return bad("category must be one of " + strings.Join(duplicatetools.Categories, ", "))
		}
	}
	if len(f.productKey) > 300 {
		return bad("product_key is too long")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > duplicateToolsMaxLimit {
			return bad("limit must be 1 to 200")
		}
		f.limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return bad("offset must be a non-negative integer")
		}
		f.offset = n
	}
	return format, f, true
}

func (f duplicateToolsFilter) matchCategory(c duplicatetools.CategoryRow) bool {
	return f.category == "" || c.Category == f.category
}

func (f duplicateToolsFilter) matchRow(r duplicatetools.Row) bool {
	return (f.category == "" || r.Category == f.category) && (f.productKey == "" || r.ProductKey == f.productKey)
}

func buildDuplicateTools(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, handler string) (duplicatetools.Report, bool) {
	id, ok := identity(w, r)
	if !ok {
		return duplicatetools.Report{}, false
	}
	logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", handler, "tenant_id", id.TenantID)
	rep, err := duplicatetools.Build(r.Context(), pool, id.TenantID, time.Now())
	if err != nil {
		if errors.Is(err, duplicatetools.ErrEstateTooLarge) {
			writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
				"the estate inventory is too large to assess in one request", nil)
			return rep, false
		}
		logger.Error("build duplicate tools report failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return rep, false
	}
	return rep, true
}

func duplicateToolsUser(r duplicatetools.Row) string {
	if r.User != nil {
		return *r.User
	}
	if r.MachineWide {
		return "machine-wide"
	}
	return ""
}

// writeDuplicateToolsCSV writes every matching row (one per device, or one
// per device and user for a per-user install). Endpoint- and
// source-supplied text goes through csvSafe (spreadsheet formula injection).
func writeDuplicateToolsCSV(w http.ResponseWriter, rep duplicatetools.Report, f duplicateToolsFilter) {
	var rows []duplicatetools.Row
	for _, row := range rep.Rows {
		if f.matchRow(row) {
			rows = append(rows, row)
		}
	}
	cw := csvAttachment(w, "duplicate-tools", len(rows))
	_ = cw.Write([]string{"device_id", "hostname", "device_last_seen", "device_stale", "category", "product_key",
		"name", "platform", "kind", "identifier", "version", "approval_state", "user", "last_seen", "generated_at"})
	gen := fmtTime(rep.GeneratedAt)
	for _, row := range rows {
		_ = cw.Write([]string{row.DeviceID, csvSafe(row.Hostname), fmtTime(row.DeviceLastSeen),
			strconv.FormatBool(row.DeviceStale), row.Category, csvSafe(row.ProductKey), csvSafe(row.Name),
			row.Platform, row.Kind, csvSafe(row.Identifier), csvSafe(row.Version), row.ApprovalState,
			csvSafe(duplicateToolsUser(row)), fmtTime(row.LastSeen), gen})
	}
	cw.Flush()
}

// PortalDuplicateToolsHandler serves
// GET /v1/portal/reports/software/duplicate-tools.
func PortalDuplicateToolsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parseDuplicateToolsFilter(w, r)
		if !ok {
			return
		}
		rep, ok := buildDuplicateTools(w, r, pool, "portal_duplicate_tools")
		if !ok {
			return
		}
		if format == "csv" {
			writeDuplicateToolsCSV(w, rep, f)
			return
		}
		cats := []duplicatetools.CategoryRow{}
		for _, c := range rep.Categories {
			if f.matchCategory(c) {
				cats = append(cats, c)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"definition": rep.Definition, "generated_at": rep.GeneratedAt, "summary": rep.Summary,
			"basis": rep.Basis, "total": len(cats), "limit": f.limit, "offset": f.offset,
			"categories": page(cats, f.limit, f.offset),
		})
	}
}
