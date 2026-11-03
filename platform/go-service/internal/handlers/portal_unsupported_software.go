package handlers

// PAT-2147: the SAM unsupported software report (PAT-2146), tenant-scoped
// and read-only. Every portal role can read it.
//
//	GET /v1/portal/reports/software/unsupported           summary, basis, Cyber Essentials evidence, product rows (paged)
//	GET /v1/portal/reports/software/unsupported/devices   per-device installation rows (paged drill-down)
//
// Both take ?format=json (default) or ?format=csv. The CSV is always the
// per-device installation rows, unpaged, so an export is the evidence behind
// every figure rather than one page of it. The tenant comes only from the
// verified portal identity. Unknown query parameters are refused so a typo
// cannot silently widen or narrow the answer.

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

	"patched.im/api/internal/lifecycle"
)

const (
	unsupportedDefaultLimit = 100
	unsupportedMaxLimit     = 500
)

type unsupportedFilter struct {
	state, kind, platform, deviceID, productKey string
	limit, offset                               int
}

func parseUnsupportedFilter(w http.ResponseWriter, r *http.Request, devices bool) (string, unsupportedFilter, bool) {
	allowed := []string{"state", "kind", "platform", "limit", "offset"}
	if devices {
		allowed = append(allowed, "device_id", "product_key")
	}
	format, ok := governanceFormat(w, r, allowed...)
	if !ok {
		return "", unsupportedFilter{}, false
	}
	q := r.URL.Query()
	f := unsupportedFilter{
		state: q.Get("state"), kind: q.Get("kind"), platform: q.Get("platform"),
		deviceID: strings.TrimSpace(q.Get("device_id")), productKey: strings.TrimSpace(q.Get("product_key")),
		limit: unsupportedDefaultLimit,
	}
	bad := func(msg string) (string, unsupportedFilter, bool) {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", msg, nil)
		return "", unsupportedFilter{}, false
	}
	switch f.state {
	case "", lifecycle.StateSupported, lifecycle.StateEndingSoon, lifecycle.StateUnsupported, lifecycle.StateUnknown:
	default:
		return bad("state must be one of supported, ending_within_90_days, unsupported, unknown")
	}
	switch f.kind {
	case "", lifecycle.KindApplication, lifecycle.KindOperatingSystem:
	default:
		return bad("kind must be application or operating_system")
	}
	switch f.platform {
	case "", "macos", "windows":
	default:
		return bad("platform must be macos or windows")
	}
	if len(f.deviceID) > 64 || len(f.productKey) > 200 {
		return bad("device_id or product_key is too long")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > unsupportedMaxLimit {
			return bad("limit must be 1 to 500")
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

func (f unsupportedFilter) matchRow(r lifecycle.Row) bool {
	return (f.state == "" || r.State == f.state) && (f.kind == "" || r.Kind == f.kind) &&
		(f.platform == "" || r.Platform == f.platform) && (f.deviceID == "" || r.DeviceID == f.deviceID) &&
		(f.productKey == "" || r.ProductKey == f.productKey)
}

func (f unsupportedFilter) matchProduct(p lifecycle.ProductRow) bool {
	return (f.state == "" || p.State == f.state) && (f.kind == "" || p.Kind == f.kind) &&
		(f.platform == "" || p.Platform == f.platform)
}

func page[T any](items []T, limit, offset int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func buildUnsupported(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, handler string) (lifecycle.Report, bool) {
	id, ok := identity(w, r)
	if !ok {
		return lifecycle.Report{}, false
	}
	logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", handler, "tenant_id", id.TenantID)
	rep, err := lifecycle.Build(r.Context(), pool, id.TenantID, time.Now())
	if err != nil {
		if errors.Is(err, lifecycle.ErrEstateTooLarge) {
			writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
				"the estate inventory is too large to assess in one request", nil)
			return rep, false
		}
		logger.Error("build unsupported software report failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return rep, false
	}
	return rep, true
}

func fmtInt(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

// writeUnsupportedCSV writes every matching installation row. Endpoint- and
// source-supplied text goes through csvSafe (spreadsheet formula injection).
func writeUnsupportedCSV(w http.ResponseWriter, rep lifecycle.Report, f unsupportedFilter) {
	var rows []lifecycle.Row
	for _, row := range rep.Rows {
		if f.matchRow(row) {
			rows = append(rows, row)
		}
	}
	cw := csvAttachment(w, "unsupported-software", len(rows))
	_ = cw.Write([]string{"device_id", "hostname", "device_last_seen", "device_stale", "kind", "product_key",
		"name", "platform", "version", "edition", "state", "cycle", "eol_date", "days_to_eol", "source",
		"source_url", "last_checked_at", "unknown_reason", "note", "generated_at"})
	gen := fmtTime(rep.GeneratedAt)
	for _, row := range rows {
		source, sourceURL := "", ""
		if row.Source != nil {
			source, sourceURL = row.Source.Name+":"+row.Source.Slug, row.Source.URL
		}
		_ = cw.Write([]string{row.DeviceID, csvSafe(row.Hostname), fmtTime(row.DeviceLastSeen),
			strconv.FormatBool(row.DeviceStale), row.Kind, csvSafe(row.ProductKey), csvSafe(row.Name), row.Platform,
			csvSafe(row.Version), csvSafe(row.Edition), row.State, csvSafe(strOrEmpty(row.Cycle)), strOrEmpty(row.EOLDate),
			fmtInt(row.DaysToEOL), csvSafe(source), csvSafe(sourceURL), fmtTimePtr(row.LastCheckedAt),
			strOrEmpty(row.ReasonText), csvSafe(strOrEmpty(row.Note)), gen})
	}
	cw.Flush()
}

// PortalUnsupportedSoftwareHandler serves GET /v1/portal/reports/software/unsupported.
func PortalUnsupportedSoftwareHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parseUnsupportedFilter(w, r, false)
		if !ok {
			return
		}
		rep, ok := buildUnsupported(w, r, pool, "portal_unsupported_software")
		if !ok {
			return
		}
		if format == "csv" {
			writeUnsupportedCSV(w, rep, f)
			return
		}
		products := []lifecycle.ProductRow{}
		for _, p := range rep.Products {
			if f.matchProduct(p) {
				products = append(products, p)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"definition": rep.Definition, "generated_at": rep.GeneratedAt, "summary": rep.Summary,
			"basis": rep.Basis, "cyber_essentials": rep.CyberEssentials,
			"total": len(products), "limit": f.limit, "offset": f.offset,
			"products": page(products, f.limit, f.offset),
		})
	}
}

// PortalUnsupportedSoftwareDevicesHandler serves
// GET /v1/portal/reports/software/unsupported/devices.
func PortalUnsupportedSoftwareDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parseUnsupportedFilter(w, r, true)
		if !ok {
			return
		}
		rep, ok := buildUnsupported(w, r, pool, "portal_unsupported_software_devices")
		if !ok {
			return
		}
		if format == "csv" {
			writeUnsupportedCSV(w, rep, f)
			return
		}
		rows := []lifecycle.Row{}
		for _, row := range rep.Rows {
			if f.matchRow(row) {
				rows = append(rows, row)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"definition": rep.Definition, "generated_at": rep.GeneratedAt, "basis": rep.Basis,
			"total": len(rows), "limit": f.limit, "offset": f.offset,
			"rows": page(rows, f.limit, f.offset),
		})
	}
}
