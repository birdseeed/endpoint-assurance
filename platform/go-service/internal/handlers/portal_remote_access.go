package handlers

// PAT-2148: the SAM remote access / RMM report (PAT-2146), tenant-scoped and
// read-only. Every portal role can read it.
//
//	GET /v1/portal/reports/software/remote-access           summary, basis, product rows (paged)
//	GET /v1/portal/reports/software/remote-access/devices    per-device (and per-user) installation rows (paged drill-down)
//
// Both take ?format=json (default) or ?format=csv. The CSV is always the
// per-device (and per-user) rows, unpaged, so an export is the evidence
// behind every figure rather than one page of it. The tenant comes only
// from the verified portal identity. Unknown query parameters are refused
// so a typo cannot silently widen or narrow the answer.

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

	"patched.im/api/internal/remoteaccess"
)

const (
	remoteAccessDefaultLimit = 100
	remoteAccessMaxLimit     = 500
)

type remoteAccessFilter struct {
	category, kind, state, platform, deviceID, productKey string
	limit, offset                                         int
}

func parseRemoteAccessFilter(w http.ResponseWriter, r *http.Request, devices bool) (string, remoteAccessFilter, bool) {
	allowed := []string{"category", "kind", "state", "platform", "limit", "offset"}
	if devices {
		allowed = append(allowed, "device_id", "product_key")
	}
	format, ok := governanceFormat(w, r, allowed...)
	if !ok {
		return "", remoteAccessFilter{}, false
	}
	q := r.URL.Query()
	f := remoteAccessFilter{
		category: q.Get("category"), kind: q.Get("kind"), state: q.Get("state"), platform: q.Get("platform"),
		deviceID: strings.TrimSpace(q.Get("device_id")), productKey: strings.TrimSpace(q.Get("product_key")),
		limit: remoteAccessDefaultLimit,
	}
	bad := func(msg string) (string, remoteAccessFilter, bool) {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", msg, nil)
		return "", remoteAccessFilter{}, false
	}
	switch f.category {
	case "", remoteaccess.CategoryRemoteAccess, remoteaccess.CategoryRMMAgent:
	default:
		return bad("category must be remote_access or rmm_agent")
	}
	switch f.kind {
	case "", remoteaccess.KindApp, remoteaccess.KindBrowserExtension, remoteaccess.KindPackage:
	default:
		return bad("kind must be app, browser_extension or package")
	}
	switch f.state {
	case "", remoteaccess.StateApproved, remoteaccess.StateUnapproved, remoteaccess.StateUnreviewed, remoteaccess.StateIgnored:
	default:
		return bad("state must be one of approved, unapproved, unreviewed, ignored")
	}
	switch f.platform {
	case "", "macos", "windows":
	default:
		return bad("platform must be macos or windows")
	}
	if len(f.deviceID) > 64 || len(f.productKey) > 300 {
		return bad("device_id or product_key is too long")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > remoteAccessMaxLimit {
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

func (f remoteAccessFilter) matchRow(r remoteaccess.Row) bool {
	return (f.category == "" || r.Category == f.category) && (f.kind == "" || r.Kind == f.kind) &&
		(f.state == "" || r.ApprovalState == f.state) && (f.platform == "" || r.Platform == f.platform) &&
		(f.deviceID == "" || r.DeviceID == f.deviceID) && (f.productKey == "" || r.ProductKey == f.productKey)
}

func (f remoteAccessFilter) matchProduct(p remoteaccess.ProductRow) bool {
	return (f.category == "" || p.Category == f.category) && (f.kind == "" || p.Kind == f.kind) &&
		(f.state == "" || p.ApprovalState == f.state) && (f.platform == "" || p.Platform == f.platform)
}

func buildRemoteAccess(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, handler string) (remoteaccess.Report, bool) {
	id, ok := identity(w, r)
	if !ok {
		return remoteaccess.Report{}, false
	}
	logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", handler, "tenant_id", id.TenantID)
	rep, err := remoteaccess.Build(r.Context(), pool, id.TenantID, time.Now())
	if err != nil {
		if errors.Is(err, remoteaccess.ErrEstateTooLarge) {
			writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
				"the estate inventory is too large to assess in one request", nil)
			return rep, false
		}
		logger.Error("build remote access report failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return rep, false
	}
	return rep, true
}

func remoteAccessUser(r remoteaccess.Row) string {
	if r.User != nil {
		return *r.User
	}
	if r.MachineWide {
		return "machine-wide"
	}
	return ""
}

// writeRemoteAccessCSV writes every matching row (one per device, or one per
// device and user for a per-user install). Endpoint- and source-supplied
// text goes through csvSafe (spreadsheet formula injection).
func writeRemoteAccessCSV(w http.ResponseWriter, rep remoteaccess.Report, f remoteAccessFilter) {
	var rows []remoteaccess.Row
	for _, row := range rep.Rows {
		if f.matchRow(row) {
			rows = append(rows, row)
		}
	}
	cw := csvAttachment(w, "remote-access", len(rows))
	_ = cw.Write([]string{"device_id", "hostname", "device_last_seen", "device_stale", "category", "kind",
		"product_key", "name", "platform", "identifier", "version", "approval_state", "user", "last_seen", "generated_at"})
	gen := fmtTime(rep.GeneratedAt)
	for _, row := range rows {
		_ = cw.Write([]string{row.DeviceID, csvSafe(row.Hostname), fmtTime(row.DeviceLastSeen),
			strconv.FormatBool(row.DeviceStale), row.Category, row.Kind, csvSafe(row.ProductKey), csvSafe(row.Name),
			row.Platform, csvSafe(row.Identifier), csvSafe(row.Version), row.ApprovalState, csvSafe(remoteAccessUser(row)),
			fmtTime(row.LastSeen), gen})
	}
	cw.Flush()
}

// PortalRemoteAccessHandler serves GET /v1/portal/reports/software/remote-access.
func PortalRemoteAccessHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parseRemoteAccessFilter(w, r, false)
		if !ok {
			return
		}
		rep, ok := buildRemoteAccess(w, r, pool, "portal_remote_access")
		if !ok {
			return
		}
		if format == "csv" {
			writeRemoteAccessCSV(w, rep, f)
			return
		}
		products := []remoteaccess.ProductRow{}
		for _, p := range rep.Products {
			if f.matchProduct(p) {
				products = append(products, p)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"definition": rep.Definition, "generated_at": rep.GeneratedAt, "summary": rep.Summary,
			"basis": rep.Basis, "total": len(products), "limit": f.limit, "offset": f.offset,
			"products": page(products, f.limit, f.offset),
		})
	}
}

// PortalRemoteAccessDevicesHandler serves
// GET /v1/portal/reports/software/remote-access/devices.
func PortalRemoteAccessDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parseRemoteAccessFilter(w, r, true)
		if !ok {
			return
		}
		rep, ok := buildRemoteAccess(w, r, pool, "portal_remote_access_devices")
		if !ok {
			return
		}
		if format == "csv" {
			writeRemoteAccessCSV(w, rep, f)
			return
		}
		rows := []remoteaccess.Row{}
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
