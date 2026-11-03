package handlers

// PAT-2152: the SAM software publisher report (PAT-2146), tenant-scoped and
// read-only. Every portal role can read it.
//
//	GET /v1/portal/reports/software/publishers           summary, basis, publisher rows (paged)
//	GET /v1/portal/reports/software/publishers/devices    per-device installation rows (paged drill-down)
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

	"patched.im/api/internal/softwaregov"
)

const (
	publisherReportDefaultLimit = 100
	publisherReportMaxLimit     = 500
)

type publisherReportFilter struct {
	group, platform, publisherKey, deviceID, productKey string
	limit, offset                                       int
}

func parsePublisherReportFilter(w http.ResponseWriter, r *http.Request, devices bool) (string, publisherReportFilter, bool) {
	allowed := []string{"group", "platform", "publisher_key", "limit", "offset"}
	if devices {
		allowed = append(allowed, "device_id", "product_key")
	}
	format, ok := governanceFormat(w, r, allowed...)
	if !ok {
		return "", publisherReportFilter{}, false
	}
	q := r.URL.Query()
	f := publisherReportFilter{
		group: q.Get("group"), platform: q.Get("platform"), publisherKey: strings.TrimSpace(q.Get("publisher_key")),
		deviceID: strings.TrimSpace(q.Get("device_id")), productKey: strings.TrimSpace(q.Get("product_key")),
		limit: publisherReportDefaultLimit,
	}
	bad := func(msg string) (string, publisherReportFilter, bool) {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", msg, nil)
		return "", publisherReportFilter{}, false
	}
	switch f.group {
	case "", softwaregov.PublisherGroupVerified, softwaregov.PublisherGroupUnsignedAdhoc,
		softwaregov.PublisherGroupInvalid, softwaregov.PublisherGroupUnverified:
	default:
		return bad("group must be one of verified, unsigned_or_adhoc, invalid, unverified")
	}
	switch f.platform {
	case "", "macos", "windows":
	default:
		return bad("platform must be macos or windows")
	}
	if len(f.deviceID) > 64 || len(f.productKey) > 300 || len(f.publisherKey) > 600 {
		return bad("device_id, product_key or publisher_key is too long")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > publisherReportMaxLimit {
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

func (f publisherReportFilter) matchRow(r softwaregov.PublisherReportRow) bool {
	return (f.group == "" || r.Group == f.group) && (f.platform == "" || r.Platform == f.platform) &&
		(f.publisherKey == "" || r.PublisherKey == f.publisherKey) &&
		(f.deviceID == "" || r.DeviceID == f.deviceID) && (f.productKey == "" || r.ProductKey == f.productKey)
}

func (f publisherReportFilter) matchPublisher(p softwaregov.PublisherRow) bool {
	return (f.group == "" || p.Group == f.group) && (f.platform == "" || p.Platform == f.platform) &&
		(f.publisherKey == "" || p.PublisherKey == f.publisherKey)
}

func buildPublisherReport(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, handler string) (softwaregov.PublisherReport, bool) {
	id, ok := identity(w, r)
	if !ok {
		return softwaregov.PublisherReport{}, false
	}
	logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", handler, "tenant_id", id.TenantID)
	rep, err := softwaregov.BuildPublisherReport(r.Context(), pool, id.TenantID, time.Now())
	if err != nil {
		if errors.Is(err, softwaregov.ErrEstateTooLarge) {
			writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
				"the estate inventory is too large to assess in one request", nil)
			return rep, false
		}
		logger.Error("build software publisher report failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return rep, false
	}
	return rep, true
}

// writePublisherReportCSV writes every matching installation row.
// Endpoint- and source-supplied text goes through csvSafe (spreadsheet
// formula injection).
func writePublisherReportCSV(w http.ResponseWriter, rep softwaregov.PublisherReport, f publisherReportFilter) {
	var rows []softwaregov.PublisherReportRow
	for _, row := range rep.Rows {
		if f.matchRow(row) {
			rows = append(rows, row)
		}
	}
	cw := csvAttachment(w, "software-publishers", len(rows))
	_ = cw.Write([]string{"device_id", "hostname", "device_last_seen", "device_stale", "group", "platform",
		"publisher_key", "identity_basis", "publisher", "trusted", "signing", "signer_class", "notarisation",
		"product_key", "name", "identifier", "version", "generated_at"})
	gen := fmtTime(rep.GeneratedAt)
	for _, row := range rows {
		_ = cw.Write([]string{row.DeviceID, csvSafe(row.Hostname), fmtTime(row.DeviceLastSeen),
			strconv.FormatBool(row.DeviceStale), row.Group, row.Platform, csvSafe(row.PublisherKey), row.IdentityBasis,
			csvSafe(strOrEmpty(row.Publisher)), strconv.FormatBool(row.Trusted), row.Signing,
			csvSafe(strOrEmpty(row.SignerClass)), row.Notarisation, csvSafe(row.ProductKey), csvSafe(row.Name),
			csvSafe(row.Identifier), csvSafe(row.Version), gen})
	}
	cw.Flush()
}

// PortalSoftwarePublishersHandler serves GET /v1/portal/reports/software/publishers.
func PortalSoftwarePublishersHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parsePublisherReportFilter(w, r, false)
		if !ok {
			return
		}
		rep, ok := buildPublisherReport(w, r, pool, "portal_software_publishers")
		if !ok {
			return
		}
		if format == "csv" {
			writePublisherReportCSV(w, rep, f)
			return
		}
		publishers := []softwaregov.PublisherRow{}
		for _, p := range rep.Publishers {
			if f.matchPublisher(p) {
				publishers = append(publishers, p)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"definition": rep.Definition, "generated_at": rep.GeneratedAt, "summary": rep.Summary,
			"basis": rep.Basis, "total": len(publishers), "limit": f.limit, "offset": f.offset,
			"publishers": page(publishers, f.limit, f.offset),
		})
	}
}

// PortalSoftwarePublishersDevicesHandler serves
// GET /v1/portal/reports/software/publishers/devices.
func PortalSoftwarePublishersDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		format, f, ok := parsePublisherReportFilter(w, r, true)
		if !ok {
			return
		}
		rep, ok := buildPublisherReport(w, r, pool, "portal_software_publishers_devices")
		if !ok {
			return
		}
		if format == "csv" {
			writePublisherReportCSV(w, rep, f)
			return
		}
		rows := []softwaregov.PublisherReportRow{}
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
