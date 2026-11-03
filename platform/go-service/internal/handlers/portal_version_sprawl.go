package handlers

// PAT-2150: the SAM version sprawl report (PAT-2146), tenant-scoped and
// read-only. Every portal role can read it.
//
//	GET /v1/portal/reports/software/version-sprawl
//
// Same envelope shape as PAT-2147's unsupported-software report: a saved
// definition, a basis stating what the answer rests on, and paged product
// rows, each carrying an optional per-version breakdown. Takes ?format=json
// (default) or ?format=csv. The CSV is always the full, unpaged product
// list, one row per product (not the per-version breakdown), so an export is
// the evidence behind every figure rather than one page of it. The tenant
// comes only from the verified portal identity. Unknown query parameters are
// refused so a typo cannot silently widen or narrow the answer.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/lifecycle"
)

const (
	sprawlDefaultLimit = 100
	sprawlMaxLimit     = 500
)

type sprawlFilter struct {
	platform      string
	limit, offset int
}

func parseSprawlFilter(w http.ResponseWriter, r *http.Request) (string, sprawlFilter, bool) {
	format, ok := governanceFormat(w, r, "platform", "limit", "offset")
	if !ok {
		return "", sprawlFilter{}, false
	}
	q := r.URL.Query()
	f := sprawlFilter{platform: q.Get("platform"), limit: sprawlDefaultLimit}
	bad := func(msg string) (string, sprawlFilter, bool) {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", msg, nil)
		return "", sprawlFilter{}, false
	}
	switch f.platform {
	case "", "macos", "windows":
	default:
		return bad("platform must be macos or windows")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > sprawlMaxLimit {
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

func (f sprawlFilter) matchProduct(p lifecycle.SprawlProduct) bool {
	return f.platform == "" || p.Platform == f.platform
}

func fmtIntPtr(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

func fmtStrPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// writeVersionSprawlCSV writes every matching product row, unpaged.
func writeVersionSprawlCSV(w http.ResponseWriter, rep lifecycle.SprawlReport, f sprawlFilter) {
	var rows []lifecycle.SprawlProduct
	for _, p := range rep.Products {
		if f.matchProduct(p) {
			rows = append(rows, p)
		}
	}
	cw := csvAttachment(w, "version-sprawl", len(rows))
	// The last column was added by PAT-2509; the ones before it keep their
	// names and order. latest_released_source now holds the plain label (for
	// example "Patched reference list"), never the machine name
	// curated_catalogue, which is not wording a customer should be shown.
	_ = cw.Write([]string{"product_key", "name", "platform", "distinct_versions", "oldest_version",
		"newest_version", "latest_released", "latest_released_source", "devices_more_than_one_major_behind",
		"devices_not_comparable", "cve_count_oldest_version", "device_count", "stale_device_count", "generated_at",
		"latest_released_checked_at"})
	gen := fmtTime(rep.GeneratedAt)
	for _, p := range rows {
		label, checked := "", ""
		if p.LatestReleasedSource != nil {
			label = p.LatestReleasedSource.Label
			checked = fmtTimePtr(p.LatestReleasedSource.CheckedAt)
		}
		cve := "not_assessed"
		if p.CVECountOnOldest != nil {
			cve = fmtIntPtr(p.CVECountOnOldest)
		}
		_ = cw.Write([]string{csvSafe(p.ProductKey), csvSafe(p.Name), p.Platform, strconv.Itoa(p.DistinctVersions),
			csvSafe(p.OldestVersion), csvSafe(p.NewestVersion), csvSafe(fmtStrPtr(p.LatestReleased)), csvSafe(label),
			strconv.Itoa(p.DevicesMoreThanOneMajorBehind), strconv.Itoa(p.DevicesNotComparable), cve,
			strconv.Itoa(p.DeviceCount), strconv.Itoa(p.StaleDeviceCount), gen, checked})
	}
	cw.Flush()
}

// PortalVersionSprawlHandler serves GET /v1/portal/reports/software/version-sprawl.
func PortalVersionSprawlHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		format, f, ok := parseSprawlFilter(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "portal_version_sprawl", "tenant_id", id.TenantID)
		rep, err := lifecycle.BuildVersionSprawl(r.Context(), pool, id.TenantID, time.Now())
		if err != nil {
			if errors.Is(err, lifecycle.ErrEstateTooLarge) {
				writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
					"the estate inventory is too large to assess in one request", nil)
				return
			}
			logger.Error("build version sprawl report failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if format == "csv" {
			writeVersionSprawlCSV(w, rep, f)
			return
		}
		products := []lifecycle.SprawlProduct{}
		for _, p := range rep.Products {
			if f.matchProduct(p) {
				products = append(products, p)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"definition": rep.Definition, "generated_at": rep.GeneratedAt, "basis": rep.Basis,
			"total": len(products), "limit": f.limit, "offset": f.offset,
			"products": page(products, f.limit, f.offset),
		})
	}
}
