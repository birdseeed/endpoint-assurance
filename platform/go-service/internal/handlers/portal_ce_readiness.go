package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// PortalCEReadinessHandler serves GET /v1/portal/ce-readiness (PAT-1927):
// the Cyber Essentials v3.3 readiness read model, per device, with no
// verdict. ?format=csv (default json) exports one row per device per
// outstanding item, or one row per device with none. ?format=pdf renders
// a dated customer evidence pack from the same read model (PAT-2364).
//
// The tenant comes only from the portalauth identity; any query parameter
// other than format is refused, so a client tenant hint can never be
// honoured. Read failures follow the existing model; PDF rendering failures
// also return 500 before writing a partial pack. Contract:
// contracts/portal-api.md.
func PortalCEReadinessHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		format, ok := ceReadinessFormat(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_ce_readiness", "tenant_id", id.TenantID)

		res, err := report.FetchPortalCEReadiness(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch ce readiness failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if format == "csv" {
			writeCEReadinessCSV(w, res)
			return
		}
		if format == "pdf" {
			pdf, err := report.RenderCEReadinessPDFCustomer(res)
			if err != nil {
				logger.Error("render ce readiness pdf failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Cache-Control", "private, no-store")
			writeInsurancePDF(w, pdf, "ce-readiness-"+res.GeneratedAt.UTC().Format("2006-01-02")+".pdf", logger)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// writeCEReadinessCSV writes one row per device per item, or one "device"
// row for a device with no items stating its state. Every row carries the
// device's reporting freshness and the generation time; item rows carry the
// item's source, observation time and due basis next to days_overdue.
// Endpoint- and feed-supplied text goes through csvSafe.
func writeCEReadinessCSV(w http.ResponseWriter, res report.PortalCEReadiness) {
	n := 0
	for _, d := range res.Devices {
		n += max(1, len(d.Items))
	}
	cw := csvAttachment(w, "ce-readiness", n)
	_ = cw.Write([]string{"device_id", "hostname", "platform", "device_state", "state_reasons", "reporting_bucket",
		"device_last_seen", "cve_evidence_state", "cve_evidence_observed_at", "os_update_evidence_state",
		"row_kind", "cve_id", "severity", "product", "installed_version", "fixed_version", "published_at",
		"due_basis", "due_at", "age_days", "days_overdue", "kev_state", "kev_fetched_at", "item_source",
		"item_observed_at", "controls_not_passing", "controls_not_evidenced", "generated_at"})
	gen := fmtTime(res.GeneratedAt)
	for _, d := range res.Devices {
		var failing, unevidenced []string
		for _, c := range d.Controls {
			switch c.State {
			case report.CEControlNotPassing:
				failing = append(failing, c.Control)
			case report.CEControlNotEvidenced:
				unevidenced = append(unevidenced, c.Control)
			}
		}
		head := []string{d.DeviceID, csvSafe(d.Hostname), csvSafe(d.Platform), d.State,
			strings.Join(d.StateReasons, ";"), d.Reporting.Bucket, fmtTimePtr(d.Reporting.ObservedAt),
			d.CVEEvidence.State, fmtTimePtr(d.CVEEvidence.ObservedAt), d.OSUpdateEvidence.State}
		tail := []string{strings.Join(failing, ";"), strings.Join(unevidenced, ";"), gen}
		if len(d.Items) == 0 {
			row := append(append([]string{}, head...), "device", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
			_ = cw.Write(append(row, tail...))
			continue
		}
		for _, it := range d.Items {
			row := append(append([]string{}, head...), "item", csvSafe(it.CVEID), it.Severity, csvSafe(it.Product),
				csvSafe(it.InstalledVersion), csvSafe(strOrEmpty(it.FixedVersion)), fmtTime(it.PublishedAt),
				it.DueBasis, fmtTime(it.DueAt), strconv.Itoa(it.AgeDays), strconv.Itoa(it.DaysOverdue),
				it.KEV.State, fmtTimePtr(it.KEV.FetchedAt), it.Source, fmtTimePtr(it.ObservedAt))
			_ = cw.Write(append(row, tail...))
		}
	}
	cw.Flush()
}

// This additive format is specific to CE readiness. Other governance endpoints
// retain their JSON/CSV-only contract. Query ambiguity is rejected before reads.
func ceReadinessFormat(w http.ResponseWriter, r *http.Request) (string, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "invalid query string", nil)
		return "", false
	}
	for key := range q {
		if key != "format" {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "unknown query parameter "+strconv.Quote(key), nil)
			return "", false
		}
	}
	if len(q["format"]) > 1 {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "format must be supplied once", nil)
		return "", false
	}
	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" && format != "pdf" {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "format must be json, csv or pdf", nil)
		return "", false
	}
	return format, true
}
