package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// PortalInsuranceEvidenceHandler serves GET /v1/portal/insurance-evidence
// (PAT-2258): answers to the endpoint questions on a cyber insurance
// renewal form, each from an existing read model with its source, freshness
// and unknown-device count, plus the questions Patched cannot evidence.
// ?format=json (default), csv (one row per question) or pdf (the customer
// PDF, the same renderer as the insurance-evidence report).
//
// Every portal role can read it, as for CE readiness. The tenant comes only
// from the portalauth identity; any query parameter other than format is
// refused, so a client tenant hint can never be honoured. Contract:
// contracts/portal-api.md.
func PortalInsuranceEvidenceHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		for k := range q {
			if k != "format" {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "unknown query parameter "+strconv.Quote(k), nil)
				return
			}
		}
		format := q.Get("format")
		if format == "" {
			format = "json"
		}
		if format != "json" && format != "csv" && format != "pdf" {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "format must be json, csv or pdf", nil)
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_insurance_evidence", "tenant_id", id.TenantID)

		res, err := report.FetchInsuranceEvidence(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch insurance evidence failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		switch format {
		case "csv":
			writeInsuranceEvidenceCSV(w, res)
		case "pdf":
			pdf, err := report.RenderInsuranceEvidencePDFCustomer(res)
			if err != nil {
				logger.Error("render insurance evidence pdf failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			writeInsurancePDF(w, pdf, "insurance-evidence-"+res.GeneratedAt.UTC().Format("2006-01-02")+".pdf", logger)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(res)
		}
	}
}

// writeInsuranceEvidenceCSV writes one row per question, in pack order,
// carrying the answer, its structured figures, freshness, source and basis.
// Free text goes through csvSafe.
func writeInsuranceEvidenceCSV(w http.ResponseWriter, res report.InsuranceEvidence) {
	cw := csvAttachment(w, "insurance-evidence", len(res.Questions))
	_ = cw.Write([]string{"question_id", "group", "title", "question", "status", "reason", "headline", "answer_text",
		"value", "unit", "percentage", "counts", "unknown_devices", "as_of", "oldest_evidence_at",
		"source_label", "source_path", "basis", "generated_at"})
	gen := fmtTime(res.GeneratedAt)
	for _, a := range res.Questions {
		value, pct, unknown := "", "", ""
		if a.Answer.Value != nil {
			value = strconv.Itoa(*a.Answer.Value)
		}
		if a.Answer.Percentage != nil {
			pct = strconv.FormatFloat(*a.Answer.Percentage, 'f', 1, 64)
		}
		if a.UnknownDevices != nil {
			unknown = strconv.Itoa(*a.UnknownDevices)
		}
		srcLabel, srcPath := "", ""
		if a.Source != nil {
			srcLabel, srcPath = a.Source.Label, a.Source.Path
		}
		_ = cw.Write([]string{a.ID, a.Group, csvSafe(a.Title), csvSafe(a.Question), a.Status, strOrEmpty(a.Reason),
			csvSafe(a.Headline), csvSafe(a.AnswerText), value, a.Answer.Unit, pct,
			report.InsuranceCountsString(a.Answer.Counts), unknown, fmtTimePtr(a.AsOf), fmtTimePtr(a.OldestEvidenceAt),
			csvSafe(srcLabel), csvSafe(srcPath), csvSafe(a.Basis), gen})
	}
	cw.Flush()
}

func writeInsurancePDF(w http.ResponseWriter, pdf []byte, filename string, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(pdf); err != nil {
		logger.Warn("pdf write to client failed", "err", err)
	}
}

// InsuranceEvidenceReportHandler serves the staff PDF.
//
// Route: GET /admin/reports/insurance-evidence/{tenantID}.pdf
func InsuranceEvidenceReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "insurance_evidence_report")
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		data, err := report.FetchInsuranceEvidence(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch insurance evidence failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pdf, err := report.RenderInsuranceEvidencePDF(data)
		if err != nil {
			logger.Error("render insurance evidence pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		writeInsurancePDF(w, pdf, fmt.Sprintf("insurance-evidence-%s-%s.pdf", stem, data.GeneratedAt.UTC().Format("20060102T150405Z")), logger)
		logger.Info("insurance evidence report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// insuranceCoverageSnapshot is the coverage frozen onto a generated
// insurance-evidence report record (PAT-1613 shape): the estate it was
// produced over and how many questions landed in each status.
func insuranceCoverageSnapshot(d report.InsuranceEvidence) map[string]any {
	statuses := map[string]int{}
	for _, q := range d.Questions {
		statuses[q.Status]++
	}
	return map[string]any{
		"source": "insurance-evidence", "devices_in_scope": d.DevicesInScope,
		"retired_excluded": d.RetiredExcluded, "question_statuses": statuses,
		"generated_at": d.GeneratedAt.UTC().Format(time.RFC3339),
	}
}
