package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// ExecutiveSummaryHandler serves the tenant-level estate executive summary PDF.
// Lives on the internal Tailscale-bound listener — same auth posture as the
// per-device report.
//
// Route: GET /admin/reports/executive-summary/{tenantID}.pdf
//
// 404 if the tenant doesn't exist; 400 if the path param isn't a UUID; 500
// otherwise.
func ExecutiveSummaryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "executive_summary")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		summary, err := report.FetchExecutiveSummary(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch executive summary failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderExecutiveSummaryPDF(summary)
		if err != nil {
			logger.Error("render executive summary pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(summary.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("executive-summary-%s-%s.pdf",
			stem,
			summary.GeneratedAt.Format("20060102T150405Z"))

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}

		logger.Info("executive summary served",
			"tenant_id", tenantID,
			"bytes", len(pdf),
			"devices", summary.Estate.TotalDevices,
		)
	}
}

// ComplianceReportHandler serves the CIS L1 compliance PDF for a given device.
// Lives on the internal Tailscale-bound listener — same auth posture as
// /admin/tenants (network restriction only; application-layer auth deferred to
// v2 hardening).
//
// Route: GET /admin/reports/{deviceID}/compliance.pdf
//
// 404 if the device doesn't exist; 400 if the path param isn't a UUID; 500
// for everything else.
func ComplianceReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "compliance_report")

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		rep, err := report.Fetch(r.Context(), pool, deviceID)
		if err != nil {
			if errors.Is(err, report.ErrDeviceNotFound) {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch report failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderPDF(rep)
		if err != nil {
			logger.Error("render pdf failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Store the SHA-256 digest of the generated PDF so the posture endpoint
		// can surface it as evidence.last_signed_report_digest.
		// Non-fatal — a digest write failure must not block report delivery.
		digest := sha256.Sum256(pdf)
		digestHex := hex.EncodeToString(digest[:])
		if _, insertErr := pool.Exec(r.Context(), `
			INSERT INTO device_report_digests (device_id, report_type, sha256)
			VALUES ($1::uuid, 'compliance', $2)
		`, deviceID, digestHex); insertErr != nil {
			logger.Warn("store report digest failed", "err", insertErr, "device_id", deviceID)
		} else {
			logger.Debug("report digest stored", "device_id", deviceID, "digest", digestHex[:16]+"…")
		}

		// Filename uses the hostname when we have one — easier for the user to
		// recognise in their Downloads folder than a UUID. Falls back to the
		// UUID when there's no hostname on the device row.
		filenameStem := rep.Device.Hostname
		if filenameStem == "" {
			filenameStem = deviceID
		}
		filename := fmt.Sprintf("compliance-%s-%s.pdf",
			sanitiseFilename(filenameStem),
			rep.GeneratedAt.Format("20060102T150405Z"))

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}

		logger.Info("report served",
			"device_id", deviceID,
			"bytes", len(pdf),
			"evaluations", len(rep.Evaluations),
			"cve_findings", len(rep.CVEFindings),
			"catalog_updates", len(rep.CatalogUpdates),
		)
	}
}

// FreeCVEReportHandler serves the tenant-level Free CVE Assessment PDF.
// Lives on the internal Tailscale-bound listener — same auth posture as the
// other report handlers.
//
// Route: GET /admin/reports/cve/{tenantID}.pdf
//
// 404 if the tenant doesn't exist; 400 if the path param isn't a UUID; 500 otherwise.
func FreeCVEReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "free_cve_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		rep, err := report.FetchFreeCVEReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch cve report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderFreeCVEPDF(rep)
		if err != nil {
			logger.Error("render cve pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(rep.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("cve-assessment-%s-%s.pdf",
			stem,
			rep.GeneratedAt.Format("20060102T150405Z"))

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}

		logger.Info("cve report served",
			"tenant_id", tenantID,
			"bytes", len(pdf),
			"cves", rep.TotalCVEs,
		)
	}
}

// looksLikeUUID is a cheap shape check — server-side validation is enforced
// by the UUID column type when we query the DB, but this short-circuits
// obviously bad input without a round trip.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// sanitiseFilename strips anything that isn't safe for a filename across
// macOS/Linux/Windows. We're paranoid — the device hostname could in
// principle be anything the user set.
func sanitiseFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "device"
	}
	return b.String()
}

// CISComplianceReportHandler serves the tenant-level CIS Compliance PDF.
//
// Route: GET /admin/reports/cis-compliance/{tenantID}.pdf
func CISComplianceReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "cis_compliance_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchCISComplianceReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch cis compliance report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderCISCompliancePDF(data)
		if err != nil {
			logger.Error("render cis compliance pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("cis-compliance-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("cis compliance report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// PatchStatusReportHandler serves the tenant-level Patch Status PDF.
//
// Route: GET /admin/reports/patch-status/{tenantID}.pdf
func PatchStatusReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "patch_status_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchPatchStatusReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch patch status report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderPatchStatusPDF(data)
		if err != nil {
			logger.Error("render patch status pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("patch-status-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("patch status report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// StaleEndpointsReportHandler serves the tenant-level Stale Endpoints PDF.
// Accepts ?threshold_days=N (default 14, range 1–365).
//
// Route: GET /admin/reports/stale-endpoints/{tenantID}.pdf
func StaleEndpointsReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "stale_endpoints_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		thresholdDays := 14
		if raw := r.URL.Query().Get("threshold_days"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 365 {
				http.Error(w, "threshold_days must be an integer between 1 and 365", http.StatusBadRequest)
				return
			}
			thresholdDays = n
		}

		data, err := report.FetchStaleEndpointsReport(r.Context(), pool, tenantID, thresholdDays)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch stale endpoints report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderStaleEndpointsPDF(data)
		if err != nil {
			logger.Error("render stale endpoints pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("stale-endpoints-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("stale endpoints report served", "tenant_id", tenantID, "bytes", len(pdf), "threshold_days", thresholdDays)
	}
}

// CertExpiryReportHandler serves the tenant-level Certificate Expiry PDF.
//
// Route: GET /admin/reports/cert-expiry/{tenantID}.pdf
func CertExpiryReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "cert_expiry_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchCertExpiryReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch cert expiry report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderCertExpiryPDF(data)
		if err != nil {
			logger.Error("render cert expiry pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("cert-expiry-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("cert expiry report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// SoftwareInventoryReportHandler serves the tenant-level Software Inventory PDF.
//
// Route: GET /admin/reports/software-inventory/{tenantID}.pdf
func SoftwareInventoryReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "software_inventory_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchSoftwareInventoryReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch software inventory report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderSoftwareInventoryPDF(data)
		if err != nil {
			logger.Error("render software inventory pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("software-inventory-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("software inventory report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// AppPolicyDriftReportHandler serves the tenant-level App Policy Drift PDF.
//
// Route: GET /admin/reports/app-policy-drift/{tenantID}.pdf
func AppPolicyDriftReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_policy_drift_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchAppPolicyDriftReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch app policy drift report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderAppPolicyDriftPDF(data)
		if err != nil {
			logger.Error("render app policy drift pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("app-policy-drift-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("app policy drift report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// BrowserExtensionsReportHandler serves the tenant-level Browser Extensions PDF.
//
// Route: GET /admin/reports/browser-extensions/{tenantID}.pdf
func BrowserExtensionsReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "browser_extensions_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchBrowserExtensionsReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch browser extensions report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderBrowserExtensionsPDF(data)
		if err != nil {
			logger.Error("render browser extensions pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("browser-extensions-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("browser extensions report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// EDRCoverageReportHandler serves the tenant-level EDR Coverage PDF.
//
// Route: GET /admin/reports/edr-coverage/{tenantID}.pdf
func EDRCoverageReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "edr_coverage_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchEDRCoverageReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch edr coverage report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderEDRCoveragePDF(data)
		if err != nil {
			logger.Error("render edr coverage pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("edr-coverage-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("edr coverage report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// DeviceHealthReportHandler serves the tenant-level Device Health PDF.
//
// Route: GET /admin/reports/device-health/{tenantID}.pdf
func DeviceHealthReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_health_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchDeviceHealthReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch device health report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderDeviceHealthPDF(data)
		if err != nil {
			logger.Error("render device health pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("device-health-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("device health report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// EncryptionPostureReportHandler serves the tenant-level Encryption Posture PDF.
//
// Route: GET /admin/reports/encryption-posture/{tenantID}.pdf
func EncryptionPostureReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "encryption_posture_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchEncryptionPostureReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch encryption posture report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderEncryptionPosturePDF(data)
		if err != nil {
			logger.Error("render encryption posture pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("encryption-posture-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("encryption posture report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}

// LocalAdminReportHandler serves the tenant-level Local Admin / Privileged Access PDF.
//
// Route: GET /admin/reports/local-admin/{tenantID}.pdf
func LocalAdminReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "local_admin_report")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		data, err := report.FetchLocalAdminReport(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch local admin report failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		pdf, err := report.RenderLocalAdminPDF(data)
		if err != nil {
			logger.Error("render local admin pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		stem := sanitiseFilename(data.Tenant)
		if stem == "device" {
			stem = tenantID
		}
		filename := fmt.Sprintf("local-admin-%s-%s.pdf", stem, data.GeneratedAt.Format("20060102T150405Z"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(pdf); err != nil {
			logger.Warn("pdf write to client failed", "err", err)
		}
		logger.Info("local admin report served", "tenant_id", tenantID, "bytes", len(pdf))
	}
}
