package handlers

// GET /v1/portal/ai-tooling/* (PAT-2021). Read-only IDE extension, package,
// local model and MCP server views for the PAT-2000 AI Tooling tab. Tenant
// scope comes only from the verified portal identity; nothing here takes a
// tenant id from the request.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// PortalToolingSummaryHandler serves GET /v1/portal/ai-tooling/summary.
func PortalToolingSummaryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := homebrewLogger(r, "portal_ai_tooling_summary", id.TenantID)
		summary, err := report.FetchToolingSummary(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch ai tooling summary failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, summary)
	}
}

// PortalToolingDevicesHandler serves GET /v1/portal/ai-tooling/devices:
// every device, paged, with per-block status and counts.
func PortalToolingDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		limit, offset := parsePagination(r)
		logger := homebrewLogger(r, "portal_ai_tooling_devices", id.TenantID)
		page, err := report.FetchToolingDevices(r.Context(), pool, id.TenantID, limit, offset)
		if err != nil {
			logger.Error("fetch ai tooling devices failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, struct {
			report.ToolingDevicePage
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}{page, limit, offset})
	}
}

// PortalToolingDeviceItemsHandler serves the paginated, allowlisted evidence
// for one device. A foreign or unknown device is deliberately the same 404.
// format=csv exports all rows for that device from the same builder.
func PortalToolingDeviceItemsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.NotFound(w, r)
			return
		}
		var exists bool
		if err := pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1::uuid AND tenant_id=$2::uuid)`, deviceID, id.TenantID).Scan(&exists); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.NotFound(w, r)
			return
		}
		format, ok := governanceFormat(w, r, "limit", "offset")
		if !ok {
			return
		}
		limit, offset := 100, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 500 {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "limit must be 1 to 500", nil)
				return
			}
			limit = n
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "offset must be a non-negative integer", nil)
				return
			}
			offset = n
		}
		rep, err := report.BuildToolingEvidenceForDevice(r.Context(), pool, id.TenantID, deviceID, time.Now())
		if err != nil {
			if errors.Is(err, report.ErrToolingEvidenceTooLarge) {
				writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large", "the AI tooling evidence exceeds the bounded report size", nil)
				return
			}
			homebrewLogger(r, "portal_ai_tooling_device_items", id.TenantID).Error("build AI tooling evidence failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		items := rep.Items
		if format == "csv" {
			writeToolingEvidenceCSV(w, items, rep.GeneratedAt)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report.ToolingEvidencePage{GeneratedAt: rep.GeneratedAt, DeviceID: deviceID,
			Total: len(items), Limit: limit, Offset: offset, Items: page(items, limit, offset)})
	}
}

func writeToolingEvidenceCSV(w http.ResponseWriter, items []report.ToolingEvidenceItem, generatedAt time.Time) {
	cw := csvAttachment(w, "ai-tooling-evidence", len(items))
	_ = cw.Write([]string{"item_id", "device_id", "hostname", "platform", "block", "unit", "entry_kind",
		"collection_status", "lower_bound", "identity_kind", "identity", "source", "name", "version",
		"policy_state", "last_used_at", "metering_state", "model_size_bytes", "mcp_transport", "mcp_runner",
		"mcp_package", "mcp_host", "assessment_state", "finding_count", "highest_severity", "advisories", "observed_at", "generated_at"})
	for _, item := range items {
		states, advisories := []string{}, []string{}
		findingCount, severity := "", ""
		for _, assessment := range item.Assessments {
			states = append(states, assessment.State)
			if assessment.FindingCount != nil {
				findingCount = strconv.Itoa(*assessment.FindingCount)
			}
			if assessment.HighestSeverity != nil {
				severity = *assessment.HighestSeverity
			}
			for _, advisory := range assessment.Advisories {
				advisories = append(advisories, advisory.Source+":"+advisory.AdvisoryID)
			}
		}
		version := ""
		if item.Version != nil {
			version = *item.Version
		}
		lastUsed, sizeBytes := "", ""
		if item.LastUsedAt != nil {
			lastUsed = fmtTime(*item.LastUsedAt)
		}
		if item.SizeBytes != nil {
			sizeBytes = strconv.FormatInt(*item.SizeBytes, 10)
		}
		_ = cw.Write([]string{item.ItemID, item.DeviceID, csvSafe(item.Hostname), item.Platform, item.Block, item.Unit,
			item.EntryKind, item.CollectionStatus, strconv.FormatBool(item.LowerBound), item.IdentityKind,
			csvSafe(item.Identity), csvSafe(item.Source), csvSafe(item.Name), csvSafe(version), item.PolicyState,
			lastUsed, item.MeteringState, sizeBytes, csvSafe(pointerCSV(item.Transport)), csvSafe(pointerCSV(item.Runner)),
			csvSafe(pointerCSV(item.Package)), csvSafe(pointerCSV(item.Host)), strings.Join(states, ";"), findingCount, severity, csvSafe(strings.Join(advisories, ";")),
			fmtTime(item.ObservedAt), fmtTime(generatedAt)})
	}
	cw.Flush()
}

func pointerCSV(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// AIToolingEvidenceReportHandler serves the registry's staff PDF route.
func AIToolingEvidenceReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, homebrewLogger(r, "admin_ai_tooling_evidence", tenantID), err)
			return
		}
		rep, err := report.BuildToolingEvidence(r.Context(), pool, tenantID, time.Now())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pdf, err := report.RenderToolingEvidencePDF(rep)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="ai-tooling-evidence.pdf"`)
		_, _ = w.Write(pdf)
	}
}
