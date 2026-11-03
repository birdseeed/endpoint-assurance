package handlers

// GET /v1/portal/homebrew/* (PAT-2013). Read-only Homebrew views for the
// PAT-1999 portal tab. Tenant scope comes only from the verified portal
// identity; nothing here takes a tenant id from the request.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

func writeHomebrewJSON(w http.ResponseWriter, logger *slog.Logger, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warn("encode portal homebrew response failed", "err", err)
	}
}

// parseHomebrewBool reads an optional true/false query flag. Anything else is
// a 400 rather than a silent default.
func parseHomebrewBool(r *http.Request, key string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "", "false", "0":
		return false, true
	case "true", "1":
		return true, true
	default:
		return false, false
	}
}

func homebrewLogger(r *http.Request, handler, tenantID string) *slog.Logger {
	return slog.With("req_id", middleware.GetReqID(r.Context()), "handler", handler, "tenant_id", tenantID)
}

func homebrewSearch(w http.ResponseWriter, r *http.Request) (string, bool) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	if len(search) > 256 {
		http.Error(w, "search must be at most 256 characters", http.StatusBadRequest)
		return "", false
	}
	return search, true
}

// PortalHomebrewSummaryHandler serves GET /v1/portal/homebrew/summary.
func PortalHomebrewSummaryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := homebrewLogger(r, "portal_homebrew_summary", id.TenantID)
		summary, err := report.FetchHomebrewSummary(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch homebrew summary failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, summary)
	}
}

// PortalHomebrewFormulaeHandler serves GET /v1/portal/homebrew/formulae.
// include_dependencies=true adds formulae installed only as dependencies.
func PortalHomebrewFormulaeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		search, ok := homebrewSearch(w, r)
		if !ok {
			return
		}
		includeDeps, ok := parseHomebrewBool(r, "include_dependencies")
		if !ok {
			http.Error(w, "include_dependencies must be true or false", http.StatusBadRequest)
			return
		}
		limit, offset := parsePagination(r)
		logger := homebrewLogger(r, "portal_homebrew_formulae", id.TenantID)
		page, err := report.FetchHomebrewFormulae(r.Context(), pool, id.TenantID, search, includeDeps, limit, offset)
		if err != nil {
			logger.Error("fetch homebrew formulae failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, struct {
			report.HomebrewFormulaPage
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}{page, limit, offset})
	}
}

// PortalHomebrewCasksHandler serves GET /v1/portal/homebrew/casks.
func PortalHomebrewCasksHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		search, ok := homebrewSearch(w, r)
		if !ok {
			return
		}
		limit, offset := parsePagination(r)
		logger := homebrewLogger(r, "portal_homebrew_casks", id.TenantID)
		page, err := report.FetchHomebrewCasks(r.Context(), pool, id.TenantID, search, limit, offset)
		if err != nil {
			logger.Error("fetch homebrew casks failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, struct {
			report.HomebrewCaskPage
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}{page, limit, offset})
	}
}

// PortalHomebrewTapsHandler serves GET /v1/portal/homebrew/taps.
// include_core=true adds homebrew/core and homebrew/cask.
func PortalHomebrewTapsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		includeCore, ok := parseHomebrewBool(r, "include_core")
		if !ok {
			http.Error(w, "include_core must be true or false", http.StatusBadRequest)
			return
		}
		limit, offset := parsePagination(r)
		logger := homebrewLogger(r, "portal_homebrew_taps", id.TenantID)
		page, err := report.FetchHomebrewTaps(r.Context(), pool, id.TenantID, includeCore, limit, offset)
		if err != nil {
			logger.Error("fetch homebrew taps failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, struct {
			report.HomebrewTapPage
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}{page, limit, offset})
	}
}

// PortalHomebrewDevicesHandler serves GET /v1/portal/homebrew/devices.
func PortalHomebrewDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		limit, offset := parsePagination(r)
		logger := homebrewLogger(r, "portal_homebrew_devices", id.TenantID)
		page, err := report.FetchHomebrewDevices(r.Context(), pool, id.TenantID, limit, offset)
		if err != nil {
			logger.Error("fetch homebrew devices failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, struct {
			report.HomebrewDevicePage
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}{page, limit, offset})
	}
}

// PortalHomebrewDeviceHandler serves GET /v1/portal/homebrew/devices/{deviceID}:
// one device's Homebrew state and a page of its brew list. kind is optional
// (formula, cask or tap). Another tenant's device is a 404, the same as a
// device that does not exist.
func PortalHomebrewDeviceHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := homebrewLogger(r, "portal_homebrew_device", id.TenantID)
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		kind := strings.TrimSpace(r.URL.Query().Get("kind"))
		switch kind {
		case "", "formula", "cask", "tap":
		default:
			http.Error(w, "kind must be formula, cask or tap", http.StatusBadRequest)
			return
		}
		owner, err := report.DeviceTenant(r.Context(), pool, deviceID)
		if err != nil || owner != id.TenantID {
			if err != nil && !errors.Is(err, report.ErrDeviceNotFound) {
				logger.Error("device ownership check failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		limit, offset := parsePagination(r)
		detail, err := report.FetchHomebrewDeviceDetail(r.Context(), pool, id.TenantID, deviceID, kind, limit, offset)
		if err != nil {
			logger.Error("fetch homebrew device failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeHomebrewJSON(w, logger, struct {
			report.HomebrewDeviceDetail
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}{detail, limit, offset})
	}
}
