package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BrowserExtRow holds one browser extension aggregated across devices.
type BrowserExtRow struct {
	Name            string
	Browser         string
	Version         string
	Enabled         bool
	RiskLevel       string
	Permissions     []string
	HostPermissions []string
	DeviceCount     int
}

// BrowserExtensionsReport contains browser extension data for a tenant.
type BrowserExtensionsReport struct {
	GeneratedAt   time.Time
	Tenant        string
	Extensions    []BrowserExtRow
	ElevatedCount int
}

// FetchBrowserExtensionsReport fetches browser extension data for a tenant.
// If the device_browser_extensions table does not exist, returns empty data.
func FetchBrowserExtensionsReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (BrowserExtensionsReport, error) {
	var r BrowserExtensionsReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT dbe.name, dbe.browser, COALESCE(dbe.version,''), dbe.enabled, dbe.risk_level,
		       dbe.permissions, dbe.host_permissions,
		       COUNT(DISTINCT dbe.device_id)::int AS device_count
		FROM device_browser_extensions dbe
		JOIN devices d ON d.id = dbe.device_id
		WHERE d.tenant_id = $1
		GROUP BY dbe.name, dbe.browser, dbe.version, dbe.enabled, dbe.risk_level,
		         dbe.permissions, dbe.host_permissions
		ORDER BY dbe.risk_level DESC, device_count DESC
		LIMIT 100
	`, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return r, nil
		}
		return r, fmt.Errorf("fetch browser extensions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ext BrowserExtRow
		var permBytes, hostPermBytes []byte
		if err := rows.Scan(&ext.Name, &ext.Browser, &ext.Version, &ext.Enabled, &ext.RiskLevel,
			&permBytes, &hostPermBytes, &ext.DeviceCount); err != nil {
			return r, fmt.Errorf("scan browser extension: %w", err)
		}
		if len(permBytes) > 0 {
			_ = json.Unmarshal(permBytes, &ext.Permissions)
		}
		if len(hostPermBytes) > 0 {
			_ = json.Unmarshal(hostPermBytes, &ext.HostPermissions)
		}
		r.Extensions = append(r.Extensions, ext)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	for _, ext := range r.Extensions {
		if strings.EqualFold(ext.RiskLevel, "elevated") {
			r.ElevatedCount++
		}
	}

	return r, nil
}

// TenantBrowserExtensionDevice is one device's install of an extension, for
// the admin JSON API's per-extension drill-down.
type TenantBrowserExtensionDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Enabled  bool   `json:"enabled"`
	OS       string `json:"os"`
}

// TenantBrowserExtension is one extension aggregated across a tenant's
// fleet, keyed by (extension_id, browser). Distinct from BrowserExtRow
// (used by the PDF report), which groups more finely and has no
// per-device breakdown.
type TenantBrowserExtension struct {
	ID          string                         `json:"id"`
	Name        string                         `json:"name"`
	Browser     string                         `json:"browser"`
	Version     string                         `json:"version"`
	Enabled     bool                           `json:"enabled"`
	RiskLevel   string                         `json:"risk_level"`
	DeviceCount int                            `json:"device_count"`
	Devices     []TenantBrowserExtensionDevice `json:"devices"`
}

// TenantBrowserExtensionsResponse is the GET /admin/tenants/{id}/browser-extensions
// response contract expected by the dashboard console (templates/console.html,
// PAT-371's _bxActivate/_bxRender).
type TenantBrowserExtensionsResponse struct {
	TenantID   string                   `json:"tenant_id"`
	Total      int                      `json:"total"`
	Extensions []TenantBrowserExtension `json:"extensions"`
}

// FetchTenantBrowserExtensions returns the per-extension, per-device browser
// extension inventory for a tenant, for the admin JSON API (PAT-561).
//
// device_browser_extensions.risk_level only has two tiers today ('normal' /
// 'elevated' — see migration 0018), but the frontend's risk chip is
// high/medium/low. We map elevated -> "high" and normal -> "low"; a "medium"
// tier can be added on both sides together if the risk classifier ever grows
// a third bucket.
func FetchTenantBrowserExtensions(ctx context.Context, pool *pgxpool.Pool, tenantID string) (TenantBrowserExtensionsResponse, error) {
	var resp TenantBrowserExtensionsResponse
	resp.TenantID = tenantID
	resp.Extensions = []TenantBrowserExtension{}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)`, tenantID).Scan(&exists); err != nil {
		return resp, fmt.Errorf("check tenant: %w", err)
	}
	if !exists {
		return resp, ErrTenantNotFound
	}

	rows, err := pool.Query(ctx, `
		SELECT
		    dbe.extension_id,
		    MAX(dbe.name)                                                  AS name,
		    dbe.browser,
		    MAX(COALESCE(dbe.version, ''))                                 AS version,
		    BOOL_OR(dbe.enabled)                                           AS enabled,
		    CASE WHEN BOOL_OR(dbe.risk_level = 'elevated')
		         THEN 'high' ELSE 'low' END                                AS risk_level,
		    COUNT(DISTINCT dbe.device_id)::int                             AS device_count,
		    jsonb_agg(jsonb_build_object(
		        'device_id', dbe.device_id,
		        'hostname',  COALESCE(d.hostname, d.serial, dbe.device_id::text),
		        'version',   COALESCE(dbe.version, ''),
		        'enabled',   dbe.enabled,
		        'os',        COALESCE(d.os_version, '')
		    ) ORDER BY d.hostname)                                         AS devices
		FROM device_browser_extensions dbe
		JOIN devices d ON d.id = dbe.device_id
		WHERE d.tenant_id = $1
		GROUP BY dbe.extension_id, dbe.browser
		ORDER BY device_count DESC, name ASC
	`, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return resp, nil
		}
		return resp, fmt.Errorf("fetch tenant browser extensions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ext TenantBrowserExtension
		var devicesBytes []byte
		if err := rows.Scan(
			&ext.ID, &ext.Name, &ext.Browser, &ext.Version, &ext.Enabled, &ext.RiskLevel,
			&ext.DeviceCount, &devicesBytes,
		); err != nil {
			return resp, fmt.Errorf("scan tenant browser extension: %w", err)
		}
		if len(devicesBytes) > 0 {
			if err := json.Unmarshal(devicesBytes, &ext.Devices); err != nil {
				return resp, fmt.Errorf("decode devices for extension %s: %w", ext.ID, err)
			}
		}
		resp.Extensions = append(resp.Extensions, ext)
	}
	if err := rows.Err(); err != nil {
		return resp, err
	}

	resp.Total = len(resp.Extensions)
	return resp, nil
}
