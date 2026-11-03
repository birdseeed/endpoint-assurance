package report

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PatchDevice holds patching info for one device.
type PatchDevice struct {
	Hostname     string
	OS           string
	OSVersion    string
	PendingCount int
}

// PatchStatusReport contains fleet-level patching data.
type PatchStatusReport struct {
	GeneratedAt time.Time
	Tenant      string
	Patching    PatchingStats
	Devices     []PatchDevice
}

// FetchPatchStatusReport fetches patch status data for a tenant.
func FetchPatchStatusReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PatchStatusReport, error) {
	var r PatchStatusReport
	r.GeneratedAt = time.Now().UTC()

	var sw platformSwitches
	err := pool.QueryRow(ctx, `
		SELECT name, macos_enabled, windows_enabled
		FROM tenants WHERE id = $1
	`, tenantID).Scan(&r.Tenant, &sw.macOSEnabled, &sw.windowsEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	if err := fetchPatchingStats(ctx, pool, tenantID, sw, &r.Patching); err != nil {
		return r, err
	}

	osFilter := enabledOSFilter(sw)
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(d.hostname,'—'), d.os, COALESCE(d.os_version,''),
		       jsonb_array_length(d.pending_updates) AS pending_count
		FROM devices d
		WHERE d.tenant_id = $1
		  AND d.pending_updates IS NOT NULL
		  AND jsonb_array_length(d.pending_updates) > 0
		  AND `+osFilter+`
		ORDER BY pending_count DESC
	`, tenantID)
	if err != nil {
		return r, fmt.Errorf("fetch patch devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d PatchDevice
		if err := rows.Scan(&d.Hostname, &d.OS, &d.OSVersion, &d.PendingCount); err != nil {
			return r, fmt.Errorf("scan patch device: %w", err)
		}
		r.Devices = append(r.Devices, d)
	}
	return r, rows.Err()
}
