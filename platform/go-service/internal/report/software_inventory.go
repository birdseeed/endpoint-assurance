package report

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SoftwareApp holds aggregated info about one app across the fleet.
type SoftwareApp struct {
	Name          string
	Version       string
	Signer        string
	Notarized     *bool
	DeviceCount   int
	LastUsed      *time.Time
	TotalLaunches *int
}

// SoftwareInventoryReport contains the software inventory for a tenant.
type SoftwareInventoryReport struct {
	GeneratedAt time.Time
	Tenant      string
	Apps        []SoftwareApp
	UnusedApps  []SoftwareApp
}

// FetchSoftwareInventoryReport fetches the software inventory for a tenant.
func FetchSoftwareInventoryReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (SoftwareInventoryReport, error) {
	var r SoftwareInventoryReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT da.name, da.version, COALESCE(da.signer,''), da.notarized,
		       COUNT(DISTINCT da.device_id)::int AS device_count,
		       MAX(da.last_used_at) AS last_used,
		       SUM(da.launch_count)::bigint AS total_launches
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1
		GROUP BY da.name, da.version, da.signer, da.notarized
		ORDER BY device_count DESC, da.name
		LIMIT 200
	`, tenantID)
	if err != nil {
		return r, fmt.Errorf("fetch software inventory: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a SoftwareApp
		var totalLaunches *int64
		if err := rows.Scan(&a.Name, &a.Version, &a.Signer, &a.Notarized,
			&a.DeviceCount, &a.LastUsed, &totalLaunches); err != nil {
			return r, fmt.Errorf("scan software app: %w", err)
		}
		if totalLaunches != nil {
			v := int(*totalLaunches)
			a.TotalLaunches = &v
		}
		r.Apps = append(r.Apps, a)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	// UnusedApps: first 20 apps with no recorded last_used
	for _, a := range r.Apps {
		if a.LastUsed == nil {
			r.UnusedApps = append(r.UnusedApps, a)
			if len(r.UnusedApps) >= 20 {
				break
			}
		}
	}

	return r, nil
}
