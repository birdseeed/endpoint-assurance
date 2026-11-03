package report

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/deviceretirement"
)

// StaleDevice represents one endpoint that hasn't checked in recently.
type StaleDevice struct {
	Hostname  string
	OS        string
	OSVersion string
	LastSeen  time.Time
	DaysSince float64
}

// RetiredDevice is a device the customer has retired (PAT-2135). It is
// listed apart from the stale endpoints, never counted among them.
type RetiredDevice struct {
	Hostname                string
	OS                      string
	LastSeen                time.Time
	RetiredAt               time.Time
	RetiredBy               string
	ReportedAfterRetirement bool
}

// StaleEndpointsReport contains the list of stale endpoints for a tenant.
type StaleEndpointsReport struct {
	GeneratedAt   time.Time
	Tenant        string
	ThresholdDays int
	Devices       []StaleDevice
	// Retired are the tenant's retired devices, whether or not they would
	// otherwise be stale. None of them is in Devices.
	Retired []RetiredDevice
}

// FetchStaleEndpointsReport fetches endpoints that haven't been seen within
// thresholdDays days.
func FetchStaleEndpointsReport(ctx context.Context, pool *pgxpool.Pool, tenantID string, thresholdDays int) (StaleEndpointsReport, error) {
	var r StaleEndpointsReport
	r.GeneratedAt = time.Now().UTC()
	r.ThresholdDays = thresholdDays

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT COALESCE(hostname,'—'), os, COALESCE(os_version,''),
		       last_seen,
		       EXTRACT(EPOCH FROM (now() - last_seen))/86400.0 AS days_since
		FROM devices d
		WHERE d.tenant_id = $1
		  AND d.last_seen < now() - ($2::int * interval '1 day')
		  AND NOT `+deviceretirement.RetiredSQL("d")+`
		ORDER BY d.last_seen
	`, tenantID, thresholdDays)
	if err != nil {
		return r, fmt.Errorf("fetch stale endpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d StaleDevice
		if err := rows.Scan(&d.Hostname, &d.OS, &d.OSVersion, &d.LastSeen, &d.DaysSince); err != nil {
			return r, fmt.Errorf("scan stale device: %w", err)
		}
		r.Devices = append(r.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	rows.Close()

	retired, err := deviceretirement.Fetch(ctx, pool, tenantID, nil)
	if err != nil {
		return r, err
	}
	if len(retired) == 0 {
		return r, nil
	}
	ids := make([]string, 0, len(retired))
	for id := range retired {
		ids = append(ids, id)
	}
	rrows, err := pool.Query(ctx, `
		SELECT id::text, COALESCE(hostname,'—'), os, last_seen
		FROM devices WHERE tenant_id = $1 AND id = ANY($2::uuid[])
	`, tenantID, ids)
	if err != nil {
		return r, fmt.Errorf("fetch retired endpoints: %w", err)
	}
	defer rrows.Close()
	for rrows.Next() {
		var id string
		var d RetiredDevice
		if err := rrows.Scan(&id, &d.Hostname, &d.OS, &d.LastSeen); err != nil {
			return r, fmt.Errorf("scan retired device: %w", err)
		}
		ret := retired[id]
		d.RetiredAt, d.RetiredBy, d.ReportedAfterRetirement = ret.RetiredAt, ret.RetiredBy, ret.ReportedAfterRetirement
		r.Retired = append(r.Retired, d)
	}
	if err := rrows.Err(); err != nil {
		return r, err
	}
	sort.Slice(r.Retired, func(i, j int) bool {
		if !r.Retired[i].RetiredAt.Equal(r.Retired[j].RetiredAt) {
			return r.Retired[i].RetiredAt.Before(r.Retired[j].RetiredAt)
		}
		return r.Retired[i].Hostname < r.Retired[j].Hostname
	})
	return r, nil
}
