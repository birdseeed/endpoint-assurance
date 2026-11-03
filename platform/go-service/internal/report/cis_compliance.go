package report

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CISComplianceReport aggregates CIS compliance data for the tenant.
type CISComplianceReport struct {
	GeneratedAt  time.Time
	Tenant       string
	Estate       EstateStats
	Compliance   ComplianceStats
	TopFailing   []TopFailingControl
	WorstDevices []WorstDevice
}

// FetchCISComplianceReport fetches the CIS compliance data for a tenant.
func FetchCISComplianceReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (CISComplianceReport, error) {
	var r CISComplianceReport
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

	if err := fetchEstateStats(ctx, pool, tenantID, sw, &r.Estate); err != nil {
		return r, err
	}
	if err := fetchComplianceStats(ctx, pool, tenantID, sw, &r.Compliance); err != nil {
		return r, err
	}

	// fetchTopFailingControls appends to sum.TopFailing; use a proxy struct.
	proxy := &ExecutiveSummary{}
	if err := fetchTopFailingControls(ctx, pool, tenantID, sw, proxy); err != nil {
		return r, err
	}
	r.TopFailing = proxy.TopFailing

	if err := fetchWorstDevices(ctx, pool, tenantID, sw, &r.WorstDevices); err != nil {
		return r, err
	}

	return r, nil
}
