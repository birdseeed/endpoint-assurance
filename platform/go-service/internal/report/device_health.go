package report

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Flag thresholds decided on PAT-684/PAT-686: battery below 70% health,
// under 10 GB free disk, or any non-Verified SMART status flags the device.
const (
	batteryFlagMaxCapacityPct = 70
	storageFlagFreeBytes      = int64(10) << 30 // 10 GiB
)

// DeviceHealthRow holds health data for one device.
type DeviceHealthRow struct {
	Hostname              string
	OS                    string
	BatteryCondition      *string
	BatteryCycleCount     *int
	BatteryMaxCapacityPct *int
	StorageUsedPct        *int
	StorageFreeBytes      *int64
	SMARTStatus           *string
}

// DeviceHealthReport contains device health data for a tenant.
type DeviceHealthReport struct {
	GeneratedAt time.Time
	Tenant      string
	Devices     []DeviceHealthRow
	Attention   []DeviceHealthRow
}

// FetchDeviceHealthReport fetches device health data for a tenant.
// If hardware tables don't exist, returns empty data.
func FetchDeviceHealthReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (DeviceHealthReport, error) {
	var r DeviceHealthReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT COALESCE(d.hostname,'—'), COALESCE(d.os,''),
		       dh.battery_condition, dh.battery_cycle_count, dh.battery_max_capacity_pct,
		       sv.used_pct, sv.free_bytes, dsk.smart_status
		FROM devices d
		LEFT JOIN device_hardware dh ON dh.device_id = d.id
		LEFT JOIN device_storage_volume sv ON sv.device_hardware_id = dh.id AND sv.mount IN ('/', 'C:\')
		LEFT JOIN device_disk dsk ON dsk.device_hardware_id = dh.id AND dsk.internal = true
		WHERE d.tenant_id = $1
		ORDER BY d.hostname
	`, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return r, nil
		}
		return r, fmt.Errorf("fetch device health: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dev DeviceHealthRow
		if err := rows.Scan(&dev.Hostname, &dev.OS,
			&dev.BatteryCondition, &dev.BatteryCycleCount, &dev.BatteryMaxCapacityPct,
			&dev.StorageUsedPct, &dev.StorageFreeBytes, &dev.SMARTStatus); err != nil {
			return r, fmt.Errorf("scan device health: %w", err)
		}
		r.Devices = append(r.Devices, dev)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	for _, dev := range r.Devices {
		if DeviceNeedsAttention(dev) {
			r.Attention = append(r.Attention, dev)
		}
	}

	return r, nil
}

// DeviceNeedsAttention applies the PAT-684/PAT-686 flag thresholds: battery
// condition not Normal/Good OR health below 70%, any non-Verified SMART
// status, or under 10 GB free disk (falling back to >85% used when the
// volume's free_bytes is unreported).
func DeviceNeedsAttention(dev DeviceHealthRow) bool {
	if dev.BatteryCondition != nil {
		bc := *dev.BatteryCondition
		if bc != "" && bc != "Normal" && bc != "Good" {
			return true
		}
	}
	if dev.BatteryMaxCapacityPct != nil && *dev.BatteryMaxCapacityPct > 0 &&
		*dev.BatteryMaxCapacityPct < batteryFlagMaxCapacityPct {
		return true
	}
	if dev.SMARTStatus != nil && *dev.SMARTStatus != "" && *dev.SMARTStatus != "Verified" {
		return true
	}
	if dev.StorageFreeBytes != nil {
		if *dev.StorageFreeBytes < storageFlagFreeBytes {
			return true
		}
	} else if dev.StorageUsedPct != nil && *dev.StorageUsedPct > 85 {
		return true
	}
	return false
}
