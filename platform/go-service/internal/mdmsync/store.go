package mdmsync

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// nullableTime returns nil for a zero time.Time so it inserts as SQL NULL
// instead of the misleading "0001-01-01" timestamp.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// SaveEntraSnapshot inserts one new msgraph_device_snapshots row (collection
// "entra_devices") plus its parsed msgraph_entra_devices rows, all in one
// transaction. It never updates a previous snapshot: every call, including
// a re-run against unchanged upstream data, produces a new snapshot id so
// history is retained.
func SaveEntraSnapshot(ctx context.Context, pool *pgxpool.Pool, tenantID string, raw []json.RawMessage, devices []EntraDevice) (snapshotID string, err error) {
	rawBody, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("mdmsync: marshal entra raw body: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("mdmsync: begin entra snapshot tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if err := tx.QueryRow(ctx,
		`INSERT INTO msgraph_device_snapshots (tenant_id, collection, record_count, raw_body)
		 VALUES ($1, 'entra_devices', $2, $3) RETURNING id`,
		tenantID, len(devices), rawBody,
	).Scan(&snapshotID); err != nil {
		return "", fmt.Errorf("mdmsync: insert entra snapshot: %w", err)
	}

	for _, d := range devices {
		if _, err := tx.Exec(ctx,
			`INSERT INTO msgraph_entra_devices
				(snapshot_id, tenant_id, device_id, display_name, operating_system,
				 operating_system_version, approximate_last_sign_in_date_time,
				 account_enabled, trust_type, is_managed)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			snapshotID, tenantID, d.DeviceID, d.DisplayName, d.OperatingSystem,
			d.OperatingSystemVersion, nullableTime(d.ApproximateLastSignInDateTime),
			d.AccountEnabled, d.TrustType, d.IsManaged,
		); err != nil {
			return "", fmt.Errorf("mdmsync: insert entra device row: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("mdmsync: commit entra snapshot: %w", err)
	}
	return snapshotID, nil
}

// SaveManagedSnapshot inserts one new msgraph_device_snapshots row
// (collection "intune_managed_devices") plus its parsed
// msgraph_intune_managed_devices rows, all in one transaction. Same
// append-only contract as SaveEntraSnapshot.
func SaveManagedSnapshot(ctx context.Context, pool *pgxpool.Pool, tenantID string, raw []json.RawMessage, devices []ManagedDevice) (snapshotID string, err error) {
	rawBody, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("mdmsync: marshal managed raw body: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("mdmsync: begin managed snapshot tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if err := tx.QueryRow(ctx,
		`INSERT INTO msgraph_device_snapshots (tenant_id, collection, record_count, raw_body)
		 VALUES ($1, 'intune_managed_devices', $2, $3) RETURNING id`,
		tenantID, len(devices), rawBody,
	).Scan(&snapshotID); err != nil {
		return "", fmt.Errorf("mdmsync: insert managed snapshot: %w", err)
	}

	for _, d := range devices {
		if _, err := tx.Exec(ctx,
			`INSERT INTO msgraph_intune_managed_devices
				(snapshot_id, tenant_id, managed_device_id, azure_ad_device_id, device_name,
				 operating_system, os_version, last_sync_date_time, enrolled_date_time,
				 compliance_state, managed_device_owner_type, management_agent,
				 device_registration_state)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			snapshotID, tenantID, d.ID, d.AzureADDeviceID, d.DeviceName,
			d.OperatingSystem, d.OSVersion, nullableTime(d.LastSyncDateTime),
			nullableTime(d.EnrolledDateTime), d.ComplianceState,
			d.ManagedDeviceOwnerType, d.ManagementAgent, d.DeviceRegistrationState,
		); err != nil {
			return "", fmt.Errorf("mdmsync: insert managed device row: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("mdmsync: commit managed snapshot: %w", err)
	}
	return snapshotID, nil
}

// SaveJoinResults persists the computed join for a (entraSnapshotID,
// intuneSnapshotID) pair, one row per JoinedDevice. Like the snapshots
// themselves, this always inserts new rows: re-running the pull records a
// new join computation rather than mutating the previous one.
func SaveJoinResults(ctx context.Context, pool *pgxpool.Pool, tenantID, entraSnapshotID, intuneSnapshotID string, joined []JoinedDevice) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("mdmsync: begin join results tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	for _, j := range joined {
		var entraDeviceID, managedDeviceID any
		if j.Entra != nil {
			entraDeviceID = j.Entra.DeviceID
		}
		if j.Managed != nil {
			managedDeviceID = j.Managed.ID
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO msgraph_device_join_results
				(tenant_id, entra_snapshot_id, intune_snapshot_id, status, join_key,
				 entra_device_id, managed_device_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			tenantID, entraSnapshotID, intuneSnapshotID, string(j.Status), j.JoinKey,
			entraDeviceID, managedDeviceID,
		); err != nil {
			return fmt.Errorf("mdmsync: insert join result row: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("mdmsync: commit join results: %w", err)
	}
	return nil
}
