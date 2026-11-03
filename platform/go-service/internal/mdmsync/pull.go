package mdmsync

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/msgraph"
)

// PullResult summarises one PullTenant run.
type PullResult struct {
	EntraSnapshotID    string
	IntuneSnapshotID   string
	EntraDeviceCount   int
	ManagedDeviceCount int
	Joined             []JoinedDevice
}

// PullTenant fetches both sides of the device ledger for one tenant
// (Entra device objects and Intune managed devices), pages each to
// exhaustion, persists a new timestamped snapshot of each (raw body +
// parsed rows), computes the join between them, and persists the join
// result. Every call inserts new rows; it never mutates a previous
// snapshot, so re-running this is safe and keeps full history.
//
// This is a plain callable function, not a scheduled job. There is no
// delta query for /deviceManagement/managedDevices, so callers should run
// this as a full pull on a daily cadence.
//
// TODO(PAT-1654 follow-up): wire this into a scheduler/cron. Deliberately
// out of scope here per the ticket brief — a scheduling mechanism should
// not be invented as a side effect of this ticket.
func PullTenant(ctx context.Context, client *msgraph.Client, pool *pgxpool.Pool, tenant msgraph.TenantConfig) (*PullResult, error) {
	if err := tenant.Validate(); err != nil {
		return nil, fmt.Errorf("mdmsync: invalid tenant config: %w", err)
	}

	entraRaw, entraDevices, err := FetchEntraDevices(ctx, client, tenant.TenantID)
	if err != nil {
		return nil, err
	}
	entraSnapshotID, err := SaveEntraSnapshot(ctx, pool, tenant.TenantID, entraRaw, entraDevices)
	if err != nil {
		return nil, err
	}

	managedRaw, managedDevices, err := FetchManagedDevices(ctx, client, tenant.TenantID)
	if err != nil {
		return nil, err
	}
	intuneSnapshotID, err := SaveManagedSnapshot(ctx, pool, tenant.TenantID, managedRaw, managedDevices)
	if err != nil {
		return nil, err
	}

	joined := JoinDevices(entraDevices, managedDevices)
	if err := SaveJoinResults(ctx, pool, tenant.TenantID, entraSnapshotID, intuneSnapshotID, joined); err != nil {
		return nil, err
	}

	return &PullResult{
		EntraSnapshotID:    entraSnapshotID,
		IntuneSnapshotID:   intuneSnapshotID,
		EntraDeviceCount:   len(entraDevices),
		ManagedDeviceCount: len(managedDevices),
		Joined:             joined,
	}, nil
}
