// Package mdmsync pulls both sides of the device ledger from Microsoft
// Graph — Entra device objects and Intune managed devices (PAT-1654) — and
// persists them per tenant as timestamped, append-only snapshots, plus the
// computed join between them.
//
// This package has no scheduling opinion: PullTenant is a plain function a
// later ticket wires to a daily cron/timer (there is no delta query for
// /deviceManagement/managedDevices, so every pull is a full pull). It also
// carries no per-tenant secret: auth is entirely the msgraph package's
// certificate-based app-only token flow (PAT-1653) against the Entra
// tenant id in msgraph.TenantConfig.
package mdmsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"patched.im/api/internal/msgraph"
)

// entraDeviceSelect and managedDeviceSelect are the exact $select field
// lists from the PAT-1654 brief. Keeping them narrow keeps payloads small —
// there is no delta query for managedDevices, so every pull is a full pull
// of every device in the tenant.
var (
	entraDeviceSelect = []string{
		"deviceId",
		"displayName",
		"operatingSystem",
		"operatingSystemVersion",
		"approximateLastSignInDateTime",
		"accountEnabled",
		"trustType",
		"isManaged",
	}
	managedDeviceSelect = []string{
		"id",
		"azureADDeviceId",
		"deviceName",
		"operatingSystem",
		"osVersion",
		"lastSyncDateTime",
		"enrolledDateTime",
		"complianceState",
		"managedDeviceOwnerType",
		"managementAgent",
		"deviceRegistrationState",
	}
)

func selectQuery(fields []string) url.Values {
	joined := ""
	for i, f := range fields {
		if i > 0 {
			joined += ","
		}
		joined += f
	}
	return url.Values{"$select": {joined}}
}

// FetchEntraDevices pulls every Entra device object for tenantID, paging to
// exhaustion via the shared msgraph.Client. It returns both the raw items
// exactly as Graph returned them (for archival) and the parsed rows.
func FetchEntraDevices(ctx context.Context, client *msgraph.Client, tenantID string) ([]json.RawMessage, []EntraDevice, error) {
	raw, err := client.GetAll(ctx, tenantID, "/devices", selectQuery(entraDeviceSelect))
	if err != nil {
		return nil, nil, fmt.Errorf("mdmsync: fetch entra devices: %w", err)
	}
	devices := make([]EntraDevice, 0, len(raw))
	for _, item := range raw {
		var d EntraDevice
		if err := json.Unmarshal(item, &d); err != nil {
			return nil, nil, fmt.Errorf("mdmsync: decode entra device: %w", err)
		}
		devices = append(devices, d)
	}
	return raw, devices, nil
}

// FetchManagedDevices pulls every Intune managed device for tenantID,
// paging to exhaustion via the shared msgraph.Client. There is no delta
// query for this endpoint (it does not exist) — this is always a full pull.
func FetchManagedDevices(ctx context.Context, client *msgraph.Client, tenantID string) ([]json.RawMessage, []ManagedDevice, error) {
	raw, err := client.GetAll(ctx, tenantID, "/deviceManagement/managedDevices", selectQuery(managedDeviceSelect))
	if err != nil {
		return nil, nil, fmt.Errorf("mdmsync: fetch managed devices: %w", err)
	}
	devices := make([]ManagedDevice, 0, len(raw))
	for _, item := range raw {
		var d ManagedDevice
		if err := json.Unmarshal(item, &d); err != nil {
			return nil, nil, fmt.Errorf("mdmsync: decode managed device: %w", err)
		}
		devices = append(devices, d)
	}
	return raw, devices, nil
}
