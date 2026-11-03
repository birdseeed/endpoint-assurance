package report

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantDecommissionDirective is the tenant-wide agent-decommission directive
// (PAT-1108) as currently stored, for the admin read surface. Absence of a
// tenant_decommission row is reported as the same inert mode="none" shape a
// stored none row would produce — the caller does not need to distinguish
// "never set" from "explicitly set to none".
type TenantDecommissionDirective struct {
	TenantID  string  `json:"tenant_id"`
	Mode      string  `json:"mode"`
	ExpiresAt *string `json:"expires_at"`
	Purge     bool    `json:"purge"`
	Reason    *string `json:"reason"`
	SetBy     string  `json:"set_by"`
	SetAt     string  `json:"set_at"`
}

// FetchTenantDecommissionDirective returns the tenant's current decommission
// directive, defaulting to mode="none" when no tenant_decommission row exists.
// Returns ErrTenantNotFound when the tenant ID doesn't resolve, same contract
// as FetchTenantAgentHealth.
//
// pool is anything with QueryRow: a *pgxpool.Pool, or a pgx.Tx when the
// caller is already inside a transaction and must not take a second pooled
// connection (PAT-2407, the portal enrolment-token mint).
func FetchTenantDecommissionDirective(ctx context.Context, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, tenantID string) (TenantDecommissionDirective, error) {
	var resp TenantDecommissionDirective
	resp.TenantID = tenantID

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID).Scan(&exists); err != nil {
		return resp, fmt.Errorf("check tenant: %w", err)
	}
	if !exists {
		return resp, ErrTenantNotFound
	}

	var mode *string
	var expiresAt *time.Time
	var purge *bool
	var reason *string
	var setBy *string
	var setAt *time.Time
	err := pool.QueryRow(ctx, `
		SELECT mode, expires_at, purge, reason, set_by, set_at
		FROM tenant_decommission
		WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&mode, &expiresAt, &purge, &reason, &setBy, &setAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No directive ever set for this tenant — the safe/inert default,
			// same contract as an explicit mode="none" row.
			resp.Mode = "none"
			return resp, nil
		}
		return resp, fmt.Errorf("fetch tenant decommission: %w", err)
	}

	if mode != nil {
		resp.Mode = *mode
	}
	if expiresAt != nil {
		s := expiresAt.UTC().Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	if purge != nil {
		resp.Purge = *purge
	}
	resp.Reason = reason
	if setBy != nil {
		resp.SetBy = *setBy
	}
	if setAt != nil {
		resp.SetAt = setAt.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

// TenantDecommissionDeviceEntry is one device's decommission state, for the
// admin per-device read surface.
type TenantDecommissionDeviceEntry struct {
	DeviceID            string  `json:"device_id"`
	Hostname            string  `json:"hostname"`
	Status              string  `json:"status"` // pending | acknowledged | removed | failed | expired_unreachable
	LastReportedOutcome string  `json:"last_reported_outcome"`
	LastReportedAt      *string `json:"last_reported_at"`

	// TerminalWithoutAcknowledgement is PAT-1108 fifth-round finding P1-E:
	// true when Status is a terminal outcome (removed/failed/expired_unreachable)
	// that was accepted with NO observed "acknowledged" (phase 1) report for
	// its directive_version — device_decommission_state.phase1_observed is
	// false. The server never rejects such a report (see
	// AgentDecommissionStatusHandler's package doc comment for why — a
	// genuine last word must never be discarded just because an earlier
	// acknowledged report was lost in transit), but a manufactured or
	// short-circuited removal should not be indistinguishable from a clean
	// two-phase one, so this surfaces it for operator review instead.
	// Always false for a non-terminal status (pending/acknowledged) — there
	// is no terminal outcome yet to be anomalous about.
	TerminalWithoutAcknowledgement bool `json:"terminal_without_acknowledgement"`
}

// TenantDecommissionDevicesResponse is the GET
// /admin/tenants/{tenantID}/decommission/devices response contract (PAT-1108).
type TenantDecommissionDevicesResponse struct {
	TenantID string                          `json:"tenant_id"`
	Total    int                             `json:"total"`
	Devices  []TenantDecommissionDeviceEntry `json:"devices"`
}

// FetchTenantDecommissionDevices returns per-device decommission state for
// every device belonging to the tenant, INCLUDING devices that have never
// reported any status. This is the "12 of 40 removed, 28 pending" query: it
// LEFT JOINs FROM devices (never an INNER JOIN from device_decommission_state),
// so a device with no row at all is still counted, with its status defaulted
// to 'pending' via COALESCE. Returns ErrTenantNotFound when the tenant ID
// doesn't resolve.
func FetchTenantDecommissionDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string) (TenantDecommissionDevicesResponse, error) {
	var resp TenantDecommissionDevicesResponse
	resp.TenantID = tenantID
	resp.Devices = []TenantDecommissionDeviceEntry{}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID).Scan(&exists); err != nil {
		return resp, fmt.Errorf("check tenant: %w", err)
	}
	if !exists {
		return resp, ErrTenantNotFound
	}

	// PAT-1108 finding 5: a device_decommission_state row is only meaningful
	// against the directive it was reported for. dds.directive_version <
	// td.directive_version means the row describes an EARLIER directive
	// (the tenant cancelled and re-issued, or issued a new one) — that
	// device has not seen the current directive at all, so it must read as
	// 'pending' (status, outcome, and last_reported_at all reset to the
	// same never-reported shape), not as a stale acknowledged/removed/failed
	// outcome left over from before. Without this, "12 of 40 removed, 28
	// pending" would incorrectly count devices against a directive that no
	// longer exists.
	rows, err := pool.Query(ctx, `
		SELECT
		    d.id::text,
		    COALESCE(d.hostname, d.serial, d.id::text) AS hostname,
		    CASE
		        WHEN dds.device_id IS NULL THEN 'pending'
		        WHEN dds.directive_version < COALESCE(td.directive_version, 0) THEN 'pending'
		        ELSE dds.status
		    END AS status,
		    CASE
		        WHEN dds.device_id IS NULL THEN ''
		        WHEN dds.directive_version < COALESCE(td.directive_version, 0) THEN ''
		        ELSE COALESCE(dds.last_reported_outcome, '')
		    END AS last_reported_outcome,
		    CASE
		        WHEN dds.device_id IS NULL THEN NULL
		        WHEN dds.directive_version < COALESCE(td.directive_version, 0) THEN NULL
		        ELSE dds.last_reported_at
		    END AS last_reported_at,
		    -- PAT-1108 fifth-round finding P1-E: only meaningful for a
		    -- CURRENT terminal outcome. A stale/absent row is already
		    -- displayed as 'pending' above (nothing terminal to flag), and a
		    -- current but non-terminal status (acknowledged) is never
		    -- anomalous by construction — see phase1_observed's column
		    -- comment (migrations/0091_agent_decommission.sql).
		    CASE
		        WHEN dds.device_id IS NULL THEN FALSE
		        WHEN dds.directive_version < COALESCE(td.directive_version, 0) THEN FALSE
		        WHEN dds.status NOT IN ('removed', 'failed', 'expired_unreachable') THEN FALSE
		        ELSE NOT dds.phase1_observed
		    END AS terminal_without_acknowledgement
		FROM devices d
		LEFT JOIN device_decommission_state dds ON dds.device_id = d.id
		LEFT JOIN tenant_decommission td ON td.tenant_id = d.tenant_id
		WHERE d.tenant_id = $1::uuid
		ORDER BY hostname
	`, tenantID)
	if err != nil {
		// Deliberately propagates rather than mapping to an empty success — an
		// unapplied migration (device_decommission_state missing) must read as
		// visibly broken, not as "zero devices decommissioning", the same
		// reasoning FetchTenantAgentHealth documents for device_agent_health.
		return resp, fmt.Errorf("fetch tenant decommission devices: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e TenantDecommissionDeviceEntry
		var lastReportedAt *time.Time
		if err := rows.Scan(&e.DeviceID, &e.Hostname, &e.Status, &e.LastReportedOutcome, &lastReportedAt, &e.TerminalWithoutAcknowledgement); err != nil {
			return resp, fmt.Errorf("scan tenant decommission device row: %w", err)
		}
		if lastReportedAt != nil {
			s := lastReportedAt.UTC().Format(time.RFC3339)
			e.LastReportedAt = &s
		}
		resp.Devices = append(resp.Devices, e)
		resp.Total++
	}
	if err := rows.Err(); err != nil {
		return resp, err
	}

	return resp, nil
}
