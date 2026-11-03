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

	"patched.im/api/internal/protectedsoftware"
)

// EDRState is the coverage state FetchEDRCoverageReport assigns to a single
// device. Exactly one of the three applies — see FetchEDRCoverageReport.
//
// PAT-2226: security_tools carries no completeness marker (see
// docs/PAYLOAD_SCHEMA.md's Security tools array — each element is just an
// id and a name), so an absent or empty list proves nothing about a device.
// Root AGENTS.md's "Absence requires authority" Hard Constraint means this
// report must never claim a device lacks EDR on that basis. Before this
// fix, every device whose reported tool didn't match one of three hardcoded
// substrings (crowdstrike/sentinelone/defender) was counted as
// "WithoutEDR" — a device genuinely running Sophos, Bitdefender, ESET,
// Jamf Protect or Huntress was told it had no EDR. There is no such state
// any more: a device is either covered (recognised), unrecognised (evidence
// was reported but didn't match anything on the protected list), or unknown
// (no evidence at all).
type EDRState string

const (
	// EDRStateCovered: at least one reported security tool matched a
	// protected_software row (category edr or security) visible to this
	// tenant — the shared baseline plus the tenant's own additions.
	EDRStateCovered EDRState = "covered"
	// EDRStateUnrecognised: security_tools carried one or more entries, but
	// none matched a protected_software edr/security row.
	EDRStateUnrecognised EDRState = "unrecognised"
	// EDRStateUnknown: no security_tools evidence was reported at all
	// (security_inventory null/absent, no security_tools key, or an empty
	// array).
	EDRStateUnknown EDRState = "unknown"
)

// EDRDevice holds EDR coverage info for one device.
type EDRDevice struct {
	// DeviceID is devices.id, so a per-device consumer (the CE readiness
	// read model, PAT-1927) can join on it rather than on a hostname.
	DeviceID string
	Hostname string
	OS       string
	State    EDRState
	// Tools holds the raw security_tools[].name values as reported by the
	// collector, so the customer can see exactly what was found — including
	// on an unrecognised device, where this is the whole point: showing
	// what to go and add to the protected list. Empty when State is
	// EDRStateUnknown.
	Tools []string
}

// EDRCoverageReport contains EDR coverage data for a tenant.
type EDRCoverageReport struct {
	GeneratedAt  time.Time
	Tenant       string
	Devices      []EDRDevice
	TotalDevices int
	Covered      int
	Unrecognised int
	Unknown      int
	// CoveragePct is Covered / TotalDevices * 100. Unrecognised and Unknown
	// devices are not folded into it in either direction — they are
	// reported as their own counts alongside it.
	CoveragePct float64
}

// edrCategories are the protected_software categories that count as EDR
// coverage for this report. mdm/backup/patched_agent/customer_defined rows
// exist in the same table for other governance purposes (PAT-1801) and must
// never mark a device "covered" here just because something matched.
var edrCategories = map[string]bool{"edr": true, "security": true}

// FetchEDRCoverageReport fetches EDR coverage data for a tenant.
func FetchEDRCoverageReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (EDRCoverageReport, error) {
	var r EDRCoverageReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname,'(no hostname)'), d.os,
		       COALESCE(d.security_inventory, '{}'::jsonb)
		FROM devices d
		WHERE d.tenant_id = $1
		ORDER BY d.hostname
	`, tenantID)
	if err != nil {
		return r, fmt.Errorf("fetch edr coverage: %w", err)
	}
	defer rows.Close()

	// secInvObj is the correct shape of devices.security_inventory — an object,
	// not a top-level array. See extractor/upsert.go and migration 0002.
	type secInvObj struct {
		SecurityTools []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"security_tools"`
	}

	for rows.Next() {
		var dev EDRDevice
		var secInvBytes []byte
		// devices.os is nullable; an absent OS reads as "", as in the
		// device health and tooling reports (PAT-2538).
		var osName *string
		if err := rows.Scan(&dev.DeviceID, &dev.Hostname, &osName, &secInvBytes); err != nil {
			return r, fmt.Errorf("scan edr device: %w", err)
		}
		dev.OS = derefOrEmpty(osName)

		var inv secInvObj
		if len(secInvBytes) > 0 {
			_ = json.Unmarshal(secInvBytes, &inv)
		}

		covered := false
		for _, t := range inv.SecurityTools {
			name := strings.TrimSpace(t.Name)
			if name != "" {
				dev.Tools = append(dev.Tools, name)
			}
			if covered {
				// Still record every reported tool name above for display,
				// but no need to keep querying once one match is found.
				continue
			}
			matched, err := edrToolMatches(ctx, pool, tenantID, t.ID, name)
			if err != nil {
				return r, fmt.Errorf("match security tool: %w", err)
			}
			if matched {
				covered = true
			}
		}

		switch {
		case covered:
			dev.State = EDRStateCovered
		case len(dev.Tools) > 0:
			dev.State = EDRStateUnrecognised
		default:
			dev.State = EDRStateUnknown
		}

		r.Devices = append(r.Devices, dev)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	r.TotalDevices = len(r.Devices)
	for _, d := range r.Devices {
		switch d.State {
		case EDRStateCovered:
			r.Covered++
		case EDRStateUnrecognised:
			r.Unrecognised++
		default:
			r.Unknown++
		}
	}
	if r.TotalDevices > 0 {
		r.CoveragePct = float64(r.Covered) / float64(r.TotalDevices) * 100.0
	}

	return r, nil
}

// edrToolMatches reports whether one reported security tool (its stable
// agent id and display name) matches a protected_software row with
// category edr or security, visible to tenantID — the shared baseline plus
// the tenant's own additions, minus any tenant override of a baseline row.
//
// PAT-2268: this calls protectedsoftware.CheckAgentSecurityTool, the single
// authoritative id-then-name resolver, rather than matching on name alone.
// An agent's display name can legitimately differ from the baseline row's
// product_name for the same product (the macOS/Windows agents report
// "Sophos Endpoint"; the baseline row is "Sophos Intercept X"), so name-only
// matching told real, baseline-covered devices they were unrecognised. Do
// not add a second id/name matcher here or anywhere else that reads
// security_tools — extend protectedsoftware.AgentToolBaselineProductName
// instead, so every caller resolves the same way.
//
// A match against a non-edr/security category (mdm, backup, patched_agent,
// customer_defined) is not treated as EDR coverage — it means the reported
// name happens to also identify something else the tenant protects, not
// that the device has EDR.
func edrToolMatches(ctx context.Context, q protectedsoftware.Querier, tenantID, id, name string) (bool, error) {
	match, err := protectedsoftware.CheckAgentSecurityTool(ctx, q, tenantID, id, name)
	if err != nil {
		return false, err
	}
	return match != nil && edrCategories[match.Category], nil
}
