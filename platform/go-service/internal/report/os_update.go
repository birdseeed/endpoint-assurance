package report

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OSUpdateStatus is the tenant-level OS-update-currency rollup (PAT-1806).
// Both endpoint agents compute this verdict locally (SOFA feed on macOS, WUA
// COM on Windows) and both send it as the payload's os_update block: the
// Windows agent on every run it produces a verdict, the macOS agent when its
// local update-status.json block is contract-valid and no more than 48 hours
// old (updater macos/patched-upload.sh, patched_os_update_merge_into_payload).
// A device whose agent sent no block, for any of those reasons, has no
// device_os_update row and lands in DevicesNotReported.
//
// Four buckets, deliberately not three: folding "never reported" into either
// "current" or "behind" would misstate the estate one way or the other. A
// device that has never sent an os_update block is unknown, not current —
// the same absence-requires-authority discipline PAT-1805 established for
// devices.pending_updates (a NULL patching state must never read as
// up to date). The same goes for a device whose agent sent a verdict this
// server cannot act on: "unknown" (the agent could not tell) or a state
// outside the vocabulary (PAT-2295). Those land in DevicesNotReported too,
// exactly as the customer portal roster reports them (osUpdatePatchPending,
// through the shared classifyOSUpdateState), so the staff rollup and the
// customer view cannot disagree about one device. DevicesBehindSecurityRelevant
// is a subset of DevicesBehind, not an additional population, reported
// separately because "how many of the behind devices actually need urgent
// attention" is the number that drives action.
type OSUpdateStatus struct {
	GeneratedAt time.Time
	Tenant      string

	DevicesCurrent                int
	DevicesBehind                 int
	DevicesBehindSecurityRelevant int // subset of DevicesBehind
	DevicesNotReported            int
}

// osUpdateVerdict is what the server is willing to say about a device from
// the state string its agent stored in device_os_update.state.
type osUpdateVerdict int

const (
	// osUpdateNoClaim: the agent said it could not tell, or sent a state this
	// server does not recognise. Neither is a statement about the device, and
	// a state added by a later agent release must not be read as pending or
	// current until it is mapped in osUpdateStates (absence requires
	// authority, root AGENTS.md).
	osUpdateNoClaim osUpdateVerdict = iota
	// osUpdateCurrent: the agent says the device is up to date.
	osUpdateCurrent
	// osUpdatePending: the agent says an update is outstanding.
	osUpdatePending
)

// osUpdateStates is the one place the agents' state vocabulary is
// interpreted (updater contracts/update-status.schema.json). Both readers of
// device_os_update.state go through it: the tenant rollup
// (FetchOSUpdateStatus) and the portal roster (osUpdatePatchPending). Adding
// a state to the contract means adding a row here, and only here.
//
// Matching is exact and case-sensitive, and the column stores what the agent
// sent verbatim (migration 0144), so "Up_To_Date" is not "up_to_date".
// "unknown" is listed only to document the contract; anything not listed is
// treated the same way.
var osUpdateStates = []struct {
	state   string
	verdict osUpdateVerdict
}{
	{"up_to_date", osUpdateCurrent},
	{"update_recommended", osUpdatePending},
	{"update_required", osUpdatePending},
	{"deadline_passed", osUpdatePending},
	{"unsupported_hardware", osUpdatePending},
	{"unknown", osUpdateNoClaim},
}

// classifyOSUpdateState maps a stored state string onto what the server may
// claim about the device. Anything outside osUpdateStates is osUpdateNoClaim.
func classifyOSUpdateState(state string) osUpdateVerdict {
	for _, e := range osUpdateStates {
		if e.state == state {
			return e.verdict
		}
	}
	return osUpdateNoClaim
}

// osUpdateStatesFor lists the recognised states that carry the given verdict,
// in osUpdateStates order. It exists so SQL can filter on the same vocabulary
// classifyOSUpdateState uses instead of repeating the strings.
func osUpdateStatesFor(v osUpdateVerdict) []string {
	var out []string
	for _, e := range osUpdateStates {
		if e.verdict == v {
			out = append(out, e.state)
		}
	}
	return out
}

// FetchOSUpdateStatus computes the four-bucket OS-update-currency rollup for
// one tenant. Devices whose platform is disabled for the tenant are excluded
// (enabledOSFilter — same convention every other executive-summary fetcher
// in this package uses). Read-only; no DB writes. Returns ErrTenantNotFound
// when the tenant ID doesn't resolve.
func FetchOSUpdateStatus(ctx context.Context, pool *pgxpool.Pool, tenantID string) (OSUpdateStatus, error) {
	var s OSUpdateStatus
	s.GeneratedAt = time.Now().UTC()

	var sw platformSwitches
	err := pool.QueryRow(ctx, `
		SELECT name, macos_enabled, windows_enabled
		FROM tenants WHERE id = $1
	`, tenantID).Scan(&s.Tenant, &sw.macOSEnabled, &sw.windowsEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return s, ErrTenantNotFound
		}
		return s, fmt.Errorf("fetch tenant: %w", err)
	}

	// current   = the device HAS a device_os_update row and its state is
	//             exactly "up_to_date", with a fresh verdict.
	// behind    = the device HAS a row and its state is one the agents' contract
	//             says has an update outstanding (osUpdatePending), fresh.
	// behind + security_relevant = the security-relevant subset of behind.
	// not_reported = everything else the server cannot make a claim from: no
	//             device_os_update row at all (this device has never sent an
	//             os_update block), a state of "unknown", or a state outside
	//             the vocabulary (PAT-2295), or stale evidence (PAT-2338).
	//             Never folded into "current" or "behind". A future agent release adding a state is not
	//             counted as behind until it is mapped in osUpdateStates.
	//
	// The state lists are bound as parameters from osUpdateStates, the same
	// table the portal roster uses. The freshness gate mirrors
	// osUpdatePatchPending: checked_at capped at receipt, legacy NULL checked_at
	// falls back to receipt, and the same seven-day window applies.
	osFilter := enabledOSFilter(sw)
	err = pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE dou.state = ANY($2::text[]) AND `+osFilter+`)::int AS current,
			COUNT(*) FILTER (WHERE dou.state = ANY($3::text[]) AND `+osFilter+`)::int AS behind,
			COUNT(*) FILTER (WHERE dou.state = ANY($3::text[]) AND dou.security_relevant AND `+osFilter+`)::int AS behind_security,
			COUNT(*) FILTER (WHERE (dou.state IS NULL OR dou.state <> ALL($2::text[] || $3::text[])) AND `+osFilter+`)::int AS not_reported
		FROM devices d
		LEFT JOIN device_os_update dou ON dou.device_id = d.id
			AND LEAST(COALESCE(dou.checked_at, dou.reported_at), dou.reported_at) >= $4
		WHERE d.tenant_id = $1
	`, tenantID, osUpdateStatesFor(osUpdateCurrent), osUpdateStatesFor(osUpdatePending), s.GeneratedAt.Add(-portalEvidenceStaleAfter),
	).Scan(&s.DevicesCurrent, &s.DevicesBehind, &s.DevicesBehindSecurityRelevant, &s.DevicesNotReported)
	if err != nil {
		return s, fmt.Errorf("os update status: %w", err)
	}

	return s, nil
}
