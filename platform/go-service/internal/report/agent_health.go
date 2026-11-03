package report

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantAgentHealthEntry is one degraded-capability row (PAT-1064): a
// directive or capability the agent could not carry out, why, since when,
// and how many times — enough for the dashboard (PAT-1067) to render "what
// was asked, why it could not be done, since when, how many times" without a
// second call.
type TenantAgentHealthEntry struct {
	Kind          string    `json:"kind"`
	Subject       string    `json:"subject"`
	Reason        string    `json:"reason"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Count         int64     `json:"count"`
	EverSucceeded bool      `json:"ever_succeeded"`
}

// TenantAgentHealthDevice is one device's degraded-capability entries, for
// the admin JSON API's per-device grouping.
type TenantAgentHealthDevice struct {
	DeviceID string                   `json:"device_id"`
	Hostname string                   `json:"hostname"`
	Degraded []TenantAgentHealthEntry `json:"degraded"`
}

// TenantAgentHealthResponse is the GET /admin/tenants/{tenantID}/agent-health
// response contract (PAT-1064). Entries are grouped per device rather than
// per fault (unlike TenantBrowserExtensionsResponse, which groups per
// extension) because the operator question this endpoint answers is
// "which of this tenant's devices are silently failing to do what we asked,
// and how" — a device-first view.
type TenantAgentHealthResponse struct {
	TenantID string                    `json:"tenant_id"`
	Total    int                       `json:"total"`
	Devices  []TenantAgentHealthDevice `json:"devices"`
}

// FetchTenantAgentHealth returns the tenant's degraded-capability entries
// grouped per device, plus a tenant-level total, for the admin JSON API
// (PAT-1064). Returns ErrTenantNotFound when the tenant ID doesn't resolve,
// same contract as FetchTenantBrowserExtensions.
func FetchTenantAgentHealth(ctx context.Context, pool *pgxpool.Pool, tenantID string) (TenantAgentHealthResponse, error) {
	var resp TenantAgentHealthResponse
	resp.TenantID = tenantID
	resp.Devices = []TenantAgentHealthDevice{}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)`, tenantID).Scan(&exists); err != nil {
		return resp, fmt.Errorf("check tenant: %w", err)
	}
	if !exists {
		return resp, ErrTenantNotFound
	}

	rows, err := pool.Query(ctx, `
		SELECT
		    dah.device_id::text,
		    COALESCE(d.hostname, d.serial, dah.device_id::text) AS hostname,
		    dah.kind, dah.subject, dah.reason,
		    dah.first_seen, dah.last_seen, dah.count, dah.ever_succeeded
		FROM device_agent_health dah
		JOIN devices d ON d.id = dah.device_id
		WHERE d.tenant_id = $1
		ORDER BY hostname, dah.kind, dah.subject
	`, tenantID)
	if err != nil {
		// Deliberately does NOT special-case "does not exist" (e.g. migration
		// 0090 not yet applied on this box) into an empty success. Doing so
		// would make an unapplied migration read as "zero degraded
		// capabilities across the whole tenant" — a clean estate is
		// indistinguishable from a broken read path, which is exactly the
		// "a control that fails safe is invisible when it fails" failure this
		// ticket's parent exists to eliminate, applied to the channel meant
		// to surface that failure mode in the first place. Propagate the
		// error; the handler (internal/handlers/agent_health.go) turns it
		// into a 500 so an unapplied migration is visibly broken, not
		// silently clean.
		return resp, fmt.Errorf("fetch tenant agent health: %w", err)
	}
	defer rows.Close()

	deviceIndex := make(map[string]int)
	for rows.Next() {
		var deviceID, hostname, kind, subject, reason string
		var firstSeen, lastSeen time.Time
		var count int64
		var everSucceeded bool
		if err := rows.Scan(&deviceID, &hostname, &kind, &subject, &reason,
			&firstSeen, &lastSeen, &count, &everSucceeded); err != nil {
			return resp, fmt.Errorf("scan tenant agent health row: %w", err)
		}

		idx, ok := deviceIndex[deviceID]
		if !ok {
			resp.Devices = append(resp.Devices, TenantAgentHealthDevice{
				DeviceID: deviceID,
				Hostname: hostname,
				Degraded: []TenantAgentHealthEntry{},
			})
			idx = len(resp.Devices) - 1
			deviceIndex[deviceID] = idx
		}

		resp.Devices[idx].Degraded = append(resp.Devices[idx].Degraded, TenantAgentHealthEntry{
			Kind:          kind,
			Subject:       subject,
			Reason:        reason,
			FirstSeen:     firstSeen,
			LastSeen:      lastSeen,
			Count:         count,
			EverSucceeded: everSucceeded,
		})
		resp.Total++
	}
	if err := rows.Err(); err != nil {
		return resp, err
	}

	return resp, nil
}

// DeviceAgentHealthEntry is one currently-open degraded-capability row for a
// single device (PAT-2099): what was asked, why it could not be done, since
// when, how recently, and how many times. Unlike TenantAgentHealthEntry this
// carries no ever_succeeded — the device-detail surfaces this feeds (portal
// and admin) show current state, not the agent's own recovery history.
type DeviceAgentHealthEntry struct {
	Kind      string    `json:"kind"`
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// FetchDeviceAgentHealth returns one device's currently open
// degraded-capability entries, unscoped by tenant. Used by the internal
// admin device-detail endpoint (GET /admin/devices/{deviceID}), which
// authenticates via ADMIN_API_TOKEN and is not tenant-restricted by design.
// Never returns a nil slice: an empty result means "no open faults right
// now", the same reading device_agent_health's own clear-on-recovery
// semantics already give it (a resolved entry is deleted, not flagged).
func FetchDeviceAgentHealth(ctx context.Context, pool *pgxpool.Pool, deviceID string) ([]DeviceAgentHealthEntry, error) {
	return fetchDeviceAgentHealth(ctx, pool, "", deviceID)
}

// FetchPortalDeviceAgentHealth is the tenant-scoped counterpart for the
// customer-facing portal (GET /v1/portal/devices/{id}). The JOIN against
// devices.tenant_id = tenantID is the authority boundary that stops a
// device belonging to a different tenant from leaking its
// degraded-capability rows, independent of (and in addition to) the
// caller's own ownership check before this is reached.
func FetchPortalDeviceAgentHealth(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) ([]DeviceAgentHealthEntry, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("fetch portal device agent health: tenantID must not be empty")
	}
	return fetchDeviceAgentHealth(ctx, pool, tenantID, deviceID)
}

// fetchDeviceAgentHealth is the shared query. An empty tenantID omits the
// tenant filter entirely (the admin, already-tenant-unscoped path); a
// non-empty tenantID adds it as the authority boundary (the portal path).
func fetchDeviceAgentHealth(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) ([]DeviceAgentHealthEntry, error) {
	entries := []DeviceAgentHealthEntry{}

	query := `
		SELECT dah.kind, dah.subject, dah.reason, dah.first_seen, dah.last_seen, dah.count
		FROM device_agent_health dah
		JOIN devices d ON d.id = dah.device_id
		WHERE dah.device_id = $1`
	args := []any{deviceID}
	if tenantID != "" {
		query += ` AND d.tenant_id = $2`
		args = append(args, tenantID)
	}
	query += ` ORDER BY dah.kind, dah.subject`

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch device agent health: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e DeviceAgentHealthEntry
		if err := rows.Scan(&e.Kind, &e.Subject, &e.Reason, &e.FirstSeen, &e.LastSeen, &e.Count); err != nil {
			return nil, fmt.Errorf("scan device agent health row: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}
