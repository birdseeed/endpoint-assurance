// Package deviceretirement reads a customer's Retire device decisions
// (PAT-2135, migration 0193 device_retirement_decisions).
//
// A device is retired when the latest decision recorded for it (highest id)
// is 'retire'. Retirement is the customer's statement that the device is
// gone, so the counting surfaces that would otherwise report a silent
// device as stale or missing report it as retired instead. It is never
// reversed automatically: a retired device that reports again stays retired
// and is flagged ReportedAfterRetirement, and only the customer's own
// 'unretire' decision ends it.
//
// Retirement does not remove a device from the roster and does not change
// how findings are computed for it.
package deviceretirement

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Querier is the read surface this package needs; satisfied by
// *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Action values stored in device_retirement_decisions.action.
const (
	ActionRetire   = "retire"
	ActionUnretire = "unretire"
)

// MaxReasonChars caps the optional reason, in characters (CHECK in 0193).
const MaxReasonChars = 500

// RetiredSQL returns a boolean SQL expression that is true when the device
// row aliased deviceAlias (it must expose id and tenant_id) is currently
// retired. deviceAlias is always a literal chosen by the caller, never input.
func RetiredSQL(deviceAlias string) string {
	return `COALESCE((SELECT drd.action FROM device_retirement_decisions drd
	          WHERE drd.tenant_id = ` + deviceAlias + `.tenant_id AND drd.device_id = ` + deviceAlias + `.id
	          ORDER BY drd.id DESC LIMIT 1), '') = 'retire'`
}

// Retirement is the read-side retirement object on the portal device roster
// and device detail. Absent (nil) when the device is not retired.
type Retirement struct {
	RetiredAt time.Time `json:"retired_at"`
	// RetiredBy is the verified portal email of the admin who retired it,
	// the same attribution the software approval history shows.
	RetiredBy string  `json:"retired_by"`
	Reason    *string `json:"reason"`
	// ReportedAfterRetirement is true when the device's latest received
	// report (devices.last_seen, the report's received_at) is after
	// RetiredAt. The device stays retired regardless.
	ReportedAfterRetirement bool `json:"reported_after_retirement"`
}

// Fetch returns the current retirement of every retired device in the
// tenant, keyed by device id. deviceIDs narrows the read; nil reads the
// whole tenant. Devices outside tenantID are never returned.
func Fetch(ctx context.Context, q Querier, tenantID string, deviceIDs []string) (map[string]Retirement, error) {
	var ids any
	if deviceIDs != nil {
		ids = deviceIDs
	}
	rows, err := q.Query(ctx, `
		SELECT d.id::text, r.decided_at, r.actor_email, r.reason, COALESCE(d.last_seen > r.decided_at, false)
		FROM devices d
		JOIN LATERAL (
			SELECT drd.action, drd.decided_at, drd.actor_email, drd.reason
			FROM device_retirement_decisions drd
			WHERE drd.tenant_id = d.tenant_id AND drd.device_id = d.id
			ORDER BY drd.id DESC
			LIMIT 1
		) r ON r.action = 'retire'
		WHERE d.tenant_id = $1::uuid
		  AND ($2::uuid[] IS NULL OR d.id = ANY($2::uuid[]))
	`, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("device retirements: %w", err)
	}
	defer rows.Close()
	out := map[string]Retirement{}
	for rows.Next() {
		var id string
		var r Retirement
		if err := rows.Scan(&id, &r.RetiredAt, &r.RetiredBy, &r.Reason, &r.ReportedAfterRetirement); err != nil {
			return nil, fmt.Errorf("scan device retirement: %w", err)
		}
		r.RetiredAt = r.RetiredAt.UTC()
		out[id] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device retirements: %w", err)
	}
	return out, nil
}

// Of returns a pointer to the device's retirement, or nil when it is not
// retired, for a map Fetch returned.
func Of(m map[string]Retirement, deviceID string) *Retirement {
	if r, ok := m[deviceID]; ok {
		return &r
	}
	return nil
}
