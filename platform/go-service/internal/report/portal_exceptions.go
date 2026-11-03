package report

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PAT-1824: GET /v1/portal/exceptions. Row/device caps mirror the
// /v1/portal/extensions convention (500 rows, capped device drill-down) —
// see portal_extensions.go for the fuller abuse-resistance argument that
// convention was built against. That argument does not carry over
// unchanged: device_browser_extensions accumulates unboundedly from
// customer-controlled agent telemetry, with no delete path, which is what
// forced the fail-closed source-row pre-check there. tenant_software_exceptions
// has no such growth path — every row is written by a named Patched
// specialist via the /admin/tenants/{id}/exceptions... routes (12 Sept
// portal decision: "a customer asks, a specialist records"), a low-volume,
// admin-only write surface, so the plain 500-row cap below is enough; no
// separate existence-probe guard is needed.
const (
	// portalExceptionsMaxRows caps how many exception rows one response
	// carries. The ORDER BY puts unaccepted, then review-overdue, rows
	// first (per the ticket: "unaccepted and review-overdue rows never cut
	// first"), so the cap bites the accepted-and-current tail.
	portalExceptionsMaxRows = 500
	// portalExceptionsMaxDevices caps the per-exception requesting-device
	// list at the first N devices by hostname. DeviceCount stays exact.
	portalExceptionsMaxDevices = 50
)

// PortalExceptionDevice is one device the exception was requested against.
type PortalExceptionDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
}

// PortalExceptionHistoryEntry is one append-only
// tenant_software_exception_changes row.
type PortalExceptionHistoryEntry struct {
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// PortalException is one tenant software exception (pinned version /
// accepted risk), shaped for GET /v1/portal/exceptions.
//
// Status is "accepted" or "unaccepted" — unaccepted is a first-class state,
// not the absence of an acceptance record (root AGENTS.md: absence
// requires authority). ReviewOverdue is computed server-side against
// today's date (see FetchPortalExceptions), never trusted from a client.
type PortalException struct {
	ID            string
	Product       string
	Version       string
	Type          string
	DeviceCount   int
	Devices       []PortalExceptionDevice
	DevicesTrunc  bool
	RequestedBy   string
	RequestedAt   time.Time
	DependsOn     string
	Acceptor      *string
	AcceptedAt    *time.Time
	Status        string
	ReviewDate    *string // "2006-01-02", nil when unset
	ReviewOverdue bool
	History       []PortalExceptionHistoryEntry
}

// PortalExceptionsResult carries the capped exception list plus the exact
// pre-cap total and a truncation flag — same shape as PortalExtensionsResult
// minus the EstateTooLarge branch, which has no analogue here (see the file
// doc comment above).
type PortalExceptionsResult struct {
	Exceptions []PortalException
	Total      int
	Truncated  bool
}

// portalExceptionsQuery ranks unaccepted rows, then review-overdue rows,
// ahead of everything else, so portalExceptionsMaxRows never cuts a row
// that needs attention while an accepted-and-current one survives —
// mirroring the ticket's "unaccepted and review-overdue rows never cut
// first" requirement for extensions. total is COUNT(*) OVER() computed in
// the `base` CTE, i.e. over every matching row before that CTE's own
// ORDER BY/LIMIT trims it — the same single-SELECT-window-function
// convention FetchPortalCVEFindingsPage and FetchPortalExtensions already
// rely on for an exact pre-cap total with no second COUNT query.
const portalExceptionsQuery = `
WITH base AS (
    SELECT
        e.id, e.product, e.version, e.type, e.depends_on,
        e.requested_by, e.requested_at, e.status, e.acceptor, e.accepted_at,
        e.review_date::text AS review_date,
        (e.review_date IS NOT NULL AND e.review_date < $2::date) AS review_overdue,
        COUNT(*) OVER()::int AS total
    FROM tenant_software_exceptions e
    WHERE e.tenant_id = $1::uuid
    ORDER BY (e.status = 'unaccepted') DESC,
             (e.review_date IS NOT NULL AND e.review_date < $2::date) DESC,
             e.product, e.version, e.id
    LIMIT $3
)
SELECT b.id::text, b.product, b.version, b.type, b.depends_on, b.requested_by, b.requested_at,
       b.status, b.acceptor, b.accepted_at, b.review_date, b.review_overdue, b.total,
       COALESCE(dc.device_count, 0), COALESCE(devs.devices, '[]'::jsonb),
       COALESCE(dc.device_count, 0) > $4
FROM base b
LEFT JOIN LATERAL (
    SELECT COUNT(*)::int AS device_count
    FROM tenant_software_exception_devices ed
    WHERE ed.exception_id = b.id
) dc ON true
LEFT JOIN LATERAL (
    SELECT jsonb_agg(jsonb_build_object('device_id', dd.device_id, 'hostname', dd.hostname)
                     ORDER BY dd.hostname, dd.device_id) AS devices
    FROM (
        SELECT ed.device_id::text AS device_id,
               COALESCE(d.hostname, d.serial, d.id::text) AS hostname
        FROM tenant_software_exception_devices ed
        JOIN devices d ON d.id = ed.device_id
        WHERE ed.exception_id = b.id
        ORDER BY COALESCE(d.hostname, d.serial, d.id::text), d.id
        LIMIT $4
    ) dd
) devs ON true
ORDER BY (b.status = 'unaccepted') DESC, b.review_overdue DESC, b.product, b.version, b.id
`

// FetchPortalExceptions returns the tenant's software exception register
// (PAT-1824), capped per the constants above. Degrades to an empty result
// (never an error) if the table has not been migrated yet — same
// convention every other portal fetcher in this package uses, so a
// platform build predating this migration serves a clean page rather than
// a 500.
func FetchPortalExceptions(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalExceptionsResult, error) {
	res := PortalExceptionsResult{Exceptions: []PortalException{}}

	var haveExceptions bool
	if err := pool.QueryRow(ctx,
		`SELECT to_regclass('tenant_software_exceptions') IS NOT NULL`,
	).Scan(&haveExceptions); err != nil {
		return res, fmt.Errorf("probe exceptions table: %w", err)
	}
	if !haveExceptions {
		return res, nil
	}

	today := time.Now().UTC().Format("2006-01-02")
	rows, err := pool.Query(ctx, portalExceptionsQuery,
		tenantID, today, portalExceptionsMaxRows, portalExceptionsMaxDevices)
	if err != nil {
		return res, fmt.Errorf("fetch portal exceptions: %w", err)
	}
	defer rows.Close()

	ids := make([]string, 0)
	for rows.Next() {
		var e PortalException
		var devicesBytes []byte
		if err := rows.Scan(
			&e.ID, &e.Product, &e.Version, &e.Type, &e.DependsOn,
			&e.RequestedBy, &e.RequestedAt, &e.Status, &e.Acceptor, &e.AcceptedAt,
			&e.ReviewDate, &e.ReviewOverdue, &res.Total,
			&e.DeviceCount, &devicesBytes, &e.DevicesTrunc,
		); err != nil {
			return res, fmt.Errorf("scan portal exception: %w", err)
		}
		if err := json.Unmarshal(devicesBytes, &e.Devices); err != nil {
			return res, fmt.Errorf("decode devices for exception %s: %w", e.ID, err)
		}
		if e.Devices == nil {
			e.Devices = []PortalExceptionDevice{}
		}
		e.History = []PortalExceptionHistoryEntry{}
		res.Exceptions = append(res.Exceptions, e)
		ids = append(ids, e.ID)
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	res.Truncated = res.Total > len(res.Exceptions)

	history, err := fetchPortalExceptionHistory(ctx, pool, ids)
	if err != nil {
		return res, err
	}
	for i := range res.Exceptions {
		res.Exceptions[i].History = history[res.Exceptions[i].ID]
	}

	return res, nil
}

// fetchPortalExceptionHistory batch-fetches the append-only decision log
// for every exception id in one query, oldest first per exception (the
// contract's example shows "requested" before "accepted" in document
// order) — never re-derived from the exception row itself, since the row
// only ever holds the CURRENT acceptor/status, not the sequence that
// produced it (root AGENTS.md: evidence and decisions are separate).
func fetchPortalExceptionHistory(ctx context.Context, pool *pgxpool.Pool, ids []string) (map[string][]PortalExceptionHistoryEntry, error) {
	out := make(map[string][]PortalExceptionHistoryEntry, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT exception_id::text, actor, action, reason, at
		FROM tenant_software_exception_changes
		WHERE exception_id = ANY($1::uuid[])
		ORDER BY exception_id, at, id
	`, ids)
	if err != nil {
		return out, fmt.Errorf("fetch exception history: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var exceptionID string
		var h PortalExceptionHistoryEntry
		if err := rows.Scan(&exceptionID, &h.Actor, &h.Action, &h.Reason, &h.At); err != nil {
			return out, fmt.Errorf("scan exception history: %w", err)
		}
		out[exceptionID] = append(out[exceptionID], h)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}
