package report

// FetchTenantAuditEvents (PAT-1022) reads audit_events
// (migrations/0098_audit_events.sql) — the durable store for POST
// /v1/events, PAT-1022's platform-side implementation of the SIEM-style
// audit trail both agents already ship.
//
// This is deliberately NOT shaped like fetchProvenancePatchHistory
// (report.go, just below): that function is single-device and unbounded by
// date (LIMIT 200, newest-first, no lower bound) because its caller is a
// device-detail page. This function is tenant-wide and date-range-bounded
// because its caller is a fleet-level compliance/audit report — "who
// installed what, over what period" — where an unbounded query over a
// table fed continuously by every device on the estate has no safe default
// the way a single device's LIMIT 200 does.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEventItem is one row of audit_events, trimmed to the fields a
// tenant-wide report needs. Optional envelope fields (label, version,
// verified_signer, reason) come back as "" rather than a pointer/NULL —
// callers building a report or CSV row don't need to distinguish "absent"
// from "empty" for these.
type AuditEventItem struct {
	ID             string
	DeviceID       string
	EventType      string
	Label          string
	Version        string
	VerifiedSigner string
	Reason         string
	Platform       string
	OccurredAt     time.Time
}

// AuditEventCursor is a composite keyset-pagination cursor: (occurred_at,
// id). occurred_at alone cannot disambiguate rows that share an identical
// timestamp — and audit_events is fed by every device on the estate
// concurrently, so exact-timestamp collisions are routine, not an edge
// case — so id (a UUID, giving a deterministic total order independent of
// timestamp resolution) breaks the tie. Both fields are required together;
// there is no valid cursor with one but not the other.
type AuditEventCursor struct {
	OccurredAt time.Time
	ID         string
}

// FetchTenantAuditEvents reads audit_events for one tenant within
// [since, until), newest first (occurred_at DESC, id DESC — see
// AuditEventCursor), capped at limit (clamped to 1..1000).
//
// Optional narrowing:
//   - before, when set, additionally requires the row to sort strictly
//     after *before in (occurred_at DESC, id DESC) order — i.e.
//     occurred_at < before.OccurredAt, OR occurred_at = before.OccurredAt
//     AND id < before.ID. This is the same cursor-pagination convention
//     dbListEnforcementAudit (internal/handlers/enforcement_audit.go)
//     uses, extended to a composite key so pagination stays stable (no
//     skipped or duplicated rows at a page boundary) even when several
//     events share the exact same occurred_at. Applied WITHIN the
//     [since, until) window rather than instead of it, so a caller can
//     page through a large date range page by page.
//   - eventType / deviceID, when non-empty, filter to an exact match.
//
// since and until are both required by the caller (the admin handler
// enforces this — see AuditEventsAdminHandler in
// internal/handlers/audit_events_admin.go); this function itself accepts
// any time.Time pair, including a zero time.Time, so it stays usable from
// tests and any future caller without inheriting that HTTP-layer default.
func FetchTenantAuditEvents(ctx context.Context, pool *pgxpool.Pool, tenantID string, since, until time.Time, limit int, before *AuditEventCursor, eventType, deviceID string) ([]AuditEventItem, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	args := []any{tenantID, since, until}
	q := `
		SELECT id::text, device_id, event_type,
		       COALESCE(label, ''), COALESCE(version, ''),
		       COALESCE(verified_signer, ''), COALESCE(reason, ''),
		       platform, occurred_at
		FROM audit_events
		WHERE tenant_id = $1::uuid
		  AND occurred_at >= $2
		  AND occurred_at < $3`

	if before != nil {
		args = append(args, before.OccurredAt, before.ID)
		occurredAtIdx := len(args) - 1
		idIdx := len(args)
		q += fmt.Sprintf(" AND (occurred_at < $%d OR (occurred_at = $%d AND id < $%d::uuid))", occurredAtIdx, occurredAtIdx, idIdx)
	}
	if eventType != "" {
		args = append(args, eventType)
		q += fmt.Sprintf(" AND event_type = $%d", len(args))
	}
	if deviceID != "" {
		args = append(args, deviceID)
		q += fmt.Sprintf(" AND device_id = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch tenant audit events: %w", err)
	}
	defer rows.Close()

	var out []AuditEventItem
	for rows.Next() {
		var it AuditEventItem
		if err := rows.Scan(&it.ID, &it.DeviceID, &it.EventType, &it.Label, &it.Version, &it.VerifiedSigner, &it.Reason, &it.Platform, &it.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan audit event row: %w", err)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit event rows: %w", err)
	}
	return out, nil
}
