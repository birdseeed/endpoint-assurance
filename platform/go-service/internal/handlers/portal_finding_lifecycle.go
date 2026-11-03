package handlers

// PAT-1969: the portal-facing half of the PAT-1878 finding lifecycle read
// contract. FindingLifecycleCurrentHandler/FindingLifecycleHistoryHandler
// (finding_lifecycle.go) are admin-only, tenant-scoped via a {tenantID} path
// parameter — the customer portal cannot reach admin routes (separate trust
// boundary, JWT-authenticated, /v1/portal/... only). These two handlers
// mirror them exactly (same SQL, same findingLifecycleCurrentRow /
// findingLifecycleEventRow shapes, same lifecycleFilters, same
// parsePagination) with the one required change: tenant scope comes
// exclusively from the authenticated portal identity (identity(w, r), which
// reads portalauth.FromContext), never from a path parameter or query
// string.

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PortalFindingLifecycleCurrentHandler returns the caller's tenant-scoped
// current lifecycle projections. See FindingLifecycleCurrentHandler's doc
// comment for the projection semantics; the only difference here is tenant
// scope.
func PortalFindingLifecycleCurrentHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		tenantID := id.TenantID
		kind, key, deviceID, ok := lifecycleFilters(r)
		if !ok {
			http.Error(w, "invalid lifecycle filter", http.StatusBadRequest)
			return
		}
		limit, offset := parsePagination(r)
		rows, err := pool.Query(r.Context(), `
			SELECT tenant_id::text, finding_kind, device_id::text, finding_key,
			       status, first_observed_at, currently_observed_at,
			       acknowledged_at, risk_accepted_at, guidance_issued_at, customer_applied_at,
			       pending_verification_at, verified_fixed_at, still_failing_at,
			       verification_unknown_at, recurred_at, recurrence_count, event_count, status_recorded_at,
			       status_observed_at, status_authoritative
			FROM finding_lifecycle_current
			WHERE tenant_id = $1::uuid
			  AND ($2::text = '' OR finding_kind = $2)
			  AND ($3::text = '' OR finding_key = $3)
			  AND ($4::uuid IS NULL OR device_id = $4::uuid)
			ORDER BY status_recorded_at DESC, finding_kind, finding_key, device_id NULLS FIRST
			LIMIT $5 OFFSET $6
		`, tenantID, kind, key, deviceID, limit, offset)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []findingLifecycleCurrentRow{}
		for rows.Next() {
			var row findingLifecycleCurrentRow
			var deviceID pgxText
			if err := rows.Scan(
				&row.TenantID, &row.FindingKind, &deviceID, &row.FindingKey,
				&row.Status, &row.FirstObservedAt, &row.CurrentlyObservedAt,
				&row.AcknowledgedAt, &row.RiskAcceptedAt, &row.GuidanceIssuedAt, &row.CustomerAppliedAt,
				&row.PendingVerificationAt, &row.VerifiedFixedAt, &row.StillFailingAt,
				&row.VerificationUnknownAt, &row.RecurredAt, &row.RecurrenceCount, &row.EventCount, &row.StatusRecordedAt,
				&row.StatusObservedAt, &row.StatusAuthoritative,
			); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			row.DeviceID = deviceID.ptr()
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"findings": out, "total": len(out), "limit": limit, "offset": offset, "returned": len(out),
		})
	}
}

// PortalFindingLifecycleHistoryHandler returns the caller's tenant-scoped
// immutable lifecycle events. See FindingLifecycleHistoryHandler's doc
// comment; the only difference here is tenant scope.
func PortalFindingLifecycleHistoryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		tenantID := id.TenantID
		kind, key, deviceID, ok := lifecycleFilters(r)
		if !ok {
			http.Error(w, "invalid lifecycle filter", http.StatusBadRequest)
			return
		}
		limit, offset := parsePagination(r)
		rows, err := pool.Query(r.Context(), `
			SELECT id, tenant_id::text, finding_kind, device_id::text, finding_key,
			       event_type, source_type, actor, reason, observed_at,
			       authoritative, evidence, recorded_at
			FROM finding_lifecycle_events
			WHERE tenant_id = $1::uuid
			  AND ($2::text = '' OR finding_kind = $2)
			  AND ($3::text = '' OR finding_key = $3)
			  AND ($4::uuid IS NULL OR device_id = $4::uuid)
			ORDER BY id
			LIMIT $5 OFFSET $6
		`, tenantID, kind, key, deviceID, limit, offset)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []findingLifecycleEventRow{}
		for rows.Next() {
			var row findingLifecycleEventRow
			var evidence []byte
			var deviceID pgxText
			if err := rows.Scan(
				&row.ID, &row.TenantID, &row.FindingKind, &deviceID, &row.FindingKey,
				&row.EventType, &row.SourceType, &row.Actor, &row.Reason, &row.ObservedAt,
				&row.Authoritative, &evidence, &row.RecordedAt,
			); err != nil || json.Unmarshal(evidence, &row.Evidence) != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			row.DeviceID = deviceID.ptr()
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": out, "total": len(out), "limit": limit, "offset": offset, "returned": len(out),
		})
	}
}
