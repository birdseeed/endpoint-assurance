package handlers

// PAT-1878 read contract for the finding lifecycle. The current endpoint is
// a projection only; the history endpoint returns the immutable audit ledger.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type findingLifecycleCurrentRow struct {
	TenantID              string     `json:"tenant_id"`
	FindingKind           string     `json:"finding_kind"`
	DeviceID              *string    `json:"device_id,omitempty"`
	FindingKey            string     `json:"finding_key"`
	Status                string     `json:"status"`
	FirstObservedAt       *time.Time `json:"first_observed_at,omitempty"`
	CurrentlyObservedAt   *time.Time `json:"currently_observed_at,omitempty"`
	AcknowledgedAt        *time.Time `json:"acknowledged_at,omitempty"`
	RiskAcceptedAt        *time.Time `json:"risk_accepted_at,omitempty"`
	GuidanceIssuedAt      *time.Time `json:"guidance_issued_at,omitempty"`
	CustomerAppliedAt     *time.Time `json:"customer_applied_at,omitempty"`
	PendingVerificationAt *time.Time `json:"pending_verification_at,omitempty"`
	VerifiedFixedAt       *time.Time `json:"verified_fixed_at,omitempty"`
	StillFailingAt        *time.Time `json:"still_failing_at,omitempty"`
	VerificationUnknownAt *time.Time `json:"verification_unknown_at,omitempty"`
	RecurredAt            *time.Time `json:"recurred_at,omitempty"`
	RecurrenceCount       int        `json:"recurrence_count"`
	EventCount            int        `json:"event_count"`
	StatusRecordedAt      time.Time  `json:"status_recorded_at"`
	StatusObservedAt      *time.Time `json:"status_observed_at,omitempty"`
	StatusAuthoritative   bool       `json:"status_authoritative"`
}

type findingLifecycleEventRow struct {
	ID            int64          `json:"id"`
	TenantID      string         `json:"tenant_id"`
	FindingKind   string         `json:"finding_kind"`
	DeviceID      *string        `json:"device_id,omitempty"`
	FindingKey    string         `json:"finding_key"`
	EventType     string         `json:"event_type"`
	SourceType    string         `json:"source_type"`
	Actor         string         `json:"actor,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	ObservedAt    *time.Time     `json:"observed_at,omitempty"`
	Authoritative bool           `json:"authoritative"`
	Evidence      map[string]any `json:"evidence"`
	RecordedAt    time.Time      `json:"recorded_at"`
}

func lifecycleFilters(r *http.Request) (kind, key string, deviceID *string, ok bool) {
	kind = strings.TrimSpace(r.URL.Query().Get("finding_kind"))
	key = strings.TrimSpace(r.URL.Query().Get("finding_key"))
	device := strings.TrimSpace(r.URL.Query().Get("device_id"))
	if kind != "" && !validFindingKinds[kind] {
		return "", "", nil, false
	}
	if device != "" {
		if !looksLikeUUID(device) {
			return "", "", nil, false
		}
		deviceID = &device
	}
	return kind, key, deviceID, true
}

// FindingLifecycleCurrentHandler returns tenant-scoped current projections.
// Closure timestamps remain present after recurrence; status alone is never
// the audit record.
func FindingLifecycleCurrentHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
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

// FindingLifecycleHistoryHandler returns immutable events. The tenant
// predicate is mandatory even when an identity filter is supplied.
func FindingLifecycleHistoryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
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
