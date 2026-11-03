package appliedconfig

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the production Store, backed by
// migrations/0127_applied_config_snapshots.sql. See store.go for the
// contract.
type PostgresStore struct {
	Pool *pgxpool.Pool
}

// NewPostgresStore wraps an existing pool. The pool's lifecycle (Close) is
// owned by the caller, same convention as every other store in this
// codebase.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{Pool: pool}
}

// rankedSnapshot is one snapshot header plus its position in its device's
// newest-first ordering (1 = current, 2 = prior).
type rankedSnapshot struct {
	id   int64
	rank int
	snap Snapshot
}

// ComparablePairs implements Store. Two queries: the snapshot headers,
// windowed down to each eligible device's two newest ok observations, then
// every profile row belonging to those headers. Fetching the profiles in one
// keyed query rather than per snapshot keeps this at a fixed two round trips
// however many devices the tenant has.
func (s *PostgresStore) ComparablePairs(ctx context.Context, tenantID string, since time.Time) ([]SnapshotPair, error) {
	headers, err := s.comparableHeaders(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}
	if len(headers) == 0 {
		return nil, nil
	}

	ids := make([]int64, 0, len(headers))
	for _, h := range headers {
		ids = append(ids, h.id)
	}
	profiles, err := s.profilesBySnapshot(ctx, ids)
	if err != nil {
		return nil, err
	}

	byDevice := map[string][]rankedSnapshot{}
	deviceOrder := make([]string, 0, len(headers))
	for _, h := range headers {
		h.snap.Profiles = profiles[h.id]
		if _, seen := byDevice[h.snap.DeviceID]; !seen {
			deviceOrder = append(deviceOrder, h.snap.DeviceID)
		}
		byDevice[h.snap.DeviceID] = append(byDevice[h.snap.DeviceID], h)
	}

	pairs := make([]SnapshotPair, 0, len(deviceOrder))
	for _, dev := range deviceOrder {
		list := byDevice[dev]
		if len(list) < 2 {
			// One ok snapshot only: nothing to compare against. Not an
			// error and not an empty diff — no pair at all.
			continue
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].rank < list[j].rank })
		current, prior := list[0].snap, list[1].snap
		if !current.ObservedAt.After(prior.ObservedAt) {
			// Two observations sharing an instant cannot be ordered, and
			// Diff would reject them. Skip rather than hand Diff a pair it
			// is guaranteed to refuse.
			continue
		}
		pairs = append(pairs, SnapshotPair{Prior: prior, Current: current})
	}

	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Current.DeviceID < pairs[j].Current.DeviceID })
	return pairs, nil
}

// comparableHeaders runs the windowed header query.
//
// collection_status = 'ok' is filtered inside `ranked`, BEFORE the window
// function runs, so a run of rate-limited collections can never displace a
// device's last good baseline out of the top two. Filtering afterwards would
// be the silent version of exactly the failure this package exists to avoid.
func (s *PostgresStore) comparableHeaders(ctx context.Context, tenantID string, since time.Time) ([]rankedSnapshot, error) {
	// A zero `since` is passed as SQL NULL, which the WHERE clause reads as
	// "no cutoff" — distinct from a real cutoff that happens to land on the
	// zero instant.
	var sinceFilter *time.Time
	if !since.IsZero() {
		t := since
		sinceFilter = &t
	}

	rows, err := s.Pool.Query(ctx, `
		WITH ranked AS (
			SELECT s.id, s.tenant_id, s.device_id, s.observed_at, s.collection_status,
			       s.profiles_count, s.profiles_truncated, s.mdm_server_url, s.mdm_supervised,
			       row_number() OVER (PARTITION BY s.device_id ORDER BY s.observed_at DESC, s.id DESC) AS rn
			FROM applied_config_snapshots s
			WHERE s.tenant_id = $1::uuid
			  AND s.collection_status = 'ok'
		),
		eligible AS (
			SELECT device_id FROM ranked
			WHERE rn = 1 AND ($2::timestamptz IS NULL OR observed_at >= $2::timestamptz)
		)
		SELECT r.id, r.tenant_id::text, r.device_id::text, r.observed_at, r.collection_status,
		       r.profiles_count, r.profiles_truncated, r.mdm_server_url, r.mdm_supervised, r.rn
		FROM ranked r
		JOIN eligible e ON e.device_id = r.device_id
		WHERE r.rn <= 2
		ORDER BY r.device_id, r.rn
	`, tenantID, sinceFilter)
	if err != nil {
		return nil, fmt.Errorf("appliedconfig: query comparable snapshots: %w", err)
	}
	defer rows.Close()

	var out []rankedSnapshot
	for rows.Next() {
		var h rankedSnapshot
		var status, supervised string
		var mdmURL *string
		if err := rows.Scan(&h.id, &h.snap.TenantID, &h.snap.DeviceID, &h.snap.ObservedAt, &status,
			&h.snap.ProfilesCount, &h.snap.ProfilesTruncated, &mdmURL, &supervised, &h.rank); err != nil {
			return nil, fmt.Errorf("appliedconfig: scan comparable snapshot: %w", err)
		}
		// The column carries a CHECK constraint so an out-of-vocabulary
		// value cannot be stored; normalising again costs nothing and keeps
		// the conservative default in exactly one place.
		h.snap.CollectionStatus, _ = NormaliseCollectionStatus(status)
		h.snap.MDMSupervised, _ = NormaliseSupervision(supervised)
		if mdmURL != nil {
			h.snap.MDMServerURL = *mdmURL
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appliedconfig: iterate comparable snapshots: %w", err)
	}
	return out, nil
}

// profilesBySnapshot loads every profile row for the given snapshot ids,
// keyed by snapshot id and kept in the agent's own list order.
func (s *PostgresStore) profilesBySnapshot(ctx context.Context, snapshotIDs []int64) (map[int64][]Profile, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT snapshot_id, profile_identifier, display_name, organization,
		       payload, payload_capped, decode_error
		FROM applied_config_profiles
		WHERE snapshot_id = ANY($1::bigint[])
		ORDER BY snapshot_id, ordinal
	`, snapshotIDs)
	if err != nil {
		return nil, fmt.Errorf("appliedconfig: query snapshot profiles: %w", err)
	}
	defer rows.Close()

	out := map[int64][]Profile{}
	for rows.Next() {
		var snapshotID int64
		var p Profile
		var payload *string
		if err := rows.Scan(&snapshotID, &p.Identifier, &p.DisplayName, &p.Organization,
			&payload, &p.PayloadCapped, &p.DecodeError); err != nil {
			return nil, fmt.Errorf("appliedconfig: scan snapshot profile: %w", err)
		}
		if payload != nil {
			p.Payload = *payload
		}
		out[snapshotID] = append(out[snapshotID], p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appliedconfig: iterate snapshot profiles: %w", err)
	}
	return out, nil
}
