package intune

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the production Store, backed by
// migrations/0124_intune_config_snapshots.sql. See store.go for the
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

// PriorObjects reads the alive objects (change_kind <> 'disappeared') from
// the tenant's most recent snapshot with status = 'complete'. A 'partial'
// snapshot is never selected here, by construction of the subquery below —
// this is the enforcement point for "a partial pull must be unusable as a
// diff input" from PAT-1662.
func (s *PostgresStore) PriorObjects(ctx context.Context, tenantID string, objectType ObjectType) (map[string]PriorObject, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT o.graph_object_id, o.last_modified_date_time, o.raw_body, o.raw_assignments
		FROM intune_config_objects o
		WHERE o.snapshot_id = (
			SELECT s2.id
			FROM intune_config_snapshots s2
			WHERE s2.tenant_id = $1::uuid
			  AND s2.object_type = $2
			  AND s2.status = 'complete'
			ORDER BY s2.started_at DESC, s2.id DESC
			LIMIT 1
		)
		AND o.change_kind <> 'disappeared'
	`, tenantID, string(objectType))
	if err != nil {
		return nil, fmt.Errorf("intune: query prior objects: %w", err)
	}
	defer rows.Close()

	result := make(map[string]PriorObject)
	for rows.Next() {
		var id string
		var p PriorObject
		var rawBody, rawAssignments []byte
		if err := rows.Scan(&id, &p.LastModifiedDateTime, &rawBody, &rawAssignments); err != nil {
			return nil, fmt.Errorf("intune: scan prior object: %w", err)
		}
		p.RawBody = json.RawMessage(rawBody)
		p.RawAssignments = json.RawMessage(rawAssignments)
		result[id] = p
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intune: iterate prior objects: %w", err)
	}
	return result, nil
}

// WriteSnapshot inserts the snapshot header and every object row in one
// transaction. Nothing here ever UPDATEs a previously committed row — a
// second call for the same tenant/object_type is always a brand new
// snapshot_id.
func (s *PostgresStore) WriteSnapshot(ctx context.Context, snap Snapshot) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("intune: begin snapshot write: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	var errText *string
	if snap.Error != "" {
		errText = &snap.Error
	}

	var snapshotID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO intune_config_snapshots
			(tenant_id, object_type, api_version, started_at, completed_at, status, error, object_count)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, snap.TenantID, string(snap.ObjectType), string(snap.APIVersion), snap.StartedAt, snap.CompletedAt,
		string(snap.Status), errText, len(snap.Objects)).Scan(&snapshotID)
	if err != nil {
		return "", fmt.Errorf("intune: insert snapshot header: %w", err)
	}

	batch := &pgx.Batch{}
	for _, o := range snap.Objects {
		var rawBody, rawAssignments []byte
		if o.RawBody != nil {
			rawBody = []byte(o.RawBody)
		}
		if o.RawAssignments != nil {
			rawAssignments = []byte(o.RawAssignments)
		}

		var lastModifiedArg interface{}
		if o.ChangeKind == ChangeDisappeared {
			lastModifiedArg = nil
		} else {
			lastModifiedArg = o.LastModifiedDateTime
		}

		batch.Queue(`
			INSERT INTO intune_config_objects
				(snapshot_id, graph_object_id, last_modified_date_time, change_kind,
				 body_changed, assignments_changed, raw_body, raw_assignments)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, snapshotID, o.GraphObjectID, lastModifiedArg, string(o.ChangeKind),
			o.BodyChanged, o.AssignmentsChanged, rawBody, rawAssignments)
	}

	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return "", fmt.Errorf("intune: insert snapshot object at index %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return "", fmt.Errorf("intune: close snapshot object batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("intune: commit snapshot write: %w", err)
	}

	return fmt.Sprintf("%d", snapshotID), nil
}

// LatestCompletePair loads the tenant's two most recent snapshot headers
// with status = 'complete' for objectType, then loads each one's alive
// objects (change_kind <> 'disappeared') in a second query keyed by
// snapshot_id — same exclusion PriorObjects applies, for the same reason:
// Diff's aliveObjects would filter tombstone rows out anyway, so fetching
// them would only cost bytes.
func (s *PostgresStore) LatestCompletePair(ctx context.Context, tenantID string, objectType ObjectType) (Snapshot, Snapshot, bool, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, started_at, completed_at, api_version
		FROM intune_config_snapshots
		WHERE tenant_id = $1::uuid
		  AND object_type = $2
		  AND status = 'complete'
		ORDER BY completed_at DESC, id DESC
		LIMIT 2
	`, tenantID, string(objectType))
	if err != nil {
		return Snapshot{}, Snapshot{}, false, fmt.Errorf("intune: query latest complete snapshots: %w", err)
	}

	type header struct {
		id          int64
		startedAt   time.Time
		completedAt time.Time
		apiVersion  string
	}
	var headers []header
	for rows.Next() {
		var h header
		if err := rows.Scan(&h.id, &h.startedAt, &h.completedAt, &h.apiVersion); err != nil {
			rows.Close()
			return Snapshot{}, Snapshot{}, false, fmt.Errorf("intune: scan snapshot header: %w", err)
		}
		headers = append(headers, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Snapshot{}, Snapshot{}, false, fmt.Errorf("intune: iterate snapshot headers: %w", err)
	}
	rows.Close()

	if len(headers) < 2 {
		// Not an error: this tenant/objectType has fewer than two complete
		// pulls on record yet, so there is nothing to diff.
		return Snapshot{}, Snapshot{}, false, nil
	}
	// ORDER BY completed_at DESC guarantees headers[0] is the newer
	// (current) and headers[1] is the older (prior).
	currentHeader, priorHeader := headers[0], headers[1]

	objRows, err := s.Pool.Query(ctx, `
		SELECT snapshot_id, graph_object_id, last_modified_date_time, change_kind,
		       body_changed, assignments_changed, raw_body, raw_assignments
		FROM intune_config_objects
		WHERE snapshot_id = ANY($1)
		  AND change_kind <> 'disappeared'
	`, []int64{priorHeader.id, currentHeader.id})
	if err != nil {
		return Snapshot{}, Snapshot{}, false, fmt.Errorf("intune: query snapshot objects: %w", err)
	}
	defer objRows.Close()

	byID := map[int64][]ObjectRecord{}
	for objRows.Next() {
		var snapshotID int64
		var rec ObjectRecord
		var changeKind string
		var lastModified *time.Time
		var rawBody, rawAssignments []byte
		if err := objRows.Scan(&snapshotID, &rec.GraphObjectID, &lastModified, &changeKind,
			&rec.BodyChanged, &rec.AssignmentsChanged, &rawBody, &rawAssignments); err != nil {
			return Snapshot{}, Snapshot{}, false, fmt.Errorf("intune: scan snapshot object: %w", err)
		}
		rec.ChangeKind = ChangeKind(changeKind)
		if lastModified != nil {
			rec.LastModifiedDateTime = *lastModified
		}
		rec.RawBody = json.RawMessage(rawBody)
		rec.RawAssignments = json.RawMessage(rawAssignments)
		byID[snapshotID] = append(byID[snapshotID], rec)
	}
	if err := objRows.Err(); err != nil {
		return Snapshot{}, Snapshot{}, false, fmt.Errorf("intune: iterate snapshot objects: %w", err)
	}

	prior := Snapshot{
		TenantID:    tenantID,
		ObjectType:  objectType,
		APIVersion:  GraphAPIVersion(priorHeader.apiVersion),
		StartedAt:   priorHeader.startedAt,
		CompletedAt: priorHeader.completedAt,
		Status:      StatusComplete,
		Objects:     byID[priorHeader.id],
	}
	current := Snapshot{
		TenantID:    tenantID,
		ObjectType:  objectType,
		APIVersion:  GraphAPIVersion(currentHeader.apiVersion),
		StartedAt:   currentHeader.startedAt,
		CompletedAt: currentHeader.completedAt,
		Status:      StatusComplete,
		Objects:     byID[currentHeader.id],
	}
	return prior, current, true, nil
}
