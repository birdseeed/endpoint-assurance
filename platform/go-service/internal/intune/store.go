package intune

import (
	"context"
	"encoding/json"
	"time"
)

// PriorObject is what the store returns about one previously-snapshotted,
// still-alive object: enough for Snapshotter to decide whether it needs
// refetching and, if not, what to carry forward verbatim.
type PriorObject struct {
	LastModifiedDateTime time.Time
	RawBody              json.RawMessage
	RawAssignments       json.RawMessage
}

// Store is the persistence seam for snapshots. A Postgres-backed
// implementation lives in postgres_store.go; tests exercise the
// orchestration in snapshot.go against an in-memory fake so it needs no
// database.
type Store interface {
	// PriorObjects returns the alive objects (everything except
	// ChangeDisappeared) from the tenant's most recent COMPLETE snapshot of
	// objectType, keyed by GraphObjectID. A partial snapshot is never
	// eligible here — see PullStatus. Returns an empty map (not an error)
	// when there is no prior complete snapshot.
	PriorObjects(ctx context.Context, tenantID string, objectType ObjectType) (map[string]PriorObject, error)

	// WriteSnapshot persists one pull run (complete or partial) atomically:
	// the snapshot header plus every object row, all in one INSERT-only
	// transaction. It never modifies a previously written snapshot.
	WriteSnapshot(ctx context.Context, s Snapshot) (snapshotID string, err error)

	// LatestCompletePair returns the tenant's two most recent COMPLETE
	// snapshots for objectType, ordered prior (older) then current (newer)
	// — ready to pass straight to Diff. Only alive objects (change_kind <>
	// disappeared) are populated on each Snapshot's Objects, matching
	// PriorObjects' own filter; Diff's aliveObjects would discard the
	// tombstone rows anyway, so there is no information lost by excluding
	// them here.
	//
	// ok is false when fewer than two complete snapshots exist yet for this
	// tenant/objectType — "nothing to diff" is the honest, expected state
	// for a tenant PAT-1662's Snapshotter has pulled zero or one times, not
	// an error condition.
	LatestCompletePair(ctx context.Context, tenantID string, objectType ObjectType) (prior, current Snapshot, ok bool, err error)
}
