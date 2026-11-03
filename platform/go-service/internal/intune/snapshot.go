package intune

import (
	"context"
	"fmt"
	"time"

	"patched.im/api/internal/msgraph"
)

// Snapshotter runs one append-only pull for a single ObjectSource against a
// single tenant, using the cheap list-then-diff change detection from
// PAT-1662: only objects whose lastModifiedDateTime moved since the last
// complete snapshot are refetched; everything else is carried forward
// verbatim with zero additional Graph calls.
type Snapshotter struct {
	Client *msgraph.Client
	Store  Store
	Source ObjectSource
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// NewSnapshotter builds a Snapshotter for one ObjectSource.
func NewSnapshotter(client *msgraph.Client, store Store, source ObjectSource) *Snapshotter {
	return &Snapshotter{Client: client, Store: store, Source: source, Now: time.Now}
}

// Run pulls one snapshot for tenantID and persists it via Store, whether it
// completes fully or fails partway through: a partial pull is recorded as
// StatusPartial rather than lost, so it can never be misread later as "every
// object not seen was deleted" (see ChangeDisappeared and PullStatus).
//
// The returned error is the pull failure, if any. A non-nil error alongside
// a successfully persisted (partial) snapshot is the expected shape of a
// mid-pull failure — check the returned Snapshot.Status/Error for what was
// actually recorded, not just whether err is nil.
func (s *Snapshotter) Run(ctx context.Context, tenantID string) (Snapshot, error) {
	now := s.Now
	if now == nil {
		now = time.Now
	}

	snap := Snapshot{
		TenantID:   tenantID,
		ObjectType: s.Source.Type(),
		APIVersion: s.Source.APIVersion(),
		StartedAt:  now(),
		Status:     StatusComplete,
	}

	prior, err := s.Store.PriorObjects(ctx, tenantID, s.Source.Type())
	if err != nil {
		return Snapshot{}, fmt.Errorf("intune: load prior snapshot: %w", err)
	}

	index, err := s.Source.ListIndex(ctx, s.Client, tenantID)
	if err != nil {
		// The cheap list call itself failed: nothing was observed this run,
		// so there is nothing honest to persist as a snapshot. The prior
		// complete snapshot (if any) remains the valid baseline untouched.
		return Snapshot{}, fmt.Errorf("intune: list index: %w", err)
	}

	seen := make(map[string]bool, len(index))
	var pullErr error
	for _, e := range index {
		seen[e.ID] = true
		p, existed := prior[e.ID]

		if existed && p.LastModifiedDateTime.Equal(e.LastModifiedDateTime) {
			snap.Objects = append(snap.Objects, ObjectRecord{
				GraphObjectID:        e.ID,
				LastModifiedDateTime: e.LastModifiedDateTime,
				ChangeKind:           ChangeUnchanged,
				RawBody:              p.RawBody,
				RawAssignments:       p.RawAssignments,
			})
			continue
		}

		body, ferr := s.Source.FetchBody(ctx, s.Client, tenantID, e.ID)
		if ferr != nil {
			pullErr = ferr
			break
		}
		assignments, ferr := s.Source.FetchAssignments(ctx, s.Client, tenantID, e.ID)
		if ferr != nil {
			pullErr = ferr
			break
		}

		rec := ObjectRecord{
			GraphObjectID:        e.ID,
			LastModifiedDateTime: e.LastModifiedDateTime,
			RawBody:              body,
			RawAssignments:       assignments,
		}
		if existed {
			rec.ChangeKind = ChangeRefreshed
			rec.BodyChanged = !bodyContentEqual(p.RawBody, body)
			rec.AssignmentsChanged = !jsonEqual(p.RawAssignments, assignments)
		} else {
			rec.ChangeKind = ChangeAppeared
			rec.BodyChanged = true
			rec.AssignmentsChanged = true
		}
		snap.Objects = append(snap.Objects, rec)
	}

	// Disappearance is only ever computed from a fully-observed list. On a
	// mid-pull failure we do not know the true current state of every
	// object, so asserting "not seen == deleted" here would be exactly the
	// false-mass-deletion failure mode PAT-1662 calls out — skip it.
	if pullErr == nil {
		for id := range prior {
			if !seen[id] {
				snap.Objects = append(snap.Objects, ObjectRecord{
					GraphObjectID: id,
					ChangeKind:    ChangeDisappeared,
				})
			}
		}
	}

	snap.CompletedAt = now()
	if pullErr != nil {
		snap.Status = StatusPartial
		snap.Error = pullErr.Error()
	}

	if _, werr := s.Store.WriteSnapshot(ctx, snap); werr != nil {
		if pullErr != nil {
			return snap, fmt.Errorf("intune: pull failed (%v) and persisting the partial snapshot also failed: %w", pullErr, werr)
		}
		return snap, fmt.Errorf("intune: persist snapshot: %w", werr)
	}

	return snap, pullErr
}
