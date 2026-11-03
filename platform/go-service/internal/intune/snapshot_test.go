package intune

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"patched.im/api/internal/msgraph"
)

const testTenantID = "tenant-a"

// failingListSource is an ObjectSource whose ListIndex always errors, used
// to exercise the "even the cheap list call fails" path without a real
// Graph server misbehaving.
type failingListSource struct {
	err error
}

func (failingListSource) Type() ObjectType            { return ObjectTypeCompliancePolicy }
func (failingListSource) APIVersion() GraphAPIVersion { return APIVersionV1 }
func (s failingListSource) ListIndex(ctx context.Context, client *msgraph.Client, tenantID string) ([]IndexEntry, error) {
	return nil, s.err
}
func (failingListSource) FetchBody(ctx context.Context, client *msgraph.Client, tenantID, objectID string) (json.RawMessage, error) {
	return nil, errors.New("not used")
}
func (failingListSource) FetchAssignments(ctx context.Context, client *msgraph.Client, tenantID, objectID string) (json.RawMessage, error) {
	return nil, errors.New("not used")
}

func newTestSnapshotter(t *testing.T, graph *fakeGraphServer) (*Snapshotter, *fakeStore) {
	t.Helper()
	client := newTestGraphClient(t, graph.handler())
	store := &fakeStore{}
	return NewSnapshotter(client, store, CompliancePolicySource{}), store
}

// TestSnapshotter_FirstRun_ObjectsAppear: with no prior snapshot, every
// object in the list is new — ChangeAppeared, and both body and assignments
// are fetched exactly once per object.
func TestSnapshotter_FirstRun_ObjectsAppear(t *testing.T) {
	graph := newFakeGraphServer()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	graph.addPolicy("p1", t0, "Policy One", json.RawMessage(`{"id":"a1","target":{"@odata.type":"#microsoft.graph.allDevicesAssignmentTarget"}}`))
	graph.addPolicy("p2", t0, "Policy Two")

	snapper, store := newTestSnapshotter(t, graph)
	snap, err := snapper.Run(context.Background(), testTenantID)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if snap.Status != StatusComplete {
		t.Fatalf("Status = %v, want complete", snap.Status)
	}
	if len(snap.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(snap.Objects))
	}
	for _, id := range []string{"p1", "p2"} {
		rec, ok := objectByID(snap.Objects, id)
		if !ok {
			t.Fatalf("missing object %s", id)
		}
		if rec.ChangeKind != ChangeAppeared {
			t.Errorf("%s: ChangeKind = %v, want appeared", id, rec.ChangeKind)
		}
		if !rec.BodyChanged || !rec.AssignmentsChanged {
			t.Errorf("%s: expected BodyChanged/AssignmentsChanged true on first appearance", id)
		}
		if graph.bodyFetchCount(id) != 1 {
			t.Errorf("%s: body fetched %d times, want 1", id, graph.bodyFetchCount(id))
		}
		if graph.assignmentFetchCount(id) != 1 {
			t.Errorf("%s: assignments fetched %d times, want 1", id, graph.assignmentFetchCount(id))
		}
	}
	if len(store.snapshots) != 1 {
		t.Fatalf("store has %d snapshots, want 1", len(store.snapshots))
	}
}

// TestSnapshotter_SecondRun_NoChanges_FetchesNoBodies is the core
// change-detection acceptance criterion: a second run against an unchanged
// upstream makes zero body/assignment fetches and produces a snapshot that
// carries forward the exact same raw bytes, i.e. diffs clean against the
// prior one.
func TestSnapshotter_SecondRun_NoChanges_FetchesNoBodies(t *testing.T) {
	graph := newFakeGraphServer()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	graph.addPolicy("p1", t0, "Policy One", json.RawMessage(`{"id":"a1"}`))

	snapper, store := newTestSnapshotter(t, graph)
	ctx := context.Background()

	if _, err := snapper.Run(ctx, testTenantID); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	first := store.latest()

	snap2, err := snapper.Run(ctx, testTenantID)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}

	if graph.listCalls != 2 {
		t.Errorf("listCalls = %d, want 2 (one cheap list call per run)", graph.listCalls)
	}
	if graph.bodyFetchCount("p1") != 1 {
		t.Errorf("body fetched %d times across two runs, want 1 (no refetch on unchanged run)", graph.bodyFetchCount("p1"))
	}
	if graph.assignmentFetchCount("p1") != 1 {
		t.Errorf("assignments fetched %d times across two runs, want 1", graph.assignmentFetchCount("p1"))
	}

	rec, ok := objectByID(snap2.Objects, "p1")
	if !ok {
		t.Fatalf("p1 missing from second snapshot")
	}
	if rec.ChangeKind != ChangeUnchanged {
		t.Errorf("ChangeKind = %v, want unchanged", rec.ChangeKind)
	}

	// Diffs clean: same object set, same raw bytes, same lastModifiedDateTime.
	firstRec, _ := objectByID(first.Objects, "p1")
	if !jsonEqual(firstRec.RawBody, rec.RawBody) {
		t.Errorf("RawBody differs between snapshot 1 and 2: %s vs %s", firstRec.RawBody, rec.RawBody)
	}
	if !jsonEqual(firstRec.RawAssignments, rec.RawAssignments) {
		t.Errorf("RawAssignments differs between snapshot 1 and 2")
	}
	if !firstRec.LastModifiedDateTime.Equal(rec.LastModifiedDateTime) {
		t.Errorf("LastModifiedDateTime differs between snapshot 1 and 2")
	}
}

// TestSnapshotter_ObjectDisappeared: a policy present in the prior complete
// snapshot but absent from the current list is recorded as a disappeared
// tombstone, not silently dropped.
func TestSnapshotter_ObjectDisappeared(t *testing.T) {
	graph := newFakeGraphServer()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	graph.addPolicy("p1", t0, "Policy One")
	graph.addPolicy("p2", t0, "Policy Two")

	snapper, _ := newTestSnapshotter(t, graph)
	ctx := context.Background()
	if _, err := snapper.Run(ctx, testTenantID); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	graph.removePolicy("p2")

	snap2, err := snapper.Run(ctx, testTenantID)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}

	rec, ok := objectByID(snap2.Objects, "p2")
	if !ok {
		t.Fatalf("disappeared object p2 missing from snapshot; must be recorded, not dropped")
	}
	if rec.ChangeKind != ChangeDisappeared {
		t.Errorf("ChangeKind = %v, want disappeared", rec.ChangeKind)
	}
	if rec.RawBody != nil || rec.RawAssignments != nil {
		t.Errorf("disappeared tombstone should carry no raw body/assignments")
	}

	p1, ok := objectByID(snap2.Objects, "p1")
	if !ok || p1.ChangeKind != ChangeUnchanged {
		t.Errorf("p1 should remain unchanged, got %+v (ok=%v)", p1, ok)
	}
}

// TestSnapshotter_BodyChanged: lastModifiedDateTime moving triggers a
// refetch, and a genuine content difference is flagged BodyChanged with
// AssignmentsChanged left false when assignments did not move.
func TestSnapshotter_BodyChanged(t *testing.T) {
	graph := newFakeGraphServer()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	assignment := json.RawMessage(`{"id":"a1","target":{"@odata.type":"#microsoft.graph.allDevicesAssignmentTarget"}}`)
	graph.addPolicy("p1", t0, "Policy One", assignment)

	snapper, _ := newTestSnapshotter(t, graph)
	ctx := context.Background()
	if _, err := snapper.Run(ctx, testTenantID); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	t1 := t0.Add(time.Minute)
	graph.addPolicy("p1", t1, "Policy One RENAMED", assignment) // same assignment, new name + timestamp

	snap2, err := snapper.Run(ctx, testTenantID)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}

	rec, ok := objectByID(snap2.Objects, "p1")
	if !ok {
		t.Fatalf("p1 missing")
	}
	if rec.ChangeKind != ChangeRefreshed {
		t.Errorf("ChangeKind = %v, want refreshed", rec.ChangeKind)
	}
	if !rec.BodyChanged {
		t.Errorf("BodyChanged = false, want true (displayName changed)")
	}
	if rec.AssignmentsChanged {
		t.Errorf("AssignmentsChanged = true, want false (assignments identical)")
	}
	if graph.bodyFetchCount("p1") != 2 {
		t.Errorf("body fetched %d times, want 2 (refetched after lastModifiedDateTime moved)", graph.bodyFetchCount("p1"))
	}
}

// TestSnapshotter_AssignmentsOnlyChanged: lastModifiedDateTime moves (Graph
// reflects the assignment change on the parent object) but the policy body
// content itself is unchanged; only the assignments differ. This is the
// scenario PAT-1662 calls out as the one that is invisible if only the
// policy body is captured.
func TestSnapshotter_AssignmentsOnlyChanged(t *testing.T) {
	graph := newFakeGraphServer()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	oldAssignment := json.RawMessage(`{"id":"a1","target":{"@odata.type":"#microsoft.graph.groupAssignmentTarget","groupId":"g1"}}`)
	graph.addPolicy("p1", t0, "Policy One", oldAssignment)

	snapper, _ := newTestSnapshotter(t, graph)
	ctx := context.Background()
	if _, err := snapper.Run(ctx, testTenantID); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	newAssignment := json.RawMessage(`{"id":"a2","target":{"@odata.type":"#microsoft.graph.groupAssignmentTarget","groupId":"g2"}}`)
	t1 := t0.Add(time.Minute)
	graph.addPolicy("p1", t1, "Policy One", newAssignment) // same display name, different assignment

	snap2, err := snapper.Run(ctx, testTenantID)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}

	rec, ok := objectByID(snap2.Objects, "p1")
	if !ok {
		t.Fatalf("p1 missing")
	}
	if rec.ChangeKind != ChangeRefreshed {
		t.Errorf("ChangeKind = %v, want refreshed", rec.ChangeKind)
	}
	if rec.BodyChanged {
		t.Errorf("BodyChanged = true, want false (policy body content identical)")
	}
	if !rec.AssignmentsChanged {
		t.Errorf("AssignmentsChanged = false, want true (targeting changed)")
	}
}

// TestSnapshotter_PartialFailureMidPull: a failure fetching one object's
// body mid-pull must mark the whole snapshot partial, must not compute
// disappearance (which would misread the failure as mass deletion), and
// must still persist what was collected. A subsequent run must treat the
// prior COMPLETE snapshot, not the partial one, as its baseline.
func TestSnapshotter_PartialFailureMidPull(t *testing.T) {
	graph := newFakeGraphServer()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	graph.addPolicy("p1", t0, "Policy One")
	graph.addPolicy("p2", t0, "Policy Two")

	snapper, store := newTestSnapshotter(t, graph)
	ctx := context.Background()
	if _, err := snapper.Run(ctx, testTenantID); err != nil {
		t.Fatalf("first (baseline) Run: %v", err)
	}
	baseline := store.latest()

	// Force both objects to need a refetch, then fail fetching p2's body.
	t1 := t0.Add(time.Minute)
	graph.addPolicy("p1", t1, "Policy One v2")
	graph.addPolicy("p2", t1, "Policy Two v2")
	graph.mu.Lock()
	graph.failBody["p2"] = true
	graph.mu.Unlock()

	snap2, err := snapper.Run(ctx, testTenantID)
	if err == nil {
		t.Fatal("expected an error from the mid-pull failure")
	}
	if snap2.Status != StatusPartial {
		t.Fatalf("Status = %v, want partial", snap2.Status)
	}
	if snap2.Error == "" {
		t.Error("Error should be populated on a partial snapshot")
	}
	if _, ok := objectByID(snap2.Objects, "p2"); ok {
		t.Error("p2's body fetch failed; it must not appear as a successfully captured object")
	}
	for _, o := range snap2.Objects {
		if o.ChangeKind == ChangeDisappeared {
			t.Errorf("partial pull must never compute disappearance (false mass-deletion risk), got tombstone for %s", o.GraphObjectID)
		}
	}

	if len(store.snapshots) != 2 {
		t.Fatalf("store has %d snapshots, want 2 (the partial one must still be persisted)", len(store.snapshots))
	}
	if store.latest().Status != StatusPartial {
		t.Fatalf("persisted snapshot Status = %v, want partial", store.latest().Status)
	}

	// A partial snapshot must be unusable as a diff baseline: PriorObjects
	// must still return the last COMPLETE snapshot's data untouched.
	prior, err := store.PriorObjects(ctx, testTenantID, ObjectTypeCompliancePolicy)
	if err != nil {
		t.Fatalf("PriorObjects: %v", err)
	}
	baselineP1, _ := objectByID(baseline.Objects, "p1")
	if !prior["p1"].LastModifiedDateTime.Equal(baselineP1.LastModifiedDateTime) {
		t.Errorf("PriorObjects baseline for p1 should still be the original complete snapshot, got LastModifiedDateTime=%v want %v",
			prior["p1"].LastModifiedDateTime, baselineP1.LastModifiedDateTime)
	}
	if !jsonEqual(prior["p1"].RawBody, baselineP1.RawBody) {
		t.Errorf("PriorObjects baseline for p1 should still carry the original complete snapshot's raw body")
	}
}

// TestSnapshotter_ListIndexFailure_NoSnapshotWritten: if even the cheap list
// call fails, nothing was observed, so nothing should be persisted — the
// prior complete snapshot remains the valid baseline untouched.
func TestSnapshotter_ListIndexFailure_NoSnapshotWritten(t *testing.T) {
	failingSource := failingListSource{err: errors.New("boom")}
	client := newTestGraphClient(t, newFakeGraphServer().handler())
	store := &fakeStore{}
	snapper := NewSnapshotter(client, store, failingSource)

	_, err := snapper.Run(context.Background(), testTenantID)
	if err == nil {
		t.Fatal("expected error")
	}
	if len(store.snapshots) != 0 {
		t.Fatalf("store has %d snapshots, want 0 when the list call itself fails", len(store.snapshots))
	}
}
