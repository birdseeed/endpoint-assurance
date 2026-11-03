package intune

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// diffTestSnapshot builds a minimal complete Snapshot fixture for Diff
// tests: same tenant/object type convention as the rest of this package's
// tests, with CompletedAt derived from a base time plus an offset so
// windows are always chronological without every test spelling out
// absolute times.
func diffTestSnapshot(t *testing.T, completedAt time.Time, objects ...ObjectRecord) Snapshot {
	t.Helper()
	return Snapshot{
		TenantID:    testTenantID,
		ObjectType:  ObjectTypeCompliancePolicy,
		APIVersion:  APIVersionV1,
		StartedAt:   completedAt.Add(-time.Second),
		CompletedAt: completedAt,
		Status:      StatusComplete,
		Objects:     objects,
	}
}

func aliveObject(id string, body string, assignments string) ObjectRecord {
	var raw json.RawMessage
	if body != "" {
		raw = json.RawMessage(body)
	}
	var rawAssign json.RawMessage
	if assignments != "" {
		rawAssign = json.RawMessage(assignments)
	}
	return ObjectRecord{
		GraphObjectID:  id,
		RawBody:        raw,
		RawAssignments: rawAssign,
	}
}

var baseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func kindsOf(e ChangeEntry) []ChangeEntryKind { return e.Kinds }

func hasKind(e ChangeEntry, k ChangeEntryKind) bool {
	for _, got := range e.Kinds {
		if got == k {
			return true
		}
	}
	return false
}

func TestDiff_ObjectAppeared_IsCreated(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime)
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"Policy One"}`, `[]`))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(cl.Entries), cl.Entries)
	}
	e := cl.Entries[0]
	if e.GraphObjectID != "p1" || e.DisplayName != "Policy One" {
		t.Errorf("entry = %+v", e)
	}
	if !reflect.DeepEqual(e.Kinds, []ChangeEntryKind{EntryCreated}) {
		t.Errorf("Kinds = %v, want [created]", e.Kinds)
	}
}

func TestDiff_ObjectDisappeared_IsDeleted(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1", `{"id":"p1","displayName":"Policy One"}`, `[]`))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(cl.Entries), cl.Entries)
	}
	e := cl.Entries[0]
	if e.GraphObjectID != "p1" || e.DisplayName != "Policy One" {
		t.Errorf("entry = %+v", e)
	}
	if !reflect.DeepEqual(e.Kinds, []ChangeEntryKind{EntryDeleted}) {
		t.Errorf("Kinds = %v, want [deleted]", e.Kinds)
	}
}

func TestDiff_Renamed_IsRenamedNotDeleteCreate(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1", `{"id":"p1","displayName":"Old Name"}`, `[]`))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"New Name"}`, `[]`))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 1 {
		t.Fatalf("got %d entries, want exactly 1 (a rename must never be delete+create): %+v", len(cl.Entries), cl.Entries)
	}
	e := cl.Entries[0]
	if !reflect.DeepEqual(e.Kinds, []ChangeEntryKind{EntryRenamed}) {
		t.Errorf("Kinds = %v, want [renamed]", e.Kinds)
	}
	if e.DisplayName != "New Name" || e.PreviousDisplayName != "Old Name" {
		t.Errorf("entry = %+v", e)
	}
	// displayName itself must not also surface as a generic setting change.
	if len(e.SettingChanges) != 0 {
		t.Errorf("SettingChanges = %+v, want none (displayName is not a setting)", e.SettingChanges)
	}
}

func TestDiff_SingleSettingChanged(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1", `{"id":"p1","displayName":"Policy One","passwordMinimumLength":6}`, `[]`))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"Policy One","passwordMinimumLength":8}`, `[]`))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(cl.Entries), cl.Entries)
	}
	e := cl.Entries[0]
	if !hasKind(e, EntrySettingsChanged) {
		t.Fatalf("Kinds = %v, want settings_changed present", e.Kinds)
	}
	if len(e.SettingChanges) != 1 {
		t.Fatalf("got %d setting changes, want 1: %+v", len(e.SettingChanges), e.SettingChanges)
	}
	sc := e.SettingChanges[0]
	if sc.Key != "passwordMinimumLength" || string(sc.Before) != "6" || string(sc.After) != "8" {
		t.Errorf("setting change = %+v", sc)
	}
}

func TestDiff_MultipleSettingsChanged_AllListed(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1", `{"id":"p1","displayName":"Policy One","passwordMinimumLength":6,"passwordRequired":false}`, `[]`))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"Policy One","passwordMinimumLength":8,"passwordRequired":true}`, `[]`))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(cl.Entries))
	}
	e := cl.Entries[0]
	if len(e.SettingChanges) != 2 {
		t.Fatalf("got %d setting changes, want 2: %+v", len(e.SettingChanges), e.SettingChanges)
	}
	// Sorted by key for determinism.
	if e.SettingChanges[0].Key != "passwordMinimumLength" || e.SettingChanges[1].Key != "passwordRequired" {
		t.Errorf("SettingChanges order = %+v", e.SettingChanges)
	}
}

func TestDiff_AssignmentAddedAndRemoved_BothReported(t *testing.T) {
	oldAssignment := `[{"id":"a1","target":{"@odata.type":"#microsoft.graph.groupAssignmentTarget","groupId":"g1"}}]`
	newAssignment := `[{"id":"a2","target":{"@odata.type":"#microsoft.graph.groupAssignmentTarget","groupId":"g2"}}]`

	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1", `{"id":"p1","displayName":"Policy One"}`, oldAssignment))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"Policy One"}`, newAssignment))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(cl.Entries))
	}
	e := cl.Entries[0]
	if !hasKind(e, EntryAssignmentChanged) {
		t.Fatalf("Kinds = %v, want assignment_changed present", e.Kinds)
	}
	if len(e.AssignmentChanges) != 2 {
		t.Fatalf("got %d assignment changes, want 2 (one added, one removed): %+v", len(e.AssignmentChanges), e.AssignmentChanges)
	}
	var sawAdded, sawRemoved bool
	for _, ac := range e.AssignmentChanges {
		switch {
		case ac.Action == AssignmentAdded && ac.GroupID == "g2":
			sawAdded = true
		case ac.Action == AssignmentRemoved && ac.GroupID == "g1":
			sawRemoved = true
		}
	}
	if !sawAdded || !sawRemoved {
		t.Errorf("AssignmentChanges = %+v, want g1 removed and g2 added", e.AssignmentChanges)
	}
}

func TestDiff_NoOpRepull_ReorderedKeysAndBumpedTimestamp_ZeroEntries(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1",
			`{"id":"p1","displayName":"Policy One","passwordRequired":true,"lastModifiedDateTime":"2026-09-01T00:00:00Z"}`,
			`[{"id":"a1","target":{"@odata.type":"#microsoft.graph.groupAssignmentTarget","groupId":"g1"}}]`))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		// Same content, keys reordered, lastModifiedDateTime bumped alone.
		aliveObject("p1",
			`{"lastModifiedDateTime":"2026-09-01T01:00:00Z","passwordRequired":true,"displayName":"Policy One","id":"p1"}`,
			`[{"target":{"groupId":"g1","@odata.type":"#microsoft.graph.groupAssignmentTarget"},"id":"a1"}]`))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 0 {
		t.Fatalf("got %d entries, want 0 for a no-op re-pull: %+v", len(cl.Entries), cl.Entries)
	}
}

func TestDiff_PartialSnapshot_Rejected(t *testing.T) {
	complete := diffTestSnapshot(t, baseTime)
	partial := diffTestSnapshot(t, baseTime.Add(time.Hour))
	partial.Status = StatusPartial

	if _, err := Diff(complete, partial); !errors.Is(err, ErrSnapshotNotComplete) {
		t.Errorf("Diff(complete, partial) error = %v, want ErrSnapshotNotComplete", err)
	}
	if _, err := Diff(partial, complete); !errors.Is(err, ErrSnapshotNotComplete) {
		t.Errorf("Diff(partial, complete) error = %v, want ErrSnapshotNotComplete", err)
	}
}

func TestDiff_MismatchedTenantOrObjectType_Rejected(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime)
	current := diffTestSnapshot(t, baseTime.Add(time.Hour))
	current.TenantID = "tenant-b"

	if _, err := Diff(prior, current); !errors.Is(err, ErrSnapshotMismatch) {
		t.Errorf("error = %v, want ErrSnapshotMismatch", err)
	}
}

func TestDiff_OutOfOrderSnapshots_Rejected(t *testing.T) {
	newer := diffTestSnapshot(t, baseTime.Add(time.Hour))
	older := diffTestSnapshot(t, baseTime)

	if _, err := Diff(newer, older); !errors.Is(err, ErrSnapshotOutOfOrder) {
		t.Errorf("error = %v, want ErrSnapshotOutOfOrder", err)
	}
}

func TestDiff_Deterministic_SameInputSameOutput(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p2", `{"id":"p2","displayName":"Two"}`, `[]`),
		aliveObject("p1", `{"id":"p1","displayName":"One","x":1}`, `[]`),
		aliveObject("p3", `{"id":"p3","displayName":"Three"}`, `[]`),
	)
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"One","x":2}`, `[]`),
		aliveObject("p3", `{"id":"p3","displayName":"Three Renamed"}`, `[]`),
		aliveObject("p4", `{"id":"p4","displayName":"Four"}`, `[]`),
	)

	first, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff (first run): %v", err)
	}
	second, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff (second run): %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Diff is not deterministic:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	// p2 deleted, p1 settings changed, p3 renamed, p4 created — expect
	// GraphObjectID-sorted order.
	want := []string{"p1", "p2", "p3", "p4"}
	var got []string
	for _, e := range first.Entries {
		got = append(got, e.GraphObjectID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Entries order = %v, want %v", got, want)
	}
}

func TestDiff_WindowIsTwoTimestamps_NeverOne(t *testing.T) {
	prior := diffTestSnapshot(t, baseTime)
	current := diffTestSnapshot(t, baseTime.Add(2*time.Hour))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !cl.WindowStart.Equal(baseTime) || !cl.WindowEnd.Equal(baseTime.Add(2*time.Hour)) {
		t.Errorf("window = [%v, %v], want [%v, %v]", cl.WindowStart, cl.WindowEnd, baseTime, baseTime.Add(2*time.Hour))
	}
	if cl.WindowStart.Equal(cl.WindowEnd) {
		t.Errorf("window start and end must not collapse to a single instant")
	}
}

func TestDiff_NoActorFieldAnywhere(t *testing.T) {
	// Trivially checkable by reflection, per the acceptance criterion: walk
	// every field name on ChangeList, ChangeEntry, SettingChange and
	// AssignmentChange and confirm none of them names or implies an actor.
	suspect := []string{"actor", "user", "who", "by", "author", "changedby", "modifiedby"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(ChangeList{}),
		reflect.TypeOf(ChangeEntry{}),
		reflect.TypeOf(SettingChange{}),
		reflect.TypeOf(AssignmentChange{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			for _, s := range suspect {
				if containsFold(name, s) {
					t.Errorf("%s.%s looks like an actor field; the honesty rule forbids one", typ.Name(), name)
				}
			}
		}
	}
}

// containsFold is a tiny case-insensitive substring check, local to this
// test so it carries no dependency on the field names it is checking.
func containsFold(s, substr string) bool {
	sl, subl := []rune(s), []rune(substr)
	toLower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}
	for i := range sl {
		sl[i] = toLower(sl[i])
	}
	for i := range subl {
		subl[i] = toLower(subl[i])
	}
	s2, sub2 := string(sl), string(subl)
	for i := 0; i+len(sub2) <= len(s2); i++ {
		if s2[i:i+len(sub2)] == sub2 {
			return true
		}
	}
	return false
}

func TestDiff_AssignmentTargetWithoutGroupID_NotDiffedAsGroup(t *testing.T) {
	// allDevicesAssignmentTarget carries no groupId; it must not blow up
	// the comparison and must not be reported as a phantom group change.
	prior := diffTestSnapshot(t, baseTime,
		aliveObject("p1", `{"id":"p1","displayName":"Policy One"}`,
			`[{"id":"a1","target":{"@odata.type":"#microsoft.graph.allDevicesAssignmentTarget"}}]`))
	current := diffTestSnapshot(t, baseTime.Add(time.Hour),
		aliveObject("p1", `{"id":"p1","displayName":"Policy One"}`,
			`[{"id":"a1","target":{"@odata.type":"#microsoft.graph.allDevicesAssignmentTarget"}}]`))

	cl, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(cl.Entries) != 0 {
		t.Fatalf("got %d entries, want 0: %+v", len(cl.Entries), cl.Entries)
	}
}
