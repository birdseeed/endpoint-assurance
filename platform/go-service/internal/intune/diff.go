// Diff engine for PAT-1664: the next layer on top of PAT-1662's snapshots
// and PAT-1663's Settings Catalog id resolution. Snapshotter already knows
// "this object's body changed"; Diff turns that into "here specifically is
// what changed" — a chronological change-list entry per object that
// differs between two snapshots of the same tenant and object type.
//
// Diff is a pure function: no Store, no Graph client, no I/O. It operates
// entirely on two Snapshot values already in hand (typically the tenant's
// two most recent complete snapshots for an object type, but Diff itself
// does not care how its caller obtained them). A later ticket can add the
// Store queries and HTTP handler that fetch a specific pair of snapshots
// and expose this as an endpoint; that is presentation-layer work, not part
// of this engine.
package intune

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"patched.im/api/internal/configdiff"
)

// ErrSnapshotNotComplete is returned by Diff when either input snapshot's
// Status is not StatusComplete. A partial snapshot is missing objects that
// a full pull would have seen, so diffing against it would report those
// objects as deleted when they never were — see PAT-1662's PullStatus doc
// and Store.PriorObjects, which enforces the same rule at the query layer.
// Diff enforces it again here because its two inputs need not come from
// PriorObjects at all.
var ErrSnapshotNotComplete = errors.New("intune: diff requires two complete snapshots")

// ErrSnapshotMismatch is returned by Diff when the two input snapshots are
// not for the same tenant and object type. Diffing across tenants or object
// types would compare unrelated objects that merely happen to share a
// graph_object_id.
var ErrSnapshotMismatch = errors.New("intune: diff inputs must be the same tenant and object type")

// ErrSnapshotOutOfOrder is returned by Diff when current was pulled at or
// before prior. Diff reports "before" and "after"; without an ordering
// guarantee those words are meaningless.
var ErrSnapshotOutOfOrder = errors.New("intune: current snapshot must be pulled after the prior snapshot")

// ChangeEntryKind classifies why an object appears in a ChangeList.
// EntryCreated and EntryDeleted are always singletons for an entry (an
// object that just appeared or disappeared cannot also be reported
// renamed, since there is no counterpart snapshot side to compare against).
// EntryRenamed, EntrySettingsChanged and EntryAssignmentChanged can co-occur
// on the same entry, because an object present in both snapshots can have
// moved on more than one of those axes in the same window.
type ChangeEntryKind string

const (
	EntryCreated           ChangeEntryKind = "created"
	EntryDeleted           ChangeEntryKind = "deleted"
	EntryRenamed           ChangeEntryKind = "renamed"
	EntrySettingsChanged   ChangeEntryKind = "settings_changed"
	EntryAssignmentChanged ChangeEntryKind = "assignment_changed"
)

// AssignmentAction says whether a group was added to or removed from an
// object's targeting between the two snapshots.
type AssignmentAction string

const (
	AssignmentAdded   AssignmentAction = "added"
	AssignmentRemoved AssignmentAction = "removed"
)

// SettingChange is one changed top-level field of an object's body: the
// field's own name (or, for object types with no better name available,
// the raw JSON key itself — see the package-level note on compliance
// policies) and its value on each side of the window. Before/After are
// canonicalised JSON (re-marshalled after decoding, so key order and
// whitespace differences never appear here) rather than the verbatim bytes
// Graph sent — that canonicalisation is exactly what makes the "reordered
// keys produce zero changes" rule hold. A field that did not exist on one
// side is represented as JSON null on that side, not as an absent field.
//
// It is an alias for configdiff.FieldChange, not a copy of it: PAT-1668
// extracted the comparison primitives this type travels with into
// internal/configdiff so the macOS applied-configuration path could reuse
// them verbatim. The alias keeps intune's own vocabulary at its API surface
// while guaranteeing there is exactly one definition of what a changed
// field looks like across the service.
type SettingChange = configdiff.FieldChange

// AssignmentChange is one group added to or removed from an object's
// targeting. Excluded distinguishes an exclusionGroupAssignmentTarget from
// an ordinary (inclusion) groupAssignmentTarget — the same group id moving
// from included to excluded (or vice versa) is a real targeting change, not
// a no-op, so it is tracked as one "removed" and one "added" entry rather
// than being masked by matching on group id alone.
type AssignmentChange struct {
	Action   AssignmentAction
	GroupID  string
	Excluded bool
}

// ChangeEntry is one changed object's chronological change-list entry.
// There is deliberately no field anywhere on this type, or on ChangeList,
// that holds or implies who made the change — Intune's Graph API does not
// give this pipeline an actor, and the honesty rule for this ticket is to
// never manufacture or leave a slot for one.
type ChangeEntry struct {
	GraphObjectID string

	// DisplayName is the object's display name as of the newer snapshot,
	// except for an EntryDeleted-only entry, where the object has no
	// newer-snapshot body and this is its last-known display name instead.
	DisplayName string

	// PreviousDisplayName is set only when Kinds contains EntryRenamed: the
	// display name before the rename.
	PreviousDisplayName string

	// Kinds is sorted for determinism: Created, Deleted, Renamed,
	// SettingsChanged, AssignmentChanged, in that fixed order, filtered to
	// whichever apply to this entry.
	Kinds []ChangeEntryKind

	// SettingChanges is sorted by Key. Non-empty only when Kinds contains
	// EntrySettingsChanged.
	SettingChanges []SettingChange

	// AssignmentChanges is sorted by (Action, GroupID, Excluded). Non-empty
	// only when Kinds contains EntryAssignmentChanged.
	AssignmentChanges []AssignmentChange
}

// ChangeList is the result of one Diff call: every object that changed
// between two snapshots of one tenant/object_type, plus the window the
// changes were detected between.
type ChangeList struct {
	TenantID   string
	ObjectType ObjectType

	// WindowStart and WindowEnd are the prior and current snapshot's
	// CompletedAt timestamps — the closest existing field to "when this
	// snapshot was pulled" (Snapshot has no separate PulledAt field; the
	// pull is complete, and its contents final, at CompletedAt). Every
	// entry in Entries was detected somewhere in this window. Diff never
	// reports a single precise-looking timestamp for a change — a change
	// is only ever known to have happened between two pulls, not at an
	// exact instant within that window.
	WindowStart time.Time
	WindowEnd   time.Time

	// Entries is sorted by GraphObjectID for determinism: the same
	// snapshot pair produces the same slice, in the same order, on every
	// call.
	Entries []ChangeEntry
}

// noiseFields lists JSON body keys known to churn without the object's
// actual content changing, so a difference in one of these fields alone
// must never produce a settings-changed entry. lastModifiedDateTime is
// Graph's own bookkeeping timestamp: it moves on every re-save, including
// an assignment-only change with an otherwise byte-identical body (see
// intune.go's bodyContentEqual, which strips the same field for the same
// reason one layer down, in Snapshotter's own body/no-body-change
// decision). This is the one place that list lives for the diff engine —
// extend it, don't scatter another exclusion into the comparison logic
// below.
var noiseFields = map[string]bool{
	"lastModifiedDateTime": true,
}

// identityFields are body keys that name or identify the object rather
// than configure it. They are excluded from the generic per-field settings
// diff because each already has dedicated representation elsewhere in the
// entry: id is the join key Diff matches objects on, and displayName
// drives EntryRenamed instead of appearing as a "setting".
var identityFields = map[string]bool{
	"id":          true,
	"displayName": true,
}

// Diff compares prior and current — two complete snapshots of the same
// tenant and object type, with prior pulled strictly before current — and
// returns the chronological change list between them.
func Diff(prior, current Snapshot) (ChangeList, error) {
	if prior.Status != StatusComplete || current.Status != StatusComplete {
		return ChangeList{}, fmt.Errorf("%w: prior status=%q current status=%q", ErrSnapshotNotComplete, prior.Status, current.Status)
	}
	if prior.TenantID != current.TenantID || prior.ObjectType != current.ObjectType {
		return ChangeList{}, fmt.Errorf("%w: prior=(%s,%s) current=(%s,%s)", ErrSnapshotMismatch,
			prior.TenantID, prior.ObjectType, current.TenantID, current.ObjectType)
	}
	if !current.CompletedAt.After(prior.CompletedAt) {
		return ChangeList{}, fmt.Errorf("%w: prior completed_at=%s current completed_at=%s",
			ErrSnapshotOutOfOrder, prior.CompletedAt, current.CompletedAt)
	}

	priorAlive := aliveObjects(prior.Objects)
	currentAlive := aliveObjects(current.Objects)

	ids := make(map[string]bool, len(priorAlive)+len(currentAlive))
	for id := range priorAlive {
		ids[id] = true
	}
	for id := range currentAlive {
		ids[id] = true
	}
	sortedIDs := make([]string, 0, len(ids))
	for id := range ids {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	entries := make([]ChangeEntry, 0, len(sortedIDs))
	for _, id := range sortedIDs {
		before, hadBefore := priorAlive[id]
		after, hadAfter := currentAlive[id]

		switch {
		case hadAfter && !hadBefore:
			entries = append(entries, ChangeEntry{
				GraphObjectID: id,
				DisplayName:   displayNameOf(after.RawBody, id),
				Kinds:         []ChangeEntryKind{EntryCreated},
			})

		case hadBefore && !hadAfter:
			entries = append(entries, ChangeEntry{
				GraphObjectID: id,
				DisplayName:   displayNameOf(before.RawBody, id),
				Kinds:         []ChangeEntryKind{EntryDeleted},
			})

		default:
			entry, err := diffObject(id, before, after)
			if err != nil {
				return ChangeList{}, fmt.Errorf("intune: diff object %s: %w", id, err)
			}
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
	}

	return ChangeList{
		TenantID:    current.TenantID,
		ObjectType:  current.ObjectType,
		WindowStart: prior.CompletedAt,
		WindowEnd:   current.CompletedAt,
		Entries:     entries,
	}, nil
}

// aliveObjects returns the objects in objs that carry a real body, keyed by
// GraphObjectID. Tombstone rows (a prior ChangeDisappeared record with a
// nil RawBody) are excluded by construction: an object is "alive" in a
// snapshot exactly when it has content to compare, regardless of what
// change_kind Snapshotter itself labelled it with in the run that produced
// this snapshot. Diff deliberately does not read ChangeKind/BodyChanged/
// AssignmentsChanged from ObjectRecord — those describe Snapshotter's own
// run-to-run bookkeeping, not the field-level comparison this ticket adds,
// and relying on them would silently assume prior/current are adjacent
// snapshots when nothing about Diff's contract requires that.
func aliveObjects(objs []ObjectRecord) map[string]ObjectRecord {
	alive := make(map[string]ObjectRecord, len(objs))
	for _, o := range objs {
		if len(o.RawBody) == 0 {
			continue
		}
		alive[o.GraphObjectID] = o
	}
	return alive
}

// diffObject compares one object present in both snapshots. It returns a
// nil entry (not an error) when nothing reportable changed — the no-op
// case a repeated pull with reordered JSON and a bumped lastModifiedDateTime
// must hit.
func diffObject(id string, before, after ObjectRecord) (*ChangeEntry, error) {
	beforeName := displayNameOf(before.RawBody, id)
	afterName := displayNameOf(after.RawBody, id)
	renamed := beforeName != afterName

	settingChanges, err := diffSettings(before.RawBody, after.RawBody)
	if err != nil {
		return nil, err
	}
	assignmentChanges, err := diffAssignments(before.RawAssignments, after.RawAssignments)
	if err != nil {
		return nil, err
	}

	if !renamed && len(settingChanges) == 0 && len(assignmentChanges) == 0 {
		return nil, nil
	}

	var kinds []ChangeEntryKind
	if renamed {
		kinds = append(kinds, EntryRenamed)
	}
	if len(settingChanges) > 0 {
		kinds = append(kinds, EntrySettingsChanged)
	}
	if len(assignmentChanges) > 0 {
		kinds = append(kinds, EntryAssignmentChanged)
	}

	entry := &ChangeEntry{
		GraphObjectID:     id,
		DisplayName:       afterName,
		Kinds:             kinds,
		SettingChanges:    settingChanges,
		AssignmentChanges: assignmentChanges,
	}
	if renamed {
		entry.PreviousDisplayName = beforeName
	}
	return entry, nil
}

// displayNameOf reads displayName out of a Graph object body. Graph objects
// carry a human-readable displayName directly (PAT-1664's brief), so this
// never needs GUID resolution; fallback is used only when the body is
// empty, unparseable, or has no displayName, so Diff always has something
// to show rather than an empty string.
func displayNameOf(body json.RawMessage, fallback string) string {
	if len(body) == 0 {
		return fallback
	}
	var m struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.DisplayName == "" {
		return fallback
	}
	return m.DisplayName
}

// settingsSkipFields is the union of noiseFields and identityFields — the
// keys configdiff.Fields must not report — built once at init rather than
// on every diffObject call.
var settingsSkipFields = func() map[string]bool {
	skip := make(map[string]bool, len(noiseFields)+len(identityFields))
	for k := range noiseFields {
		skip[k] = true
	}
	for k := range identityFields {
		skip[k] = true
	}
	return skip
}()

// diffSettings compares two object bodies field by field, skipping identity
// and noise fields, and returns every field that differs — sorted by key
// for deterministic output. Values are compared after JSON-decoding both
// sides, so key reordering or whitespace differences between the two raw
// bodies never produce a spurious change.
//
// The comparison itself lives in internal/configdiff (extracted by
// PAT-1668). What stays here is the part that is Intune's own: which keys
// count as noise and which as identity.
func diffSettings(beforeRaw, afterRaw json.RawMessage) ([]SettingChange, error) {
	return configdiff.Fields(beforeRaw, afterRaw, settingsSkipFields)
}

// assignmentKey identifies one group's targeting relationship on an object:
// the group id plus whether this is an exclusion. Two assignments with the
// same group id but different Excluded are genuinely different targeting
// states, not the same key with a changed attribute — see AssignmentChange.
type assignmentKey struct {
	GroupID  string
	Excluded bool
}

// diffAssignments compares two raw_assignments JSON arrays and returns
// which groups were added to or removed from targeting, keyed by group id
// (and include/exclude) rather than by the assignment's own "id" — Graph
// reissues assignment ids on essentially any change to an assignment, so
// comparing by assignment id would report a churned-but-identical
// assignment as a spurious remove+add. Assignment targets with no group id
// (allDevicesAssignmentTarget, allLicensedUsersAssignmentTarget) carry no
// group identity to diff and are not represented here — see PAT-1664's
// scope note: this ticket compares assignments "by group id", not general
// targeting-type changes.
func diffAssignments(beforeRaw, afterRaw json.RawMessage) ([]AssignmentChange, error) {
	before, err := decodeAssignmentGroups(beforeRaw)
	if err != nil {
		return nil, fmt.Errorf("decode prior assignments: %w", err)
	}
	after, err := decodeAssignmentGroups(afterRaw)
	if err != nil {
		return nil, fmt.Errorf("decode current assignments: %w", err)
	}

	var changes []AssignmentChange
	for key := range before {
		if !after[key] {
			changes = append(changes, AssignmentChange{Action: AssignmentRemoved, GroupID: key.GroupID, Excluded: key.Excluded})
		}
	}
	for key := range after {
		if !before[key] {
			changes = append(changes, AssignmentChange{Action: AssignmentAdded, GroupID: key.GroupID, Excluded: key.Excluded})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		if a.GroupID != b.GroupID {
			return a.GroupID < b.GroupID
		}
		return !a.Excluded && b.Excluded
	})
	return changes, nil
}

// decodeAssignmentGroups extracts the set of group-targeting keys out of a
// raw_assignments JSON array. Each assignment item is expected to look
// like {"id":"...","target":{"@odata.type":"#microsoft.graph.
// groupAssignmentTarget","groupId":"..."}} (or the exclusion variant) —
// the shape Graph actually returns for compliance policy assignments; any
// item without a group id in its target is skipped, not errored, since a
// non-group target is a legitimate assignment this comparison simply does
// not cover.
func decodeAssignmentGroups(raw json.RawMessage) (map[assignmentKey]bool, error) {
	result := map[assignmentKey]bool{}
	if len(raw) == 0 {
		return result, nil
	}
	var items []struct {
		Target struct {
			ODataType string `json:"@odata.type"`
			GroupID   string `json:"groupId"`
		} `json:"target"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Target.GroupID == "" {
			continue
		}
		result[assignmentKey{
			GroupID:  item.Target.GroupID,
			Excluded: strings.Contains(item.Target.ODataType, "exclusionGroupAssignmentTarget"),
		}] = true
	}
	return result, nil
}
