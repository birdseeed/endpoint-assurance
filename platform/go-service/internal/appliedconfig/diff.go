package appliedconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"patched.im/api/internal/configdiff"
)

// ErrCollectionNotOK is returned by Diff when either input snapshot's
// CollectionStatus is not CollectionOK. A rate-limited or unavailable
// collection did run, but it could not read the device's real state — the
// agent served a cached profile list instead. Diffing against that would
// report cached-versus-current churn as real configuration change, and
// would report a genuinely empty cache as every profile having vanished.
// This is the same rule internal/intune applies to a partial pull, enforced
// the same way: reject, never guess.
var ErrCollectionNotOK = errors.New("appliedconfig: diff requires two snapshots whose collection_status is ok")

// ErrSnapshotMismatch is returned by Diff when the two input snapshots are
// not for the same tenant and device. Profile identifiers are only unique
// within a device, so comparing across devices would match unrelated
// profiles that merely share an identifier.
var ErrSnapshotMismatch = errors.New("appliedconfig: diff inputs must be the same tenant and device")

// ErrSnapshotOutOfOrder is returned by Diff when current was observed at or
// before prior. Diff reports a window with a start and an end; without an
// ordering guarantee those words are meaningless.
var ErrSnapshotOutOfOrder = errors.New("appliedconfig: current snapshot must be observed after the prior snapshot")

// ChangeKind classifies how a profile's observed state differs between the
// two snapshots.
//
// The vocabulary is observational on purpose. A profile that is no longer in
// the list is "no longer present", not "removed" — Patched saw it stop being
// there and has no evidence of anyone removing it. Likewise "appeared"
// rather than "deployed" or "assigned".
//
// ProfileAppeared and ProfileNoLongerPresent are always singletons for an
// entry: a profile that is present on only one side has no counterpart to
// compare fields against. The remaining kinds can co-occur, because a
// profile present on both sides can have moved on more than one axis in the
// same window.
type ChangeKind string

const (
	// ProfileAppeared: the profile is in the current snapshot and was not
	// in the prior one.
	ProfileAppeared ChangeKind = "profile_appeared"

	// ProfileNoLongerPresent: the profile was in the prior snapshot and is
	// not in the current one. Only ever emitted when the current snapshot's
	// list is complete — see DiffNotes.SuppressedByTruncation.
	ProfileNoLongerPresent ChangeKind = "profile_no_longer_present"

	// ProfilePayloadChanged: the profile is present on both sides and its
	// payload differs. See PayloadComparison for how the two sides were
	// compared.
	ProfilePayloadChanged ChangeKind = "profile_payload_changed"

	// ProfileDisplayNameChanged: the profile is present on both sides under
	// a different display name.
	ProfileDisplayNameChanged ChangeKind = "profile_display_name_changed"

	// ProfileOrganizationChanged: the profile is present on both sides with
	// a different organization string.
	ProfileOrganizationChanged ChangeKind = "profile_organization_changed"
)

// kindOrder fixes the order ChangeKinds appear in a ProfileChange.Kinds
// slice, so the same pair of snapshots always produces byte-identical
// output.
var kindOrder = map[ChangeKind]int{
	ProfileAppeared:            0,
	ProfileNoLongerPresent:     1,
	ProfileDisplayNameChanged:  2,
	ProfileOrganizationChanged: 3,
	ProfilePayloadChanged:      4,
}

// PayloadComparison records how the two sides of a payload were actually
// compared, so a reader never has to assume.
type PayloadComparison string

const (
	// ComparisonCanonicalJSON: both sides parsed as JSON and were compared
	// structurally, so a re-serialisation that only reordered keys produced
	// no change.
	ComparisonCanonicalJSON PayloadComparison = "canonical_json"

	// ComparisonRawText: at least one side did not parse as JSON — almost
	// always because it was head-capped — so the two sides were compared as
	// verbatim text. Two payloads identical up to the cap compare equal
	// under this mode even if they differ past it; CapLimited says so.
	ComparisonRawText PayloadComparison = "raw_text"

	// ComparisonNotCompared: at least one side carried DecodeError, so the
	// payload content was never readable and no comparison was attempted.
	// This is never reported as a change.
	ComparisonNotCompared PayloadComparison = "not_compared"
)

// Field keys used in the per-profile comparison document. They are the keys
// that appear in ProfileChange.FieldChanges.
const (
	fieldDisplayName  = "display_name"
	fieldOrganization = "organization"
	fieldPayload      = "payload"
)

// identifierField names the profile's join key. comparisonDocument already
// leaves it out of the document it builds — the identifier is what the two
// sides were matched ON, so it cannot differ between them — and this skip
// set keeps that exclusion explicit at the comparison call, so a later
// change to comparisonDocument cannot quietly turn identity into a reported
// "setting". Same identity-field exclusion internal/intune applies to a
// Graph object's id.
var identifierField = map[string]bool{"identifier": true}

// ProfileChange is one profile's change entry for one device.
//
// There is deliberately no field here, or on any type in this package, that
// holds or implies who made the change. A Mac reports what is installed; it
// does not report who installed it, and no amount of MDM context recovers
// that. Nor is there a policy name: an applied profile's identifier and
// display name come from the profile itself, never from an authored policy
// object.
type ProfileChange struct {
	// ObservationKind is always ObservationKind ("applied_configuration").
	// It is set on every entry rather than only at the report level so a row
	// stays labelled after it is extracted from its container.
	ObservationKind string

	// DeviceID is the device this was observed on. Applied configuration is
	// only ever a per-device observation, so there is no such thing as an
	// entry here without one.
	DeviceID string

	ProfileIdentifier string

	// DisplayName is the profile's display name as of the later
	// observation, except for a ProfileNoLongerPresent entry where it is
	// the last name the profile was observed under.
	DisplayName string

	// PreviousDisplayName is set only when Kinds contains
	// ProfileDisplayNameChanged.
	PreviousDisplayName string

	// Kinds is sorted by kindOrder for determinism.
	Kinds []ChangeKind

	// FieldChanges is sorted by Key, and non-empty only for a profile
	// present on both sides. Keys are display_name, organization and
	// payload. Values are canonical JSON.
	FieldChanges []configdiff.FieldChange

	// PayloadComparison says how the payload sides were compared. It is
	// ComparisonNotCompared for an appeared/no-longer-present entry too:
	// there is only one side, so nothing was compared.
	PayloadComparison PayloadComparison

	// PayloadCapped is true when either side's payload was head-capped by
	// the agent. On a ProfilePayloadChanged entry it means the reported
	// before/after values are fragments; on any entry it means a
	// no-difference verdict for this profile only holds up to the cap.
	PayloadCapped bool

	// ObservedBetweenStart and ObservedBetweenEnd are the two snapshots'
	// observation times. A change is only ever known to have happened
	// somewhere inside this window. There is no single change timestamp
	// anywhere in this package, because no such timestamp is observable.
	ObservedBetweenStart time.Time
	ObservedBetweenEnd   time.Time

	// MDMServerURL is the management server the device was enrolled with as
	// of the later observation, empty when unenrolled. It attributes the
	// observation to a management platform without claiming a policy.
	MDMServerURL string
}

// DiffNotes records everything Diff deliberately did not conclude, so an
// under-report is visible rather than silent. A caller that ignores these
// is reading "no change" as stronger evidence than it is.
type DiffNotes struct {
	// UnreadablePayloadIdentifiers lists profiles present on both sides
	// where at least one side carried DecodeError. Their payloads were not
	// compared; an unknown payload is never read as an empty one.
	UnreadablePayloadIdentifiers []string

	// CapLimitedIdentifiers lists profiles present on both sides where at
	// least one side's payload was head-capped. A "no change" verdict for
	// these holds only up to the cap.
	CapLimitedIdentifiers []string

	// SuppressedByTruncation lists profiles where an appeared or
	// no-longer-present conclusion was available but unsound, because the
	// relevant side's profile list was truncated by the agent's array cap
	// and so cannot support an absence claim. Specifically: an appearance
	// needs a complete prior list, and a disappearance needs a complete
	// current list.
	SuppressedByTruncation []string

	// AmbiguousIdentifiers is the set of profile identifiers that occurred
	// more than once within a single snapshot, deduplicated across both
	// sides. Only the first occurrence on each side was compared; the rest
	// are unresolvable without inventing a tie-break.
	AmbiguousIdentifiers []string

	// UnidentifiedProfiles counts profiles observed with no identifier at
	// all — the shape the agent emits for a profile it could not decode.
	// They cannot be matched across snapshots, so they are never diffed.
	UnidentifiedProfiles int
}

// Empty reports whether Diff had no caveats to record.
func (n DiffNotes) Empty() bool {
	return len(n.UnreadablePayloadIdentifiers) == 0 &&
		len(n.CapLimitedIdentifiers) == 0 &&
		len(n.SuppressedByTruncation) == 0 &&
		len(n.AmbiguousIdentifiers) == 0 &&
		n.UnidentifiedProfiles == 0
}

// DeviceChangeSet is the result of one Diff call: how one device's applied
// configuration differed between two observations of it.
type DeviceChangeSet struct {
	// ObservationKind is always ObservationKind.
	ObservationKind string

	TenantID string
	DeviceID string

	// ObservedBetweenStart and ObservedBetweenEnd are the prior and current
	// snapshots' observation times — the window every entry was detected
	// in.
	ObservedBetweenStart time.Time
	ObservedBetweenEnd   time.Time

	// MDMServerURL as of the later observation; PreviousMDMServerURL as of
	// the earlier one. They are reported as plain state rather than as a
	// change entry: enrolment is a property of the device, not a profile.
	MDMServerURL         string
	PreviousMDMServerURL string

	// MDMSupervised as of the later observation.
	MDMSupervised Supervision

	// Changes is sorted by ProfileIdentifier for determinism, and contains
	// only profiles that actually differed.
	Changes []ProfileChange

	Notes DiffNotes
}

// Diff compares two ok snapshots of the same device — prior observed
// strictly before current — and returns what changed between them.
//
// It is a pure function: no store, no I/O, no clock. How the caller obtained
// the two snapshots is not Diff's concern, which is precisely why it
// re-checks the collection-status rule itself rather than trusting the query
// that loaded them.
func Diff(prior, current Snapshot) (DeviceChangeSet, error) {
	if prior.CollectionStatus != CollectionOK || current.CollectionStatus != CollectionOK {
		return DeviceChangeSet{}, fmt.Errorf("%w: prior=%q current=%q",
			ErrCollectionNotOK, prior.CollectionStatus, current.CollectionStatus)
	}
	if prior.TenantID != current.TenantID || prior.DeviceID != current.DeviceID {
		return DeviceChangeSet{}, fmt.Errorf("%w: prior=(%s,%s) current=(%s,%s)", ErrSnapshotMismatch,
			prior.TenantID, prior.DeviceID, current.TenantID, current.DeviceID)
	}
	if !current.ObservedAt.After(prior.ObservedAt) {
		return DeviceChangeSet{}, fmt.Errorf("%w: prior observed_at=%s current observed_at=%s",
			ErrSnapshotOutOfOrder, prior.ObservedAt, current.ObservedAt)
	}

	var notes DiffNotes
	priorByID := indexProfiles(prior.Profiles, &notes)
	currentByID := indexProfiles(current.Profiles, &notes)

	ids := make(map[string]bool, len(priorByID)+len(currentByID))
	for id := range priorByID {
		ids[id] = true
	}
	for id := range currentByID {
		ids[id] = true
	}
	sortedIDs := make([]string, 0, len(ids))
	for id := range ids {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	base := ProfileChange{
		ObservationKind:      ObservationKind,
		DeviceID:             current.DeviceID,
		ObservedBetweenStart: prior.ObservedAt,
		ObservedBetweenEnd:   current.ObservedAt,
		MDMServerURL:         current.MDMServerURL,
	}

	changes := make([]ProfileChange, 0, len(sortedIDs))
	for _, id := range sortedIDs {
		before, hadBefore := priorByID[id]
		after, hadAfter := currentByID[id]

		switch {
		case hadAfter && !hadBefore:
			// An appearance is only sound if the prior list was complete.
			// A truncated prior list may simply not have reached this
			// profile.
			if prior.ProfilesTruncated {
				notes.SuppressedByTruncation = append(notes.SuppressedByTruncation, id)
				continue
			}
			entry := base
			entry.ProfileIdentifier = id
			entry.DisplayName = after.DisplayName
			entry.Kinds = []ChangeKind{ProfileAppeared}
			entry.PayloadComparison = ComparisonNotCompared
			entry.PayloadCapped = after.PayloadCapped
			changes = append(changes, entry)

		case hadBefore && !hadAfter:
			// A disappearance is only sound if the current list is
			// complete, for the mirror-image reason.
			if current.ProfilesTruncated {
				notes.SuppressedByTruncation = append(notes.SuppressedByTruncation, id)
				continue
			}
			entry := base
			entry.ProfileIdentifier = id
			entry.DisplayName = before.DisplayName
			entry.Kinds = []ChangeKind{ProfileNoLongerPresent}
			entry.PayloadComparison = ComparisonNotCompared
			entry.PayloadCapped = before.PayloadCapped
			changes = append(changes, entry)

		default:
			entry, err := diffProfile(base, id, before, after, &notes)
			if err != nil {
				return DeviceChangeSet{}, fmt.Errorf("appliedconfig: diff profile %s on device %s: %w", id, current.DeviceID, err)
			}
			if entry != nil {
				changes = append(changes, *entry)
			}
		}
	}

	sort.Strings(notes.UnreadablePayloadIdentifiers)
	sort.Strings(notes.CapLimitedIdentifiers)
	sort.Strings(notes.SuppressedByTruncation)
	// Ambiguity is recorded per snapshot, so an identifier duplicated on
	// both sides lands here twice; the note is a set of identifiers, not a
	// count of occurrences.
	notes.AmbiguousIdentifiers = sortedSet(notes.AmbiguousIdentifiers)

	return DeviceChangeSet{
		ObservationKind:      ObservationKind,
		TenantID:             current.TenantID,
		DeviceID:             current.DeviceID,
		ObservedBetweenStart: prior.ObservedAt,
		ObservedBetweenEnd:   current.ObservedAt,
		MDMServerURL:         current.MDMServerURL,
		PreviousMDMServerURL: prior.MDMServerURL,
		MDMSupervised:        current.MDMSupervised,
		Changes:              changes,
		Notes:                notes,
	}, nil
}

// sortedSet returns the distinct values of in, sorted. nil in, nil out — an
// empty note stays empty rather than becoming an allocated empty slice that
// serialises differently.
func sortedSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// indexProfiles keys a snapshot's profiles by identifier. Profiles with no
// identifier cannot be matched across snapshots and are counted, not
// guessed at; a repeated identifier keeps its first occurrence and is
// recorded as ambiguous rather than silently last-wins.
func indexProfiles(profiles []Profile, notes *DiffNotes) map[string]Profile {
	byID := make(map[string]Profile, len(profiles))
	seenDuplicate := map[string]bool{}
	for _, p := range profiles {
		if p.Identifier == "" {
			notes.UnidentifiedProfiles++
			continue
		}
		if _, exists := byID[p.Identifier]; exists {
			if !seenDuplicate[p.Identifier] {
				seenDuplicate[p.Identifier] = true
				notes.AmbiguousIdentifiers = append(notes.AmbiguousIdentifiers, p.Identifier)
			}
			continue
		}
		byID[p.Identifier] = p
	}
	return byID
}

// diffProfile compares one profile present in both snapshots. It returns a
// nil entry (not an error) when nothing reportable changed — the no-op case
// a repeated collection of an unchanged Mac must hit, including when the
// payload was re-serialised with its keys in a different order.
func diffProfile(base ProfileChange, id string, before, after Profile, notes *DiffNotes) (*ProfileChange, error) {
	comparison := ComparisonCanonicalJSON
	payloadCapped := before.PayloadCapped || after.PayloadCapped
	comparePayload := true

	if before.DecodeError || after.DecodeError {
		// The profile is observed as present on both sides — that part
		// stands. Its payload content was never readable on at least one
		// side, so it is not compared and never reported as changed.
		comparePayload = false
		comparison = ComparisonNotCompared
		notes.UnreadablePayloadIdentifiers = append(notes.UnreadablePayloadIdentifiers, id)
	} else if payloadCapped {
		notes.CapLimitedIdentifiers = append(notes.CapLimitedIdentifiers, id)
	}

	beforeDoc, beforeJSON, err := comparisonDocument(before, comparePayload)
	if err != nil {
		return nil, fmt.Errorf("build prior comparison document: %w", err)
	}
	afterDoc, afterJSON, err := comparisonDocument(after, comparePayload)
	if err != nil {
		return nil, fmt.Errorf("build current comparison document: %w", err)
	}
	if comparePayload && !(beforeJSON && afterJSON) {
		// At least one payload did not parse as JSON — a head-capped
		// fragment, in practice. Both sides were compared as verbatim
		// text instead, which is sound for "these differ" but bounded for
		// "these match".
		comparison = ComparisonRawText
	}

	fieldChanges, err := configdiff.Fields(beforeDoc, afterDoc, identifierField)
	if err != nil {
		return nil, err
	}
	if len(fieldChanges) == 0 {
		return nil, nil
	}

	var kinds []ChangeKind
	for _, fc := range fieldChanges {
		switch fc.Key {
		case fieldDisplayName:
			kinds = append(kinds, ProfileDisplayNameChanged)
		case fieldOrganization:
			kinds = append(kinds, ProfileOrganizationChanged)
		case fieldPayload:
			kinds = append(kinds, ProfilePayloadChanged)
		}
	}
	sort.Slice(kinds, func(i, j int) bool { return kindOrder[kinds[i]] < kindOrder[kinds[j]] })

	entry := base
	entry.ProfileIdentifier = id
	entry.DisplayName = after.DisplayName
	entry.Kinds = kinds
	entry.FieldChanges = fieldChanges
	entry.PayloadComparison = comparison
	entry.PayloadCapped = payloadCapped
	if before.DisplayName != after.DisplayName {
		entry.PreviousDisplayName = before.DisplayName
	}
	return &entry, nil
}

// comparisonDocument renders one profile as the JSON object the field
// comparison runs over. The payload is canonicalised when it parses as
// JSON, so a re-serialisation that only reordered keys is not a change; when
// it does not parse — a head-capped fragment — it is carried as its verbatim
// text so the two sides still compare byte for byte rather than being
// dropped. The second return says whether the payload parsed.
//
// When includePayload is false the payload key is omitted from BOTH sides by
// the caller, so its absence can never itself register as a change.
func comparisonDocument(p Profile, includePayload bool) (json.RawMessage, bool, error) {
	doc := map[string]interface{}{
		fieldDisplayName:  p.DisplayName,
		fieldOrganization: p.Organization,
	}
	parsed := true
	if includePayload {
		canonical, ok := configdiff.Canonicalise(json.RawMessage(p.Payload))
		parsed = ok
		if ok {
			doc[fieldPayload] = json.RawMessage(canonical)
		} else {
			// Not JSON (or empty): compare the verbatim text.
			doc[fieldPayload] = p.Payload
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, parsed, err
	}
	return raw, parsed, nil
}
