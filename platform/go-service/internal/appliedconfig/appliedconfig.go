// Package appliedconfig models the configuration that was actually observed
// in place on a Mac, and detects how it changed between two observations.
//
// # Applied configuration is not authored policy
//
// This is the single rule the whole package is built around. A Mac's
// `profiles list` output says what landed on that machine. It does not say
// what an administrator authored in a management console, and the two
// routinely diverge: a push can be pending, a profile can be removed
// locally, a stale push can linger. Nothing in this package names a policy,
// carries a policy identifier, or phrases a change as an administrative
// action. Every output row is labelled ObservationKind
// ("applied_configuration") and carries the device it was observed on plus
// the window it was observed between.
//
// The authored-policy side of the house is internal/intune (PAT-1662 pulls
// the objects, PAT-1664 diffs them). That package's vocabulary — policy,
// assignment, Graph object — deliberately does not appear here, and this
// package's output is deliberately not merged into it. Where a tenant has
// both paths running against the same Mac, a configuration change can show
// up on both: that is one change with two independent observations, and a
// report that adds them together double-counts. PAT-1668 leaves the two
// paths uncorrelated on purpose; correlating them is a product decision
// about how a joint finding should read, not something to guess at in a
// diff engine. MDMServerURL is carried through so an applied-config change
// can at least be attributed to the management platform that is enrolled,
// with no policy name required.
//
// # What the agent sends
//
// The wire shape is the macOS agent's `applied_configuration` object
// (PAT-1667, updater/macos/lib/config_profiles.sh), ingested by
// internal/extractor and stored append-only by migration
// 0127_applied_config_snapshots.sql: one immutable snapshot per device per
// collection run, with every profile body kept verbatim.
//
// # Absence requires authority
//
// Three separate things can make a profile list look empty or short, and
// only one of them means profiles went away:
//
//   - CollectionStatus is rate_limited or unavailable — the collection ran
//     but could not read the real state (macOS rate-limits the `profiles`
//     family to roughly one call per 23 hours, and the agent then serves a
//     cached list rather than failing the run). Such a snapshot is stored,
//     flagged, and rejected outright as a diff input by Diff.
//   - ProfilesTruncated — more profiles exist than the agent's array cap
//     reports, so a profile missing from the list may simply be past the
//     cap. Diff suppresses exactly the conclusions that would be unsound
//     (see DiffNotes.SuppressedByTruncation) and reports the rest.
//   - The device stopped reporting entirely — there is no new snapshot at
//     all. That produces no change entries, because there is nothing new to
//     compare; see LatestPairs, which will not pair a device that has not
//     run since the caller's cutoff.
//
// A collection that failed and a device that never ran are different
// situations and stay distinguishable: the first is a stored snapshot with
// a non-ok CollectionStatus, the second is the absence of a snapshot row.
package appliedconfig

import "time"

// ObservationKind labels every row this package emits. It is a constant, not
// a field a caller can set, so no output of this package can ever be
// presented as anything other than configuration observed on a device.
const ObservationKind = "applied_configuration"

// CollectionStatus is the agent's own verdict on whether this run managed to
// read the device's real configuration state.
type CollectionStatus string

const (
	// CollectionOK means `profiles list` returned a parseable result this
	// run. Only an ok snapshot is a sound diff input.
	CollectionOK CollectionStatus = "ok"

	// CollectionRateLimited means macOS refused the call because one was
	// made too recently. The agent served its last-known-good cache
	// instead, so the profile list in such a snapshot is stale by an
	// unknown amount and must never be read as current state.
	CollectionRateLimited CollectionStatus = "rate_limited"

	// CollectionUnavailable means the call failed for any other reason
	// (unparseable output, a changed macOS output format, a missing tool).
	// Same rule as rate_limited: stored, never diffed.
	CollectionUnavailable CollectionStatus = "unavailable"
)

// NormaliseCollectionStatus maps a raw wire value onto a known status. An
// unrecognised value becomes CollectionUnavailable rather than CollectionOK:
// a status this code does not understand is not evidence that collection
// succeeded, and the conservative reading is the only one that cannot
// manufacture a false mass-removal signal. The second return says whether
// the input was recognised, so a caller can log the raw value it dropped.
func NormaliseCollectionStatus(raw string) (CollectionStatus, bool) {
	switch CollectionStatus(raw) {
	case CollectionOK:
		return CollectionOK, true
	case CollectionRateLimited:
		return CollectionRateLimited, true
	case CollectionUnavailable:
		return CollectionUnavailable, true
	default:
		return CollectionUnavailable, false
	}
}

// Supervision mirrors the agent's mdm_supervised field, which comes from an
// undocumented Apple tool and is explicitly allowed to be unknown.
type Supervision string

const (
	SupervisedYes     Supervision = "Yes"
	SupervisedNo      Supervision = "No"
	SupervisedUnknown Supervision = "Unknown"
)

// NormaliseSupervision maps a raw wire value onto a known supervision state,
// defaulting to SupervisedUnknown. The second return says whether the input
// was recognised.
func NormaliseSupervision(raw string) (Supervision, bool) {
	switch Supervision(raw) {
	case SupervisedYes:
		return SupervisedYes, true
	case SupervisedNo:
		return SupervisedNo, true
	case SupervisedUnknown:
		return SupervisedUnknown, true
	default:
		return SupervisedUnknown, false
	}
}

// Profile is one device-scope configuration profile as observed on a Mac.
//
// Payload is the profile's serialised payload items exactly as the agent
// sent them — a JSON document in the ordinary case, but head-capped to a
// fixed byte budget when the profile is large, in which case it is a
// truncated fragment that will not parse. It is deliberately carried as a
// string rather than a parsed structure, and stored verbatim, because a
// reparse is lossy and because the capped case has no valid parse at all.
//
// DecodeError marks a profile whose payload the agent itself could not
// serialise. The profile is genuinely present on the device — that part is
// observed — but its payload content is unknown, and this package never
// reads an unknown payload as an empty one.
type Profile struct {
	Identifier    string
	DisplayName   string
	Organization  string
	Payload       string
	PayloadCapped bool
	DecodeError   bool
}

// Snapshot is one device's applied configuration as observed in one
// collection run. It is immutable evidence: a later run is always a new
// Snapshot, never an edit of this one.
type Snapshot struct {
	TenantID string
	DeviceID string

	// ObservedAt is the agent's own collected_at for the run — when the
	// device looked like this, not when the server heard about it.
	ObservedAt time.Time

	CollectionStatus CollectionStatus

	// ProfilesCount is the count the agent reported. It can exceed
	// len(Profiles) when the agent's array cap truncated the list, which is
	// exactly what ProfilesTruncated flags.
	ProfilesCount     int
	ProfilesTruncated bool

	// MDMServerURL is the enrolled management server, empty when the Mac is
	// not enrolled. It is the only attribution this package offers: it says
	// which platform manages the device, never which policy produced a
	// profile.
	MDMServerURL  string
	MDMSupervised Supervision

	Profiles []Profile
}
