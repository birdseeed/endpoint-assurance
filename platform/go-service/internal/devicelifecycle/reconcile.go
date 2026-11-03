// Package devicelifecycle implements the pure reconciliation and lifecycle
// state logic for PAT-1595, with no DB dependency. Handlers in
// internal/handlers/device_lifecycle.go call these functions with rows
// already fetched from Postgres; that keeps the three-bucket reconciliation
// and six-state classification — the two behaviours the ticket calls out
// for boundary-case unit tests — testable without a live database, matching
// this codebase's convention of table-driven unit tests for pure functions
// (see internal/evaluator).
//
// Principle this package exists to hold: Patched is never the authority on
// what devices exist, only on what it observed and when. Nothing here
// treats an absence of agent evidence as proof of anything — see
// ClassifyState.
package devicelifecycle

import (
	"strings"
	"time"
)

// UploadedDevice is one entry from a tenant's uploaded device list.
type UploadedDevice struct {
	ExternalID string
	Serial     string
	HWUUID     string
	Hostname   string
}

// ObservedDevice is one device the agent has itself reported — a row from
// the devices table.
type ObservedDevice struct {
	ID       string
	Serial   string
	HWUUID   string
	Hostname string
	LastSeen time.Time
}

// Bucket is which of the three reconciliation buckets a device falls into.
type Bucket string

const (
	// BucketNormal: on the uploaded list AND seen by the agent.
	BucketNormal Bucket = "normal"
	// BucketCoverageGap: on the uploaded list, never seen by the agent —
	// the number that sells the assessment.
	BucketCoverageGap Bucket = "coverage_gap"
	// BucketUntracked: seen by the agent, not on the uploaded list — usually
	// the finding an assessor cares about most.
	BucketUntracked Bucket = "untracked"
)

// MatchedDevice pairs an uploaded list entry with the observed device it
// matched to.
type MatchedDevice struct {
	Uploaded UploadedDevice
	Observed ObservedDevice
}

// ReconciliationResult is the three-bucket split, plus uploaded rows this
// could not even attempt to match (no usable identifier at all). Unmatchable
// rows are never silently dropped — a bad upload row still needs to be
// visible as a data-quality problem, not disappear.
type ReconciliationResult struct {
	Normal      []MatchedDevice
	CoverageGap []UploadedDevice
	Untracked   []ObservedDevice
	Unmatchable []UploadedDevice
}

// matchKey returns the strongest available identifier for a device,
// lower-cased and trimmed, or "" if none is usable. hw_uuid is preferred
// over serial over hostname — the same "strongest identifier first, no
// fuzzy fallback" rule PAT-1801's protected_software matching uses: a
// device that matches nothing on this key is never guessed at.
func matchKey(hwUUID, serial, hostname string) string {
	for _, v := range []string{hwUUID, serial, hostname} {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			return v
		}
	}
	return ""
}

// Reconcile splits an uploaded device list against the agent's own observed
// devices into the three buckets required by PAT-1595 item 2. Every
// uploaded row and every observed row is accounted for in exactly one
// output slice (Unmatchable is the sole exception, for rows with no usable
// identifier at all).
func Reconcile(uploaded []UploadedDevice, observed []ObservedDevice) ReconciliationResult {
	byKey := make(map[string]ObservedDevice, len(observed))
	for _, o := range observed {
		if k := matchKey(o.HWUUID, o.Serial, o.Hostname); k != "" {
			byKey[k] = o
		}
	}

	var res ReconciliationResult
	matched := make(map[string]bool, len(uploaded))
	for _, u := range uploaded {
		k := matchKey(u.HWUUID, u.Serial, u.Hostname)
		if k == "" {
			res.Unmatchable = append(res.Unmatchable, u)
			continue
		}
		if o, ok := byKey[k]; ok {
			res.Normal = append(res.Normal, MatchedDevice{Uploaded: u, Observed: o})
			matched[k] = true
		} else {
			res.CoverageGap = append(res.CoverageGap, u)
		}
	}
	for _, o := range observed {
		k := matchKey(o.HWUUID, o.Serial, o.Hostname)
		if k != "" && matched[k] {
			continue
		}
		res.Untracked = append(res.Untracked, o)
	}
	return res
}

// State is one of the six PAT-1595 device lifecycle states.
type State string

const (
	StateReporting State = "reporting"
	StateQuiet     State = "quiet"
	StateStale     State = "stale"
	StateDormant   State = "dormant"
	StateRemoved   State = "removed"
	StateNeverSeen State = "never_seen"
)

// Thresholds are the tenant-overridable day boundaries between states.
type Thresholds struct {
	QuietDays   int
	StaleDays   int
	DormantDays int
}

// DefaultThresholds must stay in sync with the CHECK constraint in
// migrations/0140_device_lifecycle.sql: quiet at 3 days, stale at 14 (the
// Cyber Essentials v3.3 patching window, deliberate), dormant at 45.
func DefaultThresholds() Thresholds {
	return Thresholds{QuietDays: 3, StaleDays: 14, DormantDays: 45}
}

// ClassifyState assigns one of the six lifecycle states.
//
// neverSeen is true when the device is on the uploaded list but the agent
// has no observed row for it at all — a CoverageGap device with no
// ObservedDevice. That is distinct from "removed", which requires something
// to have been actively said about a device the agent HAS seen before.
//
// activeDisposition is true when an un-superseded disposition record exists
// for this device saying it is decommissioned, on leave, lost or
// unaccounted for. No caller in this codebase sets it true yet — the
// disposition-record table (PAT-1595 item 4) is a deferred follow-up — but
// the state and the parameter are reserved now so that follow-up does not
// need to touch this signature or its tests.
//
// Absence of last-seen evidence never classifies as "reporting" or any
// state that could read as healthy (root AGENTS.md "Absence requires
// authority"): a device this cannot see is either neverSeen, or if the
// agent has gone silent past every threshold, dormant — never silently
// promoted to compliant.
func ClassifyState(lastSeen *time.Time, now time.Time, neverSeen, activeDisposition bool, t Thresholds) State {
	if neverSeen || lastSeen == nil {
		return StateNeverSeen
	}
	if activeDisposition {
		return StateRemoved
	}
	age := now.Sub(*lastSeen)
	switch {
	case age < time.Duration(t.QuietDays)*24*time.Hour:
		return StateReporting
	case age < time.Duration(t.StaleDays)*24*time.Hour:
		return StateQuiet
	case age < time.Duration(t.DormantDays)*24*time.Hour:
		return StateStale
	default:
		return StateDormant
	}
}

// ReappearedSince reports whether a device has been observed again after a
// disposition was recorded for it — the trigger for the PAT-1595 item 5
// reappearance rule: a device someone certified gone being back on the
// network is a finding, not something to silently re-absorb into
// "reporting". Exposed now, ahead of the disposition table it will read
// from, so the follow-up ticket that adds that table can reuse this
// boundary logic (and its tests) unchanged.
func ReappearedSince(lastSeen *time.Time, dispositionRecordedAt time.Time) bool {
	return lastSeen != nil && lastSeen.After(dispositionRecordedAt)
}
