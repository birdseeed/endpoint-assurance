package appliedconfig

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrTenantMismatch is returned by Rollup when a change set belongs to a
// different tenant than the one being rolled up. Grouping across tenants
// would put one customer's devices in another's finding.
var ErrTenantMismatch = errors.New("appliedconfig: every change set in a rollup must belong to the same tenant")

// DeviceObservation is one device's contribution to a grouped finding: which
// device, and the window the change was observed between on that device.
// Each device has its own window, because each device reports on its own
// schedule — collapsing them into one estate-wide timestamp would invent
// precision that does not exist.
type DeviceObservation struct {
	DeviceID             string
	ObservedBetweenStart time.Time
	ObservedBetweenEnd   time.Time

	// MDMServerURL is the management server this device was enrolled with
	// at the later observation, empty when unenrolled.
	MDMServerURL string
}

// ProfileChangeGroup is one grouped finding: the same profile changing the
// same way across however many devices observed it.
//
// Grouping is by (ProfileIdentifier, Kind). A profile that changed payload on
// forty Macs is one group with forty affected devices, not forty findings.
// A profile that appeared on some Macs and disappeared from others in the
// same window is two groups, because those are two different observations
// and merging them would describe neither.
type ProfileChangeGroup struct {
	// ObservationKind is always ObservationKind ("applied_configuration").
	ObservationKind string

	ProfileIdentifier string
	Kind              ChangeKind

	// DisplayName is the name carried by the most recently observed device
	// in this group. Profiles can be renamed, and different Macs can be
	// mid-rollout, so this is a label for the reader, not an identity.
	DisplayName string

	AffectedDeviceCount int

	// AffectedDevices is sorted by DeviceID. It is the full list, not a
	// sample: a grouped finding that cannot name its devices is not
	// actionable.
	AffectedDevices []DeviceObservation

	// MDMServerURLs is the distinct, sorted set of management servers the
	// affected devices were enrolled with. This is the attribution this
	// package offers — which platform manages the Macs that changed — and
	// it is a set rather than a single value because an estate can have
	// more than one. An empty string entry is omitted; UnenrolledDevices
	// counts those instead, so "no MDM" is never silently rendered as "no
	// attribution available".
	MDMServerURLs []string

	// UnenrolledDevices counts affected devices with no MDM server URL.
	UnenrolledDevices int

	// EarliestObservedStart and LatestObservedEnd bound every affected
	// device's window. They are not a change time: the change happened
	// somewhere inside each device's own window, and this pair only says
	// where all of those windows sit.
	EarliestObservedStart time.Time
	LatestObservedEnd     time.Time

	// PayloadCappedOnAnyDevice is true when at least one affected device's
	// comparison was bounded by the agent's payload cap.
	PayloadCappedOnAnyDevice bool
}

// EstateReport is the estate-wide rollup for one tenant.
type EstateReport struct {
	// ObservationKind is always ObservationKind.
	ObservationKind string

	TenantID string

	// ConsideredFrom is the cutoff the caller asked for: only devices whose
	// newest ok collection run happened at or after this instant were
	// eligible to contribute. A device that stopped reporting before this
	// point contributes nothing — not an empty result, no entries at all.
	// Zero when the caller supplied change sets directly.
	ConsideredFrom time.Time

	// DeviceChangeSets holds the per-device detail behind the groups,
	// sorted by DeviceID. Only devices with at least one change appear.
	DeviceChangeSets []DeviceChangeSet

	// Groups is sorted by (ProfileIdentifier, Kind).
	Groups []ProfileChangeGroup

	// DevicesWithChanges is the number of devices contributing at least one
	// change entry.
	DevicesWithChanges int

	// DevicesCompared is the number of devices that had two ok snapshots to
	// compare, whether or not anything changed. The gap between this and
	// DevicesWithChanges is how many Macs were checked and found unchanged
	// — without it, "three findings" reads the same whether three Macs or
	// three hundred were looked at.
	DevicesCompared int
}

// SnapshotPair is two ok snapshots of one device, ordered.
type SnapshotPair struct {
	Prior   Snapshot
	Current Snapshot
}

// LatestPairs selects, for each device present in snapshots, the newest ok
// snapshot and the newest ok snapshot observed strictly before it — the pair
// Diff should be given for that device.
//
// A device is skipped entirely, contributing no pair and therefore no change
// entries, when any of the following holds:
//
//   - it has fewer than two ok snapshots (nothing to compare against);
//   - its newest ok snapshot was observed before since (it has not produced
//     a new collection run in the window the caller cares about — a device
//     that stopped reporting must never look like one that lost every
//     profile);
//   - its snapshots are all non-ok (collection ran but could not read state).
//
// Non-ok snapshots are filtered out here rather than being paired and
// rejected later, so a run of rate-limited collections never displaces the
// last good baseline. Pass the zero time for since to consider every
// device's newest run regardless of age.
//
// The returned slice is sorted by DeviceID.
func LatestPairs(snapshots []Snapshot, since time.Time) []SnapshotPair {
	byDevice := map[string][]Snapshot{}
	for _, s := range snapshots {
		if s.CollectionStatus != CollectionOK {
			continue
		}
		byDevice[s.DeviceID] = append(byDevice[s.DeviceID], s)
	}

	pairs := make([]SnapshotPair, 0, len(byDevice))
	for _, snaps := range byDevice {
		if len(snaps) < 2 {
			continue
		}
		// Newest first. Ties on ObservedAt keep a stable, deterministic
		// order so the same input always yields the same pair.
		sort.SliceStable(snaps, func(i, j int) bool {
			return snaps[i].ObservedAt.After(snaps[j].ObservedAt)
		})
		current := snaps[0]
		if !since.IsZero() && current.ObservedAt.Before(since) {
			continue
		}
		var prior *Snapshot
		for i := 1; i < len(snaps); i++ {
			if snaps[i].ObservedAt.Before(current.ObservedAt) {
				prior = &snaps[i]
				break
			}
		}
		if prior == nil {
			continue
		}
		pairs = append(pairs, SnapshotPair{Prior: *prior, Current: current})
	}

	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Current.DeviceID < pairs[j].Current.DeviceID })
	return pairs
}

// EstateChanges is the whole per-tenant pass: pick each device's comparable
// pair of observations, diff them, and roll the results up into grouped
// findings.
//
// It is a plain callable function with no scheduler behind it. When it runs
// is the caller's business; PAT-1668 deliberately does not add a timer.
func EstateChanges(tenantID string, snapshots []Snapshot, since time.Time) (EstateReport, error) {
	pairs := LatestPairs(snapshots, since)

	sets := make([]DeviceChangeSet, 0, len(pairs))
	for _, p := range pairs {
		if p.Current.TenantID != tenantID || p.Prior.TenantID != tenantID {
			return EstateReport{}, fmt.Errorf("%w: device %s is in tenant %q, not %q",
				ErrTenantMismatch, p.Current.DeviceID, p.Current.TenantID, tenantID)
		}
		set, err := Diff(p.Prior, p.Current)
		if err != nil {
			return EstateReport{}, fmt.Errorf("appliedconfig: device %s: %w", p.Current.DeviceID, err)
		}
		sets = append(sets, set)
	}

	report, err := Rollup(tenantID, sets)
	if err != nil {
		return EstateReport{}, err
	}
	report.ConsideredFrom = since
	report.DevicesCompared = len(pairs)
	return report, nil
}

// Rollup groups per-device change sets into estate-wide findings.
//
// It is a grouping step over Diff's output, not a change to it: every
// per-device entry survives intact in DeviceChangeSets, and the groups are
// an additional view over them. That separation is what keeps a grouped
// finding from becoming the only record of what any individual Mac observed.
func Rollup(tenantID string, sets []DeviceChangeSet) (EstateReport, error) {
	type groupKey struct {
		identifier string
		kind       ChangeKind
	}

	groups := map[groupKey]*ProfileChangeGroup{}
	// mdmSeen tracks which server URLs a group has already recorded, so
	// MDMServerURLs stays a set without a second pass.
	mdmSeen := map[groupKey]map[string]bool{}
	// latestName remembers which observation supplied a group's display
	// name, so the newest one wins deterministically.
	latestName := map[groupKey]time.Time{}

	withChanges := 0
	kept := make([]DeviceChangeSet, 0, len(sets))

	for _, set := range sets {
		if set.TenantID != tenantID {
			return EstateReport{}, fmt.Errorf("%w: device %s is in tenant %q, not %q",
				ErrTenantMismatch, set.DeviceID, set.TenantID, tenantID)
		}
		if len(set.Changes) == 0 {
			continue
		}
		withChanges++
		kept = append(kept, set)

		for _, ch := range set.Changes {
			for _, kind := range ch.Kinds {
				key := groupKey{identifier: ch.ProfileIdentifier, kind: kind}
				g, exists := groups[key]
				if !exists {
					g = &ProfileChangeGroup{
						ObservationKind:       ObservationKind,
						ProfileIdentifier:     ch.ProfileIdentifier,
						Kind:                  kind,
						DisplayName:           ch.DisplayName,
						EarliestObservedStart: ch.ObservedBetweenStart,
						LatestObservedEnd:     ch.ObservedBetweenEnd,
					}
					groups[key] = g
					mdmSeen[key] = map[string]bool{}
					latestName[key] = ch.ObservedBetweenEnd
				}

				g.AffectedDevices = append(g.AffectedDevices, DeviceObservation{
					DeviceID:             ch.DeviceID,
					ObservedBetweenStart: ch.ObservedBetweenStart,
					ObservedBetweenEnd:   ch.ObservedBetweenEnd,
					MDMServerURL:         ch.MDMServerURL,
				})
				if ch.PayloadCapped {
					g.PayloadCappedOnAnyDevice = true
				}
				if ch.MDMServerURL == "" {
					g.UnenrolledDevices++
				} else if !mdmSeen[key][ch.MDMServerURL] {
					mdmSeen[key][ch.MDMServerURL] = true
					g.MDMServerURLs = append(g.MDMServerURLs, ch.MDMServerURL)
				}
				if ch.ObservedBetweenStart.Before(g.EarliestObservedStart) {
					g.EarliestObservedStart = ch.ObservedBetweenStart
				}
				if ch.ObservedBetweenEnd.After(g.LatestObservedEnd) {
					g.LatestObservedEnd = ch.ObservedBetweenEnd
				}
				if ch.ObservedBetweenEnd.After(latestName[key]) && ch.DisplayName != "" {
					latestName[key] = ch.ObservedBetweenEnd
					g.DisplayName = ch.DisplayName
				}
			}
		}
	}

	out := make([]ProfileChangeGroup, 0, len(groups))
	for _, g := range groups {
		sort.Slice(g.AffectedDevices, func(i, j int) bool {
			return g.AffectedDevices[i].DeviceID < g.AffectedDevices[j].DeviceID
		})
		sort.Strings(g.MDMServerURLs)
		g.AffectedDeviceCount = len(g.AffectedDevices)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProfileIdentifier != out[j].ProfileIdentifier {
			return out[i].ProfileIdentifier < out[j].ProfileIdentifier
		}
		return kindOrder[out[i].Kind] < kindOrder[out[j].Kind]
	})

	sort.Slice(kept, func(i, j int) bool { return kept[i].DeviceID < kept[j].DeviceID })

	return EstateReport{
		ObservationKind:    ObservationKind,
		TenantID:           tenantID,
		DeviceChangeSets:   kept,
		Groups:             out,
		DevicesWithChanges: withChanges,
		DevicesCompared:    len(sets),
	}, nil
}
