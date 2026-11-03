package appliedconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// deviceSnapshot builds an ok snapshot for a named device.
func deviceSnapshot(deviceID string, observedAt time.Time, mdmURL string, profiles ...Profile) Snapshot {
	return Snapshot{
		TenantID:         tenantA,
		DeviceID:         deviceID,
		ObservedAt:       observedAt,
		CollectionStatus: CollectionOK,
		ProfilesCount:    len(profiles),
		MDMServerURL:     mdmURL,
		MDMSupervised:    SupervisedYes,
		Profiles:         profiles,
	}
}

// ── Acceptance: one grouped finding across many devices ──────────────────────

// TestEstateChanges_OneGroupedFindingAcrossManyDevices is the criterion
// verbatim: the same profile changing on N devices is ONE finding with an
// affected-device count and list, not N findings.
func TestEstateChanges_OneGroupedFindingAcrossManyDevices(t *testing.T) {
	const deviceCount = 40

	var snaps []Snapshot
	for i := 0; i < deviceCount; i++ {
		id := fmt.Sprintf("dddddddd-0000-0000-0000-%012d", i)
		// Each Mac reports on its own schedule, so each has its own window.
		prior := t1.Add(time.Duration(i) * time.Minute)
		current := t2.Add(time.Duration(i) * time.Minute)
		snaps = append(snaps,
			deviceSnapshot(id, prior, mdmJamf, profileFirewall(fwPayload)),
			deviceSnapshot(id, current, mdmJamf, profileFirewall(fwPayloadChanged)),
		)
	}

	report, err := EstateChanges(tenantA, snaps, time.Time{})
	if err != nil {
		t.Fatalf("EstateChanges: %v", err)
	}

	if len(report.Groups) != 1 {
		t.Fatalf("got %d groups, want exactly 1 grouped finding: %+v", len(report.Groups), report.Groups)
	}
	g := report.Groups[0]
	if g.ProfileIdentifier != "org.example.firewall" || g.Kind != ProfilePayloadChanged {
		t.Errorf("group = (%s, %s), want (org.example.firewall, profile_payload_changed)", g.ProfileIdentifier, g.Kind)
	}
	if g.AffectedDeviceCount != deviceCount {
		t.Errorf("affected device count = %d, want %d", g.AffectedDeviceCount, deviceCount)
	}
	if len(g.AffectedDevices) != deviceCount {
		t.Fatalf("affected device list has %d entries, want %d", len(g.AffectedDevices), deviceCount)
	}
	// Each affected device keeps its own window; the group only bounds them.
	for _, d := range g.AffectedDevices {
		if d.DeviceID == "" || d.ObservedBetweenStart.IsZero() || d.ObservedBetweenEnd.IsZero() {
			t.Errorf("affected device entry is incomplete: %+v", d)
		}
		if d.ObservedBetweenStart.Before(g.EarliestObservedStart) || d.ObservedBetweenEnd.After(g.LatestObservedEnd) {
			t.Errorf("device window %+v falls outside the group bounds (%s, %s)",
				d, g.EarliestObservedStart, g.LatestObservedEnd)
		}
	}
	// Attribution without a policy name.
	if !reflect.DeepEqual(g.MDMServerURLs, []string{mdmJamf}) {
		t.Errorf("MDMServerURLs = %v, want [%s]", g.MDMServerURLs, mdmJamf)
	}
	if g.UnenrolledDevices != 0 {
		t.Errorf("UnenrolledDevices = %d, want 0", g.UnenrolledDevices)
	}

	if report.DevicesWithChanges != deviceCount {
		t.Errorf("DevicesWithChanges = %d, want %d", report.DevicesWithChanges, deviceCount)
	}
	if report.DevicesCompared != deviceCount {
		t.Errorf("DevicesCompared = %d, want %d", report.DevicesCompared, deviceCount)
	}
	// The per-device detail survives grouping.
	if len(report.DeviceChangeSets) != deviceCount {
		t.Errorf("DeviceChangeSets = %d, want %d", len(report.DeviceChangeSets), deviceCount)
	}
}

// TestRollup_DifferentKindsOfTheSameProfileStaySeparate: a profile that
// appeared on some Macs and vanished from others in the same window is two
// findings. Merging them would describe neither.
func TestRollup_DifferentKindsOfTheSameProfileStaySeparate(t *testing.T) {
	appeared, err := Diff(
		deviceSnapshot(deviceA, t1, mdmJamf),
		deviceSnapshot(deviceA, t2, mdmJamf, profilePasscode()),
	)
	if err != nil {
		t.Fatalf("Diff A: %v", err)
	}
	vanished, err := Diff(
		deviceSnapshot(deviceB, t1, mdmIntne, profilePasscode()),
		deviceSnapshot(deviceB, t2, mdmIntne),
	)
	if err != nil {
		t.Fatalf("Diff B: %v", err)
	}

	report, err := Rollup(tenantA, []DeviceChangeSet{appeared, vanished})
	if err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	if len(report.Groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(report.Groups), report.Groups)
	}
	for _, g := range report.Groups {
		if g.AffectedDeviceCount != 1 {
			t.Errorf("group %s/%s has %d devices, want 1", g.ProfileIdentifier, g.Kind, g.AffectedDeviceCount)
		}
	}
	// Sorted by identifier then by the fixed kind order: appeared before
	// no-longer-present.
	if report.Groups[0].Kind != ProfileAppeared || report.Groups[1].Kind != ProfileNoLongerPresent {
		t.Errorf("group order = [%s %s], want [profile_appeared profile_no_longer_present]",
			report.Groups[0].Kind, report.Groups[1].Kind)
	}
}

// TestRollup_MultiKindEntryJoinsEveryMatchingGroup: an entry carrying two
// kinds contributes to both groups, so neither undercounts.
func TestRollup_MultiKindEntryJoinsEveryMatchingGroup(t *testing.T) {
	before := profileFirewall(fwPayload)
	after := profileFirewall(fwPayloadChanged)
	after.DisplayName = "Firewall (v2)"

	set, err := Diff(deviceSnapshot(deviceA, t1, mdmJamf, before), deviceSnapshot(deviceA, t2, mdmJamf, after))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 || len(set.Changes[0].Kinds) != 2 {
		t.Fatalf("expected one entry with two kinds, got %+v", set.Changes)
	}

	report, err := Rollup(tenantA, []DeviceChangeSet{set})
	if err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	if len(report.Groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per kind): %+v", len(report.Groups), report.Groups)
	}
	if report.DevicesWithChanges != 1 {
		t.Errorf("DevicesWithChanges = %d, want 1 — the device must not be counted twice", report.DevicesWithChanges)
	}
}

// TestRollup_MixedManagementPlatformsAreBothAttributed: the same profile
// identifier changing on Macs managed by two different servers is still one
// finding, and it names both servers rather than picking one.
func TestRollup_MixedManagementPlatformsAreBothAttributed(t *testing.T) {
	var sets []DeviceChangeSet
	for _, tc := range []struct{ device, mdm string }{
		{deviceA, mdmJamf},
		{deviceB, mdmIntne},
		{deviceC, ""}, // unenrolled
	} {
		set, err := Diff(
			deviceSnapshot(tc.device, t1, tc.mdm, profileFirewall(fwPayload)),
			deviceSnapshot(tc.device, t2, tc.mdm, profileFirewall(fwPayloadChanged)),
		)
		if err != nil {
			t.Fatalf("Diff %s: %v", tc.device, err)
		}
		sets = append(sets, set)
	}

	report, err := Rollup(tenantA, sets)
	if err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	if len(report.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(report.Groups))
	}
	g := report.Groups[0]
	if g.AffectedDeviceCount != 3 {
		t.Errorf("affected devices = %d, want 3", g.AffectedDeviceCount)
	}
	if !reflect.DeepEqual(g.MDMServerURLs, []string{mdmIntne, mdmJamf}) {
		t.Errorf("MDMServerURLs = %v, want both servers sorted", g.MDMServerURLs)
	}
	if g.UnenrolledDevices != 1 {
		t.Errorf("UnenrolledDevices = %d, want 1 — an unenrolled Mac must not silently vanish from attribution", g.UnenrolledDevices)
	}
}

// ── Acceptance: a device that stopped reporting produces zero entries ────────

func TestEstateChanges_DeviceThatStoppedReportingProducesNoEntries(t *testing.T) {
	// deviceA is still reporting and genuinely changed.
	// deviceB has plenty of history but its last run predates the cutoff:
	// it stopped reporting. It must contribute nothing at all — not an
	// empty change set, not a "lost every profile" finding.
	snaps := []Snapshot{
		deviceSnapshot(deviceA, t1, mdmJamf, profileFirewall(fwPayload)),
		deviceSnapshot(deviceA, t2, mdmJamf, profileFirewall(fwPayloadChanged)),

		deviceSnapshot(deviceB, t0.Add(-48*time.Hour), mdmJamf, profileFirewall(fwPayload), profilePasscode()),
		deviceSnapshot(deviceB, t0.Add(-24*time.Hour), mdmJamf, profileFirewall(fwPayload), profilePasscode()),
	}

	report, err := EstateChanges(tenantA, snaps, t1)
	if err != nil {
		t.Fatalf("EstateChanges: %v", err)
	}
	if report.DevicesCompared != 1 {
		t.Errorf("DevicesCompared = %d, want 1 — the silent device must not be compared at all", report.DevicesCompared)
	}
	for _, g := range report.Groups {
		for _, d := range g.AffectedDevices {
			if d.DeviceID == deviceB {
				t.Errorf("the device that stopped reporting appears in group %s/%s", g.ProfileIdentifier, g.Kind)
			}
		}
	}
	if len(report.Groups) != 1 || report.Groups[0].ProfileIdentifier != "org.example.firewall" {
		t.Errorf("groups = %+v, want only deviceA's firewall change", report.Groups)
	}
	if !report.ConsideredFrom.Equal(t1) {
		t.Errorf("ConsideredFrom = %s, want %s", report.ConsideredFrom, t1)
	}
}

// TestLatestPairs_SkipsDeviceWithOnlyOneObservation: a Mac that has reported
// exactly once has no baseline, so its entire profile list is not "every
// profile appeared".
func TestLatestPairs_SkipsDeviceWithOnlyOneObservation(t *testing.T) {
	snaps := []Snapshot{deviceSnapshot(deviceA, t2, mdmJamf, profileFirewall(fwPayload))}
	if pairs := LatestPairs(snaps, time.Time{}); len(pairs) != 0 {
		t.Errorf("got %d pairs from a single observation, want 0: %+v", len(pairs), pairs)
	}
}

// TestLatestPairs_FailedRunsNeverDisplaceTheBaseline: a burst of rate-limited
// runs between two good ones must not push the last good observation out of
// the comparison, and must never itself be paired.
func TestLatestPairs_FailedRunsNeverDisplaceTheBaseline(t *testing.T) {
	failed := func(at time.Time, status CollectionStatus) Snapshot {
		s := deviceSnapshot(deviceA, at, mdmJamf, profileFirewall(fwPayload))
		s.CollectionStatus = status
		return s
	}
	snaps := []Snapshot{
		deviceSnapshot(deviceA, t0, mdmJamf, profileFirewall(fwPayload)),
		failed(t0.Add(6*time.Hour), CollectionRateLimited),
		failed(t0.Add(12*time.Hour), CollectionUnavailable),
		failed(t1, CollectionRateLimited),
		deviceSnapshot(deviceA, t2, mdmJamf, profileFirewall(fwPayloadChanged)),
	}

	pairs := LatestPairs(snaps, time.Time{})
	if len(pairs) != 1 {
		t.Fatalf("got %d pairs, want 1: %+v", len(pairs), pairs)
	}
	if !pairs[0].Prior.ObservedAt.Equal(t0) || !pairs[0].Current.ObservedAt.Equal(t2) {
		t.Errorf("pair = (%s, %s), want the two ok observations (%s, %s)",
			pairs[0].Prior.ObservedAt, pairs[0].Current.ObservedAt, t0, t2)
	}
	if pairs[0].Prior.CollectionStatus != CollectionOK || pairs[0].Current.CollectionStatus != CollectionOK {
		t.Error("a non-ok snapshot reached a diff pair")
	}
}

// TestLatestPairs_AllRunsFailedYieldsNoPair: a Mac whose every recent
// collection failed is checked and found uncomparable, not diffed against a
// cached list.
func TestLatestPairs_AllRunsFailedYieldsNoPair(t *testing.T) {
	failed := func(at time.Time) Snapshot {
		s := deviceSnapshot(deviceA, at, mdmJamf)
		s.CollectionStatus = CollectionRateLimited
		return s
	}
	snaps := []Snapshot{failed(t0), failed(t1), failed(t2)}
	if pairs := LatestPairs(snaps, time.Time{}); len(pairs) != 0 {
		t.Errorf("got %d pairs from all-failed collections, want 0", len(pairs))
	}
}

// ── Determinism and validation ───────────────────────────────────────────────

func TestEstateChanges_IsDeterministic(t *testing.T) {
	var snaps []Snapshot
	// Deliberately interleaved and out of device order.
	for _, d := range []string{deviceC, deviceA, deviceB} {
		snaps = append(snaps,
			deviceSnapshot(d, t2, mdmJamf, profileFirewall(fwPayloadChanged), profilePasscode()),
			deviceSnapshot(d, t1, mdmJamf, profileFirewall(fwPayload)),
		)
	}

	first, err := EstateChanges(tenantA, snaps, time.Time{})
	if err != nil {
		t.Fatalf("EstateChanges: %v", err)
	}
	firstJSON, _ := json.Marshal(first)
	for i := 0; i < 20; i++ {
		again, err := EstateChanges(tenantA, snaps, time.Time{})
		if err != nil {
			t.Fatalf("EstateChanges (run %d): %v", i, err)
		}
		againJSON, _ := json.Marshal(again)
		if string(firstJSON) != string(againJSON) {
			t.Fatalf("EstateChanges is not deterministic.\nrun 0: %s\nrun %d: %s", firstJSON, i, againJSON)
		}
	}

	var ids []string
	for _, g := range first.Groups {
		ids = append(ids, string(g.Kind)+"/"+g.ProfileIdentifier)
	}
	want := []string{
		string(ProfilePayloadChanged) + "/org.example.firewall",
		string(ProfileAppeared) + "/org.example.passcode",
	}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("groups = %v, want %v", ids, want)
	}
	for _, g := range first.Groups {
		var devices []string
		for _, d := range g.AffectedDevices {
			devices = append(devices, d.DeviceID)
		}
		if !reflect.DeepEqual(devices, []string{deviceA, deviceB, deviceC}) {
			t.Errorf("group %s device list = %v, want sorted", g.ProfileIdentifier, devices)
		}
	}
}

func TestRollup_RejectsCrossTenantChangeSets(t *testing.T) {
	set, err := Diff(
		deviceSnapshot(deviceA, t1, mdmJamf, profileFirewall(fwPayload)),
		deviceSnapshot(deviceA, t2, mdmJamf, profileFirewall(fwPayloadChanged)),
	)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if _, err := Rollup("22222222-2222-2222-2222-222222222222", []DeviceChangeSet{set}); !errors.Is(err, ErrTenantMismatch) {
		t.Errorf("error = %v, want ErrTenantMismatch", err)
	}
}

func TestRollup_UnchangedDevicesAreCountedButNotGrouped(t *testing.T) {
	changed, err := Diff(
		deviceSnapshot(deviceA, t1, mdmJamf, profileFirewall(fwPayload)),
		deviceSnapshot(deviceA, t2, mdmJamf, profileFirewall(fwPayloadChanged)),
	)
	if err != nil {
		t.Fatalf("Diff A: %v", err)
	}
	unchanged, err := Diff(
		deviceSnapshot(deviceB, t1, mdmJamf, profileFirewall(fwPayload)),
		deviceSnapshot(deviceB, t2, mdmJamf, profileFirewall(fwPayload)),
	)
	if err != nil {
		t.Fatalf("Diff B: %v", err)
	}

	report, err := Rollup(tenantA, []DeviceChangeSet{changed, unchanged})
	if err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	if report.DevicesWithChanges != 1 {
		t.Errorf("DevicesWithChanges = %d, want 1", report.DevicesWithChanges)
	}
	// The denominator matters: "one finding" reads very differently
	// depending on how many Macs were actually looked at.
	if report.DevicesCompared != 2 {
		t.Errorf("DevicesCompared = %d, want 2", report.DevicesCompared)
	}
	if len(report.DeviceChangeSets) != 1 {
		t.Errorf("DeviceChangeSets = %d, want only the device that changed", len(report.DeviceChangeSets))
	}
}

// TestNormaliseCollectionStatus_UnknownIsConservative: a status this code
// does not recognise must never be read as a successful collection.
func TestNormaliseCollectionStatus_UnknownIsConservative(t *testing.T) {
	got, known := NormaliseCollectionStatus("some_future_status")
	if known {
		t.Error("an unrecognised status was reported as known")
	}
	if got != CollectionUnavailable {
		t.Errorf("got %q, want %q — an unknown status is not evidence collection succeeded", got, CollectionUnavailable)
	}
	if got, known := NormaliseCollectionStatus("ok"); !known || got != CollectionOK {
		t.Errorf(`NormaliseCollectionStatus("ok") = (%q, %v)`, got, known)
	}
	if got, known := NormaliseSupervision("maybe"); known || got != SupervisedUnknown {
		t.Errorf(`NormaliseSupervision("maybe") = (%q, %v), want (Unknown, false)`, got, known)
	}
}
