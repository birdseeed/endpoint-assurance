package devicelifecycle

import (
	"testing"
	"time"
)

func TestReconcile_ThreeBuckets(t *testing.T) {
	uploaded := []UploadedDevice{
		{ExternalID: "u1", Serial: "SN-NORMAL"},         // matches observed by serial
		{ExternalID: "u2", HWUUID: "AAAA-1111"},         // matches observed by hw_uuid
		{ExternalID: "u3", Serial: "SN-GHOST"},          // never observed: coverage gap
		{ExternalID: "u4", Hostname: "mixed-case-Host"}, // matches by lower-cased hostname
		{ExternalID: "u5"},                              // no identifier at all: unmatchable
	}
	observed := []ObservedDevice{
		{ID: "d1", Serial: "sn-normal"},         // case-insensitive match on serial
		{ID: "d2", HWUUID: "aaaa-1111"},         // case-insensitive match on hw_uuid
		{ID: "d3", Hostname: "mixed-case-host"}, // matches u4
		{ID: "d4", Serial: "SN-UNTRACKED"},      // never uploaded: untracked
	}

	res := Reconcile(uploaded, observed)

	if len(res.Normal) != 3 {
		t.Fatalf("Normal: got %d, want 3 (%+v)", len(res.Normal), res.Normal)
	}
	normalObservedIDs := map[string]bool{}
	for _, m := range res.Normal {
		normalObservedIDs[m.Observed.ID] = true
	}
	for _, want := range []string{"d1", "d2", "d3"} {
		if !normalObservedIDs[want] {
			t.Errorf("Normal missing observed device %s", want)
		}
	}

	if len(res.CoverageGap) != 1 || res.CoverageGap[0].ExternalID != "u3" {
		t.Fatalf("CoverageGap: got %+v, want [u3]", res.CoverageGap)
	}

	if len(res.Untracked) != 1 || res.Untracked[0].ID != "d4" {
		t.Fatalf("Untracked: got %+v, want [d4]", res.Untracked)
	}

	if len(res.Unmatchable) != 1 || res.Unmatchable[0].ExternalID != "u5" {
		t.Fatalf("Unmatchable: got %+v, want [u5]", res.Unmatchable)
	}
}

func TestReconcile_EmptyInputs(t *testing.T) {
	res := Reconcile(nil, nil)
	if len(res.Normal) != 0 || len(res.CoverageGap) != 0 || len(res.Untracked) != 0 || len(res.Unmatchable) != 0 {
		t.Fatalf("expected all-empty result, got %+v", res)
	}
}

func TestReconcile_HWUUIDPreferredOverSerial(t *testing.T) {
	// Same device reported with a mismatched serial (e.g. a re-imaged serial
	// field) but a matching hw_uuid must still land in Normal, not
	// CoverageGap+Untracked — hw_uuid is the strongest identifier.
	uploaded := []UploadedDevice{{ExternalID: "u1", HWUUID: "HW-1", Serial: "OLD-SERIAL"}}
	observed := []ObservedDevice{{ID: "d1", HWUUID: "HW-1", Serial: "NEW-SERIAL"}}

	res := Reconcile(uploaded, observed)
	if len(res.Normal) != 1 {
		t.Fatalf("expected hw_uuid match to land in Normal, got %+v", res)
	}
	if len(res.CoverageGap) != 0 || len(res.Untracked) != 0 {
		t.Fatalf("expected no coverage gap or untracked devices, got %+v", res)
	}
}

func TestClassifyState_SixStates(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	th := DefaultThresholds() // quiet=3, stale=14, dormant=45

	daysAgo := func(d float64) *time.Time {
		ts := now.Add(-time.Duration(d * float64(24*time.Hour)))
		return &ts
	}

	cases := []struct {
		name              string
		lastSeen          *time.Time
		neverSeen         bool
		activeDisposition bool
		want              State
	}{
		{"never seen, no last_seen at all", nil, true, false, StateNeverSeen},
		{"nil last_seen without neverSeen flag is still never_seen", nil, false, false, StateNeverSeen},
		{"just now", daysAgo(0), false, false, StateReporting},
		{"just under quiet boundary", daysAgo(2.99), false, false, StateReporting},
		{"exactly at quiet boundary", daysAgo(3), false, false, StateQuiet},
		{"mid quiet range", daysAgo(7), false, false, StateQuiet},
		{"just under stale boundary", daysAgo(13.99), false, false, StateQuiet},
		{"exactly at stale boundary", daysAgo(14), false, false, StateStale},
		{"mid stale range", daysAgo(30), false, false, StateStale},
		{"just under dormant boundary", daysAgo(44.99), false, false, StateStale},
		{"exactly at dormant boundary", daysAgo(45), false, false, StateDormant},
		{"long dormant", daysAgo(400), false, false, StateDormant},
		{"active disposition overrides age", daysAgo(400), false, true, StateRemoved},
		{"active disposition overrides even a fresh last_seen", daysAgo(0), false, true, StateRemoved},
		{"neverSeen wins over activeDisposition", daysAgo(400), true, true, StateNeverSeen},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyState(c.lastSeen, now, c.neverSeen, c.activeDisposition, th)
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestClassifyState_TenantOverriddenThresholds(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	th := Thresholds{QuietDays: 1, StaleDays: 5, DormantDays: 10}
	lastSeen := now.Add(-6 * 24 * time.Hour)

	got := ClassifyState(&lastSeen, now, false, false, th)
	if got != StateStale {
		t.Fatalf("got %s, want %s under tightened thresholds", got, StateStale)
	}
}

func TestReappearedSince(t *testing.T) {
	recorded := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	before := recorded.Add(-time.Hour)
	after := recorded.Add(time.Hour)

	if ReappearedSince(&before, recorded) {
		t.Error("last_seen before disposition must not count as reappeared")
	}
	if !ReappearedSince(&after, recorded) {
		t.Error("last_seen after disposition must count as reappeared")
	}
	if ReappearedSince(nil, recorded) {
		t.Error("nil last_seen must never count as reappeared")
	}
}
