package report

import (
	"reflect"
	"testing"
	"time"
)

// PAT-2295: the rollup and the portal roster read one vocabulary. These tests
// need no database; the SQL half is covered by os_update_db_test.go and
// integration/os_update_rollup_portal_test.go.
func TestClassifyOSUpdateState(t *testing.T) {
	tests := []struct {
		state string
		want  osUpdateVerdict
	}{
		{"up_to_date", osUpdateCurrent},
		{"update_recommended", osUpdatePending},
		{"update_required", osUpdatePending},
		{"deadline_passed", osUpdatePending},
		{"unsupported_hardware", osUpdatePending},
		{"unknown", osUpdateNoClaim},
		{"banana", osUpdateNoClaim},
		{"", osUpdateNoClaim},
		// Exact match only, as the column stores what the agent sent verbatim.
		{"Up_To_Date", osUpdateNoClaim},
		{" up_to_date", osUpdateNoClaim},
		{"UPDATE_REQUIRED", osUpdateNoClaim},
	}
	for _, tc := range tests {
		if got := classifyOSUpdateState(tc.state); got != tc.want {
			t.Errorf("classifyOSUpdateState(%q) = %d, want %d", tc.state, got, tc.want)
		}
	}
}

// The lists bound into the rollup's SQL come from the same table the
// classifier reads, so they cannot name a state the classifier disagrees with.
func TestOSUpdateStatesForMatchesClassifier(t *testing.T) {
	if got, want := osUpdateStatesFor(osUpdateCurrent), []string{"up_to_date"}; !reflect.DeepEqual(got, want) {
		t.Errorf("current states = %v, want %v", got, want)
	}
	wantPending := []string{"update_recommended", "update_required", "deadline_passed", "unsupported_hardware"}
	if got := osUpdateStatesFor(osUpdatePending); !reflect.DeepEqual(got, wantPending) {
		t.Errorf("pending states = %v, want %v", got, wantPending)
	}

	seen := map[string]bool{}
	for _, e := range osUpdateStates {
		if seen[e.state] {
			t.Errorf("osUpdateStates lists %q twice; the first entry would win silently", e.state)
		}
		seen[e.state] = true
	}
	for _, v := range []osUpdateVerdict{osUpdateCurrent, osUpdatePending} {
		for _, s := range osUpdateStatesFor(v) {
			if got := classifyOSUpdateState(s); got != v {
				t.Errorf("state %q is listed for verdict %d but classifies as %d", s, v, got)
			}
		}
	}
}

// Every state in the table is read the same way by the roster: a current state
// is not pending, a pending state is, and a no-claim state is nil.
func TestOSUpdatePatchPendingUsesSharedVocabulary(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour)
	for _, e := range osUpdateStates {
		got := osUpdatePatchPending(e.state, &fresh, &fresh, now)
		switch e.verdict {
		case osUpdateCurrent:
			if got == nil || *got {
				t.Errorf("%q: patch_pending = %v, want false", e.state, got)
			}
		case osUpdatePending:
			if got == nil || !*got {
				t.Errorf("%q: patch_pending = %v, want true", e.state, got)
			}
		default:
			if got != nil {
				t.Errorf("%q: patch_pending = %v, want nil", e.state, *got)
			}
		}
	}
}
