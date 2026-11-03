package softwaregov

import "testing"

func TestPresenceStateRequiresInitialization(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state presenceState
		want  bool
	}{
		{"missing", presenceState{}, false},
		{"empty initialized", presenceState{initialized: true}, true},
		{"stale", presenceState{initialized: true, policyVersion: 2, summaryVersion: 1}, false},
		{"current", presenceState{initialized: true, policyVersion: 2, summaryVersion: 2}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.current(); got != tc.want {
				t.Fatalf("current() = %v, want %v", got, tc.want)
			}
		})
	}
}
