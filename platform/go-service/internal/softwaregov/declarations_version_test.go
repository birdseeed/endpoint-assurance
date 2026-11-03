package softwaregov

import "testing"

// An installed version that is not entirely numeric dotted is unknown: never
// reported below the minimum and never treated as satisfying it.
func TestMinimumVersionBelowUnknownIsNeverOutsideOrInside(t *testing.T) {
	for _, tc := range []struct {
		installed, minimum string
		below, known       bool
	}{
		{"1.9", "2.0", true, true},
		{"2.0", "2.0", false, true},
		{"2", "2.0.0", false, true},
		{"2.0.1", "2.0", false, true},
		{"10.0", "9.9", false, true},
		{"1.2.3-beta", "2.0", false, false},
		{"2024a", "2.0", false, false},
		{"v2.1", "2.0", false, false},
		{"2..1", "2.0", false, false},
		{"2.1 (build 7)", "2.0", false, false},
		{"", "2.0", false, false},
		{" 1.0", "2.0", false, false},
		{"1.0", ">=2.0", false, false},
		{"1.0", "2.0-rc1", false, false},
		{"1234567890.1", "2.0", false, false},
	} {
		below, known := minimumVersionBelow(tc.installed, tc.minimum)
		if below != tc.below || known != tc.known {
			t.Errorf("minimumVersionBelow(%q, %q) = (%v, %v), want (%v, %v)", tc.installed, tc.minimum, below, known, tc.below, tc.known)
		}
	}
}
