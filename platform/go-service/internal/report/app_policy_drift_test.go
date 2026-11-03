package report

import "testing"

// TestAppPolicyEvidenceBasis covers the PAT-1725 weakest-instance rule in
// isolation from the DB: identifier_match only when every matched device
// was tied via a real identifier (bundle_id/team_id), name_match_only as
// soon as one device matched only by name, unknown when nothing matched.
func TestAppPolicyEvidenceBasis(t *testing.T) {
	cases := []struct {
		name              string
		devicesWithApp    int
		identifierMatched int
		want              string
	}{
		{"no devices matched", 0, 0, "unknown"},
		{"all devices identifier-matched", 3, 3, "identifier_match"},
		{"single device, identifier-matched", 1, 1, "identifier_match"},
		{"one of several devices name-only", 3, 2, "name_match_only"},
		{"all devices name-only", 2, 0, "name_match_only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appPolicyEvidenceBasis(tc.devicesWithApp, tc.identifierMatched)
			if got != tc.want {
				t.Errorf("appPolicyEvidenceBasis(%d, %d) = %q, want %q",
					tc.devicesWithApp, tc.identifierMatched, got, tc.want)
			}
		})
	}
}
