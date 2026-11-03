package report

import "testing"

// PAT-443: guard the canonical tier-status source. If tier_status.json is
// malformed or missing a tier, loadTierStatuses panics at init — this test
// makes that a clear test failure and asserts the parsed values are sane.
func TestTierStatusesLoadedFromCanonicalSource(t *testing.T) {
	valid := map[string]bool{TierStatusAvailable: true, TierStatusComingSoon: true}

	for name, got := range map[string]string{
		"report":                   TierStatuses.Report,
		"patch":                    TierStatuses.PatchAndDeploy,
		"full_endpoint_management": TierStatuses.FullEndpointManagement,
	} {
		if !valid[got] {
			t.Errorf("tier %q: status %q is not one of %q / %q",
				name, got, TierStatusAvailable, TierStatusComingSoon)
		}
	}

	// Report is the launched tier; if the canonical source ever stops marking it
	// available that's almost certainly a mistake worth catching.
	if TierStatuses.Report != TierStatusAvailable {
		t.Errorf("report tier should be %q, got %q", TierStatusAvailable, TierStatuses.Report)
	}
}
