package removal

import (
	"strings"
	"testing"
)

func sp(s string) *string { return &s }

// TestTargetIdentityMapping proves a campaign target reaches the PAT-1801
// protected-software check without translation. If this ever needs a
// conversion table, the campaign has grown an identity scheme of its own and
// the protected check can be pointed at the wrong product.
func TestTargetIdentityMapping(t *testing.T) {
	target := Target{TeamID: sp("ABCDE12345"), BundleID: sp("com.example.app"), Name: sp("Example"), Platform: "macos"}
	id := target.Identity()

	if id.TeamID == nil || *id.TeamID != "ABCDE12345" {
		t.Fatalf("team_id did not survive: %+v", id)
	}
	if id.BundleID == nil || *id.BundleID != "com.example.app" {
		t.Fatalf("bundle_id did not survive: %+v", id)
	}
	// The display name has to land on ProcessName: protected_software matches
	// that column against both process_name and product_name.
	if id.ProcessName == nil || *id.ProcessName != "Example" {
		t.Fatalf("name did not map to ProcessName: %+v", id)
	}
}

func TestWeakestEvidence(t *testing.T) {
	cases := []struct {
		devices, identifierMatched int
		want                       string
	}{
		{0, 0, EvidenceUnknown},
		{3, 3, EvidenceIdentifierMatch},
		{3, 2, EvidenceNameMatchOnly},
		{3, 0, EvidenceNameMatchOnly},
		{1, 1, EvidenceIdentifierMatch},
	}
	for _, c := range cases {
		if got := weakestEvidence(c.devices, c.identifierMatched); got != c.want {
			t.Fatalf("weakestEvidence(%d, %d) = %q, want %q", c.devices, c.identifierMatched, got, c.want)
		}
	}
}

func TestNormalisePlatform(t *testing.T) {
	cases := map[string]string{
		"macos": "macos", "MacOS": "macos", " windows ": "windows",
		"any": "any", "": "any", "linux": "any", "macOS ": "macos",
	}
	for in, want := range cases {
		if got := normalisePlatform(in); got != want {
			t.Fatalf("normalisePlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestResidueNeverClaimsRemoval guards the wording contract: residue is what
// stays behind. A preview that described residue as removed would be the
// exact overclaim the product boundary forbids.
func TestResidueNeverClaimsRemoval(t *testing.T) {
	items := residueAlwaysPresent()
	if len(items) == 0 {
		t.Fatal("residue must never be empty: a removal always leaves something")
	}
	for _, item := range items {
		lower := strings.ToLower(item.Description)
		for _, forbidden := range []string{"will be removed", "is removed", "are removed", "deleted"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("residue item claims removal (%q): %q", forbidden, item.Description)
			}
		}
		if item.Basis == "" {
			t.Fatalf("residue item has no basis: %q", item.Description)
		}
		if strings.Contains(item.Description, "—") {
			t.Fatalf("residue copy contains an em dash: %q", item.Description)
		}
	}
}
