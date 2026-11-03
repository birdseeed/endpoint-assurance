package catalogmatch

import "testing"

func ptr(s string) *string { return &s }

func TestProductMatchesRequiresNameBeforeSigner(t *testing.T) {
	shared := "UBF8T346G9"
	cases := []struct {
		label                           string
		identifier, name, team, catalog string
		signer                          *string
		want                            bool
	}{
		{"same product, same signer", "com.microsoft.Word", "Microsoft Word", shared, "Microsoft Word", ptr(shared), true},
		{"shared signer, different product", "com.microsoft.edgemac", "Microsoft Edge", shared, "Microsoft Word", ptr(shared), false},
		{"naming variant, either direction", "com.microsoft.teams", "Microsoft Teams classic", shared, "Microsoft Teams", ptr(shared), true},
		{"case-insensitive signer", "com.microsoft.Word", "Microsoft Word", "ubf8t346g9", "Microsoft Word", ptr(shared), true},
		{"signed entry, no team id evidence", "com.microsoft.Word", "Microsoft Word", "", "Microsoft Word", ptr(shared), false},
		{"signed entry, other team id", "com.microsoft.Word", "Microsoft Word", "ZZZZZZZZZZ", "Microsoft Word", ptr(shared), false},
		{"unsigned entry, name only", "com.microsoft.Word", "Word", "", "Microsoft Word", nil, true},
		{"empty installed name, signer alone", "com.microsoft.Word", "", shared, "Microsoft Word", ptr(shared), false},
		{"empty catalogue name", "com.microsoft.Word", "Microsoft Word", shared, "  ", ptr(shared), false},
		{"helper app", "us.zoom.xos.ZoomAutoUpdater", "Zoom", "BJ4HAAB9B3", "Zoom", ptr("BJ4HAAB9B3"), false},
	}
	for _, c := range cases {
		if got := ProductMatches(c.identifier, c.name, c.team, c.catalog, c.signer); got != c.want {
			t.Errorf("%s: ProductMatches = %v, want %v", c.label, got, c.want)
		}
	}
}

func TestExactProductMatchesNeedsTheSameName(t *testing.T) {
	shared := "UBF8T346G9"
	cases := []struct {
		label                           string
		identifier, name, team, catalog string
		signer                          *string
		want                            bool
	}{
		{"exact name, right signer", "com.microsoft.Word", "Microsoft Word", shared, "Microsoft Word", ptr(shared), true},
		{"exact name, unsigned entry, no team id", "com.microsoft.Word", "Microsoft Word", "", "Microsoft Word", nil, true},
		{"different case and surrounding spaces", "com.microsoft.Word", "  MICROSOFT word ", shared, "Microsoft Word", ptr(shared), true},
		{"installed name contains the entry name", "com.microsoft.teams", "Microsoft Teams classic", shared, "Microsoft Teams", ptr(shared), false},
		{"entry name contains the installed name", "com.microsoft.teams", "Teams", shared, "Microsoft Teams", ptr(shared), false},
		{"unsigned entry, installed name contains it", "zoom.us", "zoom.us", "", "Zoom", nil, false},
		{"exact name, wrong signer", "com.microsoft.Word", "Microsoft Word", "ZZZZZZZZZZ", "Microsoft Word", ptr(shared), false},
		{"signed entry, product with no team id", "com.microsoft.Word", "Microsoft Word", "", "Microsoft Word", ptr(shared), false},
		{"signer agrees, name does not", "com.microsoft.edgemac", "Microsoft Edge", shared, "Microsoft Word", ptr(shared), false},
		{"helper name", "us.zoom.xos", "Zoom Helper", "BJ4HAAB9B3", "Zoom Helper", ptr("BJ4HAAB9B3"), false},
		{"helper identifier", "us.zoom.xos.ZoomAutoUpdater", "Zoom", "BJ4HAAB9B3", "Zoom", ptr("BJ4HAAB9B3"), false},
		{"empty installed name", "com.microsoft.Word", "", shared, "", ptr(shared), false},
		{"empty installed name, real entry", "com.microsoft.Word", "  ", shared, "Microsoft Word", ptr(shared), false},
		{"empty entry name, real product", "com.microsoft.Word", "Microsoft Word", shared, "", ptr(shared), false},
		{"both names empty, unsigned", "x", "", "", "", nil, false},
	}
	for _, c := range cases {
		if got := ExactProductMatches(c.identifier, c.name, c.team, c.catalog, c.signer); got != c.want {
			t.Errorf("%s: ExactProductMatches = %v, want %v", c.label, got, c.want)
		}
	}
}

// Whatever the exact rule accepts the loose rule accepts too: the strict rule
// is a narrowing of the loose one, not a different one.
func TestExactProductMatchesIsNarrowerThanProductMatches(t *testing.T) {
	shared := "UBF8T346G9"
	names := []string{"Microsoft Teams", "Microsoft Teams classic", "Teams", "microsoft teams", "", "Zoom Helper"}
	signers := []*string{nil, ptr(shared), ptr("ZZZZZZZZZZ")}
	for _, installed := range names {
		for _, catalog := range names {
			for _, team := range []string{"", shared} {
				for _, signer := range signers {
					exact := ExactProductMatches("com.example.app", installed, team, catalog, signer)
					loose := ProductMatches("com.example.app", installed, team, catalog, signer)
					if exact && !loose {
						t.Errorf("installed %q, catalogue %q, team %q: exact matched but loose did not", installed, catalog, team)
					}
				}
			}
		}
	}
}
