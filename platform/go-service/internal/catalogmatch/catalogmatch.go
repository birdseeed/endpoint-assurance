// Package catalogmatch holds the rules for deciding whether an installed
// product is the product an app_catalog_entries row describes (PAT-2509).
//
// There are two rules, and which one a caller may use depends on who reads the
// result.
//
//   - ExactProductMatches is for anything a customer reads. The installed
//     display name must equal the catalogue name, and where the entry has a
//     verified signer the Team ID must agree too. The version sprawl report's
//     "latest released" reference uses it: a name that merely contains another
//     is not the same product ("Microsoft Teams classic" has its own version
//     line, "zoom.us" against a "Zoom" entry is a guess), and "not known" is the
//     right answer to a partial match.
//   - ProductMatches is the looser rule the staff tenant apps view uses to
//     tolerate naming variants: one name may contain the other. It must not be
//     used for a figure shown to a customer.
//
// In both, a vendor's Team ID commonly signs many unrelated products
// (Microsoft's UBF8T346G9 signs Word, Excel, Teams, Edge and VS Code), so a
// signer can only narrow a product-name match. It can never create one. A
// helper or sub-app never matches either. The package has no dependencies so
// the Go readers of the catalogue share the rules without an import cycle.
//
// The SQL readers of the catalogue (GET /v1/posture and others) apply their own
// joins; they cannot call Go.
package catalogmatch

import "strings"

// IsNonActionableSubApp reports whether a name or identifier describes a
// helper or vendor sub-app (a crash reporter, an updater, a renderer, a
// plugin host). Such rows may stay visible as inventory evidence but must
// never be matched to a product's catalogue entry, or they would borrow its
// version.
func IsNonActionableSubApp(name, identifier string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	i := strings.ToLower(strings.TrimSpace(identifier))
	nameMarkers := []string{
		" helper", "helper ", "crashpad", "crash reporter", "crashreporter",
		"updater", "renderer", " plugin", "zoom airhost", "zoomairhost", "cpt host", "cpthost",
	}
	identifierMarkers := []string{
		".helper", ".renderer", ".crashpad", ".crashreporter", ".updater",
		"autoupdater", "zoomairhost", "cpthost", ".plugin", ".webview",
		".gpu", ".notificationcenter", ".sandboxhelper", ".xpc", ".agent",
	}
	for _, marker := range nameMarkers {
		if strings.Contains(n, marker) {
			return true
		}
	}
	for _, marker := range identifierMarkers {
		if strings.Contains(i, marker) {
			return true
		}
	}
	return false
}

// ProductMatches is the looser rule, for the staff tenant apps view only. It
// reports whether an installed product (its identifier, display name and, on
// macOS, Team ID) is the product a catalogue entry (its display name and
// verified signer, nil when the entry has none) describes, tolerating naming
// variants: both names must be non-empty and one must contain the other,
// case-insensitively, so "Microsoft Teams classic" matches "Microsoft Teams".
// Do not use it for anything a customer reads; use ExactProductMatches.
//
// An entry with a verified signer also requires the installed Team ID to be
// that signer, so a product with no Team ID evidence never matches a signed
// entry. A helper or sub-app never matches.
func ProductMatches(identifier, installedName, installedTeamID, catalogName string, catalogSigner *string) bool {
	installed, catalog, ok := comparableNames(installedName, catalogName)
	if !ok {
		return false
	}
	if !strings.Contains(installed, catalog) && !strings.Contains(catalog, installed) {
		return false
	}
	return eligible(identifier, installedName, installedTeamID, catalogSigner)
}

// ExactProductMatches is the strict rule, for anything a customer reads. It
// reports whether an installed product is exactly the product a catalogue entry
// describes: the display names must be equal, ignoring case and surrounding
// spaces, and both non-empty. A name that contains the other, in either
// direction, does not match. An entry with a verified signer also requires the
// installed Team ID to be that signer, so a product with no Team ID evidence
// never matches a signed entry. A helper or sub-app never matches.
func ExactProductMatches(identifier, installedName, installedTeamID, catalogName string, catalogSigner *string) bool {
	installed, catalog, ok := comparableNames(installedName, catalogName)
	if !ok || installed != catalog {
		return false
	}
	return eligible(identifier, installedName, installedTeamID, catalogSigner)
}

// comparableNames lower-cases and trims both names. ok is false when either is
// empty: an empty name is not a product, and strings.Contains(x, "") is true.
func comparableNames(installedName, catalogName string) (installed, catalog string, ok bool) {
	installed = strings.ToLower(strings.TrimSpace(installedName))
	catalog = strings.ToLower(strings.TrimSpace(catalogName))
	return installed, catalog, installed != "" && catalog != ""
}

// eligible is the part of the rule both matchers share, once the names agree
// by their own test: the product must not be a helper or sub-app, and where the
// entry has a verified signer the installed Team ID must be that signer.
//
// The Team ID comparison is case-insensitive. Inventory normalises Team IDs to
// upper case at ingestion, so this is a belt-and-braces measure and not
// something the data should need.
func eligible(identifier, installedName, installedTeamID string, catalogSigner *string) bool {
	if IsNonActionableSubApp(installedName, identifier) {
		return false
	}
	if catalogSigner != nil && !strings.EqualFold(installedTeamID, *catalogSigner) {
		return false
	}
	return true
}
