// Package wingetid owns the canonical PackageIdentifier validation shared by
// authenticated inventory, reviewed policy, and signed catalogue authority.
package wingetid

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// packageIdentifierRE is Microsoft's current Winget PackageIdentifier
// production. Matching is intentionally case-sensitive; callers may choose a
// canonical storage spelling only after validating the exact supplied value.
var packageIdentifierRE = regexp.MustCompile(`^[^.\s\\/:*?"<>|\x01-\x1f]{1,32}(\.[^.\s\\/:*?"<>|\x01-\x1f]{1,32}){1,7}$`)

// Valid reports whether value is an exact, unpadded Winget PackageIdentifier.
func Valid(value string) bool {
	return value == strings.TrimSpace(value) && utf8.RuneCountInString(value) <= 128 &&
		packageIdentifierRE.MatchString(value)
}
