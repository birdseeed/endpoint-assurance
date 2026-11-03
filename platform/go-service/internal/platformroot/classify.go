package platformroot

import "strings"

// SuspiciousSubjectPatterns are case-insensitive substrings that, combined
// with a device's platform, suggest a certificate's subject was chosen to
// impersonate a well-known platform root CA even though its thumbprint does
// not match anything in platform_root_certificates.
//
// The Windows patterns are exactly the substrings PAT-1737 removed from the
// Windows agent's IsBuiltInRoot filter (updater commit 1eb4ad2a,
// windows/src/Service/CertCollector.cs): that filter silently dropped any
// certificate whose subject contained "Microsoft" or "Windows" before it
// ever reached the platform, and because the collection run still reported
// `complete`, the server then pruned the hidden row — so a rogue certificate
// named like a Microsoft one was invisible end to end. PAT-1737's own fix
// was "classification of platform certificates is server-side"; this is
// that server-side classification, and it reuses the identical substrings
// only as a flag on a certificate that is still reported and still visible
// — never to exclude or hide a row, which is exactly the mistake PAT-1737
// fixed.
//
// There is no equivalent removed macOS filter (the macOS agent has only
// ever read System.keychain, never SystemRootCertificates.keychain), so the
// macOS pattern is this package's own, narrowly scoped the same way: the one
// word that names the platform whose roots are being impersonated.
var SuspiciousSubjectPatterns = map[string][]string{
	PlatformWindows: {"Microsoft", "Windows"},
	PlatformMacOS:   {"Apple"},
}

// noSuspiciousSubjectMatch is a POSIX regex that cannot match any real
// subject (Postgres SQL identifiers/certificate CNs never contain a NUL
// byte). Used by SuspiciousSubjectRegexOrNoMatch as the safe fallback for a
// platform with no patterns defined, instead of "" — an empty `~*` pattern
// matches every string, the opposite of "no suspicious patterns".
const noSuspiciousSubjectMatch = "\x00NEVER-MATCHES\x00"

// SuspiciousSubjectRegex returns a Postgres ~* (case-insensitive POSIX
// regex) alternation matching any of platform's suspicious substrings, e.g.
// "Microsoft|Windows". Returns "" for a platform with no patterns defined —
// callers building SQL should use SuspiciousSubjectRegexOrNoMatch instead,
// which never returns "".
func SuspiciousSubjectRegex(platform string) string {
	patterns := SuspiciousSubjectPatterns[platform]
	if len(patterns) == 0 {
		return ""
	}
	return strings.Join(patterns, "|")
}

// SuspiciousSubjectRegexOrNoMatch is SuspiciousSubjectRegex, but never
// returns "": a platform with no patterns defined gets a regex that cannot
// match anything, so a future platform added to platform_root_certificates
// without a corresponding entry in SuspiciousSubjectPatterns fails closed
// (nothing flagged) instead of an empty `~*` comparison flagging every
// certificate as suspicious. This is the function SQL-query callers should
// use; SuspiciousSubjectRegex itself stays available for callers (tests,
// documentation) that want to observe the "no patterns" case directly.
func SuspiciousSubjectRegexOrNoMatch(platform string) string {
	if r := SuspiciousSubjectRegex(platform); r != "" {
		return r
	}
	return noSuspiciousSubjectMatch
}

// MatchesSuspiciousSubject reports whether subject contains one of
// platform's suspicious substrings (case-insensitive). A Go-side equivalent
// of the SQL `~*` check built from SuspiciousSubjectRegex, used by tests and
// any non-SQL caller so both stay driven by the same pattern table.
func MatchesSuspiciousSubject(platform, subject string) bool {
	for _, p := range SuspiciousSubjectPatterns[platform] {
		if strings.Contains(strings.ToLower(subject), strings.ToLower(p)) {
			return true
		}
	}
	return false
}
