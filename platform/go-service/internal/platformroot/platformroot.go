// Package platformroot classifies device_certificates rows against the
// published Microsoft and Apple trusted-root-program certificate lists
// (PAT-1738).
//
// A rogue certificate authority planted in a Windows LocalMachine\Root/CA
// store, or (in principle) a macOS System.keychain, is one of the strongest
// findings an assessment can surface — and was previously invisible, because
// reporting the full Root/CA stores without classification would flood every
// assessment with expired-but-legitimate platform roots nobody can act on
// (the Windows staging VM's Root store alone holds 27 certificates, 8 of
// them expired legacy Microsoft/VeriSign/Thawte roots).
//
// This package is the fetch/parse/upsert seam for the classification data
// (platform_root_certificates, migration 0137), mirroring internal/oscve's
// shape: pure parsers unit-testable against committed fixtures, a thin live
// fetcher, and a batched idempotent upsert. Classification itself (the LEFT
// JOIN against device_certificates) lives in the callers that need it
// (internal/report/cert_expiry.go, internal/handlers/health_admin.go) rather
// than here, per PAT-1738's own instruction not to store it as a mutable
// column.
package platformroot

import "time"

// Platform values stored in platform_root_certificates.platform and matched
// against the device's platform. Reuses the exact literals internal/oscve
// already established for the same two-platform domain (os_cve_advisories),
// rather than defining a second pair of "macos"/"windows" constants.
const (
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
)

// Source identifiers recorded on every platform_root_certificates row,
// naming the exact published list a thumbprint came from.
const (
	SourceMicrosoftCCADB      = "microsoft-ccadb"
	SourceAppleCCADBTLSServer = "apple-ccadb-tls-server-auth"
)

// RootCert is one platform-root certificate thumbprint parsed from a
// published list, ready to upsert into platform_root_certificates.
type RootCert struct {
	ThumbprintSHA1 string // lowercase hex SHA-1, same algorithm/casing as device_certificates.sha1
	Platform       string // PlatformWindows | PlatformMacOS
	Source         string
	SourceURL      string
	SubjectCN      string // human debugging/audit only
	FetchedAt      time.Time
}
