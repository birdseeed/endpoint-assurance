package softwaregov

import (
	"fmt"
	"sort"
	"strings"

	"patched.im/api/internal/cvepipeline"
)

// New software urgency (PAT-2093): how urgently a newly found product needs
// a decision, from its trust evidence and its CVE state. This file is the
// pure classifier; newsoftware_urgency.go gathers the evidence.
//
// The most severe applicable level wins:
//
//   - critical: a known critical or high CVE on an installed version; or an
//     installation the macOS collector reported unsigned (signing_status
//     "unsigned", PAT-2112), or the Windows agent reported unsigned
//     (signature_state "unsigned", PAT-2116: no embedded signature and a
//     proven clean catalog miss); or an
//     unidentifiable product (known by display name only, with no publisher
//     or Team ID evidence at all).
//   - high: anything else whose publisher trust is not established. On macOS
//     that is an ad hoc signed installation, a signer that is not a
//     distribution identity, an installation whose signature validates but
//     whose certificate chain does not anchor to Apple ("untrusted",
//     PAT-2117: a self-signed certificate can still name itself "Developer ID
//     Application: ..."), an installation whose signature does not validate
//     against the code at all ("invalid", PAT-2117), Developer ID signing
//     whose notarisation is not confirmed, missing or unestablished signing
//     evidence, or no single Team ID. An untrusted or invalid installation
//     never counts as trusted and never sets a publisher basis, even when its
//     signed_by or Team ID looks legitimate. On Windows (PAT-2113) it is an
//     installation whose Authenticode signature is invalid (the file changed
//     after signing), one with no Authenticode verdict (the agent reported
//     unknown, or sent no evidence: an older agent), a valid signature that
//     chains to an enterprise root (PAT-2116: a root only this device's
//     trust store vouches for, so the signer is not independently
//     verifiable, however Microsoft-like its subject), or valid signatures
//     with no single signer, or no single root. The registry Publisher
//     string is a claim, not a signature, and never establishes trust. Any
//     known CVE below high severity (medium, low, or unrated) is also high.
//   - not_assessed: a trusted product whose CVE state is not assessed (no CPE
//     mapping) or pending (not yet matched at its installed versions). An
//     unassessed CVE state is never read as "no known CVEs", so such a
//     product is never medium or low.
//   - medium: trusted publisher, CVE state assessed with no known CVEs.
//   - low: as medium, and the publisher already has an approved product in
//     this tenant. On macOS that is the product's Team ID on an approved
//     application policy. On Windows (PAT-2121) it is the product's
//     Authenticode publisher key (AuthenticodePublisherKey: root thumbprint
//     plus normalised leaf Subject DN) on an approved Windows policy for a
//     different product, where the server derived that key from the tenant's
//     own evidence when the approval was written. A Windows product has a key
//     only when every installation is valid and pinned to one microsoft or
//     public root, so an enterprise root, or an older agent that sends no
//     root, never reaches low.
//
// Missing evidence is always unknown, never trusted (root AGENTS.md:
// "absence requires authority"). Excluded products (approved, ignored, and
// Patched's own agent) are filtered before classification.

// Urgency levels, most severe first.
const (
	UrgencyCritical    = "critical"
	UrgencyHigh        = "high"
	UrgencyNotAssessed = "not_assessed"
	UrgencyMedium      = "medium"
	UrgencyLow         = "low"
)

// urgencyRank orders levels for "most severe wins" and for sorting.
var urgencyRank = map[string]int{
	UrgencyCritical:    5,
	UrgencyHigh:        4,
	UrgencyNotAssessed: 3,
	UrgencyMedium:      2,
	UrgencyLow:         1,
}

// Reason codes. Each reason carries the level it sets on its own.
const (
	ReasonCVECriticalOrHigh         = "cve_critical_or_high"
	ReasonUnsigned                  = "unsigned"
	ReasonAdhocSigned               = "adhoc_signed"
	ReasonUnidentifiable            = "unidentifiable"
	ReasonCVEMedium                 = "cve_medium"
	ReasonCVELowOrUnrated           = "cve_low_or_unrated"
	ReasonSigningUnknown            = "signing_unknown"
	ReasonUntrustedSigner           = "untrusted_signer"
	ReasonAuthenticodeInvalid       = "authenticode_invalid"
	ReasonSignatureInvalid          = "signature_invalid"
	ReasonNotarisationNotConfirmed  = "notarisation_not_confirmed"
	ReasonAuthenticodeNotCollected  = "authenticode_not_collected"
	ReasonEnterpriseRoot            = "enterprise_root"
	ReasonUnknownPublisher          = "unknown_publisher"
	ReasonCVENotAssessed            = "cve_not_assessed"
	ReasonCVEPending                = "cve_pending"
	ReasonTrustedNoKnownCVEs        = "trusted_publisher_no_known_cves"
	ReasonPublisherHasApprovedItems = "publisher_has_approved_products"
	// ReasonAuthenticodePublisherApproved is the Windows twin of
	// ReasonPublisherHasApprovedItems (PAT-2121).
	ReasonAuthenticodePublisherApproved = "authenticode_publisher_has_approved_products"
)

// macOS signer classes, from the leaf codesign Authority the collector
// reports (updater macos/lib/apps.sh, `codesign -dvv`).
const (
	SignerDeveloperID = "developer_id" // "Developer ID Application: …": notarisation expected
	SignerAppStore    = "app_store"    // Mac App Store / iOS App Store distribution
	SignerApple       = "apple"        // Apple's own platform signing
	SignerOther       = "other"        // development, ad hoc chain or unknown CA: not a distribution identity
	SignerMixed       = "mixed"        // installations disagree
)

// Signing states in UrgencyTrust.Signing.
const (
	SigningSigned       = "signed"
	SigningUnsigned     = "unsigned"
	SigningAdhoc        = "adhoc"
	SigningUnknown      = "unknown"
	SigningNotCollected = "not_collected" // Windows: no Authenticode evidence was reported
	// SigningInvalid is shared: a Windows Authenticode digest mismatch
	// (PAT-2113) and a macOS signature that does not validate against the
	// code at all (PAT-2117) are the same fact on both platforms -- signed,
	// but the signature is wrong -- so they share one wire value.
	SigningInvalid = "invalid"
	// SigningUntrusted is macOS only (PAT-2117): the signature validates but
	// its certificate chain does not anchor to Apple.
	SigningUntrusted = "untrusted"
)

// Notarisation states in UrgencyTrust.Notarisation.
const (
	NotarisationConfirmed     = "confirmed"
	NotarisationNotConfirmed  = "not_confirmed"
	NotarisationNotApplicable = "not_applicable"
	NotarisationUnknown       = "unknown"
)

// Publisher bases in UrgencyTrust.PublisherBasis.
const (
	PublisherBasisTeamID            = "team_id"
	PublisherBasisAppleSignature    = "apple_signature"
	PublisherBasisAuthenticode      = "authenticode_signer"
	PublisherBasisRegistryPublisher = "registry_publisher_unverified"
	PublisherBasisNone              = "none"
)

// signerSentinel is what the macOS collector sends as signed_by when
// `codesign -dvv` printed no Authority line. That covers a truly unsigned or
// ad hoc signed binary, but also codesign failing (unreadable bundle, TCC
// denial, broken signature), so on its own it is NOT evidence of unsigned: it
// reads as signing unknown, like a missing field. Unsigned and ad hoc need
// the collector's explicit signing_status (PAT-2112), counted in
// ExplicitUnsigned and ExplicitAdhoc; a sentinel row with signing_status
// "error", or with none (an older agent), stays signing unknown.
const signerSentinel = "unknown"

// UrgencyReason is one fact that set, or contributed to, a product's level.
type UrgencyReason struct {
	Code   string `json:"code"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
}

// UrgencyTrust is the trust evidence a level was computed from, rolled up
// across the product's current installations (all installations when every
// one has since been removed).
type UrgencyTrust struct {
	Trusted        bool    `json:"trusted"`
	Signing        string  `json:"signing"`
	SignerClass    *string `json:"signer_class"`
	Notarisation   string  `json:"notarisation"`
	Publisher      *string `json:"publisher"`
	PublisherBasis string  `json:"publisher_basis"`
	// PublisherHasApprovedProducts is true when the product's publisher is
	// on an approved application policy in this tenant: on macOS its Team
	// ID, on Windows its Authenticode publisher key on an approved policy
	// for a different product (PAT-2121). A Windows registry publisher, or
	// an Authenticode Subject DN without its root, is never used.
	PublisherHasApprovedProducts bool `json:"publisher_has_approved_products"`
	// Installations is how many installations the evidence covers.
	Installations int `json:"installations"`
}

// UrgencyCVE is the product's CVE state. Severity is null unless the product
// has CPE mapping coverage (state assessed or pending); not_assessed is
// never a count of zero.
type UrgencyCVE struct {
	State        string                      `json:"state"`
	FindingCount *int                        `json:"finding_count"`
	Severity     *cvepipeline.SeverityCounts `json:"severity"`
}

// trustFacts is the raw per-product evidence newsoftware_urgency.go reads
// from software_installations and each installation's latest observation.
type trustFacts struct {
	Platform string
	// Ident is the product's normalised identifier (PAT-2121: an approval
	// of the product itself never counts as its publisher's other product).
	Ident string
	// NameOnly is the product's identity basis: no identifier was reported.
	NameOnly bool
	// DisplayNameOnly counts installations known by display name alone, with
	// no publisher, signer or Team ID (identity kind display_name).
	DisplayNameOnly int
	Installations   int
	// SignerReported counts installations whose observation carried a
	// signed_by value at all (the sentinel included).
	SignerReported int
	// SignerUnestablished counts installations whose signed_by was the
	// collector's sentinel and that carry no explicit unsigned or ad hoc
	// signing_status: no signing authority could be established.
	SignerUnestablished int
	// ExplicitUnsigned counts installations whose signing_status is
	// "unsigned" (PAT-2112): codesign said the code is not signed at all.
	ExplicitUnsigned int
	// ExplicitAdhoc counts installations whose signing_status is "adhoc"
	// (PAT-2112): signed with no identity, so no publisher can be read.
	ExplicitAdhoc int
	// ExplicitUntrusted counts installations whose signing_status is
	// "untrusted" (PAT-2117): the signature validates but the certificate
	// chain does not anchor to Apple. signed_by and the Team ID may still
	// look like a genuine Developer ID, so neither is ever read as a
	// publisher basis for these.
	ExplicitUntrusted int
	// ExplicitInvalid counts installations whose signing_status is "invalid"
	// (PAT-2117): the signature does not validate against the code at all
	// (tampered, or broken after signing).
	ExplicitInvalid int
	// NotarisedTrue counts installations whose notarization_status is
	// "notarized" (PAT-2112). The legacy notarized boolean is not read: no
	// collector before PAT-2112 could ever set it true, and "unknown" or an
	// absent status is not confirmation.
	NotarisedTrue int
	// Signers is the distinct real signing authorities (sentinel excluded).
	Signers []string
	// TeamInstallations counts installations with a macOS Team ID identity.
	TeamInstallations int
	TeamIDs           []string
	// PublisherInstallations counts installations with a publisher string.
	PublisherInstallations int
	Publishers             []string
	// Windows Authenticode evidence (PAT-2113), from each installation's
	// observed_signature_state. An installation with none is not counted
	// in any of the three.
	SignatureValid   int
	SignatureInvalid int
	SignatureUnknown int
	// SignatureUnsigned (PAT-2116) counts installations reported unsigned.
	SignatureUnsigned int
	// SignatureValidSigned counts valid installations that carry a signer.
	SignatureValidSigned int
	// AuthenticodeSigners is the distinct signers on valid installations.
	AuthenticodeSigners []string
	// The Authenticode root of valid installations (PAT-2116). RootPublic
	// counts root_kind microsoft or public, RootPublicPinned those of them
	// that also carry a root thumbprint, and AuthenticodeRoots is those
	// thumbprints, distinct. RootEnterprise counts root_kind enterprise.
	// RootLegacy counts valid installations with none of the PAT-2116
	// publisher fields at all: an agent older than updater #668. A valid
	// installation in none of these carries some publisher fields but no
	// recognised root_kind, so its root is unestablished.
	RootPublic        int
	RootPublicPinned  int
	AuthenticodeRoots []string
	RootEnterprise    int
	RootLegacy        int
}

// macSignerClass classifies one leaf codesign Authority.
func macSignerClass(signer string) string {
	s := strings.TrimSpace(signer)
	switch {
	case strings.HasPrefix(s, "Developer ID Application:"):
		return SignerDeveloperID
	case s == "Apple Mac OS Application Signing", s == "Apple iPhone OS Application Signing":
		return SignerAppStore
	case s == "Software Signing", s == "macOS Software Signing":
		return SignerApple
	default:
		return SignerOther
	}
}

func strPtr(s string) *string { return &s }

// publisherApprovals is what this tenant's approved application policies
// vouch for.
type publisherApprovals struct {
	// teams is the Team IDs (upper case) on approved policies that apply on
	// macOS.
	teams map[string]bool
	// authenticode maps a Windows publisher key on an approved Windows
	// policy to the normalised identifiers of the products approved under it
	// (PAT-2121).
	authenticode map[string]map[string]bool
}

// classifyUrgency applies the PAT-2093 rules to one product, against what
// this tenant's approved application policies vouch for. It returns the
// level, the reasons (most severe first) and the trust summary.
func classifyUrgency(f trustFacts, cve cvepipeline.EstateAssessment, approved publisherApprovals) (string, []UrgencyReason, UrgencyTrust) {
	var reasons []UrgencyReason
	add := func(code, level, detail string) {
		reasons = append(reasons, UrgencyReason{Code: code, Level: level, Detail: detail})
	}
	trust := UrgencyTrust{Installations: f.Installations, PublisherBasis: PublisherBasisNone,
		Signing: SigningUnknown, Notarisation: NotarisationUnknown}

	if f.NameOnly && f.DisplayNameOnly > 0 {
		add(ReasonUnidentifiable, UrgencyCritical,
			"known by display name only, with no identifier, publisher or Team ID evidence")
	}

	switch f.Platform {
	case "macos":
		trust.Trusted = classifyMacTrust(f, approved.teams, &trust, add)
	default:
		// Windows (and anything not macOS).
		trust.Trusted = classifyWindowsTrust(f, &trust, add)
		if trust.Trusted {
			if key := windowsPublisherKey(f); key != "" {
				for ident := range approved.authenticode[key] {
					if ident != f.Ident {
						trust.PublisherHasApprovedProducts = true
						break
					}
				}
			}
		}
	}

	clean := false
	switch cve.State {
	case cvepipeline.StateNotAssessed:
		add(ReasonCVENotAssessed, UrgencyNotAssessed,
			"no CVE mapping covers this product, so no CVE statement can be made")
	default:
		sev := cve.Severity
		if n := sev.Critical + sev.High; n > 0 {
			add(ReasonCVECriticalOrHigh, UrgencyCritical,
				fmt.Sprintf("%d critical and %d high severity known CVEs on installed versions", sev.Critical, sev.High))
		}
		if sev.Medium > 0 {
			add(ReasonCVEMedium, UrgencyHigh, fmt.Sprintf("%d medium severity known CVEs", sev.Medium))
		}
		if n := sev.Low + sev.Unrated; n > 0 {
			add(ReasonCVELowOrUnrated, UrgencyHigh,
				fmt.Sprintf("%d low severity and %d unrated known CVEs", sev.Low, sev.Unrated))
		}
		if cve.State == cvepipeline.StatePending {
			add(ReasonCVEPending, UrgencyNotAssessed,
				"not yet matched at every installed version, so the CVE statement is incomplete")
		} else if cve.FindingCount != nil && *cve.FindingCount == 0 {
			clean = true
		}
	}

	if trust.Trusted && clean {
		switch {
		case trust.PublisherHasApprovedProducts && f.Platform == "macos":
			add(ReasonPublisherHasApprovedItems, UrgencyLow,
				"trusted publisher with no known CVEs whose Team ID already has approved products here")
		case trust.PublisherHasApprovedProducts:
			add(ReasonAuthenticodePublisherApproved, UrgencyLow,
				"trusted publisher with no known CVEs whose Authenticode publisher (signer and root) already has approved products here")
		default:
			add(ReasonTrustedNoKnownCVEs, UrgencyMedium,
				"trusted publisher with no known CVEs, not yet approved")
		}
	}

	if len(reasons) == 0 {
		// Unreachable by construction; fail towards attention, not quiet.
		add(ReasonSigningUnknown, UrgencyHigh, "trust could not be established")
	}
	sort.SliceStable(reasons, func(i, j int) bool {
		if ri, rj := urgencyRank[reasons[i].Level], urgencyRank[reasons[j].Level]; ri != rj {
			return ri > rj
		}
		return reasons[i].Code < reasons[j].Code
	})
	return reasons[0].Level, reasons, trust
}

// classifyWindowsTrust fills trust for a Windows product from its Authenticode
// evidence (PAT-2113, PAT-2116) and reports whether its publisher is trusted:
// every installation valid, with one signer they all agree on, and a root
// that is not enterprise. Installations that report a root (microsoft or
// public) must also agree on one root thumbprint. An installation valid with
// no PAT-2116 publisher fields at all comes from an agent older than updater
// #668, which sends no root: it is read as PAT-2113 read it (its agreed
// signer alone is trusted), so an estate mid-upgrade does not regress. Every
// applicable reason is reported and the worst installation wins. It never
// sets PublisherHasApprovedProducts: classifyUrgency does that from the
// product's publisher key (windowsPublisherKey, PAT-2121).
func classifyWindowsTrust(f trustFacts, trust *UrgencyTrust, add func(code, level, detail string)) bool {
	trust.Notarisation = NotarisationNotApplicable
	if f.SignatureUnsigned > 0 {
		add(ReasonUnsigned, UrgencyCritical,
			fmt.Sprintf("%d of %d installations are reported unsigned: no Authenticode signature, embedded or in a Windows catalog",
				f.SignatureUnsigned, f.Installations))
	}
	if f.SignatureInvalid > 0 {
		add(ReasonAuthenticodeInvalid, UrgencyHigh,
			fmt.Sprintf("%d of %d installations have an Authenticode signature that does not match the file, which changed after it was signed",
				f.SignatureInvalid, f.Installations))
	}
	if f.RootEnterprise > 0 {
		add(ReasonEnterpriseRoot, UrgencyHigh,
			fmt.Sprintf("%d of %d installations are signed through an enterprise root the device trusts; not independently verifiable",
				f.RootEnterprise, f.Installations))
	}
	missing := f.Installations - f.SignatureValid - f.SignatureInvalid - f.SignatureUnknown - f.SignatureUnsigned
	if missing < 0 {
		missing = 0
	}
	if f.Installations == 0 || f.SignatureUnknown > 0 || missing > 0 {
		add(ReasonAuthenticodeNotCollected, UrgencyHigh,
			fmt.Sprintf("no Authenticode verdict on %d of %d installations (%d reported unknown: an untrusted chain, no executable resolved or verification unavailable; %d reported none: an older agent)",
				f.SignatureUnknown+missing, f.Installations, f.SignatureUnknown, missing))
	}
	switch {
	case f.SignatureUnsigned > 0:
		trust.Signing = SigningUnsigned
	case f.SignatureInvalid > 0:
		trust.Signing = SigningInvalid
	case f.SignatureUnknown > 0:
		trust.Signing = SigningUnknown
	case f.Installations == 0 || missing > 0:
		trust.Signing = SigningNotCollected
	default:
		trust.Signing = SigningSigned
	}

	if trust.Signing == SigningSigned {
		// The enterprise reason above already says why: basis stays none.
		if f.RootEnterprise > 0 {
			return false
		}
		detail := ""
		switch unestablished := f.SignatureValid - f.RootPublic - f.RootEnterprise - f.RootLegacy; {
		case unestablished > 0:
			detail = fmt.Sprintf("the Authenticode root of %d of %d installations could not be established", unestablished, f.Installations)
		case f.RootPublic > 0 && (len(f.AuthenticodeRoots) != 1 || f.RootPublicPinned != f.RootPublic):
			detail = "installations disagree on the Authenticode root"
			if len(f.AuthenticodeRoots) <= 1 {
				detail = "the Authenticode root thumbprint could not be read"
			}
		case len(f.AuthenticodeSigners) == 1 && f.SignatureValidSigned == f.Installations:
			trust.Publisher = strPtr(f.AuthenticodeSigners[0])
			trust.PublisherBasis = PublisherBasisAuthenticode
			return true
		case len(f.AuthenticodeSigners) > 1:
			detail = "installations disagree on the Authenticode signer"
		default:
			detail = "the Authenticode signature is valid but its signer could not be read"
		}
		add(ReasonUnknownPublisher, UrgencyHigh, detail)
		return false
	}

	// No Authenticode trust: the registry Publisher is shown, unverified.
	if len(f.Publishers) == 1 && f.PublisherInstallations == f.Installations && f.Installations > 0 {
		trust.Publisher = strPtr(f.Publishers[0])
		trust.PublisherBasis = PublisherBasisRegistryPublisher
	} else {
		detail := "no installation reports a publisher"
		if len(f.Publishers) > 1 || (f.PublisherInstallations > 0 && f.PublisherInstallations < f.Installations) {
			detail = "installations disagree on the publisher"
		}
		add(ReasonUnknownPublisher, UrgencyHigh, detail)
	}
	return false
}

// classifyMacTrust fills trust for a macOS product and reports whether its
// publisher is trusted.
func classifyMacTrust(f trustFacts, approvedTeams map[string]bool, trust *UrgencyTrust, add func(code, level, detail string)) bool {
	classes := map[string]bool{}
	for _, s := range f.Signers {
		classes[macSignerClass(s)] = true
	}
	// Every applicable signing reason is reported; trust.Signing is the worst
	// instance: unsigned, then invalid, then untrusted, then ad hoc, then
	// unknown.
	explicit := f.ExplicitUnsigned + f.ExplicitAdhoc + f.ExplicitUntrusted + f.ExplicitInvalid
	if f.ExplicitUnsigned > 0 {
		add(ReasonUnsigned, UrgencyCritical,
			fmt.Sprintf("%d of %d installations are reported unsigned", f.ExplicitUnsigned, f.Installations))
	}
	if f.ExplicitAdhoc > 0 {
		add(ReasonAdhocSigned, UrgencyHigh,
			fmt.Sprintf("%d of %d installations are ad hoc signed, which carries no signing identity, so no publisher can be established",
				f.ExplicitAdhoc, f.Installations))
	}
	// PAT-2117: the collector verified the signature but the certificate
	// chain does not anchor to Apple -- a self-signed certificate can still
	// name itself "Developer ID Application: ...", so this is evidence the
	// string-based signer class alone cannot see.
	if f.ExplicitUntrusted > 0 {
		add(ReasonUntrustedSigner, UrgencyHigh,
			"signed with a certificate that does not chain to Apple, so the signer name is unverified")
	}
	if f.ExplicitInvalid > 0 {
		add(ReasonSignatureInvalid, UrgencyHigh,
			fmt.Sprintf("%d of %d installations have a signature that does not validate against the code, which was tampered with or broken after signing",
				f.ExplicitInvalid, f.Installations))
	}
	unknown := false
	switch {
	case f.SignerUnestablished > 0:
		unknown = true
		add(ReasonSigningUnknown, UrgencyHigh,
			fmt.Sprintf("the collector could not establish a signing authority on %d of %d installations (codesign could not read it, or an agent too old to say whether it is unsigned or ad hoc signed)",
				f.SignerUnestablished, f.Installations))
	case f.Installations == 0 || f.SignerReported < f.Installations || (len(f.Signers) == 0 && explicit == 0):
		unknown = true
		add(ReasonSigningUnknown, UrgencyHigh,
			fmt.Sprintf("%d of %d installations carry no signing evidence", f.Installations-f.SignerReported, f.Installations))
	}
	switch {
	case f.ExplicitUnsigned > 0:
		trust.Signing = SigningUnsigned
	case f.ExplicitInvalid > 0:
		trust.Signing = SigningInvalid
	case f.ExplicitUntrusted > 0:
		trust.Signing = SigningUntrusted
	case f.ExplicitAdhoc > 0:
		trust.Signing = SigningAdhoc
	case unknown:
		trust.Signing = SigningUnknown
	default:
		trust.Signing = SigningSigned
	}

	if len(classes) == 1 {
		for c := range classes {
			trust.SignerClass = strPtr(c)
		}
	} else if len(classes) > 1 {
		trust.SignerClass = strPtr(SignerMixed)
	}
	// The explicit untrusted reason above already covers a self-signed
	// certificate that copies the Developer ID naming convention; only add
	// this generic fallback when there is no more specific PAT-2117 evidence,
	// so the same product never reports untrusted_signer twice.
	if classes[SignerOther] && f.ExplicitUntrusted == 0 {
		add(ReasonUntrustedSigner, UrgencyHigh,
			"signed by an authority that is not a Developer ID, App Store or Apple distribution identity")
	}

	if trust.Signing == SigningSigned {
		if classes[SignerDeveloperID] {
			if f.NotarisedTrue == f.Installations {
				trust.Notarisation = NotarisationConfirmed
			} else {
				trust.Notarisation = NotarisationNotConfirmed
				add(ReasonNotarisationNotConfirmed, UrgencyHigh,
					fmt.Sprintf("Developer ID signed; notarisation reported on %d of %d installations", f.NotarisedTrue, f.Installations))
			}
		} else {
			trust.Notarisation = NotarisationNotApplicable
		}
	}

	var team string
	if len(f.TeamIDs) == 1 && f.TeamInstallations == f.Installations {
		team = normalisedTeamID("macos", f.TeamIDs[0])
	}
	appleOnly := trust.Signing == SigningSigned && len(classes) == 1 && classes[SignerApple]
	switch {
	case f.ExplicitUntrusted > 0 || f.ExplicitInvalid > 0:
		// PAT-2117: an untrusted or invalid signature never establishes a
		// publisher basis, even when the Team ID reported alongside it looks
		// like a real one -- a forged or tampered certificate can carry any
		// Team ID string. trust.PublisherBasis stays at its "none" default,
		// and the untrusted/invalid reason already added above explains why.
	case team != "":
		trust.Publisher = strPtr(team)
		trust.PublisherBasis = PublisherBasisTeamID
		trust.PublisherHasApprovedProducts = approvedTeams[team]
	case appleOnly:
		trust.Publisher = strPtr("Apple")
		trust.PublisherBasis = PublisherBasisAppleSignature
	default:
		detail := "no Team ID reported"
		if len(f.TeamIDs) > 1 || (f.TeamInstallations > 0 && f.TeamInstallations < f.Installations) {
			detail = "installations disagree on the Team ID"
		} else if len(f.TeamIDs) == 1 {
			detail = "the reported Team ID is not a valid Apple Team ID"
		}
		add(ReasonUnknownPublisher, UrgencyHigh, detail)
	}

	return trust.Signing == SigningSigned && !classes[SignerOther] &&
		trust.Notarisation != NotarisationNotConfirmed && trust.PublisherBasis != PublisherBasisNone
}

// windowsPublisherKey is the Authenticode publisher key of a Windows product
// whose trust classifyWindowsTrust established (PAT-2121), or "". It needs
// every installation pinned to one microsoft or public root with one signer:
// an estate that still has an older agent's rootless installation has no
// key, and neither does anything with an enterprise root. The same rule as
// DeriveAuthenticodePublisherKey, which records the key on approval.
func windowsPublisherKey(f trustFacts) string {
	if f.Installations == 0 || f.RootEnterprise > 0 || f.SignatureValid != f.Installations ||
		f.RootPublicPinned != f.Installations || len(f.AuthenticodeRoots) != 1 ||
		f.SignatureValidSigned != f.Installations || len(f.AuthenticodeSigners) != 1 {
		return ""
	}
	return AuthenticodePublisherKey(f.AuthenticodeRoots[0], f.AuthenticodeSigners[0])
}
