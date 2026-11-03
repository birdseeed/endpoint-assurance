package softwaregov

import (
	"testing"

	"patched.im/api/internal/cvepipeline"
)

// PAT-2093: one case per urgency rule, macOS and Windows.

const devID = "Developer ID Application: Example Ltd (ABCDE12345)"

func intp(n int) *int { return &n }

func assessedClean() cvepipeline.EstateAssessment {
	return cvepipeline.EstateAssessment{State: cvepipeline.StateAssessed, FindingCount: intp(0)}
}

func assessedWith(sev cvepipeline.SeverityCounts, n int) cvepipeline.EstateAssessment {
	return cvepipeline.EstateAssessment{State: cvepipeline.StateAssessed, FindingCount: intp(n), Severity: sev}
}

func notAssessed() cvepipeline.EstateAssessment {
	return cvepipeline.EstateAssessment{State: cvepipeline.StateNotAssessed}
}

// trustedMac is a Developer ID signed, notarised product with one Team ID.
func trustedMac() trustFacts {
	return trustFacts{Platform: "macos", Installations: 2, SignerReported: 2, NotarisedTrue: 2,
		Signers: []string{devID}, TeamInstallations: 2, TeamIDs: []string{"ABCDE12345"}}
}

func windowsWithPublisher() trustFacts {
	return trustFacts{Platform: "windows", Installations: 1, PublisherInstallations: 1,
		Publishers: []string{"Example Corporation"}}
}

// teams is publisherApprovals with approved macOS Team IDs only.
func teams(m map[string]bool) publisherApprovals {
	return publisherApprovals{teams: m}
}

func hasReason(reasons []UrgencyReason, code string) bool {
	for _, r := range reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func TestClassifyUrgencyRules(t *testing.T) {
	approved := map[string]bool{"ABCDE12345": true}
	cases := []struct {
		name     string
		facts    func() trustFacts
		cve      cvepipeline.EstateAssessment
		approved map[string]bool
		want     string
		reason   string
	}{
		{"critical: critical CVE on a trusted mac product", trustedMac,
			assessedWith(cvepipeline.SeverityCounts{Critical: 1}, 1), approved, UrgencyCritical, ReasonCVECriticalOrHigh},
		{"critical: high CVE", trustedMac,
			assessedWith(cvepipeline.SeverityCounts{High: 2}, 2), nil, UrgencyCritical, ReasonCVECriticalOrHigh},
		{"critical: high CVE known while pending", trustedMac,
			cvepipeline.EstateAssessment{State: cvepipeline.StatePending, FindingCount: intp(1),
				Severity: cvepipeline.SeverityCounts{High: 1}}, nil, UrgencyCritical, ReasonCVECriticalOrHigh},
		{"critical: high CVE on Windows", windowsWithPublisher,
			assessedWith(cvepipeline.SeverityCounts{High: 1}, 1), nil, UrgencyCritical, ReasonCVECriticalOrHigh},
		{"critical: installation explicitly reported unsigned", func() trustFacts {
			f := trustedMac()
			f.ExplicitUnsigned, f.NotarisedTrue = 1, 1
			return f
		}, assessedClean(), approved, UrgencyCritical, ReasonUnsigned},
		{"critical: an unsigned-only product (PAT-2112)", func() trustFacts {
			return trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitUnsigned: 1}
		}, assessedClean(), nil, UrgencyCritical, ReasonUnsigned},
		{"high: ad hoc signed installation (PAT-2112)", func() trustFacts {
			f := trustedMac()
			f.ExplicitAdhoc, f.Signers, f.SignerReported = 1, []string{devID}, 2
			return f
		}, assessedClean(), approved, UrgencyHigh, ReasonAdhocSigned},
		{"high: an ad hoc-only product (PAT-2112)", func() trustFacts {
			return trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitAdhoc: 1}
		}, assessedClean(), nil, UrgencyHigh, ReasonAdhocSigned},
		{"high: collector's Unknown signer is signing unknown, not unsigned", func() trustFacts {
			f := trustedMac()
			f.SignerUnestablished, f.NotarisedTrue = 1, 1
			return f
		}, assessedClean(), approved, UrgencyHigh, ReasonSigningUnknown},
		{"critical: unidentifiable name-only product", func() trustFacts {
			return trustFacts{Platform: "macos", NameOnly: true, Installations: 1, DisplayNameOnly: 1, SignerReported: 1, Signers: []string{devID}}
		}, notAssessed(), nil, UrgencyCritical, ReasonUnidentifiable},
		{"critical: unidentifiable on Windows", func() trustFacts {
			return trustFacts{Platform: "windows", NameOnly: true, Installations: 1, DisplayNameOnly: 1}
		}, notAssessed(), nil, UrgencyCritical, ReasonUnidentifiable},
		{"high: Developer ID signed, notarisation not confirmed", func() trustFacts {
			f := trustedMac()
			f.NotarisedTrue = 1
			return f
		}, assessedClean(), approved, UrgencyHigh, ReasonNotarisationNotConfirmed},
		{"high: development certificate is not a distribution identity", func() trustFacts {
			f := trustedMac()
			f.Signers = []string{"Apple Development: someone@example.com (XYZ)"}
			return f
		}, assessedClean(), approved, UrgencyHigh, ReasonUntrustedSigner},
		{"high: missing signing evidence is unknown, not trusted", func() trustFacts {
			f := trustedMac()
			f.SignerReported, f.Signers = 1, []string{devID}
			return f
		}, assessedClean(), approved, UrgencyHigh, ReasonSigningUnknown},
		{"high: no signing evidence at all (older agent or backfill)", func() trustFacts {
			return trustFacts{Platform: "macos", Installations: 1, TeamInstallations: 1, TeamIDs: []string{"ABCDE12345"}}
		}, assessedClean(), approved, UrgencyHigh, ReasonSigningUnknown},
		{"high: unknown publisher (no Team ID)", func() trustFacts {
			f := trustedMac()
			f.TeamInstallations, f.TeamIDs = 0, nil
			return f
		}, assessedClean(), nil, UrgencyHigh, ReasonUnknownPublisher},
		{"high: installations disagree on Team ID", func() trustFacts {
			f := trustedMac()
			f.TeamIDs = []string{"ABCDE12345", "ZZZZZ99999"}
			return f
		}, assessedClean(), approved, UrgencyHigh, ReasonUnknownPublisher},
		{"high: medium CVE on a trusted product", trustedMac,
			assessedWith(cvepipeline.SeverityCounts{Medium: 1}, 1), approved, UrgencyHigh, ReasonCVEMedium},
		{"high: low or unrated CVE is still a known CVE", trustedMac,
			assessedWith(cvepipeline.SeverityCounts{Unrated: 1}, 1), approved, UrgencyHigh, ReasonCVELowOrUnrated},
		{"high: Windows with a registry publisher and no known CVEs", windowsWithPublisher,
			assessedClean(), approved, UrgencyHigh, ReasonAuthenticodeNotCollected},
		{"high: Windows with no publisher", func() trustFacts {
			return trustFacts{Platform: "windows", Installations: 1}
		}, assessedClean(), nil, UrgencyHigh, ReasonUnknownPublisher},
		{"not_assessed: trusted, CVE state not assessed, publisher approved", trustedMac,
			notAssessed(), approved, UrgencyNotAssessed, ReasonCVENotAssessed},
		{"not_assessed: trusted, CVE matching pending with zero findings so far", trustedMac,
			cvepipeline.EstateAssessment{State: cvepipeline.StatePending, FindingCount: intp(0)}, approved,
			UrgencyNotAssessed, ReasonCVEPending},
		{"medium: trusted, assessed clean, publisher not yet approved", trustedMac,
			assessedClean(), nil, UrgencyMedium, ReasonTrustedNoKnownCVEs},
		{"medium: App Store signed needs no notarisation", func() trustFacts {
			f := trustedMac()
			f.Signers, f.NotarisedTrue = []string{"Apple Mac OS Application Signing"}, 0
			return f
		}, assessedClean(), nil, UrgencyMedium, ReasonTrustedNoKnownCVEs},
		{"medium: Apple platform signing, publisher Apple", func() trustFacts {
			return trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, Signers: []string{"Software Signing"},
				TeamInstallations: 1, TeamIDs: []string{"NOT SET"}}
		}, assessedClean(), nil, UrgencyMedium, ReasonTrustedNoKnownCVEs},
		{"low: trusted, assessed clean, publisher already approved", trustedMac,
			assessedClean(), approved, UrgencyLow, ReasonPublisherHasApprovedItems},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, reasons, _ := classifyUrgency(tc.facts(), tc.cve, teams(tc.approved))
			if level != tc.want {
				t.Fatalf("level = %q, want %q; reasons %+v", level, tc.want, reasons)
			}
			if !hasReason(reasons, tc.reason) {
				t.Fatalf("reasons %+v lack %q", reasons, tc.reason)
			}
			if reasons[0].Level != level {
				t.Fatalf("first reason %+v does not carry the level %q", reasons[0], level)
			}
		})
	}
}

// An unassessed CVE state must never read as "no known CVEs": whatever the
// trust evidence, a not_assessed or pending product is never medium or low.
func TestClassifyUrgencyNotAssessedNeverLowOrMedium(t *testing.T) {
	approved := map[string]bool{"ABCDE12345": true}
	for _, cve := range []cvepipeline.EstateAssessment{
		notAssessed(),
		{State: cvepipeline.StatePending, FindingCount: intp(0)},
		// A not_assessed state with a stray zero count is still not assessed.
		{State: cvepipeline.StateNotAssessed, FindingCount: intp(0)},
	} {
		level, reasons, trust := classifyUrgency(trustedMac(), cve, teams(approved))
		if !trust.Trusted {
			t.Fatalf("fixture is not trusted: %+v", trust)
		}
		if level == UrgencyLow || level == UrgencyMedium {
			t.Fatalf("cve %+v: level %q reads as no known CVEs; reasons %+v", cve, level, reasons)
		}
		if level != UrgencyNotAssessed {
			t.Fatalf("cve %+v: level %q, want not_assessed", cve, level)
		}
		if hasReason(reasons, ReasonTrustedNoKnownCVEs) || hasReason(reasons, ReasonPublisherHasApprovedItems) {
			t.Fatalf("cve %+v: reasons claim no known CVEs: %+v", cve, reasons)
		}
	}
}

// The most severe applicable reason sets the level, and every applicable
// reason is reported.
func TestClassifyUrgencyMostSevereWinsAndAllReasonsReported(t *testing.T) {
	f := trustedMac()
	f.ExplicitUnsigned, f.NotarisedTrue = 1, 0
	level, reasons, _ := classifyUrgency(f, assessedWith(cvepipeline.SeverityCounts{Medium: 1}, 1), teams(nil))
	if level != UrgencyCritical {
		t.Fatalf("level %q, want critical", level)
	}
	for _, code := range []string{ReasonUnsigned, ReasonCVEMedium} {
		if !hasReason(reasons, code) {
			t.Fatalf("reasons %+v lack %q", reasons, code)
		}
	}
	for i := 1; i < len(reasons); i++ {
		if urgencyRank[reasons[i].Level] > urgencyRank[reasons[i-1].Level] {
			t.Fatalf("reasons not most severe first: %+v", reasons)
		}
	}
}

// Windows with no Authenticode evidence is never trusted, and a registry
// publisher string is never treated as a signing identity, even when an
// approved macOS policy happens to carry the same text.
func TestClassifyUrgencyWindowsNeverTrusted(t *testing.T) {
	f := windowsWithPublisher()
	f.Publishers = []string{"ABCDE12345"}
	level, reasons, trust := classifyUrgency(f, assessedClean(), teams(map[string]bool{"ABCDE12345": true}))
	if trust.Trusted || trust.PublisherHasApprovedProducts {
		t.Fatalf("windows trust = %+v, want untrusted with no approved publisher", trust)
	}
	if trust.Signing != SigningNotCollected || trust.PublisherBasis != PublisherBasisRegistryPublisher {
		t.Fatalf("windows trust = %+v", trust)
	}
	if level != UrgencyHigh || !hasReason(reasons, ReasonAuthenticodeNotCollected) {
		t.Fatalf("level %q reasons %+v, want high with authenticode_not_collected", level, reasons)
	}
}

// The sentinel alone must never produce the unsigned verdict.
func TestClassifyUrgencySentinelNeverUnsigned(t *testing.T) {
	f := trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, SignerUnestablished: 1}
	level, reasons, trust := classifyUrgency(f, assessedClean(), teams(nil))
	if level != UrgencyHigh || hasReason(reasons, ReasonUnsigned) || trust.Signing != SigningUnknown {
		t.Fatalf("level %q signing %q reasons %+v, want high signing_unknown and no unsigned", level, trust.Signing, reasons)
	}
}

func TestMacSignerClass(t *testing.T) {
	for signer, want := range map[string]string{
		devID:                                 SignerDeveloperID,
		"Apple Mac OS Application Signing":    SignerAppStore,
		"Apple iPhone OS Application Signing": SignerAppStore,
		"Software Signing":                    SignerApple,
		"macOS Software Signing":              SignerApple,
		"Apple Development: x (Y)":            SignerOther,
		"Mac Developer: x (Y)":                SignerOther,
		"Some Self Signed CA":                 SignerOther,
	} {
		if got := macSignerClass(signer); got != want {
			t.Errorf("macSignerClass(%q) = %q, want %q", signer, got, want)
		}
	}
}

func TestIsPatchedAgent(t *testing.T) {
	cases := []struct {
		platform, ident, name string
		nameOnly, want        bool
	}{
		{"macos", "im.patched.updater.menubar", "Patched", false, true},
		{"macos", "im.patched.updater.selfservice", "Patched Self Service", false, true},
		{"windows", "{a1b2c3d4-0000-0000-0000-000000000000}", "Patched Agent", false, true},
		{"windows", "patched agent", "Patched Agent", true, true},
		// The bundle ID is macOS identity only; the bare word "Patched" is not.
		{"windows", "im.patched.updater.menubar", "Patched", false, false},
		{"macos", "com.example.patched", "Patched", false, false},
		{"macos", "im.patched.updater.menubar", "x", true, false},
	}
	for _, tc := range cases {
		if got := isPatchedAgent(tc.platform, tc.ident, tc.name, tc.nameOnly); got != tc.want {
			t.Errorf("isPatchedAgent(%q, %q, %q, %v) = %v, want %v", tc.platform, tc.ident, tc.name, tc.nameOnly, got, tc.want)
		}
	}
}

func TestAddressableIdentity(t *testing.T) {
	team, key := addressableIdentity("macos", "com.example.app", trustedMac())
	if team == nil || *team != "ABCDE12345" || key == nil || *key != "application:macos:com.example.app:ABCDE12345" {
		t.Fatalf("trusted mac: team %v key %v", team, key)
	}
	f := trustedMac()
	f.TeamIDs = []string{"ABCDE12345", "ZZZZZ99999"}
	if team, key := addressableIdentity("macos", "com.example.app", f); team != nil || key != nil {
		t.Fatalf("disagreeing teams: team %v key %v, want both null", team, key)
	}
	f.TeamIDs = []string{"NOT SET"}
	if team, key := addressableIdentity("macos", "com.example.app", f); team != nil || key != nil {
		t.Fatalf("malformed team: team %v key %v, want both null", team, key)
	}
	f = trustedMac()
	f.TeamInstallations, f.TeamIDs = 0, nil
	if team, key := addressableIdentity("macos", "com.example.app", f); team != nil || key == nil || *key != "application:macos:com.example.app" {
		t.Fatalf("bundle only: team %v key %v", team, key)
	}
	if team, key := addressableIdentity("windows", "vendor.tool", windowsWithPublisher()); team != nil || key == nil || *key != "application:windows:vendor.tool" {
		t.Fatalf("windows: team %v key %v", team, key)
	}
}

// PAT-2112: the explicit signing_status sets the signing verdict, is not
// double-reported as signing unknown, and every applicable reason is kept
// when installations differ.
func TestClassifyUrgencyExplicitSigningStatus(t *testing.T) {
	cases := []struct {
		name         string
		facts        trustFacts
		level        string
		signing      string
		reasons      []string
		absent       []string
		notarisation string
	}{
		{"unsigned only", trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitUnsigned: 1},
			UrgencyCritical, SigningUnsigned, []string{ReasonUnsigned}, []string{ReasonSigningUnknown, ReasonAdhocSigned}, NotarisationUnknown},
		{"ad hoc only", trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitAdhoc: 1},
			UrgencyHigh, SigningAdhoc, []string{ReasonAdhocSigned}, []string{ReasonSigningUnknown, ReasonUnsigned}, NotarisationUnknown},
		{"unsigned beside ad hoc and codesign error", trustFacts{Platform: "macos", Installations: 3, SignerReported: 3,
			ExplicitUnsigned: 1, ExplicitAdhoc: 1, SignerUnestablished: 1},
			UrgencyCritical, SigningUnsigned, []string{ReasonUnsigned, ReasonAdhocSigned, ReasonSigningUnknown}, nil, NotarisationUnknown},
		{"ad hoc beside a Developer ID installation", trustFacts{Platform: "macos", Installations: 2, SignerReported: 2,
			ExplicitAdhoc: 1, NotarisedTrue: 1, Signers: []string{devID}, TeamInstallations: 1, TeamIDs: []string{"ABCDE12345"}},
			UrgencyHigh, SigningAdhoc, []string{ReasonAdhocSigned}, []string{ReasonSigningUnknown}, NotarisationUnknown},
		{"codesign error stays signing unknown", trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, SignerUnestablished: 1},
			UrgencyHigh, SigningUnknown, []string{ReasonSigningUnknown}, []string{ReasonUnsigned, ReasonAdhocSigned}, NotarisationUnknown},
		{"notarised Developer ID, clean, trusted Team ID", trustedMac(),
			UrgencyMedium, SigningSigned, []string{ReasonTrustedNoKnownCVEs}, []string{ReasonNotarisationNotConfirmed}, NotarisationConfirmed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, reasons, trust := classifyUrgency(tc.facts, assessedClean(), teams(nil))
			if level != tc.level || trust.Signing != tc.signing || trust.Notarisation != tc.notarisation {
				t.Fatalf("level %q signing %q notarisation %q, want %q %q %q; reasons %+v",
					level, trust.Signing, trust.Notarisation, tc.level, tc.signing, tc.notarisation, reasons)
			}
			for _, code := range tc.reasons {
				if !hasReason(reasons, code) {
					t.Fatalf("reasons %+v lack %q", reasons, code)
				}
			}
			for _, code := range tc.absent {
				if hasReason(reasons, code) {
					t.Fatalf("reasons %+v carry %q", reasons, code)
				}
			}
			seen := map[string]bool{}
			for _, r := range reasons {
				if seen[r.Code] {
					t.Fatalf("reason %q reported twice: %+v", r.Code, reasons)
				}
				seen[r.Code] = true
			}
			if trust.Trusted && tc.signing != SigningSigned {
				t.Fatalf("trusted with signing %q", trust.Signing)
			}
		})
	}
}

const winSigner = "CN=Example Corporation, O=Example Corporation, L=Redmond, S=Washington, C=US"

// trustedWindows is a product whose every installation the agent reported
// Authenticode valid, with one signer (PAT-2113), from an agent older than
// updater #668: no root is reported (RootLegacy).
func trustedWindows() trustFacts {
	f := windowsWithPublisher()
	f.Installations, f.PublisherInstallations = 2, 2
	f.SignatureValid, f.SignatureValidSigned, f.AuthenticodeSigners = 2, 2, []string{winSigner}
	f.RootLegacy = 2
	return f
}

// PAT-2113: Windows urgency from the agent's Authenticode signature_state.
func TestClassifyUrgencyWindowsAuthenticode(t *testing.T) {
	// Every Team ID and publisher string an attacker could align is on the
	// approved list: Windows must still never reach low.
	approved := map[string]bool{"ABCDE12345": true, winSigner: true, "EXAMPLE CORPORATION": true}
	cases := []struct {
		name      string
		facts     func() trustFacts
		cve       cvepipeline.EstateAssessment
		level     string
		reason    string
		absent    []string
		signing   string
		publisher string
		basis     string
		trusted   bool
	}{
		{"valid, one signer, clean CVEs: medium, never low", trustedWindows, assessedClean(),
			UrgencyMedium, ReasonTrustedNoKnownCVEs, []string{ReasonAuthenticodeNotCollected, ReasonPublisherHasApprovedItems},
			SigningSigned, winSigner, PublisherBasisAuthenticode, true},
		{"valid but CVE not assessed", trustedWindows, notAssessed(),
			UrgencyNotAssessed, ReasonCVENotAssessed, []string{ReasonAuthenticodeNotCollected},
			SigningSigned, winSigner, PublisherBasisAuthenticode, true},
		{"valid with a critical CVE", trustedWindows, assessedWith(cvepipeline.SeverityCounts{Critical: 1}, 1),
			UrgencyCritical, ReasonCVECriticalOrHigh, nil, SigningSigned, winSigner, PublisherBasisAuthenticode, true},
		{"invalid on one installation: high", func() trustFacts {
			f := trustedWindows()
			f.SignatureValid, f.SignatureValidSigned, f.SignatureInvalid = 1, 1, 1
			return f
		}, assessedClean(), UrgencyHigh, ReasonAuthenticodeInvalid, []string{ReasonTrustedNoKnownCVEs},
			SigningInvalid, "Example Corporation", PublisherBasisRegistryPublisher, false},
		{"unknown reported: authenticode_not_collected", func() trustFacts {
			f := windowsWithPublisher()
			f.SignatureUnknown = 1
			return f
		}, assessedClean(), UrgencyHigh, ReasonAuthenticodeNotCollected, []string{ReasonAuthenticodeInvalid},
			SigningUnknown, "Example Corporation", PublisherBasisRegistryPublisher, false},
		{"absent: authenticode_not_collected", windowsWithPublisher, assessedClean(),
			UrgencyHigh, ReasonAuthenticodeNotCollected, nil,
			SigningNotCollected, "Example Corporation", PublisherBasisRegistryPublisher, false},
		{"valid on one of two installations, the other absent", func() trustFacts {
			f := trustedWindows()
			f.SignatureValid, f.SignatureValidSigned = 1, 1
			return f
		}, assessedClean(), UrgencyHigh, ReasonAuthenticodeNotCollected, []string{ReasonTrustedNoKnownCVEs},
			SigningNotCollected, "Example Corporation", PublisherBasisRegistryPublisher, false},
		{"valid, installations disagree on the signer", func() trustFacts {
			f := trustedWindows()
			f.AuthenticodeSigners = []string{winSigner, "CN=Other Ltd"}
			return f
		}, assessedClean(), UrgencyHigh, ReasonUnknownPublisher, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"valid, signer unreadable", func() trustFacts {
			f := trustedWindows()
			f.SignatureValidSigned, f.AuthenticodeSigners = 0, nil
			return f
		}, assessedClean(), UrgencyHigh, ReasonUnknownPublisher, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, reasons, trust := classifyUrgency(tc.facts(), tc.cve, teams(approved))
			if level != tc.level || !hasReason(reasons, tc.reason) {
				t.Fatalf("level %q reasons %+v, want %q with %q", level, reasons, tc.level, tc.reason)
			}
			for _, code := range tc.absent {
				if hasReason(reasons, code) {
					t.Fatalf("reasons %+v carry %q", reasons, code)
				}
			}
			if trust.Signing != tc.signing || trust.PublisherBasis != tc.basis || trust.Trusted != tc.trusted ||
				deref(trust.Publisher) != tc.publisher {
				t.Fatalf("trust = %+v (publisher %q), want signing %q basis %q publisher %q trusted %v",
					trust, deref(trust.Publisher), tc.signing, tc.basis, tc.publisher, tc.trusted)
			}
			if trust.PublisherHasApprovedProducts || trust.Notarisation != NotarisationNotApplicable || trust.SignerClass != nil {
				t.Fatalf("windows trust = %+v", trust)
			}
		})
	}
}

// PAT-2117: an untrusted or invalid macOS signature never counts as trusted
// and never sets a publisher basis, even when its signed_by looks like a
// genuine Developer ID and its Team ID already has an approved product here.
// Mixing either with a properly signed, notarised installation still reads
// as the worst instance, not medium or low.
func TestClassifyUrgencyMacUntrustedAndInvalidNeverTrusted(t *testing.T) {
	approved := map[string]bool{"ABCDE12345": true}

	untrustedOnly := trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitUntrusted: 1,
		Signers: []string{devID}, TeamInstallations: 1, TeamIDs: []string{"ABCDE12345"}}
	level, reasons, trust := classifyUrgency(untrustedOnly, assessedClean(), teams(approved))
	if level != UrgencyHigh || !hasReason(reasons, ReasonUntrustedSigner) {
		t.Fatalf("untrusted: level %q reasons %+v, want high with untrusted_signer", level, reasons)
	}
	if trust.Trusted || trust.Signing != SigningUntrusted || trust.PublisherBasis != PublisherBasisNone || trust.Publisher != nil {
		t.Fatalf("untrusted trust = %+v, want signing untrusted, no publisher basis, never trusted", trust)
	}

	invalidOnly := trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitInvalid: 1,
		Signers: []string{devID}, TeamInstallations: 1, TeamIDs: []string{"ABCDE12345"}}
	level, reasons, trust = classifyUrgency(invalidOnly, assessedClean(), teams(approved))
	if level != UrgencyHigh || !hasReason(reasons, ReasonSignatureInvalid) {
		t.Fatalf("invalid: level %q reasons %+v, want high with signature_invalid", level, reasons)
	}
	if trust.Trusted || trust.Signing != SigningInvalid || trust.PublisherBasis != PublisherBasisNone || trust.Publisher != nil {
		t.Fatalf("invalid trust = %+v, want signing invalid, no publisher basis, never trusted", trust)
	}

	// Mixed with a properly signed, notarised installation on the same
	// product: worst wins, so it is still high, not medium or low, despite
	// the Team ID already having an approved product here.
	mixedUntrusted := trustedMac()
	mixedUntrusted.ExplicitUntrusted, mixedUntrusted.NotarisedTrue = 1, 1
	level, reasons, trust = classifyUrgency(mixedUntrusted, assessedClean(), teams(approved))
	if level != UrgencyHigh || !hasReason(reasons, ReasonUntrustedSigner) || trust.Trusted || trust.Signing != SigningUntrusted {
		t.Fatalf("mixed untrusted+signed: level %q reasons %+v trust %+v", level, reasons, trust)
	}

	mixedInvalid := trustedMac()
	mixedInvalid.ExplicitInvalid, mixedInvalid.NotarisedTrue = 1, 1
	level, reasons, trust = classifyUrgency(mixedInvalid, assessedClean(), teams(approved))
	if level != UrgencyHigh || !hasReason(reasons, ReasonSignatureInvalid) || trust.Trusted || trust.Signing != SigningInvalid {
		t.Fatalf("mixed invalid+signed: level %q reasons %+v trust %+v", level, reasons, trust)
	}

	// Both on one product: invalid (tampered code) outranks untrusted
	// (self-signed but internally consistent) for trust.Signing, and both
	// reasons are still reported.
	both := trustFacts{Platform: "macos", Installations: 2, SignerReported: 2,
		ExplicitUntrusted: 1, ExplicitInvalid: 1, Signers: []string{devID}}
	level, reasons, trust = classifyUrgency(both, assessedClean(), teams(approved))
	if level != UrgencyHigh || !hasReason(reasons, ReasonUntrustedSigner) || !hasReason(reasons, ReasonSignatureInvalid) {
		t.Fatalf("both: level %q reasons %+v, want high with both reasons", level, reasons)
	}
	if trust.Signing != SigningInvalid {
		t.Fatalf("both: trust.Signing = %q, want invalid (worst instance wins)", trust.Signing)
	}

	// An untrusted verdict beside a signer whose text does not even look
	// like a Developer ID must not double-report untrusted_signer: the
	// explicit PAT-2117 evidence and the generic string-based fallback are
	// the same fact, not two.
	otherCA := trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitUntrusted: 1,
		Signers: []string{"Some Self Signed CA"}}
	level, reasons, trust = classifyUrgency(otherCA, assessedClean(), teams(approved))
	count := 0
	for _, r := range reasons {
		if r.Code == ReasonUntrustedSigner {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("untrusted with non-Developer-ID signer text: reasons %+v, want untrusted_signer exactly once", reasons)
	}
	if level != UrgencyHigh || trust.Trusted {
		t.Fatalf("otherCA untrusted: level %q trust %+v", level, trust)
	}
}

const (
	winRootA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	winRootB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// msLookingSigner is what an enterprise-issued certificate can claim.
	msLookingSigner = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)

// pinnedWindows is trustedWindows from an updater #668 agent: every
// installation valid, one signer, one microsoft or public root (PAT-2116).
func pinnedWindows() trustFacts {
	f := trustedWindows()
	f.RootLegacy = 0
	f.RootPublic, f.RootPublicPinned, f.AuthenticodeRoots = 2, 2, []string{winRootA}
	return f
}

// PAT-2116: Windows urgency from unsigned and the Authenticode root.
func TestClassifyUrgencyWindowsAuthenticodeRoot(t *testing.T) {
	approved := map[string]bool{"ABCDE12345": true, winSigner: true, msLookingSigner: true,
		winRootA: true, "EXAMPLE CORPORATION": true}
	cases := []struct {
		name      string
		facts     func() trustFacts
		cve       cvepipeline.EstateAssessment
		level     string
		reasons   []string
		absent    []string
		signing   string
		publisher string
		basis     string
		trusted   bool
	}{
		{"pinned public or microsoft root, one signer, clean CVEs: medium, never low", pinnedWindows, assessedClean(),
			UrgencyMedium, []string{ReasonTrustedNoKnownCVEs},
			[]string{ReasonPublisherHasApprovedItems, ReasonEnterpriseRoot, ReasonUnknownPublisher},
			SigningSigned, winSigner, PublisherBasisAuthenticode, true},
		{"enterprise root is never trusted, even with a Microsoft-looking subject", func() trustFacts {
			f := pinnedWindows()
			f.AuthenticodeSigners = []string{msLookingSigner}
			f.RootPublic, f.RootPublicPinned, f.AuthenticodeRoots, f.RootEnterprise = 0, 0, nil, 2
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonEnterpriseRoot},
			[]string{ReasonTrustedNoKnownCVEs, ReasonPublisherHasApprovedItems},
			SigningSigned, "", PublisherBasisNone, false},
		{"one enterprise installation beside a public one: not trusted", func() trustFacts {
			f := pinnedWindows()
			f.RootPublic, f.RootPublicPinned, f.RootEnterprise = 1, 1, 1
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonEnterpriseRoot}, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"enterprise beside a pre-#668 installation: not trusted", func() trustFacts {
			f := trustedWindows()
			f.RootLegacy, f.RootEnterprise = 1, 1
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonEnterpriseRoot}, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"installations disagree on the root: not trusted", func() trustFacts {
			f := pinnedWindows()
			f.AuthenticodeRoots = []string{winRootA, winRootB}
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonUnknownPublisher}, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"public root without a thumbprint: not trusted", func() trustFacts {
			f := pinnedWindows()
			f.RootPublicPinned = 1
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonUnknownPublisher}, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"publisher fields but no recognised root kind: not trusted", func() trustFacts {
			f := pinnedWindows()
			f.RootPublic, f.RootPublicPinned, f.AuthenticodeRoots = 1, 1, []string{winRootA}
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonUnknownPublisher}, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"missing root_kind (pre-#668 agent): agreed signer trusted as before", trustedWindows, assessedClean(),
			UrgencyMedium, []string{ReasonTrustedNoKnownCVEs}, []string{ReasonUnknownPublisher, ReasonEnterpriseRoot},
			SigningSigned, winSigner, PublisherBasisAuthenticode, true},
		{"pre-#668 installation beside a pinned one: trusted", func() trustFacts {
			f := pinnedWindows()
			f.RootPublic, f.RootPublicPinned, f.RootLegacy = 1, 1, 1
			return f
		}, assessedClean(), UrgencyMedium, []string{ReasonTrustedNoKnownCVEs}, nil,
			SigningSigned, winSigner, PublisherBasisAuthenticode, true},
		{"pinned but the signers disagree: not trusted", func() trustFacts {
			f := pinnedWindows()
			f.AuthenticodeSigners = []string{winSigner, "CN=Other Ltd"}
			return f
		}, assessedClean(), UrgencyHigh, []string{ReasonUnknownPublisher}, []string{ReasonTrustedNoKnownCVEs},
			SigningSigned, "", PublisherBasisNone, false},
		{"one installation unsigned: critical", func() trustFacts {
			f := pinnedWindows()
			f.SignatureValid, f.SignatureValidSigned, f.RootPublic, f.RootPublicPinned, f.SignatureUnsigned = 1, 1, 1, 1, 1
			return f
		}, assessedClean(), UrgencyCritical, []string{ReasonUnsigned}, []string{ReasonTrustedNoKnownCVEs},
			SigningUnsigned, "Example Corporation", PublisherBasisRegistryPublisher, false},
		{"unsigned beats invalid, enterprise, unknown and absent", func() trustFacts {
			f := windowsWithPublisher()
			f.Installations, f.PublisherInstallations = 6, 6
			f.SignatureUnsigned, f.SignatureInvalid, f.SignatureUnknown = 1, 1, 1
			f.SignatureValid, f.SignatureValidSigned, f.AuthenticodeSigners, f.RootEnterprise = 2, 2, []string{msLookingSigner}, 2
			return f
		}, assessedClean(), UrgencyCritical,
			[]string{ReasonUnsigned, ReasonAuthenticodeInvalid, ReasonEnterpriseRoot, ReasonAuthenticodeNotCollected},
			[]string{ReasonTrustedNoKnownCVEs}, SigningUnsigned, "Example Corporation", PublisherBasisRegistryPublisher, false},
		{"unsigned with no CVE mapping is still critical", func() trustFacts {
			f := windowsWithPublisher()
			f.SignatureUnsigned = 1
			return f
		}, notAssessed(), UrgencyCritical, []string{ReasonUnsigned, ReasonCVENotAssessed},
			[]string{ReasonAuthenticodeNotCollected}, SigningUnsigned, "Example Corporation", PublisherBasisRegistryPublisher, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, reasons, trust := classifyUrgency(tc.facts(), tc.cve, teams(approved))
			if level != tc.level {
				t.Fatalf("level %q reasons %+v, want %q", level, reasons, tc.level)
			}
			for _, code := range tc.reasons {
				if !hasReason(reasons, code) {
					t.Fatalf("reasons %+v lack %q", reasons, code)
				}
			}
			for _, code := range tc.absent {
				if hasReason(reasons, code) {
					t.Fatalf("reasons %+v carry %q", reasons, code)
				}
			}
			if trust.Signing != tc.signing || trust.PublisherBasis != tc.basis || trust.Trusted != tc.trusted ||
				deref(trust.Publisher) != tc.publisher {
				t.Fatalf("trust = %+v (publisher %q), want signing %q basis %q publisher %q trusted %v",
					trust, deref(trust.Publisher), tc.signing, tc.basis, tc.publisher, tc.trusted)
			}
			if trust.PublisherHasApprovedProducts || level == UrgencyLow {
				t.Fatalf("windows reached low / approved: %q %+v", level, trust)
			}
		})
	}
}
