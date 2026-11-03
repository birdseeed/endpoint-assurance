package softwaregov

import "testing"

// PAT-2152: the publisher report's pure classifier. One case per required
// acceptance scenario (a signed trusted publisher, a signed untrusted
// publisher, an unsigned install, an install with no signing evidence), on
// both platforms where the evidence exists, plus a regression proving the
// publisher is never taken from installer metadata (the registry Publisher
// string or a Windows agent's claimed name) when signing evidence does not
// establish it.

const testTeamID = "ABCDE12345"

func macTrusted() trustFacts {
	return trustFacts{Platform: "macos", Installations: 2, SignerReported: 2, NotarisedTrue: 2,
		Signers: []string{devID}, TeamInstallations: 2, TeamIDs: []string{testTeamID}}
}

func winValidPinned(signer, root string) trustFacts {
	return trustFacts{Platform: "windows", Installations: 2, SignatureValid: 2, SignatureValidSigned: 2,
		AuthenticodeSigners: []string{signer}, RootPublic: 2, RootPublicPinned: 2, AuthenticodeRoots: []string{root}}
}

func TestClassifyPublisherMacTrustedApproved(t *testing.T) {
	c := classifyPublisher("macos", macTrusted(), map[string]bool{testTeamID: true}, nil)
	if c.Group != PublisherGroupVerified {
		t.Fatalf("group = %q, want verified", c.Group)
	}
	if c.IdentityBasis != PublisherBasisTeamID {
		t.Fatalf("identity basis = %q, want team_id", c.IdentityBasis)
	}
	if !c.Trusted {
		t.Fatal("trusted = false, want true: the Team ID is on an approved policy")
	}
	if c.Publisher == nil || *c.Publisher != testTeamID {
		t.Fatalf("publisher = %v, want %q", c.Publisher, testTeamID)
	}
}

// TestClassifyPublisherMacVerifiedButNotApproved is the "signed untrusted
// publisher" acceptance case on macOS: a Team ID is established, but this
// tenant has never approved anything from it.
func TestClassifyPublisherMacVerifiedButNotApproved(t *testing.T) {
	c := classifyPublisher("macos", macTrusted(), map[string]bool{}, nil)
	if c.Group != PublisherGroupVerified {
		t.Fatalf("group = %q, want verified", c.Group)
	}
	if c.Trusted {
		t.Fatal("trusted = true, want false: no approved policy names this Team ID")
	}
	if c.Publisher == nil || *c.Publisher != testTeamID {
		t.Fatalf("publisher = %v, want %q", c.Publisher, testTeamID)
	}
}

// TestClassifyPublisherMacUnsigned is the "unsigned install" acceptance case.
func TestClassifyPublisherMacUnsigned(t *testing.T) {
	f := trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitUnsigned: 1}
	c := classifyPublisher("macos", f, nil, nil)
	if c.Group != PublisherGroupUnsignedAdhoc {
		t.Fatalf("group = %q, want unsigned_or_adhoc", c.Group)
	}
	if c.Publisher != nil {
		t.Fatalf("publisher = %v, want nil: unsigned software has no publisher", c.Publisher)
	}
	if c.Trusted {
		t.Fatal("trusted = true, want false")
	}
}

// TestClassifyPublisherMacNoEvidence is the "install with no signing
// evidence" acceptance case: an agent too old to report signing_status at
// all leaves signed_by unreported.
func TestClassifyPublisherMacNoEvidence(t *testing.T) {
	f := trustFacts{Platform: "macos", Installations: 1}
	c := classifyPublisher("macos", f, map[string]bool{testTeamID: true}, nil)
	if c.Group != PublisherGroupUnverified {
		t.Fatalf("group = %q, want unverified", c.Group)
	}
	if c.Publisher != nil {
		t.Fatalf("publisher = %v, want nil", c.Publisher)
	}
}

// TestClassifyPublisherMacInvalidNeverBasis: an untrusted (non-Apple-chained)
// or invalid (tampered) signature never establishes a publisher, even when
// the reported Team ID looks legitimate -- a forged certificate can carry
// any Team ID string (PAT-2117).
func TestClassifyPublisherMacInvalidNeverBasis(t *testing.T) {
	f := trustFacts{Platform: "macos", Installations: 1, SignerReported: 1, ExplicitUntrusted: 1,
		Signers: []string{devID}, TeamInstallations: 1, TeamIDs: []string{testTeamID}}
	c := classifyPublisher("macos", f, map[string]bool{testTeamID: true}, nil)
	if c.Group != PublisherGroupInvalid {
		t.Fatalf("group = %q, want invalid", c.Group)
	}
	if c.Publisher != nil {
		t.Fatalf("publisher = %v, want nil: an untrusted chain never sets a publisher basis", c.Publisher)
	}
	if c.Trusted {
		t.Fatal("trusted = true, want false")
	}
}

func TestClassifyPublisherWindowsTrustedApproved(t *testing.T) {
	signer, root := "CN=Example Ltd, O=Example Ltd, C=GB", sha256Fixture("root-a")
	key := AuthenticodePublisherKey(root, signer)
	c := classifyPublisher("windows", winValidPinned(signer, root), nil, map[string]map[string]bool{key: {"other-product": true}})
	if c.Group != PublisherGroupVerified {
		t.Fatalf("group = %q, want verified", c.Group)
	}
	if c.IdentityBasis != PublisherBasisAuthenticode {
		t.Fatalf("identity basis = %q, want authenticode_signer", c.IdentityBasis)
	}
	if !c.Trusted {
		t.Fatal("trusted = false, want true: the publisher key is on an approved policy")
	}
	if c.PublisherKey != key {
		t.Fatalf("publisher key = %q, want %q (root-pinned)", c.PublisherKey, key)
	}
}

// TestClassifyPublisherWindowsVerifiedButNotApproved is the "signed
// untrusted publisher" acceptance case on Windows.
func TestClassifyPublisherWindowsVerifiedButNotApproved(t *testing.T) {
	signer, root := "CN=Example Ltd, O=Example Ltd, C=GB", sha256Fixture("root-a")
	c := classifyPublisher("windows", winValidPinned(signer, root), nil, map[string]map[string]bool{})
	if c.Group != PublisherGroupVerified {
		t.Fatalf("group = %q, want verified", c.Group)
	}
	if c.Trusted {
		t.Fatal("trusted = true, want false: no approved policy names this publisher key")
	}
}

// TestClassifyPublisherWindowsUnsigned is the "unsigned install" acceptance
// case on Windows.
func TestClassifyPublisherWindowsUnsigned(t *testing.T) {
	f := trustFacts{Platform: "windows", Installations: 1, SignatureUnsigned: 1}
	c := classifyPublisher("windows", f, nil, nil)
	if c.Group != PublisherGroupUnsignedAdhoc {
		t.Fatalf("group = %q, want unsigned_or_adhoc", c.Group)
	}
	if c.Publisher != nil {
		t.Fatal("publisher != nil, want nil for an unsigned install")
	}
}

// TestClassifyPublisherWindowsNoEvidence is the "install with no signing
// evidence" acceptance case on Windows: no observation carries the PAT-2113
// fields at all (an agent older than the reviewed evidence targets).
func TestClassifyPublisherWindowsNoEvidence(t *testing.T) {
	f := trustFacts{Platform: "windows", Installations: 1}
	c := classifyPublisher("windows", f, nil, map[string]map[string]bool{"authenticode:x:CN=Anyone": {"p": true}})
	if c.Group != PublisherGroupUnverified {
		t.Fatalf("group = %q, want unverified", c.Group)
	}
	if c.Publisher != nil {
		t.Fatal("publisher != nil, want nil")
	}
}

// TestClassifyPublisherWindowsRegistryPublisherNeverLeaks is the core
// never-fall-back-to-installer-metadata regression. With no Authenticode
// trust at all, classifyWindowsTrust itself sets Publisher to the raw
// registry Publisher string (PublisherBasisRegistryPublisher) as an
// explicitly-unverified fallback for the overview. This report must never
// surface that value under any name.
func TestClassifyPublisherWindowsRegistryPublisherNeverLeaks(t *testing.T) {
	f := windowsWithPublisher() // Installations: 1, Publishers: ["Example Corporation"]
	c := classifyPublisher("windows", f, nil, nil)
	if c.Group != PublisherGroupUnverified {
		t.Fatalf("group = %q, want unverified", c.Group)
	}
	if c.Publisher != nil {
		t.Fatalf("publisher = %q, want nil: the registry Publisher string must never be shown as the publisher", *c.Publisher)
	}
	if c.IdentityBasis != PublisherBasisNone {
		t.Fatalf("identity_basis = %q, want none", c.IdentityBasis)
	}
}

// TestClassifyPublisherWindowsInvalid is the "invalid signature" case: a
// digest mismatch (the file changed after signing) never establishes a
// publisher.
func TestClassifyPublisherWindowsInvalid(t *testing.T) {
	f := trustFacts{Platform: "windows", Installations: 1, SignatureInvalid: 1}
	c := classifyPublisher("windows", f, nil, nil)
	if c.Group != PublisherGroupInvalid {
		t.Fatalf("group = %q, want invalid", c.Group)
	}
	if c.Publisher != nil {
		t.Fatal("publisher != nil, want nil for an invalid signature")
	}
}

// TestClassifyPublisherWindowsEnterpriseRootUnverified: a valid Authenticode
// signature that chains to an enterprise root is not independently
// verifiable (PAT-2116) and windowsPublisherKey refuses it a pin, so it must
// never be shown as a verified publisher even though it carries a plausible
// signer name.
func TestClassifyPublisherWindowsEnterpriseRootUnverified(t *testing.T) {
	f := trustFacts{Platform: "windows", Installations: 1, SignatureValid: 1, SignatureValidSigned: 1,
		AuthenticodeSigners: []string{"CN=Internal IT, O=Example Corp"}, RootEnterprise: 1}
	c := classifyPublisher("windows", f, nil, nil)
	if c.Group != PublisherGroupUnverified {
		t.Fatalf("group = %q, want unverified (enterprise root is never independently verifiable)", c.Group)
	}
	if c.Publisher != nil {
		t.Fatal("publisher != nil, want nil: an enterprise-root signer is never shown as the publisher")
	}
}

// TestClassifyPublisherWindowsLegacyNoRootUnverified: an older agent (before
// updater #668) that reports a valid Authenticode signature and signer but no
// root evidence at all (RootLegacy) cannot be pinned (PAT-2121 needs the root
// thumbprint). PAT-2093's own urgency classifier still treats the bare
// signer as trusted for back-compat -- classifyWindowsTrust itself DOES set
// Publisher and return true here -- so this test only passes because
// classifyPublisher's own downgrade (clearing Publisher when
// windowsPublisherKey has no pin) runs on top of it. Deleting that downgrade
// turns this red: it is not passing by construction of the shared classifier.
func TestClassifyPublisherWindowsLegacyNoRootUnverified(t *testing.T) {
	f := trustFacts{Platform: "windows", Installations: 1, SignatureValid: 1, SignatureValidSigned: 1,
		AuthenticodeSigners: []string{"CN=Legacy Vendor, O=Legacy Vendor Ltd"}, RootLegacy: 1}

	// Confirm the premise: PAT-2093's classifier alone reports this signer
	// as trusted (this is the back-compat behaviour classifyPublisher must
	// override for this report, not a case that was already safe).
	trust := UrgencyTrust{PublisherBasis: PublisherBasisNone, Signing: SigningUnknown, Notarisation: NotarisationUnknown}
	if trusted := classifyWindowsTrust(f, &trust, func(string, string, string) {}); !trusted || trust.Publisher == nil {
		t.Fatalf("premise failed: classifyWindowsTrust(legacy no-root) = trusted %v publisher %v, want true and non-nil", trusted, trust.Publisher)
	}

	c := classifyPublisher("windows", f, nil, nil)
	if c.Group != PublisherGroupUnverified {
		t.Fatalf("group = %q, want unverified (no root pin)", c.Group)
	}
	if c.Publisher != nil {
		t.Fatal("publisher != nil, want nil: an unpinned legacy signer is never shown as the publisher")
	}
}

// TestPublisherBucketExhaustive locks every Signing value to exactly one
// report group, so a new signing state added to urgency.go cannot silently
// fall through to the wrong bucket.
func TestPublisherBucketExhaustive(t *testing.T) {
	cases := []struct {
		signing  string
		verified bool
		want     string
	}{
		{SigningUnsigned, false, PublisherGroupUnsignedAdhoc},
		{SigningUnsigned, true, PublisherGroupUnsignedAdhoc},
		{SigningAdhoc, false, PublisherGroupUnsignedAdhoc},
		{SigningInvalid, false, PublisherGroupInvalid},
		{SigningInvalid, true, PublisherGroupInvalid},
		{SigningUntrusted, false, PublisherGroupInvalid},
		{SigningUnknown, false, PublisherGroupUnverified},
		{SigningNotCollected, false, PublisherGroupUnverified},
		{SigningSigned, false, PublisherGroupUnverified},
		{SigningSigned, true, PublisherGroupVerified},
	}
	for _, c := range cases {
		if got := publisherBucket(c.signing, c.verified); got != c.want {
			t.Errorf("publisherBucket(%q, %v) = %q, want %q", c.signing, c.verified, got, c.want)
		}
	}
}

// sha256Fixture returns a deterministic, valid-shaped 64 lower-case hex
// string for a test root thumbprint, distinct per label.
func sha256Fixture(label string) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i := range out {
		out[i] = hex[(int(label[i%len(label)])+i)%16]
	}
	return string(out)
}
