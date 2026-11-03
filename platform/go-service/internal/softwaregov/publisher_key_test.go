package softwaregov

import (
	"strings"
	"testing"

	"patched.im/api/internal/cvepipeline"
)

// PAT-2121: the Windows publisher key and its normalisation.
func TestAuthenticodePublisherKey(t *testing.T) {
	root := strings.Repeat("a", 64)
	dn := "CN=Example Ltd, O=Example Ltd, C=GB"
	want := "authenticode:" + root + ":" + dn
	cases := []struct {
		name, root, dn, want string
	}{
		{"canonical", root, dn, want},
		{"leading and trailing whitespace trimmed", root, "  \t" + dn + " \n", want},
		{"inner whitespace runs collapse to one space", root, "CN=Example   Ltd,\tO=Example Ltd,  C=GB", want},
		{"root thumbprint trimmed", " " + root + " ", dn, want},
		{"case is kept", root, "CN=EXAMPLE LTD, O=Example Ltd, C=GB",
			"authenticode:" + root + ":CN=EXAMPLE LTD, O=Example Ltd, C=GB"},
		{"separators are not re-spaced", root, "CN=Example Ltd,O=Example Ltd,C=GB",
			"authenticode:" + root + ":CN=Example Ltd,O=Example Ltd,C=GB"},
		{"uppercase root is not a thumbprint", strings.ToUpper(strings.Repeat("ab", 32)), dn, ""},
		{"short root", strings.Repeat("a", 63), dn, ""},
		{"non-hex root", strings.Repeat("g", 64), dn, ""},
		{"empty root", "", dn, ""},
		{"empty subject", root, "", ""},
		{"whitespace-only subject", root, " \t\n ", ""},
		{"control character in subject", root, "CN=Example\x00 Ltd", ""},
		{"overlong subject", root, strings.Repeat("x", 513), ""},
		{"512 characters is allowed", root, strings.Repeat("x", 512), "authenticode:" + root + ":" + strings.Repeat("x", 512)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuthenticodePublisherKey(tc.root, tc.dn); got != tc.want {
				t.Fatalf("AuthenticodePublisherKey(%q, %q) = %q, want %q", tc.root, tc.dn, got, tc.want)
			}
		})
	}
	// Deterministic: the normalised DN is a fixed point.
	k := AuthenticodePublisherKey(root, "  CN=A \t B  ")
	if again := AuthenticodePublisherKey(root, strings.TrimPrefix(k, "authenticode:"+root+":")); again != k {
		t.Fatalf("normalisation not idempotent: %q then %q", k, again)
	}
	// A different root never shares a key with the same subject.
	if AuthenticodePublisherKey(root, dn) == AuthenticodePublisherKey(strings.Repeat("b", 64), dn) {
		t.Fatal("different roots produced the same key")
	}
}

func TestWindowsPublisherKey(t *testing.T) {
	key := AuthenticodePublisherKey(winRootA, winSigner)
	if key == "" {
		t.Fatal("fixture has no key")
	}
	if got := windowsPublisherKey(pinnedWindows()); got != key {
		t.Fatalf("pinned product key %q, want %q", got, key)
	}
	for name, mut := range map[string]func(*trustFacts){
		"pre-#668 installation beside a pinned one": func(f *trustFacts) { f.RootPublic, f.RootPublicPinned, f.RootLegacy = 1, 1, 1 },
		"enterprise root": func(f *trustFacts) {
			f.RootPublic, f.RootPublicPinned, f.AuthenticodeRoots, f.RootEnterprise = 0, 0, nil, 2
		},
		"roots disagree":   func(f *trustFacts) { f.AuthenticodeRoots = []string{winRootA, winRootB} },
		"signers disagree": func(f *trustFacts) { f.AuthenticodeSigners = []string{winSigner, "CN=Other"} },
		"one not valid":    func(f *trustFacts) { f.SignatureValid, f.SignatureInvalid = 1, 1 },
		"no installations": func(f *trustFacts) { *f = trustFacts{Platform: "windows"} },
	} {
		f := pinnedWindows()
		mut(&f)
		if got := windowsPublisherKey(f); got != "" {
			t.Errorf("%s: key %q, want none", name, got)
		}
	}
}

// PAT-2121: a trusted Windows product whose publisher key is on an approved
// policy for a different product reads low.
func TestClassifyUrgencyWindowsPublisherApproved(t *testing.T) {
	key := AuthenticodePublisherKey(winRootA, winSigner)
	otherProduct := publisherApprovals{authenticode: map[string]map[string]bool{key: {"{other-product}": true}}}
	sameProduct := publisherApprovals{authenticode: map[string]map[string]bool{key: {"{this-product}": true}}}
	otherRoot := publisherApprovals{authenticode: map[string]map[string]bool{
		AuthenticodePublisherKey(winRootB, winSigner): {"{other-product}": true}}}
	withIdent := func(f trustFacts) trustFacts { f.Ident = "{this-product}"; return f }

	cases := []struct {
		name         string
		facts        trustFacts
		approved     publisherApprovals
		level        string
		reason       string
		approvedFlag bool
	}{
		{"same key on another approved product: low", withIdent(pinnedWindows()), otherProduct,
			UrgencyLow, ReasonAuthenticodePublisherApproved, true},
		{"only this product approved under the key: medium", withIdent(pinnedWindows()), sameProduct,
			UrgencyMedium, ReasonTrustedNoKnownCVEs, false},
		{"same subject, other root: medium", withIdent(pinnedWindows()), otherRoot,
			UrgencyMedium, ReasonTrustedNoKnownCVEs, false},
		{"no approvals: medium", withIdent(pinnedWindows()), publisherApprovals{},
			UrgencyMedium, ReasonTrustedNoKnownCVEs, false},
		{"macOS Team ID approvals never apply to Windows", withIdent(pinnedWindows()),
			publisherApprovals{teams: map[string]bool{winSigner: true, key: true}},
			UrgencyMedium, ReasonTrustedNoKnownCVEs, false},
		{"pre-#668 installation: trusted but no key, medium", func() trustFacts {
			f := withIdent(pinnedWindows())
			f.RootPublic, f.RootPublicPinned, f.RootLegacy = 1, 1, 1
			return f
		}(), otherProduct, UrgencyMedium, ReasonTrustedNoKnownCVEs, false},
		{"enterprise root with the same subject: high", func() trustFacts {
			f := withIdent(pinnedWindows())
			f.RootPublic, f.RootPublicPinned, f.RootEnterprise = 0, 0, 2
			return f
		}(), otherProduct, UrgencyHigh, ReasonEnterpriseRoot, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, reasons, trust := classifyUrgency(tc.facts, assessedClean(), tc.approved)
			if level != tc.level || !hasReason(reasons, tc.reason) {
				t.Fatalf("level %q reasons %+v, want %q with %q", level, reasons, tc.level, tc.reason)
			}
			if trust.PublisherHasApprovedProducts != tc.approvedFlag {
				t.Fatalf("publisher_has_approved_products = %v, want %v", trust.PublisherHasApprovedProducts, tc.approvedFlag)
			}
			if hasReason(reasons, ReasonPublisherHasApprovedItems) {
				t.Fatalf("windows carried the macOS Team ID reason: %+v", reasons)
			}
		})
	}

	// A CVE still outranks the approved publisher.
	f := withIdent(pinnedWindows())
	level, _, _ := classifyUrgency(f, assessedWith(cvepipeline.SeverityCounts{Medium: 1}, 1), otherProduct)
	if level != UrgencyHigh {
		t.Fatalf("medium CVE on an approved publisher: %q, want high", level)
	}
	// And an unassessed CVE state is never low.
	level, _, _ = classifyUrgency(f, notAssessed(), otherProduct)
	if level != UrgencyNotAssessed {
		t.Fatalf("unassessed CVE on an approved publisher: %q, want not_assessed", level)
	}
}
