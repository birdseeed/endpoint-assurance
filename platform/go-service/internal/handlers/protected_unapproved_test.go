package handlers

import (
	"testing"

	"patched.im/api/internal/protectedsoftware"
)

// PAT-2088: the one rule both the operator admin API and the customer portal
// apply when protected software is set Unapproved.
func TestProtectedUnapprovedRule(t *testing.T) {
	edr := &protectedsoftware.Match{Category: "edr", ProductName: "Acme EDR"}
	for _, tc := range []struct {
		name             string
		match            *protectedsoftware.Match
		feedsEnforcement bool
		wantWarn         bool
		wantRefuse       bool
	}{
		{"not protected", nil, false, false, false},
		{"not protected, enforcing path", nil, true, false, false},
		{"protected, governance only: warn and allow", edr, false, true, false},
		{"protected, would feed enforcement: refuse", edr, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := protectedUnapprovedRule(tc.match, tc.feedsEnforcement)
			if v.Warn() != tc.wantWarn || v.Refuse != tc.wantRefuse {
				t.Fatalf("verdict warn=%v refuse=%v, want warn=%v refuse=%v", v.Warn(), v.Refuse, tc.wantWarn, tc.wantRefuse)
			}
			if v.Match != tc.match {
				t.Fatalf("verdict match = %+v, want %+v", v.Match, tc.match)
			}
		})
	}
	// No application Unapproved feeds enforcement today (see
	// protected_unapproved.go), so both paths warn and allow.
	if applicationUnapprovedFeedsEnforcement {
		t.Fatal("an application Unapproved is marked as feeding enforcement; revisit the PAT-2088 reasoning and both handlers' refusal paths")
	}
}

func TestObservedProtectionIdentityUsesOnlyMatchingIdentityFields(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		observed             observedProtectionIdentity
		wantBundle, wantTeam string
	}{
		{"mac bundle", observedProtectionIdentity{platform: "macos", kind: "macos_bundle", identifier: "com.example.app", name: "Agent.exe"}, "com.example.app", ""},
		{"mac signed bundle", observedProtectionIdentity{platform: "macos", kind: "macos_bundle_team", identifier: "com.example.app", companion: "TEAM123", name: "Agent"}, "com.example.app", "TEAM123"},
		{"winget is not MSI", observedProtectionIdentity{platform: "windows", kind: "windows_winget", identifier: "Vendor.Agent", name: "Agent.exe", companion: "Vendor"}, "", ""},
		{"native id is not MSI", observedProtectionIdentity{platform: "windows", kind: "windows_native_publisher", identifier: "registry-key", name: "Agent", companion: "Vendor"}, "", ""},
		{"validated Windows signer", observedProtectionIdentity{platform: "windows", kind: "windows_winget", identifier: "Vendor.Agent", name: "Agent", signer: "Verified Signer"}, "", "Verified Signer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.observed.protectedIdentity()
			value := func(p *string) string {
				if p == nil {
					return ""
				}
				return *p
			}
			if value(id.BundleID) != tc.wantBundle || value(id.TeamID) != tc.wantTeam {
				t.Fatalf("identity = %+v, want bundle=%q team=%q", id, tc.wantBundle, tc.wantTeam)
			}
			if id.ProcessName != nil || id.WinProductCode != nil || id.WinPublisher != nil {
				t.Fatalf("display/package evidence was recast as a process/MSI identity: %+v", id)
			}
			if value(id.ProductName) != tc.observed.name {
				t.Fatalf("lost product-name evidence: %+v", id)
			}
		})
	}
}
