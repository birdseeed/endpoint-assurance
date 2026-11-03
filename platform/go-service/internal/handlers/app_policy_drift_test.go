package handlers

import (
	"testing"

	"patched.im/api/internal/report"
)

func TestDevicePolicyPlatformAcceptsVersionedWindowsNames(t *testing.T) {
	for _, raw := range []string{"Windows", "Windows 11", "windows/10.0.26100"} {
		if got := devicePolicyPlatform(raw); got != "windows" {
			t.Fatalf("devicePolicyPlatform(%q) = %q, want windows", raw, got)
		}
	}
}

// TestCompareVersions covers the dot-separated version ordering used by the
// version_below_minimum drift check. Pure function; no DB required.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int // -1 => a<b, 0 => equal, 1 => a>b (sign only)
	}{
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexicographic
		{"2.0", "1.9.9", 1},
		{"1.2", "1.2.0", 0}, // missing trailing segment treated as 0
		{"1.2.1", "1.2", 1},
		{"120.0.6099.234", "120.0.6099.71", 1},
		{"", "1.0.0", 0}, // unknown installed version is never below floor
		{"1.0.0", "", 0}, // empty floor never flags
		{"", "", 0},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		if sign(got) != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestResolveAppPolicyDrift_ExactPlatformApprovalOverridesAnyUnapproved(t *testing.T) {
	index := buildTenantPolicyIndex([]tenantPolicy{
		{ID: 1, TeamID: strPtr("TEAM-EXAMPLE"), Platform: "any", Policy: "unapproved"},
		{ID: 2, TeamID: strPtr("TEAM-EXAMPLE"), Platform: "macos", Policy: "approved"},
	})

	policy, ok := index.resolveAppPolicy("team-example", "", "", "Example App", "macOS")
	if !ok || policy.ID != 2 || policy.Policy != "approved" {
		t.Fatalf("exact macOS approval must override any-platform unapproved policy, got ok=%v policy=%+v", ok, policy)
	}
}

func TestResolveAppPolicyDrift_ExactOverrideRemainsPlatformScoped(t *testing.T) {
	index := buildTenantPolicyIndex([]tenantPolicy{
		{ID: 1, BundleID: strPtr("com.example.app"), Platform: "any", Policy: "unapproved"},
		{ID: 2, BundleID: strPtr("com.example.app"), Platform: "windows", Policy: "approved"},
	})
	windowsPolicy, windowsOK := index.resolveAppPolicy("", "COM.EXAMPLE.APP", "", "Example App", "Windows")
	if !windowsOK || windowsPolicy.ID != 2 || windowsPolicy.Policy != "approved" {
		t.Fatalf("windows exact approval not selected: ok=%v policy=%+v", windowsOK, windowsPolicy)
	}
	macPolicy, macOK := index.resolveAppPolicy("", "COM.EXAMPLE.APP", "", "Example App", "macOS")
	if !macOK || macPolicy.ID != 1 || macPolicy.Policy != "unapproved" {
		t.Fatalf("windows approval must not override macOS any fallback: ok=%v policy=%+v", macOK, macPolicy)
	}
}

func TestResolveAppPolicyDrift_StrongerIdentityBeatsWeakerExactPlatform(t *testing.T) {
	index := buildTenantPolicyIndex([]tenantPolicy{
		{ID: 1, TeamID: strPtr("TEAM-EXAMPLE"), Platform: "any", Policy: "unapproved"},
		{ID: 2, Name: strPtr("Example App"), Platform: "macos", Policy: "approved"},
	})

	policy, ok := index.resolveAppPolicy("TEAM-EXAMPLE", "", "", "Example App", "macOS")
	if !ok || policy.ID != 1 || policy.Policy != "unapproved" {
		t.Fatalf("strong Team ID policy must beat weaker exact-platform name policy, got ok=%v policy=%+v", ok, policy)
	}
}

func TestResolveAppPolicy_ExactUnmanagedOverridesAnyRegardlessOfRowOrder(t *testing.T) {
	orders := [][]tenantPolicy{
		{
			{ID: 1, BundleID: strPtr("com.example.app"), Platform: "any", Policy: "unapproved"},
			{ID: 2, BundleID: strPtr("com.example.app"), Platform: "macos", Policy: "unmanaged"},
		},
		{
			{ID: 2, BundleID: strPtr("com.example.app"), Platform: "macos", Policy: "unmanaged"},
			{ID: 1, BundleID: strPtr("com.example.app"), Platform: "any", Policy: "unapproved"},
		},
	}

	for i, policies := range orders {
		index := buildTenantPolicyIndex(policies)
		policy, ok := index.resolveAppPolicy("", "COM.EXAMPLE.APP", "", "Example App", "macOS")
		if !ok || policy.ID != 2 || policy.Policy != "unmanaged" {
			t.Fatalf("order %d: exact unmanaged must override inherited unapproved, got ok=%v policy=%+v", i, ok, policy)
		}
	}
}

func TestResolveAppPolicy_SharedTeamIDRequiresWholeStoredIdentityRegardlessOfRowOrder(t *testing.T) {
	appA := tenantPolicy{
		ID:       1,
		TeamID:   strPtr("TEAM-SHARED"),
		BundleID: strPtr("com.example.bundle-a"),
		Name:     strPtr("Bundle A"),
		Platform: "macos",
		Policy:   "approved",
	}
	appB := tenantPolicy{
		ID:       2,
		TeamID:   strPtr("TEAM-SHARED"),
		BundleID: strPtr("com.example.bundle-b"),
		Name:     strPtr("Bundle B"),
		Platform: "any",
		Policy:   "unapproved",
	}

	for i, policies := range [][]tenantPolicy{{appA, appB}, {appB, appA}} {
		index := buildTenantPolicyIndex(policies)
		policy, ok := index.resolveAppPolicy("team-shared", "COM.EXAMPLE.BUNDLE-B", "", "bundle b", "macOS")
		if !ok || policy.ID != appB.ID || policy.Policy != "unapproved" {
			t.Fatalf("order %d: Bundle B must resolve to its own unapproved tuple, got ok=%v policy=%+v", i, ok, policy)
		}
	}
}

func TestResolveAppPolicy_MoreSpecificMatchingTupleWinsDeterministically(t *testing.T) {
	policies := []tenantPolicy{
		{ID: 1, TeamID: strPtr("TEAM-SHARED"), Platform: "macos", Policy: "approved"},
		{ID: 2, TeamID: strPtr("TEAM-SHARED"), BundleID: strPtr("com.example.app"), Platform: "macos", Policy: "unapproved"},
	}
	for i, order := range [][]tenantPolicy{policies, {policies[1], policies[0]}} {
		policy, ok := buildTenantPolicyIndex(order).resolveAppPolicy("TEAM-SHARED", "com.example.app", "", "Example App", "macOS")
		if !ok || policy.ID != 2 {
			t.Fatalf("order %d: more-specific matching tuple must win, got ok=%v policy=%+v", i, ok, policy)
		}
	}
}

func TestEffectiveTenantPolicies_PlatformOverridePreservesDistinctMandatoryIdentities(t *testing.T) {
	policies := []tenantPolicy{
		{ID: 1, BundleID: strPtr("com.example.app"), Platform: "any", Policy: "mandatory"},
		{ID: 2, BundleID: strPtr("com.example.app"), Platform: "macos", Policy: "approved"},
		{ID: 3, Name: strPtr("Example App"), Platform: "any", Policy: "mandatory"},
	}

	macPolicies := effectiveTenantPolicies(policies, "macOS")
	if len(macPolicies) != 2 || macPolicies[0].ID != 3 || macPolicies[1].ID != 2 {
		t.Fatalf("macOS effective policies must override only the matching bundle identity, got %+v", macPolicies)
	}
	windowsPolicies := effectiveTenantPolicies(policies, "Windows")
	if len(windowsPolicies) != 2 || windowsPolicies[0].ID != 3 || windowsPolicies[1].ID != 1 {
		t.Fatalf("Windows must retain both inherited mandatory identities, got %+v", windowsPolicies)
	}
}

func TestEffectiveTenantPolicies_SharedTeamIDKeepsDistinctBundleObligations(t *testing.T) {
	policies := []tenantPolicy{
		{ID: 3, TeamID: strPtr("TEAM-SHARED"), BundleID: strPtr("com.example.bundle-b"), Name: strPtr("Bundle B"), Platform: "any", Policy: "mandatory"},
		{ID: 2, TeamID: strPtr("TEAM-SHARED"), BundleID: strPtr("com.example.bundle-a"), Name: strPtr("Bundle A"), Platform: "macos", Policy: "approved"},
		{ID: 1, TeamID: strPtr("TEAM-SHARED"), BundleID: strPtr("com.example.bundle-a"), Name: strPtr("Bundle A"), Platform: "any", Policy: "mandatory"},
	}

	effective := effectiveTenantPolicies(policies, "macOS")
	if len(effective) != 2 || effective[0].ID != 2 || effective[1].ID != 3 {
		t.Fatalf("exact Bundle A approval must replace only its full-tuple any-platform counterpart while mandatory Bundle B survives deterministically, got %+v", effective)
	}
	if mandatoryPolicySatisfiedDrift(effective[1], nil, "macOS") {
		t.Fatal("mandatory Bundle B must remain unsatisfied for empty inventory")
	}
	if mandatoryPolicySatisfied(effective[1], nil, "macOS") {
		t.Fatal("posture must also keep mandatory Bundle B unsatisfied for empty inventory")
	}
}

func TestTenantPolicyIdentityKeyIncludesEveryPersistedIdentityField(t *testing.T) {
	base := tenantPolicy{
		TeamID:   strPtr("TEAM-SHARED"),
		BundleID: strPtr("com.example.bundle"),
		WingetID: strPtr("example.package"),
		Name:     strPtr("Example App"),
	}
	keys := map[string]string{}
	for name, policy := range map[string]tenantPolicy{
		"base":             base,
		"different team":   {TeamID: strPtr("TEAM-OTHER"), BundleID: base.BundleID, WingetID: base.WingetID, Name: base.Name},
		"different bundle": {TeamID: base.TeamID, BundleID: strPtr("com.example.other"), WingetID: base.WingetID, Name: base.Name},
		"different winget": {TeamID: base.TeamID, BundleID: base.BundleID, WingetID: strPtr("example.other"), Name: base.Name},
		"different name":   {TeamID: base.TeamID, BundleID: base.BundleID, WingetID: base.WingetID, Name: strPtr("Other App")},
	} {
		key := tenantPolicyIdentityKey(policy)
		if previous, exists := keys[key]; exists {
			t.Fatalf("%s collapsed onto %s despite a distinct persisted identity field", name, previous)
		}
		keys[key] = name
	}
}

// TestMandatoryPolicySatisfiedDrift_OverlappingPolicyOnSameApp is the
// admin-drift-report sibling of the PAT-1147 posture.go regression: a
// device has one installed app (Opera, bundle_id com.operasoftware.Opera)
// and two tenant_app_policies rows both able to match it — one 'approved'
// keyed by bundle_id, one 'mandatory' keyed by name only. Before the fix,
// resolveAppPolicy's first-match-wins resolution (team_id > bundle_id >
// name) only ever recorded the bundle_id-keyed policy as matched, so the
// name-keyed mandatory policy was falsely reported missing even though
// Opera was installed. mandatoryPolicySatisfiedDrift must test each
// mandatory policy independently against the full app list instead.
func TestMandatoryPolicySatisfiedDrift_OverlappingPolicyOnSameApp(t *testing.T) {
	apps := []appRow{
		{DeviceID: "dev-1", Name: "Opera", BundleID: "com.operasoftware.Opera"},
	}
	mandatoryByName := tenantPolicy{
		ID:              2,
		Name:            strPtr("Opera"),
		Platform:        "any",
		Policy:          "mandatory",
		EnforcementTier: "app_management",
	}
	if !mandatoryPolicySatisfiedDrift(mandatoryByName, apps, "macOS") {
		t.Error("mandatory policy keyed by name must be satisfied by an installed app matching that name, even though a different policy also matches it by bundle_id")
	}
}

// TestMandatoryPolicySatisfiedDrift_GenuinelyMissing is the control: a
// mandatory policy for an app that is NOT installed on the device must
// still be reported missing.
func TestMandatoryPolicySatisfiedDrift_GenuinelyMissing(t *testing.T) {
	apps := []appRow{
		{DeviceID: "dev-1", Name: "Opera", BundleID: "com.operasoftware.Opera"},
	}
	mandatoryMissingApp := tenantPolicy{
		ID:              3,
		Name:            strPtr("CrowdStrike Falcon"),
		BundleID:        strPtr("com.crowdstrike.falcon"),
		Platform:        "any",
		Policy:          "mandatory",
		EnforcementTier: "app_management",
	}
	if mandatoryPolicySatisfiedDrift(mandatoryMissingApp, apps, "macOS") {
		t.Error("mandatory policy for an app genuinely absent from the device must not be reported satisfied")
	}
}

func TestMandatoryVersionBelowMinimumDrift_OverlappingUnmanagedDoesNotSuppressDistinctMandatory(t *testing.T) {
	policies := []tenantPolicy{
		{ID: 1, BundleID: strPtr("com.example.app"), Platform: "any", Policy: "mandatory", MinVersion: strPtr("3.0"), EnforcementTier: "patch"},
		{ID: 2, BundleID: strPtr("com.example.app"), Platform: "macos", Policy: "unmanaged", EnforcementTier: "report"},
		{ID: 3, Name: strPtr("Example App"), Platform: "any", Policy: "mandatory", MinVersion: strPtr("2.0"), EnforcementTier: "patch"},
	}
	apps := []appRow{{Name: "Example App", BundleID: "com.example.app", Version: "1.0"}}

	matches := mandatoryVersionBelowMinimumDrift(policies, apps, "macOS")
	if len(matches) != 1 {
		t.Fatalf("want one finding from the distinct effective mandatory policy, got %+v", matches)
	}
	if matches[0].Policy.ID != 3 || matches[0].Policy.MinVersion == nil || *matches[0].Policy.MinVersion != "2.0" {
		t.Fatalf("same-identity macOS unmanaged override must suppress only the inherited bundle floor, got %+v", matches[0].Policy)
	}
}

func TestMandatoryVersionBelowMinimumDrift_DeduplicatesIdenticalFindings(t *testing.T) {
	policies := []tenantPolicy{
		{ID: 1, BundleID: strPtr("com.example.app"), Platform: "any", Policy: "mandatory", MinVersion: strPtr("2.0"), EnforcementTier: "patch"},
		{ID: 2, Name: strPtr("Example App"), Platform: "any", Policy: "mandatory", MinVersion: strPtr("2.0"), EnforcementTier: "patch"},
	}
	apps := []appRow{{Name: "Example App", BundleID: "com.example.app", Version: "1.0"}}

	if matches := mandatoryVersionBelowMinimumDrift(policies, apps, "macOS"); len(matches) != 1 {
		t.Fatalf("identical overlapping mandatory findings must be emitted once, got %+v", matches)
	}
}

func TestMandatoryPolicySatisfied_SharedTeamDoesNotSatisfyContradictoryBundle(t *testing.T) {
	policy := tenantPolicy{
		TeamID:   strPtr("TEAM-SHARED"),
		BundleID: strPtr("com.example.bundle-b"),
		Name:     strPtr("Bundle B"),
		Platform: "any",
		Policy:   "mandatory",
	}
	driftApps := []appRow{{Name: "Bundle A", BundleID: "com.example.bundle-a", TeamID: "TEAM-SHARED"}}
	if mandatoryPolicySatisfiedDrift(policy, driftApps, "macOS") {
		t.Fatal("admin drift treated shared Team ID as satisfying contradictory Bundle B obligation")
	}
	postureApps := []report.App{{Name: "Bundle A", BundleID: "com.example.bundle-a", TeamID: "TEAM-SHARED"}}
	if mandatoryPolicySatisfied(policy, postureApps, "macOS") {
		t.Fatal("posture treated shared Team ID as satisfying contradictory Bundle B obligation")
	}
}

func TestWingetPolicyRequiresTypedValidWindowsObservation(t *testing.T) {
	policy := tenantPolicy{ID: 1, WingetID: strPtr("Example.Package"), Platform: "windows", Policy: "mandatory"}
	index := buildTenantPolicyIndex([]tenantPolicy{policy})

	native := appRow{Name: "Example", BundleID: "Example.Package", IdentifierKind: "native"}
	for _, observation := range []appRow{native, {Name: native.Name, BundleID: native.BundleID}} {
		if _, ok := index.resolveAppPolicy("", observation.BundleID, observation.IdentifierKind, observation.Name, "Windows"); ok {
			t.Fatalf("%q identifier matched a Winget policy", observation.IdentifierKind)
		}
		if mandatoryPolicySatisfiedDrift(policy, []appRow{observation}, "Windows") {
			t.Fatalf("%q identifier satisfied a mandatory Winget policy in admin drift", observation.IdentifierKind)
		}
		if mandatoryPolicySatisfied(policy, []report.App{{Name: observation.Name, BundleID: observation.BundleID, IdentifierKind: observation.IdentifierKind}}, "Windows") {
			t.Fatalf("%q identifier satisfied a mandatory Winget policy in posture", observation.IdentifierKind)
		}
	}

	winget := native
	winget.IdentifierKind = "winget"
	if got, ok := index.resolveAppPolicy("", winget.BundleID, winget.IdentifierKind, winget.Name, "Windows"); !ok || got.ID != policy.ID {
		t.Fatalf("typed canonical Winget identifier did not resolve policy: ok=%v policy=%+v", ok, got)
	}
	if !mandatoryPolicySatisfiedDrift(policy, []appRow{winget}, "Windows") {
		t.Fatal("typed canonical Winget identifier did not satisfy mandatory policy in admin drift")
	}
	if !mandatoryPolicySatisfied(policy, []report.App{{Name: winget.Name, BundleID: winget.BundleID, IdentifierKind: winget.IdentifierKind}}, "Windows") {
		t.Fatal("typed canonical Winget identifier did not satisfy mandatory policy in posture")
	}
}

// Platform scoping is deliberately NOT mandatoryPolicySatisfiedDrift's
// responsibility (see its doc comment): the caller must resolve effective
// policies BEFORE calling it, so that a policy that doesn't apply to the
// device's OS is omitted entirely rather than treated as "unsatisfied" and
// flagged mandatory_missing. That loop-level behavior is covered by
// TestTenantAppPolicyDriftHandler_PlatformMismatchedPolicySkippedNotFlagged
// in app_policy_drift_db_test.go (a unit test on this function alone can't
// exercise the bug — it was the *caller's* loop that mishandled the
// combined signal, not this function).
