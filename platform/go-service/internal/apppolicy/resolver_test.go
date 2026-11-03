package apppolicy

import "testing"

func TestMandatoryGuardDoesNotSuppressUnrelatedAppOnSameDevice(t *testing.T) {
	mandatory := Policy{ID: 1, BundleID: str("com.example.security"), Name: str("Security Agent"), Platform: "macos", Policy: "mandatory", Source: SourceOperator}
	portal := Policy{ID: 2, BundleID: str("com.example.editor"), Platform: "macos", Policy: "approved", Source: SourcePortal}
	index := BuildIndex([]Policy{mandatory, portal})
	if got, ok := index.Resolve("", "com.example.security", "", "Security Agent", "macOS"); !ok || got.ID != mandatory.ID {
		t.Fatalf("security app resolved %+v ok=%v", got, ok)
	}
	if got, ok := index.Resolve("", "com.example.editor", "", "Editor", "macOS"); !ok || got.ID != portal.ID {
		t.Fatalf("unrelated editor resolved %+v ok=%v, want portal approval", got, ok)
	}
}

func TestMandatoryGuardDoesNotSuppressDifferentSignerWithSameBundle(t *testing.T) {
	mandatory := Policy{ID: 1, TeamID: str("SECURITYTEAM"), BundleID: str("com.example.shared"), Platform: "macos", Policy: "mandatory", Source: SourceOperator}
	portal := Policy{ID: 2, TeamID: str("EDITORTEAM"), BundleID: str("com.example.shared"), Platform: "macos", Policy: "approved", Source: SourcePortal}
	for _, order := range [][]Policy{{mandatory, portal}, {portal, mandatory}} {
		got, ok := BuildIndex(order).Resolve("EDITORTEAM", "com.example.shared", "", "Editor", "macOS")
		if !ok || got.ID != portal.ID {
			t.Fatalf("different signer resolved %+v ok=%v, want portal approval", got, ok)
		}
	}
}

func str(s string) *string { return &s }

// PAT-2091: an operator mandatory row is never outranked by a portal-set
// row, whatever the specificity.
func TestResolveOperatorMandatoryBeatsMoreSpecificPortalRow(t *testing.T) {
	mandatoryByName := Policy{ID: 1, Name: str("Zoom Workplace"), Platform: "any", Policy: "mandatory", Source: SourceOperator}
	portalByAlias := Policy{ID: 2, BundleID: str("Zoom.Zoom"), Platform: "windows", Policy: "approved", Source: SourcePortal}

	for _, order := range [][]Policy{{mandatoryByName, portalByAlias}, {portalByAlias, mandatoryByName}} {
		got, ok := BuildIndex(order).Resolve("", "Zoom.Zoom", "winget", "Zoom Workplace", "Windows")
		if !ok || got.ID != mandatoryByName.ID {
			t.Fatalf("resolved %+v ok=%v, want the operator's mandatory row", got, ok)
		}
	}

	// A device that reports the alias but not the mandatory name still gets
	// the customer's decision: the guard applies only where mandatory matches.
	got, ok := BuildIndex([]Policy{mandatoryByName, portalByAlias}).Resolve("", "Zoom.Zoom", "winget", "Zoom (per user)", "Windows")
	if !ok || got.ID != portalByAlias.ID {
		t.Fatalf("resolved %+v ok=%v, want the portal row when mandatory does not match", got, ok)
	}
}

// The same identity keyed twice: an operator mandatory row for any platform
// and a portal row for the exact platform. Exact platform normally wins; a
// portal row must not win that way either.
func TestResolveOperatorMandatoryAnyBeatsPortalExactPlatformSameIdentity(t *testing.T) {
	mandatoryAny := Policy{ID: 1, BundleID: str("com.example.app"), Platform: "any", Policy: "mandatory", Source: SourceOperator}
	portalMac := Policy{ID: 2, BundleID: str("com.example.app"), Platform: "macos", Policy: "unapproved", Source: SourcePortal}
	index := BuildIndex([]Policy{portalMac, mandatoryAny})
	if got, ok := index.Resolve("", "com.example.app", "", "Example", "macOS"); !ok || got.ID != mandatoryAny.ID {
		t.Fatalf("resolved %+v ok=%v, want the operator's mandatory row", got, ok)
	}
	effective := EffectivePolicies([]Policy{portalMac, mandatoryAny}, "macOS")
	if len(effective) != 1 || effective[0].ID != mandatoryAny.ID {
		t.Fatalf("effective policies = %+v, want only the operator's mandatory row", effective)
	}
}

// The guard leaves the operator's own precedence alone and is independent of
// order: with an operator mandatory row, a more specific operator row and a
// yet more specific portal row, the result is what the operator's rows alone
// resolve to.
func TestResolveMandatoryGuardKeepsOperatorPrecedence(t *testing.T) {
	mandatory := Policy{ID: 1, Name: str("Tool"), Platform: "any", Policy: "mandatory", Source: SourceOperator}
	operatorApproved := Policy{ID: 2, BundleID: str("com.example.tool"), Platform: "any", Policy: "approved", Source: SourceOperator}
	portal := Policy{ID: 3, BundleID: str("com.example.tool"), TeamID: str("TEAMID0001"), Platform: "macos", Policy: "unapproved", Source: SourcePortal}
	orders := [][]Policy{
		{mandatory, operatorApproved, portal}, {portal, operatorApproved, mandatory},
		{operatorApproved, portal, mandatory}, {portal, mandatory, operatorApproved},
	}
	for _, order := range orders {
		got, ok := BuildIndex(order).Resolve("TEAMID0001", "com.example.tool", "", "Tool", "macOS")
		if !ok || got.ID != operatorApproved.ID {
			t.Fatalf("resolved %+v ok=%v, want the operator's more specific approved row", got, ok)
		}
	}
}

// Without an operator mandatory row, a portal row takes part as before, and
// a row with no recorded source is the operator's.
func TestResolvePortalRowsUnchangedWithoutMandatory(t *testing.T) {
	operatorName := Policy{ID: 1, Name: str("Tool"), Platform: "any", Policy: "unapproved"}
	portal := Policy{ID: 2, BundleID: str("com.example.tool"), Platform: "macos", Policy: "approved", Source: SourcePortal}
	got, ok := BuildIndex([]Policy{operatorName, portal}).Resolve("", "com.example.tool", "", "Tool", "macOS")
	if !ok || got.ID != portal.ID {
		t.Fatalf("resolved %+v ok=%v, want the more specific portal row", got, ok)
	}
	// A mandatory row with no source is the operator's too.
	legacyMandatory := Policy{ID: 3, Name: str("Tool"), Platform: "macos", Policy: "mandatory"}
	got, ok = BuildIndex([]Policy{legacyMandatory, portal}).Resolve("", "com.example.tool", "", "Tool", "macOS")
	if !ok || got.ID != legacyMandatory.ID {
		t.Fatalf("resolved %+v ok=%v, want the source-less mandatory row", got, ok)
	}
	// A mandatory row for another platform does not guard this one.
	windowsMandatory := Policy{ID: 4, Name: str("Tool"), Platform: "windows", Policy: "mandatory", Source: SourceOperator}
	got, ok = BuildIndex([]Policy{windowsMandatory, portal}).Resolve("", "com.example.tool", "", "Tool", "macOS")
	if !ok || got.ID != portal.ID {
		t.Fatalf("resolved %+v ok=%v, want the portal row on macOS", got, ok)
	}
}
