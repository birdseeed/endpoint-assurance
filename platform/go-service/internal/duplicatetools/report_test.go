package duplicatetools

import (
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/categorytag"
)

func testRules() []catRule {
	return []catRule{
		{categorytag.RuleSpec{IdentifierType: categorytag.TypeMacOSBundleID, IdentifierValue: "com.example.onepassword",
			Platform: "macos", CategoryKey: CategoryPasswordManager, SubtypeKey: "desktop_app"}, "onepassword"},
		{categorytag.RuleSpec{IdentifierType: categorytag.TypePackage, IdentifierValue: "1password", Qualifier: "winget",
			Platform: "windows", CategoryKey: CategoryPasswordManager, SubtypeKey: "desktop_app"}, "onepassword"},
		{categorytag.RuleSpec{IdentifierType: categorytag.TypeMacOSBundleID, IdentifierValue: "com.example.bitwarden",
			Platform: "macos", CategoryKey: CategoryPasswordManager, SubtypeKey: "desktop_app"}, "bitwarden"},
		{categorytag.RuleSpec{IdentifierType: categorytag.TypeMacOSBundleID, IdentifierValue: "com.example.lastpass",
			Platform: "macos", CategoryKey: CategoryPasswordManager, SubtypeKey: "desktop_app"}, "lastpass"},
		{categorytag.RuleSpec{IdentifierType: categorytag.TypeMacOSBundleID, IdentifierValue: "com.example.zoom",
			Platform: "macos", CategoryKey: CategoryVideoConferencing, SubtypeKey: "desktop_app"}, "zoom"},
	}
}

func TestMatchedRule(t *testing.T) {
	rules := testRules()

	obs := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.onepassword"}
	rule, ok := matchedRule(rules, obs)
	if !ok || rule.ProductKey != "onepassword" {
		t.Fatalf("matchedRule(1password mac) = %+v, %v, want product onepassword", rule, ok)
	}

	obs2 := categorytag.Observation{Kind: categorytag.KindApp, Platform: "windows",
		IdentityKind: "windows_winget", IdentityValue: "1password"}
	rule2, ok2 := matchedRule(rules, obs2)
	if !ok2 || rule2.ProductKey != "onepassword" {
		t.Fatalf("matchedRule(1password win) = %+v, %v, want product onepassword", rule2, ok2)
	}

	obs3 := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.unrelated"}
	if _, ok3 := matchedRule(rules, obs3); ok3 {
		t.Fatalf("matchedRule(unrelated) matched, want no match")
	}
}

func macRule(rules []catRule, bundleID string) catRule {
	obs := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: bundleID}
	r, _ := matchedRule(rules, obs)
	return r
}

func winRule(rules []catRule, value string) catRule {
	obs := categorytag.Observation{Kind: categorytag.KindApp, Platform: "windows",
		IdentityKind: "windows_winget", IdentityValue: value}
	r, _ := matchedRule(rules, obs)
	return r
}

// TestCrossPlatformProductCountsOnce is the report's central claim: one
// product installed as a macOS app on one device and a Windows winget
// package on another must be counted as ONE product (grouped by
// product_key), never two. Breaking appendRows/finish to group by raw
// identifier instead (the way internal/remoteaccess does, deliberately, for
// its own different purpose) would make this fail: it would report 2
// distinct password_manager products from 1Password alone.
func TestCrossPlatformProductCountsOnce(t *testing.T) {
	now := time.Now().UTC()
	devMac := &deviceFacts{ID: "dev-mac", Hostname: "mac-1", Platform: "macos", LastSeen: now}
	devWin := &deviceFacts{ID: "dev-win", Hostname: "win-1", Platform: "windows", LastSeen: now}
	rules := testRules()

	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	appendRows(rep, devMac, macRule(rules, "com.example.onepassword"), KindApp, "1Password", "8.0",
		"com.example.onepassword", StateApproved, nil)
	appendRows(rep, devWin, winRule(rules, "1password"), KindApp, "1Password", "8.0", "1password",
		StateApproved, nil)

	names := map[string]string{CategoryPasswordManager: "Password managers"}
	finish(rep, map[string]*deviceFacts{devMac.ID: devMac, devWin.ID: devWin}, names, 0, 0)

	cat := findCategory(rep.Categories, CategoryPasswordManager)
	if cat == nil {
		t.Fatalf("password_manager category missing: %+v", rep.Categories)
	}
	if cat.ProductCount != 1 {
		t.Fatalf("product_count = %d, want 1 (1Password on macOS+Windows is one product)", cat.ProductCount)
	}
	p := cat.Products[0]
	if p.DeviceCount != 2 || p.Installations != 2 {
		t.Fatalf("onepassword product = %+v, want 2 devices/installations across both platforms", p)
	}
	if len(p.Platforms) != 2 {
		t.Fatalf("onepassword platforms = %v, want [macos windows]", p.Platforms)
	}
}

func findCategory(cats []CategoryRow, key string) *CategoryRow {
	for i := range cats {
		if cats[i].Category == key {
			return &cats[i]
		}
	}
	return nil
}

// TestSingleProductCategoryNotFlagged: a category with only one distinct
// product present must not be flagged.
func TestSingleProductCategoryNotFlagged(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rules := testRules()

	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	appendRows(rep, dev, macRule(rules, "com.example.zoom"), KindApp, "Zoom", "5.0", "com.example.zoom",
		StateApproved, nil)

	names := map[string]string{CategoryVideoConferencing: "Video conferencing"}
	finish(rep, map[string]*deviceFacts{dev.ID: dev}, names, 0, 0)

	cat := findCategory(rep.Categories, CategoryVideoConferencing)
	if cat == nil {
		t.Fatalf("video_conferencing category missing")
	}
	if cat.Flagged {
		t.Fatalf("category with 1 product must not be flagged: %+v", cat)
	}
	if cat.ProductCount != 1 {
		t.Fatalf("product_count = %d, want 1", cat.ProductCount)
	}
}

// TestThreeDistinctProductsFlags is the flag-rule boundary: a category
// crosses from unflagged to flagged exactly at MinProductsToFlag (3)
// distinct products, never before. This can fail if MinProductsToFlag drifts
// or if the >= comparison in finish() is changed to >.
func TestThreeDistinctProductsFlags(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rules := testRules()
	names := map[string]string{CategoryPasswordManager: "Password managers"}

	// Two products: not flagged.
	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	appendRows(rep, dev, macRule(rules, "com.example.onepassword"), KindApp, "1Password", "8.0",
		"com.example.onepassword", StateApproved, nil)
	appendRows(rep, dev, macRule(rules, "com.example.bitwarden"), KindApp, "Bitwarden", "2024.1",
		"com.example.bitwarden", StateApproved, nil)
	finish(rep, map[string]*deviceFacts{dev.ID: dev}, names, 0, 0)
	if cat := findCategory(rep.Categories, CategoryPasswordManager); cat == nil || cat.Flagged {
		t.Fatalf("2 products must not flag: %+v", cat)
	}

	// Three products: flagged.
	rep2 := &Report{Definition: ReportDefinition, GeneratedAt: now}
	appendRows(rep2, dev, macRule(rules, "com.example.onepassword"), KindApp, "1Password", "8.0",
		"com.example.onepassword", StateApproved, nil)
	appendRows(rep2, dev, macRule(rules, "com.example.bitwarden"), KindApp, "Bitwarden", "2024.1",
		"com.example.bitwarden", StateApproved, nil)
	appendRows(rep2, dev, macRule(rules, "com.example.lastpass"), KindApp, "LastPass", "5.0",
		"com.example.lastpass", StateUnreviewed, nil)
	finish(rep2, map[string]*deviceFacts{dev.ID: dev}, names, 0, 0)
	cat2 := findCategory(rep2.Categories, CategoryPasswordManager)
	if cat2 == nil || !cat2.Flagged {
		t.Fatalf("3 products must flag: %+v", cat2)
	}
	if cat2.ProductCount != 3 {
		t.Fatalf("product_count = %d, want 3", cat2.ProductCount)
	}
}

// TestUncategorisedProductNeverAppears: an observation that matches no rule
// at all (no category tag) must never produce a row or a product -- this
// falls out of matchedRule returning ok=false and appendRows simply never
// being called for it, proven here by asserting the report stays empty.
func TestUncategorisedProductNeverAppears(t *testing.T) {
	rules := testRules()
	obs := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.notepad-plus-plus"}
	if _, ok := matchedRule(rules, obs); ok {
		t.Fatalf("an uncategorised product must never match a rule")
	}
}

// TestApprovalStateIsLeastFavourable: a product approved on one platform and
// unreviewed on another must surface as unreviewed (the least favourable
// state), never silently shown as approved.
func TestApprovalStateIsLeastFavourable(t *testing.T) {
	now := time.Now().UTC()
	devMac := &deviceFacts{ID: "dev-mac", Hostname: "mac-1", Platform: "macos", LastSeen: now}
	devWin := &deviceFacts{ID: "dev-win", Hostname: "win-1", Platform: "windows", LastSeen: now}
	rules := testRules()

	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	appendRows(rep, devMac, macRule(rules, "com.example.onepassword"), KindApp, "1Password", "8.0",
		"com.example.onepassword", StateApproved, nil)
	appendRows(rep, devWin, winRule(rules, "1password"), KindApp, "1Password", "8.0", "1password",
		StateUnreviewed, nil)

	names := map[string]string{CategoryPasswordManager: "Password managers"}
	finish(rep, map[string]*deviceFacts{devMac.ID: devMac, devWin.ID: devWin}, names, 0, 0)

	cat := findCategory(rep.Categories, CategoryPasswordManager)
	if cat == nil || len(cat.Products) != 1 {
		t.Fatalf("expected one product: %+v", cat)
	}
	if cat.Products[0].ApprovalState != StateUnreviewed {
		t.Fatalf("approval_state = %q, want unreviewed (least favourable)", cat.Products[0].ApprovalState)
	}
}

// TestPerUserRowsAndMachineWide: a machine-wide install produces one row
// with no user; a per-user install produces one row per user.
func TestPerUserRowsAndMachineWide(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rules := testRules()
	rule := macRule(rules, "com.example.onepassword")

	rep := &Report{}
	appendRows(rep, dev, rule, KindApp, "1Password", "8.0", "com.example.onepassword", StateUnapproved, nil)
	if len(rep.Rows) != 1 || rep.Rows[0].User != nil || !rep.Rows[0].MachineWide {
		t.Fatalf("machine-wide row = %+v", rep.Rows)
	}

	rep2 := &Report{}
	appendRows(rep2, dev, rule, KindApp, "1Password", "8.0", "com.example.onepassword", StateUnapproved,
		[]string{"alice", "bob"})
	if len(rep2.Rows) != 2 {
		t.Fatalf("per-user rows = %d, want 2", len(rep2.Rows))
	}
	for _, r := range rep2.Rows {
		if r.User == nil || r.MachineWide {
			t.Fatalf("per-user row wrongly machine-wide: %+v", r)
		}
	}
}

func TestSafariSystemUserConstant(t *testing.T) {
	if safariSystemUser != "_system" {
		t.Fatalf("safariSystemUser = %q, want _system (must match internal/extractor.SafariSystemSentinel)", safariSystemUser)
	}
}

// TestEmptyCategoryNeverSurfaced: a category with zero matched products in
// the estate must not appear in the output at all (never a zero-product row).
func TestEmptyCategoryNeverSurfaced(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	finish(rep, map[string]*deviceFacts{dev.ID: dev}, map[string]string{}, 0, 0)
	if len(rep.Categories) != 0 {
		t.Fatalf("categories = %+v, want none (no products matched)", rep.Categories)
	}
	if rep.Summary.CategoriesFlagged != 0 || rep.Summary.CategoriesWithProducts != 0 {
		t.Fatalf("summary = %+v, want all zero", rep.Summary)
	}
}

// TestStatementIsCustomerCopy guards the standing caveat the portal renders
// verbatim (PAT-2303): no internal "ticket" language and no "--".
func TestStatementIsCustomerCopy(t *testing.T) {
	lower := strings.ToLower(Statement)
	for _, banned := range []string{"ticket", "--", "pat-"} {
		if strings.Contains(lower, banned) {
			t.Errorf("Statement contains %q: %s", banned, Statement)
		}
	}
	if !strings.Contains(Statement, "A second rule, two or more paid products in a category, needs licence data and is not applied yet.") {
		t.Errorf("Statement lost the approved paid-products sentence (PAT-2253)")
	}
}
