package categorytag

import (
	"errors"
	"testing"
)

func mustRule(t *testing.T, spec RuleSpec) RuleSpec {
	t.Helper()
	if spec.CategoryKey == "" {
		spec.CategoryKey = "ai_tooling"
	}
	if spec.SubtypeKey == "" {
		spec.SubtypeKey = "desktop_app"
	}
	norm, err := NormalizeRule(spec)
	if err != nil {
		t.Fatalf("NormalizeRule(%+v): %v", spec, err)
	}
	return norm
}

// Every rule type matches its fixture observation, including the types whose
// observations are not ingested yet (IDE extensions, npm, pip, Homebrew, MCP).
// Each case also carries a near miss that must not match.
func TestEachRuleTypeMatchesItsFixtureObservation(t *testing.T) {
	cases := []struct {
		name  string
		rule  RuleSpec
		match Observation
		miss  Observation
	}{
		{
			name:  "macos bundle id",
			rule:  RuleSpec{IdentifierType: TypeMacOSBundleID, IdentifierValue: " Com.Example.AIDesktop "},
			match: Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle_team", IdentityValue: "com.example.aidesktop", TeamID: "ABCDE12345"},
			miss:  Observation{Kind: KindApp, Platform: "macos", IdentityKind: "display_name", IdentityValue: "com.example.aidesktop"},
		},
		{
			// The observation shape is exactly what the extractor stores:
			// identity_value_normalized is the lowercased bundle ID and the
			// Team ID comes from codesign. A sibling app from the same vendor
			// (same Team ID, different bundle) must not match.
			name:  "macos team id plus bundle id",
			rule:  RuleSpec{IdentifierType: TypeMacOSTeamID, IdentifierValue: "abcde12345", Qualifier: "Com.Example.AIDesktop"},
			match: Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle_team", IdentityValue: "com.example.aidesktop", TeamID: "ABCDE12345"},
			miss:  Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle_team", IdentityValue: "com.example.wordprocessor", TeamID: "ABCDE12345"},
		},
		{
			name:  "windows authenticode publisher plus product name",
			rule:  RuleSpec{IdentifierType: TypeWindowsAuthenticode, IdentifierValue: "Example AI, Inc.", Qualifier: "Example  Desktop"},
			match: Observation{Kind: KindApp, Platform: "windows", IdentityKind: "windows_native_publisher", IdentityValue: "exampledesktop", Signer: "example ai, inc.", Name: "Example Desktop"},
			miss:  Observation{Kind: KindApp, Platform: "windows", IdentityKind: "windows_native_publisher", IdentityValue: "exampledesktop", Signer: "example ai, inc.", Name: "Example Updater"},
		},
		{
			name:  "chrome web store extension on chrome",
			rule:  RuleSpec{IdentifierType: TypeBrowserExtension, Qualifier: StoreChromeWebStore, IdentifierValue: "abcdefghijklmnopabcdefghijklmnop", SubtypeKey: "browser_extension"},
			match: Observation{Kind: KindBrowserExtension, Platform: "macos", Browser: "chrome", Identifier: "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"},
			miss:  Observation{Kind: KindBrowserExtension, Platform: "macos", Browser: "firefox", Identifier: "abcdefghijklmnopabcdefghijklmnop"},
		},
		{
			name:  "chrome web store extension installed in edge",
			rule:  RuleSpec{IdentifierType: TypeBrowserExtension, Qualifier: StoreChromeWebStore, IdentifierValue: "abcdefghijklmnopabcdefghijklmnop", SubtypeKey: "browser_extension"},
			match: Observation{Kind: KindBrowserExtension, Platform: "windows", Browser: "edge", Identifier: "abcdefghijklmnopabcdefghijklmnop"},
			miss:  Observation{Kind: KindBrowserExtension, Platform: "windows", Browser: "safari", Identifier: "abcdefghijklmnopabcdefghijklmnop"},
		},
		{
			name:  "edge add-ons extension",
			rule:  RuleSpec{IdentifierType: TypeBrowserExtension, Qualifier: StoreEdgeAddons, IdentifierValue: "pppppppppppppppppppppppppppppppp", SubtypeKey: "browser_extension"},
			match: Observation{Kind: KindBrowserExtension, Platform: "windows", Browser: "edge", Identifier: "pppppppppppppppppppppppppppppppp"},
			miss:  Observation{Kind: KindBrowserExtension, Platform: "windows", Browser: "chrome", Identifier: "pppppppppppppppppppppppppppppppp"},
		},
		{
			name:  "firefox add-ons extension",
			rule:  RuleSpec{IdentifierType: TypeBrowserExtension, Qualifier: StoreFirefoxAddons, IdentifierValue: "helper@example.ai", SubtypeKey: "browser_extension"},
			match: Observation{Kind: KindBrowserExtension, Platform: "macos", Browser: "firefox", Identifier: "Helper@Example.ai"},
			miss:  Observation{Kind: KindBrowserExtension, Platform: "macos", Browser: "chrome", Identifier: "helper@example.ai"},
		},
		{
			// PAT-2074: Safari app-extension IDs are bundle identifiers
			// (device_browser_extensions.extension_id for browser = "safari",
			// PAT-2064), not store IDs, so they take no ID-shape check.
			name:  "safari app extension",
			rule:  RuleSpec{IdentifierType: TypeBrowserExtension, Qualifier: StoreSafariAppExtension, IdentifierValue: "com.1password.safari.extension", SubtypeKey: "browser_extension"},
			match: Observation{Kind: KindBrowserExtension, Platform: "macos", Browser: "safari", Identifier: "Com.1Password.Safari.Extension"},
			miss:  Observation{Kind: KindBrowserExtension, Platform: "macos", Browser: "chrome", Identifier: "com.1password.safari.extension"},
		},
		{
			name:  "vs code marketplace extension",
			rule:  RuleSpec{IdentifierType: TypeIDEExtension, Qualifier: MarketplaceVSCode, IdentifierValue: "ExampleAI.copilot-helper", SubtypeKey: "ide_extension"},
			match: Observation{Kind: KindIDEExtension, Platform: "macos", Marketplace: "vscode_marketplace", Identifier: "exampleai.copilot-helper"},
			miss:  Observation{Kind: KindIDEExtension, Platform: "macos", Marketplace: "open_vsx", Identifier: "exampleai.copilot-helper"},
		},
		{
			name:  "open vsx extension",
			rule:  RuleSpec{IdentifierType: TypeIDEExtension, Qualifier: MarketplaceOpenVSX, IdentifierValue: "exampleai.helper", SubtypeKey: "ide_extension"},
			match: Observation{Kind: KindIDEExtension, Platform: "windows", Marketplace: "open_vsx", Identifier: "ExampleAI.Helper"},
			miss:  Observation{Kind: KindIDEExtension, Platform: "windows", Marketplace: "open_vsx", Identifier: "exampleai.helper2"},
		},
		{
			name:  "jetbrains marketplace plugin",
			rule:  RuleSpec{IdentifierType: TypeIDEExtension, Qualifier: MarketplaceJetBrains, IdentifierValue: "com.example.ai-assistant", SubtypeKey: "ide_extension"},
			match: Observation{Kind: KindIDEExtension, Platform: "macos", Marketplace: "jetbrains_marketplace", Identifier: "com.example.ai-assistant"},
			miss:  Observation{Kind: KindIDEExtension, Platform: "macos", Marketplace: "vscode_marketplace", Identifier: "com.example.ai-assistant"},
		},
		{
			name:  "homebrew formula",
			rule:  RuleSpec{IdentifierType: TypePackage, Qualifier: SourceBrewFormula, IdentifierValue: "Ollama", SubtypeKey: "local_runtime"},
			match: Observation{Kind: KindPackage, Platform: "macos", Source: "brew_formula", Identifier: "ollama"},
			miss:  Observation{Kind: KindPackage, Platform: "macos", Source: "brew_cask", Identifier: "ollama"},
		},
		{
			name:  "homebrew cask",
			rule:  RuleSpec{IdentifierType: TypePackage, Qualifier: SourceBrewCask, IdentifierValue: "example-ai", SubtypeKey: "desktop_app"},
			match: Observation{Kind: KindPackage, Platform: "macos", Source: "brew_cask", Identifier: "example-ai"},
			miss:  Observation{Kind: KindPackage, Platform: "windows", Source: "brew_cask", Identifier: "example-ai"},
		},
		{
			name:  "npm package",
			rule:  RuleSpec{IdentifierType: TypePackage, Qualifier: SourceNPM, IdentifierValue: "@example/ai-cli", SubtypeKey: "cli"},
			match: Observation{Kind: KindPackage, Platform: "windows", Source: "npm", Identifier: "@example/ai-cli"},
			miss:  Observation{Kind: KindPackage, Platform: "windows", Source: "pip", Identifier: "@example/ai-cli"},
		},
		{
			name:  "pip package uses PEP 503 name equivalence",
			rule:  RuleSpec{IdentifierType: TypePackage, Qualifier: SourcePip, IdentifierValue: "Example_AI.SDK", SubtypeKey: "cli"},
			match: Observation{Kind: KindPackage, Platform: "macos", Source: "pip", Identifier: "example-ai-sdk"},
			miss:  Observation{Kind: KindPackage, Platform: "macos", Source: "pip", Identifier: "example-ai-sdk2"},
		},
		{
			name:  "winget package matches an ingested winget app",
			rule:  RuleSpec{IdentifierType: TypePackage, Qualifier: SourceWinget, IdentifierValue: "Example.AIDesktop", SubtypeKey: "desktop_app"},
			match: Observation{Kind: KindApp, Platform: "windows", IdentityKind: "windows_winget", IdentityValue: "example.aidesktop"},
			miss:  Observation{Kind: KindApp, Platform: "windows", IdentityKind: "windows_native", IdentityValue: "example.aidesktop"},
		},
		{
			name:  "mcp server name",
			rule:  RuleSpec{IdentifierType: TypeMCPServer, IdentifierValue: "Example-Filesystem", SubtypeKey: "mcp_server"},
			match: Observation{Kind: KindMCPServer, Platform: "macos", Identifier: "example-filesystem"},
			miss:  Observation{Kind: KindMCPServer, Platform: "macos", Identifier: "example-filesystem-2"},
		},
		{
			// PAT-2094: a kind rule ignores the identifier entirely, so an
			// MCP server with no usable name still matches; only a
			// different Observation.Kind is a miss.
			name:  "mcp server kind, name-independent",
			rule:  RuleSpec{IdentifierType: TypeKind, IdentifierValue: "mcp_server", SubtypeKey: "mcp_server"},
			match: Observation{Kind: KindMCPServer, Platform: "windows"},
			miss:  Observation{Kind: KindPackage, Platform: "windows", Source: "npm", Identifier: "mcp_server"},
		},
	}
	seenTypes := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := mustRule(t, tc.rule)
			seenTypes[rule.IdentifierType] = true
			if !Matches(rule, tc.match) {
				t.Fatalf("rule %+v did not match %+v (keys %v)", rule, tc.match, Keys(tc.match))
			}
			if Matches(rule, tc.miss) {
				t.Fatalf("rule %+v matched near miss %+v", rule, tc.miss)
			}
		})
	}
	for _, typ := range IdentifierTypes() {
		if !seenTypes[typ] {
			t.Errorf("identifier type %s has no fixture case", typ)
		}
	}
}

// Platform scoping: a rule scoped to one platform does not match the other,
// and an "any" rule matches both.
func TestRulePlatformScope(t *testing.T) {
	obsMac := Observation{Kind: KindMCPServer, Platform: "macos", Identifier: "srv"}
	obsWin := Observation{Kind: KindMCPServer, Platform: "windows", Identifier: "srv"}
	anyRule := mustRule(t, RuleSpec{IdentifierType: TypeMCPServer, IdentifierValue: "srv", SubtypeKey: "mcp_server"})
	macRule := mustRule(t, RuleSpec{IdentifierType: TypeMCPServer, IdentifierValue: "srv", Platform: "macos", SubtypeKey: "mcp_server"})
	if !Matches(anyRule, obsMac) || !Matches(anyRule, obsWin) {
		t.Fatal("platform any rule must match both platforms")
	}
	if !Matches(macRule, obsMac) || Matches(macRule, obsWin) {
		t.Fatal("macos rule must match macOS only")
	}
}

// StoresForBrowser must return the Safari app-extension store for "safari"
// (PAT-2074), never guess for an unknown browser, and leave the existing
// Chromium/Edge/Firefox mappings untouched.
func TestStoresForBrowser(t *testing.T) {
	cases := []struct {
		browser string
		want    []string
	}{
		{"safari", []string{StoreSafariAppExtension}},
		{" Safari ", []string{StoreSafariAppExtension}},
		{"firefox", []string{StoreFirefoxAddons}},
		{"edge", []string{StoreChromeWebStore, StoreEdgeAddons}},
		{"chrome", []string{StoreChromeWebStore}},
		{"some_unknown_browser", nil},
	}
	for _, tc := range cases {
		got := StoresForBrowser(tc.browser)
		if len(got) != len(tc.want) {
			t.Fatalf("StoresForBrowser(%q) = %v, want %v", tc.browser, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("StoresForBrowser(%q) = %v, want %v", tc.browser, got, tc.want)
			}
		}
	}
}

// Identity is not packaging: a display name or a publisher alone never makes
// a key, and a registry Publisher is not an Authenticode signer.
func TestNoKeyFromDisplayNameOrPublisherAlone(t *testing.T) {
	o := Observation{Kind: KindApp, Platform: "windows", IdentityKind: "name_publisher", IdentityValue: "example desktop", Name: "Example Desktop"}
	if keys := Keys(o); len(keys) != 0 {
		t.Fatalf("name-only Windows app produced keys %v", keys)
	}
	if _, err := NormalizeRule(RuleSpec{IdentifierType: TypeWindowsAuthenticode, IdentifierValue: "Example AI, Inc.", CategoryKey: "ai_tooling", SubtypeKey: "desktop_app"}); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("publisher-only authenticode rule accepted: %v", err)
	}
}

func TestNormalizeRuleRejects(t *testing.T) {
	bad := []RuleSpec{
		{IdentifierType: "display_name", IdentifierValue: "x"},
		{IdentifierType: TypeMacOSBundleID, IdentifierValue: ""},
		{IdentifierType: TypeMacOSBundleID, IdentifierValue: "com.x", Platform: "windows"},
		{IdentifierType: TypeMacOSTeamID, IdentifierValue: "SHORT"},
		{IdentifierType: TypeBrowserExtension, IdentifierValue: "not-a-chrome-id", Qualifier: StoreChromeWebStore},
		{IdentifierType: TypeBrowserExtension, IdentifierValue: "abcdefghijklmnopabcdefghijklmnop", Qualifier: "opera_addons"},
		{IdentifierType: TypePackage, IdentifierValue: "x", Qualifier: "cargo"},
		{IdentifierType: TypePackage, IdentifierValue: "x", Qualifier: SourceWinget, Platform: "macos"},
		{IdentifierType: TypeMCPServer, IdentifierValue: "x", Qualifier: "extra"},
		// PAT-2094: a kind rule is restricted to the explicit allowlist
		// (mcp_server only) -- any other kind, a qualifier, or narrowing the
		// platform away from "any" is refused.
		{IdentifierType: TypeKind, IdentifierValue: "local_model"},
		{IdentifierType: TypeKind, IdentifierValue: "app"},
		{IdentifierType: TypeKind, IdentifierValue: "mcp_server", Qualifier: "extra"},
		{IdentifierType: TypeKind, IdentifierValue: "mcp_server", Platform: "macos"},
	}
	for _, spec := range bad {
		spec.CategoryKey, spec.SubtypeKey = "ai_tooling", "cli"
		if _, err := NormalizeRule(spec); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("NormalizeRule(%+v) = %v, want ErrInvalidRule", spec, err)
		}
	}
}

// A bare Team ID is vendor evidence and is refused, the same way a Windows
// publisher without a product name is.
func TestBareTeamIDRuleRefused(t *testing.T) {
	_, err := NormalizeRule(RuleSpec{IdentifierType: TypeMacOSTeamID, IdentifierValue: "UBF8T346G9",
		CategoryKey: "ai_tooling", SubtypeKey: "desktop_app"})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("bare Team ID rule accepted: %v", err)
	}
	// With the bundle qualifier, the rule key equals the key the observation
	// produces, so the two can actually meet.
	rule := mustRule(t, RuleSpec{IdentifierType: TypeMacOSTeamID, IdentifierValue: "UBF8T346G9", Qualifier: "com.example.ai"})
	obs := Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle_team", IdentityValue: "com.example.ai", TeamID: "UBF8T346G9"}
	found := false
	for _, k := range Keys(obs) {
		if k == rule.Key() {
			found = true
		}
	}
	if !found {
		t.Fatalf("rule key %+v not among observation keys %+v", rule.Key(), Keys(obs))
	}
}

// Absence is no opinion: an observation missing the field a rule tests does
// not contradict it; a different value does.
func TestContradictsNeedsAPositiveDifferentValue(t *testing.T) {
	team := mustRule(t, RuleSpec{IdentifierType: TypeMacOSTeamID, IdentifierValue: "UBF8T346G9", Qualifier: "com.example.ai"})
	auth := mustRule(t, RuleSpec{IdentifierType: TypeWindowsAuthenticode, IdentifierValue: "Example AI, Inc.", Qualifier: "Example AI"})
	cases := []struct {
		name string
		rule RuleSpec
		obs  Observation
		want bool
	}{
		{"team id missing", team, Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle", IdentityValue: "com.example.ai"}, false},
		{"team id different", team, Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle_team", IdentityValue: "com.example.ai", TeamID: "ZZZZZZZZZZ"}, true},
		{"bundle different", team, Observation{Kind: KindApp, Platform: "macos", IdentityKind: "macos_bundle_team", IdentityValue: "com.example.other", TeamID: "UBF8T346G9"}, true},
		{"signer missing", auth, Observation{Kind: KindApp, Platform: "windows", IdentityKind: "windows_winget", IdentityValue: "example.ai", Name: "Example AI"}, false},
		{"signer different", auth, Observation{Kind: KindApp, Platform: "windows", IdentityKind: "windows_winget", IdentityValue: "example.ai", Name: "Example AI", Signer: "Someone Else Ltd"}, true},
		{"name missing (extractor fallback)", auth, Observation{Kind: KindApp, Platform: "windows", Name: "PAT2015.Fallback", NameUnknown: true, Signer: "example ai, inc."}, false},
		{"name different", auth, Observation{Kind: KindApp, Platform: "windows", Name: "Example Updater", Signer: "example ai, inc."}, true},
		{"matching", auth, Observation{Kind: KindApp, Platform: "windows", Name: "Example AI", Signer: "example ai, inc."}, false},
	}
	for _, tc := range cases {
		if got := Contradicts(tc.rule, tc.obs); got != tc.want {
			t.Errorf("%s: Contradicts = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// PAT-2094: InstallationObservation is the one place that turns a
// software_installations row's stored identity_kind into the matcher's view.
// Before this ticket homebrew_formula and homebrew_cask fell through to the
// KindApp default (an empty Observation with no bundle identity), so Keys()
// produced nothing and no package rule could ever match a Homebrew
// installation even though the extractor already stores one
// (internal/extractor/homebrew_inventory.go). homebrew_tap must keep falling
// through: no rule type matches a tap.
func TestInstallationObservationHomebrew(t *testing.T) {
	kind, o := InstallationObservation("homebrew_formula", "ollama", "homebrew/core")
	if kind != KindPackage || o.Source != SourceBrewFormula || o.Identifier != "ollama" {
		t.Fatalf("homebrew_formula -> kind=%s obs=%+v", kind, o)
	}
	kind, o = InstallationObservation("homebrew_cask", "example-ai", "homebrew/cask")
	if kind != KindPackage || o.Source != SourceBrewCask || o.Identifier != "example-ai" {
		t.Fatalf("homebrew_cask -> kind=%s obs=%+v", kind, o)
	}
	kind, o = InstallationObservation("homebrew_tap", "homebrew/core", "")
	if kind != KindApp {
		t.Fatalf("homebrew_tap -> kind=%s obs=%+v, want KindApp (no rule type matches a tap)", kind, o)
	}
	o.Platform, o.IdentityKind, o.IdentityValue = "macos", "homebrew_tap", "homebrew/core"
	if keys := Keys(o); len(keys) != 0 {
		t.Fatalf("homebrew_tap produced keys %v, want none", keys)
	}

	formulaRule := mustRule(t, RuleSpec{IdentifierType: TypePackage, Qualifier: SourceBrewFormula, IdentifierValue: "Ollama", SubtypeKey: "local_runtime"})
	_, formulaObs := InstallationObservation("homebrew_formula", "ollama", "")
	formulaObs.Platform = "macos"
	if !Matches(formulaRule, formulaObs) {
		t.Fatalf("brew_formula rule did not match installation-derived observation %+v", formulaObs)
	}

	caskRule := mustRule(t, RuleSpec{IdentifierType: TypePackage, Qualifier: SourceBrewCask, IdentifierValue: "example-ai", SubtypeKey: "desktop_app"})
	_, caskObs := InstallationObservation("homebrew_cask", "example-ai", "homebrew/cask")
	caskObs.Platform = "macos"
	if !Matches(caskRule, caskObs) {
		t.Fatalf("brew_cask rule did not match installation-derived observation %+v", caskObs)
	}
	// A non-AI formula must stay untagged against an AI-only formula rule.
	_, unrelated := InstallationObservation("homebrew_formula", "imagemagick", "")
	unrelated.Platform = "macos"
	if Matches(formulaRule, unrelated) {
		t.Fatalf("brew_formula rule matched an unrelated formula %+v", unrelated)
	}
}

// PAT-2094: a kind rule tags an MCP server observation reconstructed exactly
// as the extractor stores one (InstallationObservation), including the
// unnamed case (an unreadable config, or a name the agent could not read) --
// the whole point being that the tag does not depend on the user-chosen
// name.
func TestKindRuleMatchesInstallationObservationMCPServer(t *testing.T) {
	rule := mustRule(t, RuleSpec{IdentifierType: TypeKind, IdentifierValue: "mcp_server", SubtypeKey: "mcp_server"})

	_, named := InstallationObservation("mcp_server", "filesystem", "claude_desktop")
	named.Platform = "macos"
	if !Matches(rule, named) {
		t.Fatalf("kind rule did not match a named mcp_server observation %+v", named)
	}

	_, unnamed := InstallationObservation("mcp_server_unnamed", "", "claude_desktop")
	unnamed.Platform = "windows"
	if !Matches(rule, unnamed) {
		t.Fatalf("kind rule did not match an unnamed mcp_server observation %+v", unnamed)
	}

	// A same-named npm package must not accidentally pick up the mcp_server
	// kind tag.
	_, pkg := InstallationObservation("npm_package", "filesystem", "")
	pkg.Platform = "macos"
	if Matches(rule, pkg) {
		t.Fatalf("kind rule matched an unrelated package observation %+v", pkg)
	}
}
