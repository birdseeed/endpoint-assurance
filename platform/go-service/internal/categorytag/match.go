// Package categorytag owns the PAT-2015 software category tag model: global
// match rules and product-identity tags, the pure matcher that decides
// whether an observation matches a rule, and the database reconciliation that
// materialises matches per tenant on ingest and on rule publish.
//
// Matching is exact equality on a normalised key tuple
// (identifier type, platform, qualifier, value). A rule produces exactly one
// key; an observation produces every key it can honestly support. The same
// Keys function is used on ingest, in the publish backfill and in tests, so
// the three can never disagree about what matches.
//
// Identity is not packaging: a display name alone never produces a key. The
// Windows Authenticode key needs the signer the agent read from the binary's
// signature, not the registry Publisher string, which any installer can set.
package categorytag

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Identifier types. The set mirrors the software_category_rules CHECK.
const (
	TypeMacOSBundleID       = "macos_bundle_id"
	TypeMacOSTeamID         = "macos_team_id"
	TypeWindowsAuthenticode = "windows_authenticode"
	TypeBrowserExtension    = "browser_extension"
	TypeIDEExtension        = "ide_extension"
	TypePackage             = "package"
	TypeMCPServer           = "mcp_server"
	// TypeKind is a kind-level rule: it matches every observation of one
	// named Observation.Kind, whatever its identifier or user-chosen name.
	// PAT-2094: an mcp_server rule (above) matches the server name the user
	// chose in their own client config, which no product rule can reliably
	// catch, yet every MCP server is AI tooling by definition -- it is what
	// gives an AI tool access to local files and systems. See kindRuleKinds
	// for how narrow this stays.
	TypeKind = "kind"
)

// Observation kinds. app, ide_extension, package, mcp_server and
// local_model are software_installations rows (PAT-2021 added the last
// four); browser_extension is a device_browser_extensions row. The value is
// also software_category_tags.observation_kind.
const (
	KindApp              = "app"
	KindBrowserExtension = "browser_extension"
	KindIDEExtension     = "ide_extension"
	KindPackage          = "package"
	KindMCPServer        = "mcp_server"
	// KindLocalModel covers local models and model runtimes. No rule type
	// matches one; runtimes are tagged through their app bundle.
	KindLocalModel = "local_model"
)

// InstallationObservation maps a software_installations identity (as the
// extractor stores it, PAT-2021) to the matcher's view. The extractor owns
// the identity kinds; this is the one place that reads them:
//
//	ide_extension  value = extension id, companion = marketplace
//	npm_package    value = npm name (NormalizePackageName(npm, ...))
//	pip_package    value = PEP 503 name (NormalizePackageName(pip, ...))
//	mcp_server     value = server name, companion = client
//
// An unidentified or unnamed item keeps its kind but has no identifier, so
// it never matches a rule. Any other identity kind is an app.
func InstallationObservation(identityKind, identityValue, companion string) (kind string, o Observation) {
	switch identityKind {
	case "ide_extension":
		return KindIDEExtension, Observation{Kind: KindIDEExtension, Identifier: identityValue, Marketplace: companion}
	case "ide_extension_unidentified":
		return KindIDEExtension, Observation{Kind: KindIDEExtension, Marketplace: companion}
	case "npm_package":
		return KindPackage, Observation{Kind: KindPackage, Source: SourceNPM, Identifier: identityValue}
	case "npm_package_unidentified":
		return KindPackage, Observation{Kind: KindPackage, Source: SourceNPM}
	case "pip_package":
		return KindPackage, Observation{Kind: KindPackage, Source: SourcePip, Identifier: identityValue}
	case "pip_package_unidentified":
		return KindPackage, Observation{Kind: KindPackage, Source: SourcePip}
	case "mcp_server":
		return KindMCPServer, Observation{Kind: KindMCPServer, Identifier: identityValue}
	case "mcp_server_unnamed":
		return KindMCPServer, Observation{Kind: KindMCPServer}
	case "local_model", "local_model_unidentified", "local_model_runtime":
		return KindLocalModel, Observation{Kind: KindLocalModel}
	case "homebrew_formula":
		// PAT-2094: package-namespace identity (AGENTS.md "identity is not
		// packaging"), the same seam Homebrew already writes through
		// (internal/extractor/homebrew_inventory.go). identityValue is
		// already the extractor's normalised formula name.
		return KindPackage, Observation{Kind: KindPackage, Source: SourceBrewFormula, Identifier: identityValue}
	case "homebrew_cask":
		return KindPackage, Observation{Kind: KindPackage, Source: SourceBrewCask, Identifier: identityValue}
		// homebrew_tap deliberately falls through to the KindApp default below:
		// no rule type matches a tap, and a tap is not itself software.
	}
	return KindApp, Observation{Kind: KindApp}
}

// Platforms.
const (
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
	PlatformAny     = "any"
)

// Browser extension stores.
const (
	StoreChromeWebStore     = "chrome_web_store"
	StoreEdgeAddons         = "edge_addons"
	StoreFirefoxAddons      = "firefox_addons"
	StoreSafariAppExtension = "safari_app_extension"
)

// IDE marketplaces.
const (
	MarketplaceVSCode    = "vscode_marketplace"
	MarketplaceOpenVSX   = "open_vsx"
	MarketplaceJetBrains = "jetbrains_marketplace"
)

// Package sources.
const (
	SourceBrewFormula = "brew_formula"
	SourceBrewCask    = "brew_cask"
	SourceNPM         = "npm"
	SourcePip         = "pip"
	SourceWinget      = "winget"
)

// ErrInvalidRule wraps every validation failure from NormalizeRule.
var ErrInvalidRule = errors.New("invalid rule")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRule, fmt.Sprintf(format, args...))
}

var (
	teamIDPattern       = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	chromiumIDPattern   = regexp.MustCompile(`^[a-p]{32}$`)
	categoryKeyPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	pipSeparatorPattern = regexp.MustCompile(`[-_.]+`)
)

// Key is one normalised match tuple.
type Key struct {
	Type      string
	Platform  string
	Qualifier string
	Value     string
}

// RuleSpec is the editable part of a rule, as an admin submits it.
type RuleSpec struct {
	IdentifierType  string `json:"identifier_type"`
	IdentifierValue string `json:"identifier_value"`
	Qualifier       string `json:"qualifier"`
	Platform        string `json:"platform"`
	CategoryKey     string `json:"category"`
	SubtypeKey      string `json:"subtype"`
	Notes           string `json:"notes"`
}

// Key returns the rule's match tuple. Only meaningful on a normalised spec.
func (s RuleSpec) Key() Key {
	return Key{Type: s.IdentifierType, Platform: s.Platform, Qualifier: s.Qualifier, Value: s.IdentifierValue}
}

// collapse lowercases and collapses internal whitespace, the same
// normalisation the extractor applies to identity_value_normalized.
func collapse(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func normalizeTeamID(value string) string {
	return strings.ToUpper(strings.Join(strings.Fields(value), " "))
}

// NormalizePackageName applies each source's own name-equivalence rules.
func NormalizePackageName(source, name string) string {
	name = strings.TrimSpace(name)
	switch source {
	case SourcePip:
		// PEP 503: runs of -, _ and . are equivalent and names are
		// case-insensitive.
		return pipSeparatorPattern.ReplaceAllString(strings.ToLower(name), "-")
	default:
		// npm names are lowercase by registry rule; Homebrew and Winget
		// identifiers are case-insensitive.
		return collapse(name)
	}
}

var validStores = map[string]bool{StoreChromeWebStore: true, StoreEdgeAddons: true, StoreFirefoxAddons: true, StoreSafariAppExtension: true}
var validMarketplaces = map[string]bool{MarketplaceVSCode: true, MarketplaceOpenVSX: true, MarketplaceJetBrains: true}
var packageSourcePlatform = map[string]string{
	SourceBrewFormula: PlatformMacOS,
	SourceBrewCask:    PlatformMacOS,
	SourceNPM:         "",
	SourcePip:         "",
	SourceWinget:      PlatformWindows,
}

// SortedKeys lists a set's keys, for error messages and the admin API.
func SortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Stores, Marketplaces and PackageSources are exposed for the admin
// vocabulary endpoint the console form reads.
func Stores() []string       { return SortedKeys(validStores) }
func Marketplaces() []string { return SortedKeys(validMarketplaces) }
func PackageSources() []string {
	out := make([]string, 0, len(packageSourcePlatform))
	for k := range packageSourcePlatform {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IdentifierTypes lists every rule type, ingested or not.
func IdentifierTypes() []string {
	return []string{TypeMacOSBundleID, TypeMacOSTeamID, TypeWindowsAuthenticode,
		TypeBrowserExtension, TypeIDEExtension, TypePackage, TypeMCPServer, TypeKind}
}

// kindRuleKinds is the exhaustive, explicit set of Observation.Kind values a
// "kind" rule may target. A kind rule is a broader match than any other rule
// type -- it ignores the identifier entirely -- so this stays a single named
// entry rather than "any kind of observation": PAT-2094 needs exactly one
// (every mcp_server observation is AI tooling, regardless of the name the
// user gave it in their own client config). Adding another kind here is a
// deliberate code change and review, never just an admin API call with a new
// identifier_value.
var kindRuleKinds = map[string]bool{KindMCPServer: true}

// NormalizeRule validates a spec and returns it normalised. Platforms that a
// type implies are forced; a conflicting explicit platform is rejected
// rather than silently overridden.
func NormalizeRule(in RuleSpec) (RuleSpec, error) {
	out := RuleSpec{
		IdentifierType: strings.TrimSpace(in.IdentifierType),
		Platform:       strings.ToLower(strings.TrimSpace(in.Platform)),
		CategoryKey:    strings.TrimSpace(in.CategoryKey),
		SubtypeKey:     strings.TrimSpace(in.SubtypeKey),
		Notes:          strings.TrimSpace(in.Notes),
	}
	if !categoryKeyPattern.MatchString(out.CategoryKey) {
		return RuleSpec{}, invalid("category must be a category key")
	}
	if !categoryKeyPattern.MatchString(out.SubtypeKey) {
		return RuleSpec{}, invalid("subtype must be a subtype key")
	}
	if len(out.Notes) > 2000 {
		return RuleSpec{}, invalid("notes must be at most 2000 characters")
	}
	value := strings.TrimSpace(in.IdentifierValue)
	qualifier := strings.TrimSpace(in.Qualifier)
	if value == "" {
		return RuleSpec{}, invalid("identifier_value is required")
	}
	if len(value) > 512 || len(qualifier) > 512 {
		return RuleSpec{}, invalid("identifier_value and qualifier must be at most 512 bytes")
	}

	forcePlatform := func(p string) error {
		if out.Platform != "" && out.Platform != p {
			return invalid("%s rules apply to platform %q only", out.IdentifierType, p)
		}
		out.Platform = p
		return nil
	}
	noQualifier := func() error {
		if qualifier != "" {
			return invalid("%s rules take no qualifier", out.IdentifierType)
		}
		return nil
	}

	switch out.IdentifierType {
	case TypeMacOSBundleID:
		if err := forcePlatform(PlatformMacOS); err != nil {
			return RuleSpec{}, err
		}
		if err := noQualifier(); err != nil {
			return RuleSpec{}, err
		}
		out.IdentifierValue = collapse(value)
	case TypeMacOSTeamID:
		if err := forcePlatform(PlatformMacOS); err != nil {
			return RuleSpec{}, err
		}
		// A Team ID alone is vendor evidence: it would tag every app the
		// vendor ships (Word, Excel and Outlook under one Microsoft Team ID).
		// The rule is the exact bundle ID signed by that Team ID.
		if qualifier == "" {
			return RuleSpec{}, invalid("macos_team_id rules need the bundle ID as qualifier; a Team ID alone is vendor evidence, not a product")
		}
		out.Qualifier = collapse(qualifier)
		out.IdentifierValue = normalizeTeamID(value)
		if !teamIDPattern.MatchString(out.IdentifierValue) {
			return RuleSpec{}, invalid("a Team ID is 10 letters or digits")
		}
	case TypeWindowsAuthenticode:
		if err := forcePlatform(PlatformWindows); err != nil {
			return RuleSpec{}, err
		}
		if qualifier == "" {
			return RuleSpec{}, invalid("windows_authenticode rules need the product name as qualifier; a publisher alone is vendor evidence, not a product")
		}
		// Unicode-aware: a non-breaking space and a regular space are the
		// same separator, and accented letters fold with strings.ToLower.
		// Go is the only authority here; the backfill's SQL filter for this
		// type is deliberately coarse (see candidateFilter).
		out.IdentifierValue = collapse(value)
		out.Qualifier = collapse(qualifier)
	case TypeBrowserExtension:
		q := strings.ToLower(qualifier)
		if !validStores[q] {
			return RuleSpec{}, invalid("browser_extension qualifier must be one of %v", Stores())
		}
		out.Qualifier = q
		out.IdentifierValue = strings.ToLower(value)
		if (q == StoreChromeWebStore || q == StoreEdgeAddons) && !chromiumIDPattern.MatchString(out.IdentifierValue) {
			return RuleSpec{}, invalid("a Chrome Web Store or Edge Add-ons extension ID is 32 letters a to p")
		}
		if err := defaultPlatform(&out); err != nil {
			return RuleSpec{}, err
		}
	case TypeIDEExtension:
		q := strings.ToLower(qualifier)
		if !validMarketplaces[q] {
			return RuleSpec{}, invalid("ide_extension qualifier must be one of %v", Marketplaces())
		}
		out.Qualifier = q
		out.IdentifierValue = collapse(value)
		if err := defaultPlatform(&out); err != nil {
			return RuleSpec{}, err
		}
	case TypePackage:
		q := strings.ToLower(qualifier)
		implied, ok := packageSourcePlatform[q]
		if !ok {
			return RuleSpec{}, invalid("package qualifier must be one of %v", PackageSources())
		}
		out.Qualifier = q
		if implied != "" {
			if err := forcePlatform(implied); err != nil {
				return RuleSpec{}, err
			}
		} else if err := defaultPlatform(&out); err != nil {
			return RuleSpec{}, err
		}
		out.IdentifierValue = NormalizePackageName(q, value)
	case TypeMCPServer:
		if err := noQualifier(); err != nil {
			return RuleSpec{}, err
		}
		out.IdentifierValue = collapse(value)
		if err := defaultPlatform(&out); err != nil {
			return RuleSpec{}, err
		}
	case TypeKind:
		if err := noQualifier(); err != nil {
			return RuleSpec{}, err
		}
		// A kind rule ignores the observation's platform by definition (an
		// MCP server is AI tooling on macOS and Windows alike), so unlike
		// every other type its platform is forced rather than defaulted: an
		// explicit macos/windows would silently narrow what "every mcp_server"
		// means.
		if err := forcePlatform(PlatformAny); err != nil {
			return RuleSpec{}, err
		}
		v := collapse(value)
		if !kindRuleKinds[v] {
			return RuleSpec{}, invalid("kind rules are limited to %v", SortedKeys(kindRuleKinds))
		}
		out.IdentifierValue = v
	default:
		return RuleSpec{}, invalid("identifier_type must be one of %v", IdentifierTypes())
	}
	if out.IdentifierValue == "" {
		return RuleSpec{}, invalid("identifier_value is empty after normalisation")
	}
	return out, nil
}

func defaultPlatform(spec *RuleSpec) error {
	switch spec.Platform {
	case "":
		spec.Platform = PlatformAny
	case PlatformAny, PlatformMacOS, PlatformWindows:
	default:
		return invalid("platform must be macos, windows or any")
	}
	return nil
}

// Observation is the matcher's platform-neutral view of one observed piece of
// software. For apps the identity fields come straight from
// software_installations (identity_kind and identity_value_normalized), so
// the matcher reads exactly what the extractor stored.
type Observation struct {
	Kind     string
	Platform string

	// Apps.
	IdentityKind  string // software_installations.identity_kind
	IdentityValue string // software_installations.identity_value_normalized
	TeamID        string // observed codesign Team ID (macOS)
	Signer        string // observed Authenticode signer (Windows) or codesign authority (macOS)
	Name          string // observed display name
	// NameUnknown is true when Name is the extractor's fallback (the path,
	// the identifier or "unknown software") because the payload carried no
	// usable display name. Such a name is no opinion and never contradicts.
	NameUnknown bool

	// Browser extensions, IDE extensions, packages and MCP servers.
	Identifier  string
	Browser     string // browser_extension: chrome | edge | firefox | ...
	Marketplace string // ide_extension
	Source      string // package
}

// chromiumBrowsers install from the Chrome Web Store. Edge also has its own
// store. An extension ID is derived from the extension's signing key, so the
// same ID in two Chromium browsers is the same extension.
var chromiumBrowsers = map[string]bool{
	"chrome": true, "chromium": true, "edge": true, "brave": true,
	"vivaldi": true, "opera": true, "arc": true,
}

// StoresForBrowser maps a reported browser to the stores whose IDs it uses.
// An unknown browser maps to none: no guessing.
//
// Safari extensions (PAT-2064) are macOS app extensions, not browser-profile
// installs: device_browser_extensions.extension_id is the Safari app
// extension's bundle identifier (e.g. "com.1password.safari.extension"), not
// a store-issued ID, and the browser value the agent sends is the literal
// "safari" (extractor.safariBrowser). safari_app_extension is its own store
// so a rule can match on that bundle identifier the same way any other
// browser_extension rule matches a store ID.
func StoresForBrowser(browser string) []string {
	b := strings.ToLower(strings.TrimSpace(browser))
	switch {
	case b == "firefox":
		return []string{StoreFirefoxAddons}
	case b == "edge":
		return []string{StoreChromeWebStore, StoreEdgeAddons}
	case b == "safari":
		return []string{StoreSafariAppExtension}
	case chromiumBrowsers[b]:
		return []string{StoreChromeWebStore}
	}
	return nil
}

// Keys returns every match key an observation supports. Each key is emitted
// twice: once for the observation's platform and once for "any", so a rule
// scoped to either platform or to both matches.
func Keys(o Observation) []Key {
	platform := strings.ToLower(strings.TrimSpace(o.Platform))
	var keys []Key
	add := func(typ, qualifier, value string) {
		if value == "" {
			return
		}
		keys = append(keys, Key{Type: typ, Platform: platform, Qualifier: qualifier, Value: value})
		if platform != PlatformAny {
			keys = append(keys, Key{Type: typ, Platform: PlatformAny, Qualifier: qualifier, Value: value})
		}
	}

	switch o.Kind {
	case KindApp:
		switch platform {
		case PlatformMacOS:
			if isBundleKind(o.IdentityKind) {
				add(TypeMacOSBundleID, "", o.IdentityValue)
				if team := normalizeTeamID(o.TeamID); teamIDPattern.MatchString(team) && o.IdentityValue != "" {
					add(TypeMacOSTeamID, o.IdentityValue, team)
				}
			}
		case PlatformWindows:
			if o.IdentityKind == "windows_winget" {
				add(TypePackage, SourceWinget, NormalizePackageName(SourceWinget, o.IdentityValue))
			}
			if signer, name := collapse(o.Signer), collapse(o.Name); signer != "" && name != "" {
				add(TypeWindowsAuthenticode, name, signer)
			}
		}
	case KindBrowserExtension:
		// Lowercased only, never trimmed: the backfill filters on
		// lower(extension_id) in SQL and the two must agree.
		id := strings.ToLower(o.Identifier)
		for _, store := range StoresForBrowser(o.Browser) {
			add(TypeBrowserExtension, store, id)
		}
	case KindIDEExtension:
		if m := strings.ToLower(strings.TrimSpace(o.Marketplace)); validMarketplaces[m] {
			add(TypeIDEExtension, m, collapse(o.Identifier))
		}
	case KindPackage:
		src := strings.ToLower(strings.TrimSpace(o.Source))
		if _, ok := packageSourcePlatform[src]; ok {
			add(TypePackage, src, NormalizePackageName(src, o.Identifier))
		}
	case KindMCPServer:
		add(TypeMCPServer, "", collapse(o.Identifier))
		// PAT-2094: every MCP server also carries the kind-level key, whether
		// or not it has a usable name (add skips empty values, but the kind
		// itself is never empty), so an unnamed server still gets tagged.
		add(TypeKind, "", KindMCPServer)
	}
	return keys
}

// Matches reports whether a normalised rule matches an observation.
func Matches(rule RuleSpec, o Observation) bool {
	want := rule.Key()
	for _, k := range Keys(o) {
		if k == want {
			return true
		}
	}
	return false
}

func isBundleKind(kind string) bool { return kind == "macos_bundle_team" || kind == "macos_bundle" }

// Contradicts reports whether an observation positively disproves a rule: a
// field the rule tests is present and carries a different value. A missing
// field is no opinion (absence requires authority), so a payload that simply
// omits team_id or signed_by never retires a live tag; only a different
// value does. A matching observation never contradicts.
func Contradicts(rule RuleSpec, o Observation) bool {
	if Matches(rule, o) {
		return false
	}
	differs := func(observed, want string) bool { return observed != "" && observed != want }
	platform := strings.ToLower(strings.TrimSpace(o.Platform))
	if rule.Platform != PlatformAny && platform != "" && platform != PlatformAny && platform != rule.Platform {
		return true
	}
	switch rule.IdentifierType {
	case TypeMacOSBundleID:
		return o.Kind == KindApp && isBundleKind(o.IdentityKind) && differs(o.IdentityValue, rule.IdentifierValue)
	case TypeMacOSTeamID:
		if o.Kind != KindApp {
			return false
		}
		if isBundleKind(o.IdentityKind) && differs(o.IdentityValue, rule.Qualifier) {
			return true
		}
		return differs(normalizeTeamID(o.TeamID), rule.IdentifierValue)
	case TypeWindowsAuthenticode:
		if o.Kind != KindApp {
			return false
		}
		if differs(collapse(o.Signer), rule.IdentifierValue) {
			return true
		}
		return !o.NameUnknown && differs(collapse(o.Name), rule.Qualifier)
	case TypeBrowserExtension:
		if o.Kind != KindBrowserExtension {
			return false
		}
		if differs(strings.ToLower(o.Identifier), rule.IdentifierValue) {
			return true
		}
		if strings.TrimSpace(o.Browser) == "" {
			return false
		}
		for _, store := range StoresForBrowser(o.Browser) {
			if store == rule.Qualifier {
				return false
			}
		}
		return true
	case TypePackage:
		if rule.Qualifier == SourceWinget && o.Kind == KindApp {
			return o.IdentityKind != "" && (o.IdentityKind != "windows_winget" || differs(o.IdentityValue, rule.IdentifierValue))
		}
		if o.Kind != KindPackage {
			return false
		}
		return differs(strings.ToLower(strings.TrimSpace(o.Source)), rule.Qualifier) ||
			differs(NormalizePackageName(rule.Qualifier, o.Identifier), rule.IdentifierValue)
	case TypeIDEExtension:
		return o.Kind == KindIDEExtension &&
			(differs(strings.ToLower(strings.TrimSpace(o.Marketplace)), rule.Qualifier) || differs(collapse(o.Identifier), rule.IdentifierValue))
	case TypeMCPServer:
		return o.Kind == KindMCPServer && differs(collapse(o.Identifier), rule.IdentifierValue)
	case TypeKind:
		// A kind rule tests only Observation.Kind, which is stable for a
		// given installation's identity (a changed kind is a different
		// identity_fingerprint, so a different installation row, not a
		// mutation of this one). Nothing an observation reports can
		// positively contradict it.
		return false
	}
	return false
}
