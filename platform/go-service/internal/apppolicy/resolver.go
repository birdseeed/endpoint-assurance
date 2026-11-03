// Package apppolicy owns the canonical tenant application-policy matching
// and precedence contract shared by posture, drift and lifecycle evaluation.
package apppolicy

import (
	"sort"
	"strings"

	"patched.im/api/internal/wingetid"
)

// Row provenance (PAT-2091, tenant_app_policies.source).
const (
	SourceOperator = "operator"
	SourcePortal   = "portal"
)

type Policy struct {
	ID              int64
	TeamID          *string
	BundleID        *string
	WingetID        *string
	Name            *string
	Platform        string
	Policy          string
	EnforcementTier string
	MinVersion      *string
	// Source is who set the row: SourceOperator or SourcePortal. Empty is
	// read as the operator's (every row that predates the column was).
	Source string
}

// operatorMandatory reports whether a row is an operator-set mandatory row,
// which no portal-set row may ever outrank (PAT-2091).
func operatorMandatory(policy Policy) bool {
	return policy.Policy == "mandatory" && policy.Source != SourcePortal
}

// withoutPortalWhenMandatory drops portal-set rows from candidates when an
// operator mandatory row among them applies on platform. A customer's
// decision, however specifically keyed, never outranks the operator's
// mandatory one (PAT-2091): the portal refuses such a write up front
// (mandatoryResolvesFor), but a portal row written before the app was first
// seen, or before the operator made it mandatory, reaches the resolver.
func withoutPortalWhenMandatory(candidates []Policy, platform string) []Policy {
	guarded := false
	for _, policy := range candidates {
		if operatorMandatory(policy) && (policy.Platform == platform || policy.Platform == "any") {
			guarded = true
			break
		}
	}
	if !guarded {
		return candidates
	}
	return withoutPortal(candidates)
}

type InstalledIdentity struct {
	TeamID   string
	BundleID string
	WingetID string
	Name     string
}

type Index struct {
	byIdentity    map[string][]Policy
	identityOrder []string
}

func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func BuildIndex(policies []Policy) Index {
	index := Index{byIdentity: map[string][]Policy{}}
	for _, policy := range policies {
		key := IdentityKey(policy)
		if key != "" {
			index.byIdentity[key] = append(index.byIdentity[key], policy)
		}
	}
	for key := range index.byIdentity {
		index.identityOrder = append(index.identityOrder, key)
	}
	sort.Strings(index.identityOrder)
	return index
}

func DevicePlatform(deviceOS string) string {
	normalized := strings.ToLower(strings.TrimSpace(deviceOS))
	if normalized == "windows" || strings.HasPrefix(normalized, "windows ") || strings.HasPrefix(normalized, "windows/") {
		return "windows"
	}
	return "macos"
}

func InstalledWingetID(identifier, identifierKind, deviceOS string) string {
	if DevicePlatform(deviceOS) != "windows" || identifierKind != "winget" || !wingetid.Valid(identifier) {
		return ""
	}
	return identifier
}

func Matches(policy Policy, installed InstalledIdentity) bool {
	matchedField := false
	matches := func(stored *string, actual string) bool {
		if stored == nil || normalize(*stored) == "" {
			return true
		}
		matchedField = true
		return normalize(*stored) == normalize(actual)
	}
	return matches(policy.TeamID, installed.TeamID) &&
		matches(policy.BundleID, installed.BundleID) &&
		matches(policy.WingetID, installed.WingetID) &&
		matches(policy.Name, installed.Name) && matchedField
}

func resolvePlatform(candidates []Policy, deviceOS string) (Policy, bool) {
	platform := DevicePlatform(deviceOS)
	candidates = withoutPortalWhenMandatory(candidates, platform)
	var exact Policy
	exactFound := false
	for _, policy := range candidates {
		if policy.Platform == platform && (!exactFound || deterministicLess(policy, exact)) {
			exact, exactFound = policy, true
		}
	}
	if exactFound {
		return exact, true
	}
	var any Policy
	anyFound := false
	for _, policy := range candidates {
		if policy.Platform == "any" && (!anyFound || deterministicLess(policy, any)) {
			any, anyFound = policy, true
		}
	}
	return any, anyFound
}

// Resolve selects the same effective policy used by the drift and posture
// surfaces: exact platform overrides any for each full identity, then the
// most specific matching identity wins across overlapping policies. One
// rule comes before both (PAT-2091): when an operator mandatory row matches
// on this platform, portal-set rows drop out of the resolution entirely, so
// the result is what the operator's rows alone resolve to. Filtering first,
// rather than special-casing the pairwise comparison, keeps the choice
// independent of iteration order.
func (index Index) Resolve(teamID, bundleID, identifierKind, name, deviceOS string) (Policy, bool) {
	installed := InstalledIdentity{
		TeamID: teamID, BundleID: bundleID,
		WingetID: InstalledWingetID(bundleID, identifierKind, deviceOS), Name: name,
	}
	platform := DevicePlatform(deviceOS)
	var matched [][]Policy
	guarded := false
	for _, key := range index.identityOrder {
		candidates := index.byIdentity[key]
		if len(candidates) == 0 || !Matches(candidates[0], installed) {
			continue
		}
		matched = append(matched, candidates)
		for _, policy := range candidates {
			if operatorMandatory(policy) && (policy.Platform == platform || policy.Platform == "any") {
				guarded = true
			}
		}
	}
	var selected Policy
	found := false
	for _, candidates := range matched {
		if guarded {
			candidates = withoutPortal(candidates)
		}
		candidate, ok := resolvePlatform(candidates, deviceOS)
		if !ok {
			continue
		}
		if !found || candidatePrecedes(candidate, selected, deviceOS) {
			selected, found = candidate, true
		}
	}
	return selected, found
}

func withoutPortal(candidates []Policy) []Policy {
	kept := make([]Policy, 0, len(candidates))
	for _, policy := range candidates {
		if policy.Source != SourcePortal {
			kept = append(kept, policy)
		}
	}
	return kept
}

func specificity(policy Policy) int {
	count := 0
	for _, value := range []*string{policy.TeamID, policy.BundleID, policy.WingetID, policy.Name} {
		if value != nil && normalize(*value) != "" {
			count++
		}
	}
	return count
}

func precedence(policy Policy, deviceOS string) int {
	present := func(value *string) bool { return value != nil && normalize(*value) != "" }
	rank := 0
	if present(policy.TeamID) {
		rank |= 8
	}
	if DevicePlatform(deviceOS) == "windows" {
		if present(policy.WingetID) {
			rank |= 4
		}
		if present(policy.BundleID) {
			rank |= 2
		}
	} else {
		if present(policy.BundleID) {
			rank |= 4
		}
		if present(policy.WingetID) {
			rank |= 2
		}
	}
	if present(policy.Name) {
		rank |= 1
	}
	return rank
}

func deterministicLess(a, b Policy) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	return IdentityKey(a)+"\x00"+a.Platform+"\x00"+a.Policy < IdentityKey(b)+"\x00"+b.Platform+"\x00"+b.Policy
}

func candidatePrecedes(candidate, current Policy, deviceOS string) bool {
	if a, b := specificity(candidate), specificity(current); a != b {
		return a > b
	}
	if a, b := precedence(candidate, deviceOS), precedence(current, deviceOS); a != b {
		return a > b
	}
	if a, b := IdentityKey(candidate), IdentityKey(current); a != b {
		return a < b
	}
	return deterministicLess(candidate, current)
}

func IdentityKey(policy Policy) string {
	field := func(value *string) string {
		if value == nil {
			return ""
		}
		return normalize(*value)
	}
	fields := []string{field(policy.TeamID), field(policy.BundleID), field(policy.WingetID), field(policy.Name)}
	if strings.Join(fields, "") == "" {
		return ""
	}
	return strings.Join(fields, "\x00")
}

func EffectivePolicies(policies []Policy, deviceOS string) []Policy {
	byIdentity := make(map[string][]Policy, len(policies))
	for _, policy := range policies {
		key := IdentityKey(policy)
		if key != "" {
			byIdentity[key] = append(byIdentity[key], policy)
		}
	}
	keys := make([]string, 0, len(byIdentity))
	for key := range byIdentity {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	effective := make([]Policy, 0, len(keys))
	for _, key := range keys {
		if policy, ok := resolvePlatform(byIdentity[key], deviceOS); ok {
			effective = append(effective, policy)
		}
	}
	return effective
}
