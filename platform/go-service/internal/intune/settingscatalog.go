// PAT-1663: resolving Settings Catalog setting-definition ids and option ids
// (raw GUIDs/machine keys like
// device_vendor_msft_policy_config_bitlocker_requiredeviceencryption) into
// the human-readable display name/description Intune's own console shows.
//
// This is deliberately a standalone resolution library, not a Settings
// Catalog ObjectSource. Settings Catalog snapshotting itself
// (/deviceManagement/configurationPolicies, beta) is future work — see
// intune.go's package doc — and will be built as its own ObjectSource later.
// That future snapshotter is expected to call Resolver.Resolve on every
// setting/option id it snapshots, but it does not need to exist yet for this
// file to be useful: the resolution logic here is pure, fixture-testable,
// and independent of whether anything is snapshotting Settings Catalog
// policies today.
//
// The one rule that matters: resolution must degrade honestly. A setting or
// option id with no known (or version-matched) definition renders as the
// raw id, explicitly marked unresolved — never a guess, never a prettified
// fake name, never a dropped row. One unresolved setting must never make
// the surrounding policy unreadable.
package intune

import "context"

// SettingOption is one selectable option of a choice-type setting
// definition (Graph's deviceManagementConfigurationOptionDefinition) —
// e.g. the "Enabled"/"Disabled" values of a boolean policy, or the entries
// of an enum.
type SettingOption struct {
	// ID is the raw Graph option id (Graph calls this itemId), e.g.
	// "device_vendor_msft_policy_config_bitlocker_requiredeviceencryption_1".
	ID          string
	DisplayName string
	Description string
}

// SettingDefinition is one Settings Catalog setting definition as returned
// by Microsoft Graph's setting-catalog definition endpoints, trimmed to the
// fields this package resolves against.
//
// Version is the Graph-reported definition version (Graph's own "version"
// field on deviceManagementConfigurationSettingDefinition, e.g. "1" or
// "2026-12-01"). Microsoft revises setting definitions between Intune
// releases without changing the definition ID, so Version is part of the
// cache key everywhere in this package — see DefinitionCache.
type SettingDefinition struct {
	ID          string
	Version     string
	DisplayName string
	Description string
	// Options is empty for non-choice setting types (e.g. simple integer or
	// string settings, which have no enumerable options to resolve).
	Options []SettingOption
}

// findOption returns the option within d.Options whose ID matches optionID.
func (d SettingDefinition) findOption(optionID string) (SettingOption, bool) {
	for _, o := range d.Options {
		if o.ID == optionID {
			return o, true
		}
	}
	return SettingOption{}, false
}

// DefinitionCache is the read seam Resolver uses to look up a cached
// SettingDefinition. Implementations must key strictly on (definitionID,
// version): a definition cached under one version must never be returned
// for a lookup at a different version. Get itself must be a pure,
// network-free lookup — the fetch-and-populate path lives in
// settingscatalog_source.go / settingscatalog_store.go, deliberately kept
// out of this interface so Resolver stays unit-testable with zero network
// calls (a fixture map is a valid DefinitionCache).
type DefinitionCache interface {
	// Get returns the cached definition for exactly (definitionID,
	// version). found is false when no definition is cached under that
	// exact (id, version) pair — including when a definition IS cached
	// under the same id but a different version, which callers must treat
	// identically to "id never seen" (see UnresolvedReason).
	Get(ctx context.Context, definitionID, version string) (def SettingDefinition, found bool, err error)
}

// VersionAwareCache is an optional extension of DefinitionCache. A cache
// that implements it lets Resolver report the more specific
// ReasonVersionMismatch (a definition is cached, just not at the requested
// version) instead of the generic ReasonUnknownDefinition. It is purely
// diagnostic — CachedVersion is never consulted to decide whether
// resolution succeeds, only to explain why it didn't — so a cache that
// doesn't implement it (e.g. a bare fixture map in a test) still resolves
// correctly, just with a less specific Reason on a miss.
type VersionAwareCache interface {
	DefinitionCache
	// CachedVersion reports the version currently cached for
	// definitionID, if any (regardless of what version a caller actually
	// asked Get for).
	CachedVersion(ctx context.Context, definitionID string) (version string, found bool, err error)
}

// UnresolvedReason classifies why Resolve produced an unresolved result.
// Kept as a distinct type (not a bare bool) so callers and tests can assert
// on *why* a row is unresolved, not just that it is.
type UnresolvedReason string

const (
	// ReasonResolved: not actually unresolved. Zero value for a resolved
	// Resolution.
	ReasonResolved UnresolvedReason = ""
	// ReasonUnknownDefinition: no definition is cached for this
	// definition ID at all (any version).
	ReasonUnknownDefinition UnresolvedReason = "unknown_definition"
	// ReasonVersionMismatch: a definition IS cached for this definition
	// ID, but not at the requested version. Applying that cached name to
	// this version's setting would risk showing a name Microsoft has since
	// changed the meaning of — so it resolves as unresolved, same as an
	// unknown definition, not as a best-effort guess.
	ReasonVersionMismatch UnresolvedReason = "version_mismatch"
	// ReasonUnknownOption: the definition resolved, but optionID was
	// non-empty and did not match any of the definition's known options.
	ReasonUnknownOption UnresolvedReason = "unknown_option"
	// ReasonCacheError: the cache lookup itself failed (e.g. a DB error).
	// Distinct from "not found" — this is an infrastructure failure, not a
	// statement about whether Microsoft has a definition for this id.
	ReasonCacheError UnresolvedReason = "cache_error"
)

// Resolution is the result of resolving one (definition id, version, option
// id) tuple. It always carries the raw ids it was asked to resolve,
// resolved or not, so a caller can render the raw id when Resolved is
// false — the row is never dropped or hidden.
type Resolution struct {
	// RawDefinitionID and RawOptionID are exactly what was requested,
	// regardless of whether resolution succeeded.
	RawDefinitionID string
	RawOptionID     string // empty when the caller had no option id to resolve

	Resolved bool
	Reason   UnresolvedReason // ReasonResolved when Resolved is true

	// DisplayName/Description describe the setting itself. Populated once
	// the definition itself resolves, which includes the ReasonUnknownOption
	// case (Resolved is false there, but the setting's own name/description
	// are still true and safe to show — only OptionDisplayName/
	// OptionDescription are withheld). Empty in every other unresolved case
	// (ReasonUnknownDefinition, ReasonVersionMismatch, ReasonCacheError).
	// Callers must switch on Reason, not just Resolved, to know which of the
	// two are safe to render.
	DisplayName string
	Description string

	// OptionDisplayName/OptionDescription describe the specific option,
	// populated only when Resolved is true AND RawOptionID was non-empty.
	OptionDisplayName string
	OptionDescription string
}

// Resolver turns raw Settings Catalog ids into human-readable names using a
// DefinitionCache. Resolver makes no network calls of its own — it only
// reads Cache — so it is safe to unit test against a fixture cache with no
// network access at all.
type Resolver struct {
	Cache DefinitionCache
}

// NewResolver builds a Resolver backed by cache.
func NewResolver(cache DefinitionCache) *Resolver {
	return &Resolver{Cache: cache}
}

// Resolve resolves one setting definition id (at definitionVersion) and,
// when optionID is non-empty, one option id within that definition's
// options.
//
// Resolve never guesses. Any of the following renders as an explicit
// unresolved Resolution carrying the raw id(s), never a partial or
// prettified name:
//   - no definition is cached for definitionID at all;
//   - a definition IS cached for definitionID, but under a different
//     version than definitionVersion (a stale-version cache hit);
//   - optionID is non-empty but does not match any option on the resolved
//     definition.
//
// A cache lookup failure (err != nil from Cache.Get) is surfaced as an
// unresolved Resolution with ReasonCacheError rather than as a returned
// error, so one broken lookup degrades to an unresolved row instead of
// aborting whatever batch of settings the caller is rendering — the same
// "surrounding rows must still render" contract applies whether the id is
// merely unknown or the cache itself is having a bad day. The error is
// preserved in the returned error value too, for callers that want to log
// or alert on cache infrastructure trouble distinctly from a normal
// resolution miss.
func (r *Resolver) Resolve(ctx context.Context, definitionID, definitionVersion, optionID string) (Resolution, error) {
	res := Resolution{
		RawDefinitionID: definitionID,
		RawOptionID:     optionID,
	}

	def, found, err := r.Cache.Get(ctx, definitionID, definitionVersion)
	if err != nil {
		res.Reason = ReasonCacheError
		return res, err
	}
	if !found {
		// Distinguish "never heard of this id" from "know this id, but not
		// at this version" purely for a more useful Reason — either way the
		// behaviour is identical: unresolved, raw id preserved.
		res.Reason = ReasonUnknownDefinition
		if vac, ok := r.Cache.(VersionAwareCache); ok {
			if _, knownAtAnyVersion, verr := vac.CachedVersion(ctx, definitionID); verr == nil && knownAtAnyVersion {
				res.Reason = ReasonVersionMismatch
			}
		}
		return res, nil
	}

	res.Resolved = true
	res.DisplayName = def.DisplayName
	res.Description = def.Description

	if optionID == "" {
		return res, nil
	}

	opt, ok := def.findOption(optionID)
	if !ok {
		// The setting definition itself resolved; only the option didn't.
		// Keep the setting's own name/description (still true and useful)
		// but mark the whole Resolution unresolved: a caller rendering
		// "DisplayName: OptionDisplayName" must not print "DisplayName: "
		// followed by a raw GUID as if that were normal.
		res.Resolved = false
		res.Reason = ReasonUnknownOption
		return res, nil
	}

	res.OptionDisplayName = opt.DisplayName
	res.OptionDescription = opt.Description
	return res, nil
}
