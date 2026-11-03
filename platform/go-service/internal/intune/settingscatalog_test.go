package intune

// Pure resolution tests: no network, no database. fixtureCache is an
// in-memory DefinitionCache built directly from a literal fixture map, so
// these tests exercise exactly Resolver.Resolve's logic.

import (
	"context"
	"testing"
)

// fixtureCache is a minimal in-memory DefinitionCache/VersionAwareCache
// keyed on "definitionID\x00version", used only by these fixture-based
// tests — the production cache is PostgresDefinitionStore.
type fixtureCache struct {
	byKey map[string]SettingDefinition
}

func newFixtureCache(defs ...SettingDefinition) *fixtureCache {
	c := &fixtureCache{byKey: map[string]SettingDefinition{}}
	for _, d := range defs {
		c.byKey[d.ID+"\x00"+d.Version] = d
	}
	return c
}

func (c *fixtureCache) Get(_ context.Context, definitionID, version string) (SettingDefinition, bool, error) {
	d, ok := c.byKey[definitionID+"\x00"+version]
	return d, ok, nil
}

func (c *fixtureCache) CachedVersion(_ context.Context, definitionID string) (string, bool, error) {
	for _, d := range c.byKey {
		if d.ID == definitionID {
			return d.Version, true, nil
		}
	}
	return "", false, nil
}

var _ DefinitionCache = (*fixtureCache)(nil)
var _ VersionAwareCache = (*fixtureCache)(nil)

const (
	bitlockerDef        = "device_vendor_msft_policy_config_bitlocker_requiredeviceencryption"
	bitlockerVersion    = "1"
	bitlockerOptEnabled = bitlockerDef + "_1"
)

func bitlockerFixture() SettingDefinition {
	return SettingDefinition{
		ID:          bitlockerDef,
		Version:     bitlockerVersion,
		DisplayName: "Require device encryption",
		Description: "Requires BitLocker device encryption for OS and fixed drives.",
		Options: []SettingOption{
			{ID: bitlockerOptEnabled, DisplayName: "Require", Description: "Encryption is required."},
			{ID: bitlockerDef + "_0", DisplayName: "Do not require", Description: "Encryption is not required."},
		},
	}
}

// TestResolve_KnownTuple_ResolvesCorrectly is the primary acceptance
// criterion: a known (definition id, version, option id) tuple against
// fixture definitions returns the correct display name/description, no
// network involved.
func TestResolve_KnownTuple_ResolvesCorrectly(t *testing.T) {
	cache := newFixtureCache(bitlockerFixture())
	r := NewResolver(cache)

	got, err := r.Resolve(context.Background(), bitlockerDef, bitlockerVersion, bitlockerOptEnabled)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Resolved {
		t.Fatalf("Resolved = false, reason %q; want true", got.Reason)
	}
	if got.DisplayName != "Require device encryption" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "Require device encryption")
	}
	if got.Description != "Requires BitLocker device encryption for OS and fixed drives." {
		t.Errorf("Description = %q", got.Description)
	}
	if got.OptionDisplayName != "Require" {
		t.Errorf("OptionDisplayName = %q, want %q", got.OptionDisplayName, "Require")
	}
	if got.OptionDescription != "Encryption is required." {
		t.Errorf("OptionDescription = %q", got.OptionDescription)
	}
	if got.RawDefinitionID != bitlockerDef || got.RawOptionID != bitlockerOptEnabled {
		t.Errorf("raw ids not preserved: %+v", got)
	}
}

// TestResolve_DefinitionWithoutOptionID_ResolvesSettingOnly covers a
// non-choice setting (or a caller with no option to resolve): the setting
// itself still resolves without requiring an option id.
func TestResolve_DefinitionWithoutOptionID_ResolvesSettingOnly(t *testing.T) {
	cache := newFixtureCache(bitlockerFixture())
	r := NewResolver(cache)

	got, err := r.Resolve(context.Background(), bitlockerDef, bitlockerVersion, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Resolved {
		t.Fatalf("Resolved = false, reason %q; want true", got.Reason)
	}
	if got.DisplayName != "Require device encryption" {
		t.Errorf("DisplayName = %q", got.DisplayName)
	}
	if got.OptionDisplayName != "" {
		t.Errorf("OptionDisplayName = %q, want empty (no option id requested)", got.OptionDisplayName)
	}
}

// TestResolve_UnknownDefinition_ResolvesUnresolvedWithRawID: an
// unknown/withdrawn definition id resolves to the raw id, explicitly marked
// unresolved — never dropped, never guessed.
func TestResolve_UnknownDefinition_ResolvesUnresolvedWithRawID(t *testing.T) {
	cache := newFixtureCache(bitlockerFixture())
	r := NewResolver(cache)

	const withdrawnID = "device_vendor_msft_policy_config_withdrawn_setting"
	got, err := r.Resolve(context.Background(), withdrawnID, "1", "some_option")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Resolved {
		t.Fatalf("Resolved = true for an unknown definition; want false")
	}
	if got.Reason != ReasonUnknownDefinition {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonUnknownDefinition)
	}
	if got.RawDefinitionID != withdrawnID {
		t.Errorf("RawDefinitionID = %q, want %q (raw id must be preserved)", got.RawDefinitionID, withdrawnID)
	}
	if got.DisplayName != "" || got.OptionDisplayName != "" {
		t.Errorf("unresolved Resolution must carry no display name; got %+v", got)
	}
}

// TestResolve_VersionMismatch_DoesNotApplyStaleCachedName is the exact
// scenario the brief calls out: a definition cached under an OLDER
// catalogue version must not be applied to a policy citing a NEWER version.
// That must resolve as unresolved, not silently reuse the old name.
func TestResolve_VersionMismatch_DoesNotApplyStaleCachedName(t *testing.T) {
	cache := newFixtureCache(bitlockerFixture()) // cached at version "1"
	r := NewResolver(cache)

	const newerVersion = "2"
	got, err := r.Resolve(context.Background(), bitlockerDef, newerVersion, bitlockerOptEnabled)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Resolved {
		t.Fatalf("Resolved = true for a version-mismatched lookup; the stale v1 cached name must not have been applied to a v2 request. Got: %+v", got)
	}
	if got.Reason != ReasonVersionMismatch {
		t.Errorf("Reason = %q, want %q (a definition IS cached for this id, just at a different version)", got.Reason, ReasonVersionMismatch)
	}
	if got.DisplayName != "" {
		t.Errorf("DisplayName = %q; the v1 name must not leak into a v2 lookup", got.DisplayName)
	}
	if got.RawDefinitionID != bitlockerDef {
		t.Errorf("RawDefinitionID = %q, want %q", got.RawDefinitionID, bitlockerDef)
	}

	// Sanity check the fixture actually still resolves at its real version —
	// proves the miss above is specifically a version mismatch, not a
	// broken fixture.
	stillWorks, err := r.Resolve(context.Background(), bitlockerDef, bitlockerVersion, bitlockerOptEnabled)
	if err != nil {
		t.Fatalf("Resolve at correct version: %v", err)
	}
	if !stillWorks.Resolved {
		t.Fatalf("definition failed to resolve at its own cached version %q: %+v", bitlockerVersion, stillWorks)
	}
}

// TestResolve_UnknownOption_SettingResolvesOptionDoesNot: the definition
// is known, but the option id isn't one of its options (e.g. Microsoft
// added/removed choices between versions without bumping the definition
// version, or a caller passed a garbage option id). The whole Resolution
// still reports unresolved — a caller must not render "Require device
// encryption: <raw guid>" as if that were a normal option name — but the
// raw ids are preserved.
func TestResolve_UnknownOption_SettingResolvesOptionDoesNot(t *testing.T) {
	cache := newFixtureCache(bitlockerFixture())
	r := NewResolver(cache)

	const bogusOption = "not_a_real_option_id"
	got, err := r.Resolve(context.Background(), bitlockerDef, bitlockerVersion, bogusOption)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Resolved {
		t.Fatalf("Resolved = true for an unknown option id; want false")
	}
	if got.Reason != ReasonUnknownOption {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonUnknownOption)
	}
	if got.RawOptionID != bogusOption {
		t.Errorf("RawOptionID = %q, want %q", got.RawOptionID, bogusOption)
	}
	if got.OptionDisplayName != "" {
		t.Errorf("OptionDisplayName = %q, want empty", got.OptionDisplayName)
	}
}

// TestResolve_CacheError_DegradesToUnresolvedNotPanic: a broken cache
// lookup must degrade to an unresolved row (with the error also returned
// for callers that want to log it), never abort resolution of the whole
// batch of settings a caller is rendering.
func TestResolve_CacheError_DegradesToUnresolvedNotPanic(t *testing.T) {
	r := NewResolver(erroringCache{})

	got, err := r.Resolve(context.Background(), bitlockerDef, bitlockerVersion, "")
	if err == nil {
		t.Fatalf("expected the cache error to be surfaced")
	}
	if got.Resolved {
		t.Fatalf("Resolved = true despite a cache error")
	}
	if got.Reason != ReasonCacheError {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonCacheError)
	}
	if got.RawDefinitionID != bitlockerDef {
		t.Errorf("RawDefinitionID = %q, want %q even on cache error", got.RawDefinitionID, bitlockerDef)
	}
}

type erroringCache struct{}

func (erroringCache) Get(context.Context, string, string) (SettingDefinition, bool, error) {
	return SettingDefinition{}, false, errCacheBoom
}

var errCacheBoom = &cacheBoomError{}

type cacheBoomError struct{}

func (*cacheBoomError) Error() string { return "simulated cache infrastructure failure" }
