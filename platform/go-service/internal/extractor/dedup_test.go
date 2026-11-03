package extractor

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestIsHelperBundle covers the Layer A suppression logic (PAT-594).
func TestIsHelperBundle(t *testing.T) {
	// A minimal payload with a parent app and a variety of helpers.
	payload := []appPart{
		{Name: "Slack", Identifier: "com.tinyspeck.slackmacgap"},
		{Name: "Slack Helper", Identifier: "com.tinyspeck.slackmacgap.helper"},
		{Name: "Slack Helper (GPU)", Identifier: "com.tinyspeck.slackmacgap.helper.GPU"},
		{Name: "Slack Helper (Renderer)", Identifier: "com.tinyspeck.slackmacgap.helper.Renderer"},
		{Name: "Slack Helper (Plugin)", Identifier: "com.tinyspeck.slackmacgap.helper.Plugin"},
		{Name: "Slack Crashpad", Identifier: "com.tinyspeck.slackmacgap.crashpad"},
		{Name: "SomeXPC", Identifier: "com.tinyspeck.slackmacgap.xpc"},
		{Name: "SomeAgent", Identifier: "com.tinyspeck.slackmacgap.agent"},
		// SandboxHelper suffix
		{Name: "Sandbox Helper", Identifier: "com.tinyspeck.slackmacgap.SandboxHelper"},
	}

	cases := []struct {
		name       string
		identifier string
		appName    string
		want       bool
	}{
		// Parent — must NOT be suppressed.
		{"parent kept", "com.tinyspeck.slackmacgap", "Slack", false},
		// Helpers with parent present — must be suppressed.
		{".helper suppressed", "com.tinyspeck.slackmacgap.helper", "Slack Helper", true},
		{".helper.GPU suppressed", "com.tinyspeck.slackmacgap.helper.GPU", "Slack Helper (GPU)", true},
		{".helper.Renderer suppressed", "com.tinyspeck.slackmacgap.helper.Renderer", "Slack Helper (Renderer)", true},
		{".helper.Plugin suppressed", "com.tinyspeck.slackmacgap.helper.Plugin", "Slack Helper (Plugin)", true},
		{".crashpad suppressed", "com.tinyspeck.slackmacgap.crashpad", "Slack Crashpad", true},
		{".xpc suppressed", "com.tinyspeck.slackmacgap.xpc", "SomeXPC", true},
		{".agent suppressed", "com.tinyspeck.slackmacgap.agent", "SomeAgent", true},
		{".SandboxHelper suppressed", "com.tinyspeck.slackmacgap.SandboxHelper", "Sandbox Helper", true},
		// Name-prefix suppression (Electron helper name, no bundle match needed).
		{"Electron Helper by name", "", "Electron Helper", true},
		{"Electron Helper (GPU) by name", "", "Electron Helper (GPU)", true},
		{"Electron Helper (Renderer) by name", "", "Electron Helper (Renderer)", true},
		// Helper suffix but parent NOT present → keep.
		{"helper with no parent kept", "com.orphan.app.helper", "Orphan Helper", false},
		// Empty identifier and non-helper name → not suppressed.
		{"empty identifier non-helper", "", "Notion", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isHelperBundle(tc.identifier, tc.appName, payload)
			if got != tc.want {
				t.Errorf("isHelperBundle(%q, %q) = %v, want %v", tc.identifier, tc.appName, got, tc.want)
			}
		})
	}
}

// TestApplyGroupRule covers the Layer B vendor prefix grouping (PAT-594).
func TestApplyGroupRule(t *testing.T) {
	rules := []appGroupRule{
		{BundlePrefix: "us.zoom.", CanonicalLabel: "zoom", CanonicalName: "Zoom"},
		{BundlePrefix: "com.discord.", CanonicalLabel: "discord", CanonicalName: "Discord"},
		{BundlePrefix: "com.spotify.", CanonicalLabel: "spotify", CanonicalName: "Spotify"},
	}

	cases := []struct {
		name       string
		identifier string
		appName    string
		wantName   string
	}{
		// Zoom sub-bundle gets canonical name.
		{"zoom sub-bundle", "us.zoom.xos.ZoomAirHost", "Zoom Meeting", "Zoom"},
		{"zoom root bundle", "us.zoom.xos", "zoom.us", "Zoom"},
		// Discord sub-bundle.
		{"discord sub-bundle", "com.discord.DiscordHelper", "Discord Helper", "Discord"},
		// Spotify.
		{"spotify", "com.spotify.client", "Spotify", "Spotify"},
		// No match — name unchanged.
		{"no match", "com.apple.Safari", "Safari", "Safari"},
		// Empty identifier — name unchanged.
		{"empty identifier", "", "Unknown App", "Unknown App"},
		// Empty rules — name unchanged.
		{"empty rules", "us.zoom.xos", "Zoom Meeting", "Zoom Meeting"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := rules
			if tc.name == "empty rules" {
				r = nil
			}
			got := applyGroupRule(tc.identifier, tc.appName, r)
			if got != tc.wantName {
				t.Errorf("applyGroupRule(%q, %q) = %q, want %q", tc.identifier, tc.appName, got, tc.wantName)
			}
		})
	}
}

// TestLoadAppGroupRulesRetainsHistoricalInstallomatorRows_DB proves retirement
// removes the fetch/write path without discarding canonical identity mappings
// already persisted by that path. It makes no durable change: both fixtures
// live inside a rolled-back transaction.
func TestLoadAppGroupRulesRetainsHistoricalInstallomatorRows_DB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping app-group-rule DB test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const (
		manualPrefix = "im.patched.retirement.manual."
		legacyPrefix = "im.patched.retirement.legacy."
	)
	for _, fixture := range []struct {
		prefix, label, name, source string
	}{
		{manualPrefix, "curated-test", "Curated Test", "manual"},
		{legacyPrefix, "retired-test", "Retired Test", "installomator_sync"},
	} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_group_rules (bundle_prefix, canonical_label, canonical_name, source)
			VALUES ($1, $2, $3, $4)
		`, fixture.prefix, fixture.label, fixture.name, fixture.source); err != nil {
			t.Fatalf("seed %s app-group rule: %v", fixture.source, err)
		}
	}

	rules, err := loadAppGroupRules(ctx, tx)
	if err != nil {
		t.Fatalf("load app-group rules: %v", err)
	}
	var manualFound, historicalFound bool
	for _, rule := range rules {
		switch rule.BundlePrefix {
		case manualPrefix:
			manualFound = true
			if got := applyGroupRule(manualPrefix+"bundle", "Unresolved", rules); got != "Curated Test" {
				t.Fatalf("manual app-group rule resolved %q, want Curated Test", got)
			}
		case legacyPrefix:
			historicalFound = true
			if got := applyGroupRule(legacyPrefix+"bundle", "Unresolved", rules); got != "Retired Test" {
				t.Fatalf("historical app-group rule resolved %q, want Retired Test", got)
			}
		}
	}
	if !manualFound {
		t.Fatal("manual app-group rule was excluded")
	}
	if !historicalFound {
		t.Fatal("historical Installomator app-group rule was excluded")
	}
}
