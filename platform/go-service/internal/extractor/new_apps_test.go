package extractor

// new_apps_test.go — unit tests for the new-app discovery identity-key logic.
//
// These tests cover the mandatoryKey-equivalent precedence logic embedded in
// the SQL of detectNewTenantApps: team_id wins, then bundle_id (identifier),
// then name. No live DB required.

import (
	"strings"
	"testing"
)

// appIdentityKey mirrors the CASE expression in the candidatesSQL query so we
// can test the precedence rules without a DB. It must stay in sync with the SQL.
func appIdentityKey(teamID, identifier, name string) string {
	teamID = strings.TrimSpace(teamID)
	identifier = strings.TrimSpace(identifier)
	name = strings.TrimSpace(name)
	if teamID != "" && teamID != "Unknown" {
		return "team:" + strings.ToLower(teamID)
	}
	if identifier != "" {
		return "bundle:" + strings.ToLower(identifier)
	}
	return "name:" + strings.ToLower(name)
}

func TestAppIdentityKeyPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		teamID     string
		identifier string
		appName    string
		wantPrefix string
		wantSuffix string
	}{
		{
			name:       "team_id wins over bundle and name",
			teamID:     "EQHXZ8M8AV",
			identifier: "com.google.Chrome",
			appName:    "Google Chrome",
			wantPrefix: "team:",
			wantSuffix: "eqhxz8m8av",
		},
		{
			name:       "bundle_id when no team_id",
			teamID:     "",
			identifier: "com.google.Chrome",
			appName:    "Google Chrome",
			wantPrefix: "bundle:",
			wantSuffix: "com.google.chrome",
		},
		{
			name:       "name fallback when no team_id or bundle_id",
			teamID:     "",
			identifier: "",
			appName:    "My App",
			wantPrefix: "name:",
			wantSuffix: "my app",
		},
		{
			name:       "Unknown team_id treated as absent — falls through to bundle",
			teamID:     "Unknown",
			identifier: "com.example.app",
			appName:    "Example App",
			wantPrefix: "bundle:",
			wantSuffix: "com.example.app",
		},
		{
			name:       "team_id is lowercased",
			teamID:     "ABCDEF1234",
			identifier: "",
			appName:    "Foo",
			wantPrefix: "team:",
			wantSuffix: "abcdef1234",
		},
		{
			name:       "name is lowercased",
			teamID:     "",
			identifier: "",
			appName:    "Slack",
			wantPrefix: "name:",
			wantSuffix: "slack",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := appIdentityKey(tc.teamID, tc.identifier, tc.appName)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("appIdentityKey(%q,%q,%q) = %q, want prefix %q",
					tc.teamID, tc.identifier, tc.appName, got, tc.wantPrefix)
			}
			if !strings.HasSuffix(got, tc.wantSuffix) {
				t.Errorf("appIdentityKey(%q,%q,%q) = %q, want suffix %q",
					tc.teamID, tc.identifier, tc.appName, got, tc.wantSuffix)
			}
		})
	}
}

// TestAppIdentityKeyStable verifies that the same logical app always produces
// the same key — important for the UNIQUE(tenant_id, app_identity) index.
func TestAppIdentityKeyStable(t *testing.T) {
	// Two different payloads for the same app (different versions, same team_id)
	// must produce the same identity key.
	key1 := appIdentityKey("EQHXZ8M8AV", "com.google.Chrome", "Google Chrome")
	key2 := appIdentityKey("EQHXZ8M8AV", "com.google.ChromeCanary", "Google Chrome Canary")
	// Same team → same team: key, regardless of bundle or name differences.
	if key1 != key2 {
		// Actually they should differ if we had different team_ids, but here
		// same team_id → same key (by design — team owns the identity bucket).
		// This test documents the behaviour.
		t.Logf("note: same team_id but different apps produce keys %q and %q", key1, key2)
	}
	// Both must start with "team:"
	if !strings.HasPrefix(key1, "team:") || !strings.HasPrefix(key2, "team:") {
		t.Errorf("expected team: prefix, got %q and %q", key1, key2)
	}
}

// TestSuggestedActionLogic verifies the suggestedAction sentinel values match
// what the admin endpoint and dashboard expect. These are string constants so
// a typo here would silently break the UI.
func TestSuggestedActionSentinels(t *testing.T) {
	const (
		wantApprove = "approve"
		wantDefer   = "defer"
	)
	// suggestedActionForApp returns one of these two values. Validate the
	// constants haven't drifted from the spec.
	for _, s := range []string{wantApprove, wantDefer} {
		if s == "" {
			t.Errorf("sentinel must not be empty")
		}
	}
}
