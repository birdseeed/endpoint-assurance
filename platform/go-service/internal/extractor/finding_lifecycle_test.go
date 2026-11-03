package extractor

import (
	"testing"
	"time"

	"patched.im/api/internal/apppolicy"
	"patched.im/api/internal/findinglifecycle"
)

func TestLifecycleObservationAuthoritativeRejectsMissingStaleAndFutureTimes(t *testing.T) {
	receivedAt := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		collectedAt time.Time
		receivedAt  time.Time
		want        bool
	}{
		{name: "current", collectedAt: receivedAt, receivedAt: receivedAt, want: true},
		{name: "oldest accepted", collectedAt: receivedAt.Add(-findinglifecycle.ObservationEvidenceMaxAge), receivedAt: receivedAt, want: true},
		{name: "too old", collectedAt: receivedAt.Add(-findinglifecycle.ObservationEvidenceMaxAge - time.Nanosecond), receivedAt: receivedAt, want: false},
		{name: "bounded clock skew", collectedAt: receivedAt.Add(findinglifecycle.ObservationFutureSkew), receivedAt: receivedAt, want: true},
		{name: "far future", collectedAt: receivedAt.Add(findinglifecycle.ObservationFutureSkew + time.Nanosecond), receivedAt: receivedAt, want: false},
		{name: "missing collection time", receivedAt: receivedAt, want: false},
		{name: "missing trusted receive time", collectedAt: receivedAt, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findinglifecycle.EvidenceTimeAuthoritative(tt.collectedAt, tt.receivedAt); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionBelowMinimumUnknownVersionCannotPass(t *testing.T) {
	minimum := "2.0"
	for _, version := range []string{"", "unknown", "1.0-beta"} {
		outcome, authoritative := versionBelowMinimumOutcome(true, &minimum, []appPart{{Version: version}}, true)
		if outcome != findinglifecycle.OutcomeUnknown || authoritative {
			t.Errorf("version %q: outcome=%q authoritative=%v, want unknown/false", version, outcome, authoritative)
		}
	}
}

func TestLifecycleUnapprovedUsesCanonicalCrossIdentitySpecificity(t *testing.T) {
	name := "Example App"
	bundleID := "com.example.app"
	policies := []apppolicy.Policy{
		{ID: 1, Name: &name, Platform: "any", Policy: "unapproved"},
		{ID: 2, BundleID: &bundleID, Platform: "macos", Policy: "approved"},
	}
	apps := []appPart{{Name: name, Identifier: bundleID}}
	index := apppolicy.BuildIndex(policies)
	if policySelectedForAnyApp(index, 1, apps, "macos") {
		t.Fatal("broad unapproved policy remained selected over specific approved policy")
	}
	selected, ok := index.Resolve("", bundleID, "", name, "macos")
	if !ok || selected.ID != 2 {
		t.Fatalf("selected policy=%+v ok=%v, want specific approved policy 2", selected, ok)
	}
}

func TestSoftwarePolicySnapshotPreservesEnforcementTier(t *testing.T) {
	policy := lifecycleSoftwarePolicy{
		ID: 42, Platform: "macos", Policy: "mandatory",
		EnforcementTier: "app_management",
	}
	snapshot := softwarePolicySnapshot(policy)
	if got := snapshot["enforcement_tier"]; got != "app_management" {
		t.Fatalf("enforcement_tier=%v, want app_management", got)
	}
}

func TestCompareLifecycleVersionsMatchesDriftContract(t *testing.T) {
	tests := []struct {
		installed string
		minimum   string
		wantSign  int
		wantKnown bool
	}{
		{installed: "1.2", minimum: "1.2.0", wantSign: 0, wantKnown: true},
		{installed: "1.2.9", minimum: "1.3", wantSign: -1, wantKnown: true},
		{installed: "2.0", minimum: "1.9", wantSign: 1, wantKnown: true},
		{installed: "", minimum: "1.0", wantKnown: false},
		{installed: "unknown", minimum: "1.0", wantKnown: false},
		{installed: "1.0-beta", minimum: "1.0", wantKnown: false},
	}
	for _, tt := range tests {
		got, known := compareLifecycleVersions(tt.installed, tt.minimum)
		if known != tt.wantKnown {
			t.Errorf("compareLifecycleVersions(%q, %q) known=%v, want %v", tt.installed, tt.minimum, known, tt.wantKnown)
			continue
		}
		if !known {
			continue
		}
		gotSign := 0
		if got < 0 {
			gotSign = -1
		} else if got > 0 {
			gotSign = 1
		}
		if gotSign != tt.wantSign {
			t.Errorf("compareLifecycleVersions(%q, %q) sign=%d, want %d", tt.installed, tt.minimum, gotSign, tt.wantSign)
		}
	}
}
